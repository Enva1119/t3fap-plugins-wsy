# -*- coding: utf-8 -*-
"""把剥壳服务挂到 T3FAP 自己的 FastAPI 应用上，共用 8521 端口。

为什么要这么干
--------------
T3FAP 的 STRM 播放入口 `/api/strm/o/<token>` 是**内核直接 302 到上游地址**
（实测 `Server: uvicorn`，302 目标 `oss.douyinbit.com`），跳完就出了 T3FAP，
解析链根本没有参与，18521 那个独立端口也没有被任何一方请求过。

但 T3FAP 是 FastAPI，插件和它跑在**同一个进程**里，`sys.modules` 里就躺着
主应用对象。所以可以 `app.mount("/api/strm/pngu", <ASGI app>)` —— 挂完之后：

    http://<NAS>:8521/api/strm/pngu/hls/u/<base64>.m3u8

播放器只碰 8521 这一个端口，不需要额外映射、不需要改 compose，其它平台的
片子照常走原来的路由（这个前缀是独立的，不影响任何已有路径）。

安全性
------
1. 整个过程包在 try/except 里，找不到 app、挂载报错、前缀冲突 —— 一律静默
   降级，只记一条日志，绝不影响插件加载与平台启动。
2. 只注册**一个**前缀，不在 `/` 上做任何事。
3. 二次挂载会先检查是否已存在同前缀路由，避免重复。
"""

from __future__ import annotations

import asyncio
import logging

log = logging.getLogger("pngunwrap.mount")

# 挂载前缀。选在 /api/strm/ 下面有两个理由：
#   1) 这个前缀在平台上本来就是**公开**的（播放器不带 token 也能 302），
#      放到别的前缀可能被鉴权中间件拦成 401；
#   2) 语义上它确实是 strm 播放入口的一部分，不容易和后台 API 混淆。
PREFIX = "/api/strm/pngu"

_STATE = {"mounted": False, "prefix": "", "app": "", "reason": ""}


def state():
    """给 health / 诊断接口看的挂载状态。"""
    return dict(_STATE)


def find_apps():
    """在已加载的模块里找 FastAPI / Starlette 主应用。

    不写死 `from core.main import app` 之类的路径 —— 平台内部模块名随版本变，
    遍历 `sys.modules` 找带 `mount` 方法且类名是 FastAPI/Starlette 的对象更稳。
    找不到就返回空列表，调用方静默降级。
    """
    import sys

    found = []
    for name, mod in list(sys.modules.items()):
        if mod is None or name.startswith("pngu"):
            continue
        try:
            obj = getattr(mod, "app", None)
        except Exception:                           # noqa: BLE001
            continue
        if obj is None:
            continue
        cls = type(obj).__name__
        if cls in ("FastAPI", "Starlette") and hasattr(obj, "mount"):
            found.append((name, obj))
    return found


def _build_asgi(proxy, prefix):
    """构造转发到 handle_path 的 ASGI 应用。"""
    import urllib.parse

    import pngu_proxy

    async def app(scope, receive, send):
        if scope.get("type") != "http":
            return
        method = (scope.get("method") or "GET").upper()
        # Starlette 不同版本对 Mount 的 path 处理不一致：新版本会裁掉前缀，
        # 旧版本 path 仍是全路径。两种都兼容 —— 看到前缀就从 path 里去掉。
        path = scope.get("path") or "/"
        if path.startswith(prefix):
            path = path[len(prefix):] or "/"

        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in (scope.get("headers") or [])}
        host = headers.get("host") or ""
        scheme = scope.get("scheme") or "http"
        # 清单里的分片地址按**播放器实际访问的地址**生成，这样局域网 IP 和
        # DDNS 域名访问同一个会话都能用。
        base = "%s://%s" % (scheme, host) if host else ""
        if proxy.public_base:
            base = proxy.public_base
        seg_prefix = "%s%s" % (base.rstrip("/"), prefix)

        try:
            # 先问「接管」模块：它自带会话与分片缓存，完全不依赖 HlsProxy，
            # 即使内存里的 pngu_proxy 是旧版（没有 handle_path）也能工作。
            import pngu_hijack
            hit = pngu_hijack.serve(path)
        except Exception as e:                      # noqa: BLE001
            log.warning("接管路由处理 %s 失败：%s", path, e)
            hit = None

        if hit is not None:
            code, ctype, blob = hit
        else:
            try:
                code, ctype, blob = await asyncio.to_thread(
                    pngu_proxy.handle_path, proxy, path, "", seg_prefix)
            except AttributeError as e:
                # 旧版 pngu_proxy 没有 handle_path —— 只影响 /hls/u/ 手动入口，
                # STRM 接管那条路不经过这里。
                log.warning("内建 handle_path 不可用（模块版本过旧）：%s", e)
                code, ctype, blob = 503, "application/json; charset=utf-8", (
                    b'{"ok": false, "error": "proxy module too old, restart t3fap"}')
            except Exception as e:                  # noqa: BLE001
                log.warning("平台内路由处理 %s 失败：%s", path, e)
                code, ctype, blob = 502, "application/json; charset=utf-8", (
                    '{"ok": false, "error": "%s: %s"}' %
                    (type(e).__name__, str(e).replace('"', "'")[:200])).encode()

        try:
            st, body, hdrs = pngu_proxy._range_of(blob, headers.get("range", ""))
        except Exception:                           # noqa: BLE001
            st, body, hdrs = code, blob, {}
        if st != 206:
            st = code

        raw = [(b"content-type", ctype.encode("latin-1"))]
        for k, v in hdrs.items():
            raw.append((k.lower().encode("latin-1"), str(v).encode("latin-1")))

        await send({"type": "http.response.start", "status": st,
                    "headers": raw})
        if method == "HEAD":
            await send({"type": "http.response.body", "body": b""})
        else:
            await send({"type": "http.response.body", "body": body})

    return app


def mount(proxy, prefix=PREFIX):
    """尝试把服务挂到平台应用上。返回 (ok, message)，永不抛。"""
    if _STATE["mounted"]:
        return True, "已挂载在 %s" % _STATE["prefix"]
    try:
        apps = find_apps()
        if not apps:
            _STATE["reason"] = "没在 sys.modules 里找到 FastAPI 应用"
            return False, _STATE["reason"]

        asgi = _build_asgi(proxy, prefix)
        last = ""
        for name, app in apps:
            try:
                # 已有同前缀就不重复挂
                existing = [getattr(r, "path", "")
                            for r in getattr(app, "routes", [])]
                if any(p == prefix for p in existing):
                    _STATE.update(mounted=True, prefix=prefix,
                                  app=name, reason="")
                    return True, "已存在，复用 %s（%s）" % (prefix, name)
                app.mount(prefix, asgi)
                _STATE.update(mounted=True, prefix=prefix, app=name, reason="")
                log.info("已把剥壳服务挂到平台应用 %s 的 %s", name, prefix)
                return True, "已挂载到 %s 的 %s" % (name, prefix)
            except Exception as e:                  # noqa: BLE001
                last = "%s: %s" % (type(e).__name__, e)
                log.warning("挂载到 %s 失败：%s", name, last)
        _STATE["reason"] = last or "没有可挂载的应用"
        return False, _STATE["reason"]
    except Exception as e:                          # noqa: BLE001
        _STATE["reason"] = "%s: %s" % (type(e).__name__, e)
        log.warning("挂载异常：%s", _STATE["reason"])
        return False, _STATE["reason"]


def unmount():
    """卸载时把路由摘掉，避免残留。

    用**原地删除**而不是 `router.routes = [...]`：Starlette 的 `app.routes`
    是 `router.routes` 的 property，替换列表会让部分引用失效；原地 del 对
    所有持有同一 list 的地方都生效。
    """
    if not _STATE["mounted"]:
        return
    try:
        apps = find_apps()
        prefix = _STATE["prefix"]
        for name, app in apps:
            router = getattr(app, "router", None)
            routes = getattr(router, "routes", None)
            if not isinstance(routes, list):
                continue
            hit = 0
            for i in range(len(routes) - 1, -1, -1):
                if getattr(routes[i], "path", "") == prefix:
                    del routes[i]
                    hit += 1
            if hit:
                log.info("已从 %s 摘掉 %s（%d 条）", name, prefix, hit)
    except Exception as e:                          # noqa: BLE001
        log.warning("卸载路由失败（不影响运行）：%s", e)
    finally:
        _STATE.update(mounted=False, prefix="", app="", reason="")


# 模块自述版本。plugin.py 会拿它和磁盘上的文件比对，不一致就说明平台热更新
# 只重载了 plugin 模块、子模块还留在 sys.modules 里，需要 importlib.reload。
__version__ = "0.4.1"
