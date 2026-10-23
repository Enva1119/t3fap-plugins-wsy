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


def _is_app(obj):
    """鸭子类型判断一个对象是不是 Starlette/FastAPI 应用。

    不看类名看结构：`mount()` + `router.routes` 是列表。这样平台的子应用、
    被包过一层的中间件宿主都能识别出来。
    """
    if obj is None:
        return False
    try:
        if not hasattr(obj, "mount"):
            return False
        router = getattr(obj, "router", None)
        return isinstance(getattr(router, "routes", None), list)
    except Exception:                               # noqa: BLE001
        return False


def _scan_modules():
    """扫 `sys.modules` 里所有模块的属性，收集应用对象。

    比只认 `mod.app` 宽得多：平台可能把 app 放在 `mod.application`、
    `mod.server.app`、`mod.runtime.app` 甚至某个容器对象里。这里把模块级
    属性逐个看一遍，再往 dict / list / 单层对象属性里探一层。
    """
    import sys

    found, seen = [], set()

    def push(name, obj):
        if not _is_app(obj) or id(obj) in seen:
            return
        seen.add(id(obj))
        found.append((name, obj))

    for mod_name, mod in list(sys.modules.items()):
        if mod is None or mod_name.startswith("pngu"):
            continue
        try:
            items = list(vars(mod).items())
        except Exception:                           # noqa: BLE001
            continue
        for attr, val in items:
            push("%s.%s" % (mod_name, attr), val)
            if isinstance(val, dict):
                for k, v in list(val.items())[:40]:
                    push("%s.%s[%s]" % (mod_name, attr, k), v)
            elif isinstance(val, (list, tuple)):
                for i, v in enumerate(list(val)[:40]):
                    push("%s.%s[%d]" % (mod_name, attr, i), v)

    # gc 兜底：**每次都扫**，不是只在「一条都没找到」时扫。
    # 平台很可能 `app = create_app()` 只活在函数里、由 uvicorn 用工厂串起来，
    # 模块属性里一个 app 都没有；此时只找到插件宿主那类次级 app，
    # 于是「挂载成功、接管却匹配不到路由」。类名是 FastAPI/Starlette 的对象
    # 就那么几个，一次扫描几十毫秒，只在启动/改配置时跑。
    try:
        import gc
        for obj in gc.get_objects():
            try:
                if type(obj).__name__ in ("FastAPI", "Starlette"):
                    push("gc:%s" % id(obj), obj)
            except Exception:                       # noqa: BLE001
                continue
    except Exception as e:                          # noqa: BLE001
        log.info("gc 兜底扫描失败（忽略）：%s", e)

    return found


def _iter_routes(app, prefix="", depth=0, root=None):
    """递归产出 (完整路径, 路由对象, **根应用**)。

    平台可能把 STRM 路由直接挂在主 app 上，也可能 `app.mount("/api", 子应用)`，
    甚至套两层。Mount 的 `path` 只是前缀，真正的路由在它挂的子应用里 ——
    所以要按 Mount 递归下去，并把前缀拼成完整路径。

    第三个元素固定返回**根应用**，因为挂载必须挂在对外服务的那个 app 上：
    挂到子应用上会变成 `/api/api/strm/pngu`，播放器访问不到。
    """
    root = root if root is not None else app
    router = getattr(app, "router", None) or app
    routes = getattr(router, "routes", None)
    if not isinstance(routes, list):
        return
    for route in list(routes):
        path = getattr(route, "path", "")
        full = (prefix + path) if isinstance(path, str) else ""
        if full:
            yield full, route, root
        if depth >= 3:
            continue
        sub = getattr(route, "app", None)
        if sub is None or not hasattr(sub, "routes"):
            continue
        for item in _iter_routes(sub, full, depth + 1, root):
            yield item


def _looks_strm(full):
    from pngu_hijack import INCLUDE_PREFIX, SELF_PREFIX
    if not isinstance(full, str):
        return False
    if not full.startswith(INCLUDE_PREFIX):
        return False
    if full.startswith(SELF_PREFIX):
        return False
    return full.endswith(".m3u8")


def strm_routes():
    """找出所有 STRM 播放入口路由，返回 [(应用名, 应用, 完整路径, 路由)]。

    0.4.1 只认「主 app 的 `router.routes` 里 path 以 `/api/strm/` 开头」，
    真机上因此报「没有匹配到 STRM 播放路由」——挂载却成功了，说明找到的
    app 跟真正在播的那个不是同一层。现在改成按**路由归属**找应用。
    """
    out, seen = [], set()
    for name, app in _scan_modules():
        for full, route, owner in _iter_routes(app):
            if not _looks_strm(full):
                continue
            key = (id(owner), full)
            if key in seen:
                continue
            seen.add(key)
            out.append((name, owner, full, route))
    return out


def find_apps():
    """可能承载平台 HTTP 服务的应用，**持有 STRM 路由的排在最前面**。

    排第一位的会被 `mount()` 用作挂载目标 —— 这一点很关键：如果挂到了
    一个不对外服务的 app 上，`/api/strm/pngu/...` 虽然「挂载成功」，
    播放器却访问不到。
    """
    apps = _scan_modules()
    owners = {id(owner) for _n, owner, _p, _r in strm_routes()}
    first = [(n, a) for n, a in apps if id(a) in owners]
    rest = [(n, a) for n, a in apps if id(a) not in owners]
    return first + rest


def diagnose():
    """排障用：找到几个应用、各自有没有 STRM 路由。"""
    apps = []
    for name, app in _scan_modules():
        paths = [p for p, _r, _o in _iter_routes(app)]
        apps.append({
            "module": name,
            "class": type(app).__name__,
            "routes": len(paths),
            "strm": [p for p in paths if "strm" in p][:12],
            "m3u8": len([p for p in paths if p.endswith(".m3u8")]),
        })
    apps.sort(key=lambda a: -len(a["strm"]))
    return {"apps": apps[:10], "mount": state()}


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


def _move_front(app, prefix):
    """把刚挂上去的那条 Mount 挪到路由表最前面。

    Starlette 按注册顺序匹配。平台常见写法是 `app.mount("/api", 子应用)`，
    它一旦排在我们前面，`/api/strm/pngu/...` 就会先进子应用、拿到 404。
    我们只占 `/api/strm/pngu` 这一个前缀，放最前面不影响任何已有路径。
    """
    try:
        routes = getattr(getattr(app, "router", None), "routes", None)
        if not isinstance(routes, list):
            return False
        idx = None
        for i in range(len(routes) - 1, -1, -1):
            r = routes[i]
            if getattr(r, "path", "") != prefix:
                continue
            # 只挪我们自己的（新挂的是最后一个匹配项）
            idx = i
            break
        if idx is None or idx == 0:
            return idx == 0
        routes.insert(0, routes.pop(idx))
        return True
    except Exception as e:                          # noqa: BLE001
        log.info("调整挂载顺序失败（忽略）：%s", e)
        return False


def mount(proxy, prefix=PREFIX):
    """尝试把服务挂到平台应用上。返回 (ok, message)，永不抛。

    挂载目标优先选**持有 STRM 路由的那个应用** —— 挂到别的 app 上虽然也会
    报成功，但播放器根本访问不到那个前缀。
    """
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
                    _move_front(app, prefix)
                    _STATE.update(mounted=True, prefix=prefix,
                                  app=name, reason="")
                    return True, "已存在，复用 %s（%s）" % (prefix, name)
                app.mount(prefix, asgi)
                # **插到最前面**。平台可能 `app.mount("/api", 子应用)`，
                # 那样 `/api/strm/pngu/...` 会先命中那个 Mount 被判 404 ——
                # Starlette 按顺序匹配，只有排到它前面才轮得到我们。
                _move_front(app, prefix)
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
__version__ = "0.4.3"
