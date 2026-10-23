# -*- coding: utf-8 -*-
"""包住平台内核的 STRM 播放入口，让**已有的 .strm 文件不用改**就能剥壳。

为什么必须这么做
----------------
`/api/strm/o/<token>.m3u8` 是内核直接 302 到上游地址（实测 `Server: uvicorn`，
302 目标 `oss.douyinbit.com`）。跳完播放器就出了 T3FAP，直接向上游 CDN 要分片。
所以插件无论挂在 18521 还是 8521，都不可能被调用 —— 这就是「装了插件、日志
里看不到任何插件请求、播放出来还是 PNG」的真正原因。**不是剥壳算法的问题**。

0.3.x 的解法是「换一种地址」：把 .strm 内容改写成
`/api/strm/pngu/hls/u/<b64>.m3u8`。但媒体库通常有几千个 .strm，改完还得重扫，
代价太大，而且一换源就白改。

0.4.0 换一条路：**把内核那条 302 路由包起来**。插件和平台同进程，
`app.router.routes` 里就是那条路由对象，它的 `.app` 属性是一个 ASGI 可调用对象。
把 `route.app` 换成我们的包装器：

    播放器 → /api/strm/o/<token>.m3u8
           → 包装器调原 route.app，拿到 302 + Location
           → 探一下上游第一片是不是 PNG 壳
               是 → 200 返回改写后的清单（分片指向 /api/strm/pngu/seg/...）
               否 → 原样把那个 302 重放回去（行为与装插件前**逐字节一致**）

因为「不是壳就原样 302」，对非 PNG 来源完全透明，没有副作用。

为什么不动 .strm 也能生效
------------------------
STRM 里存的还是门票地址 `/api/strm/o/<token>.m3u8`，播放器请求的也还是它。
被换掉的只是内核里「谁来响应这个请求」。所以媒体库不用重扫，源地址变了也不用
改文件（门票地址是稳定的）。

安全边界
--------
1. 只包 `.m3u8` 结尾的 `/api/strm/*` 路由，不碰 `/api/media`、不碰后台 API。
2. 只对 3xx 重定向做判断；200 / 206 / 404 等一律**直接透传**，不缓冲不改动。
3. 探测失败、超时、异常 —— 一律回落到重放原 302，绝不阻断播放。
4. 全程 try/except，包装失败只记日志，不影响插件加载与平台启动。
5. 卸载时把原 `route.app` 装回去。
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import threading
import time

log = logging.getLogger("pngunwrap.hijack")

# 只处理这个前缀下的 .m3u8 路由（平台的 STRM 播放入口都在这里）
INCLUDE_PREFIX = "/api/strm/"
# 我们自己挂的前缀，别包自己
SELF_PREFIX = "/api/strm/pngu"

REDIRECT_CODES = (301, 302, 303, 307, 308)

# 探测第一片时取多少字节。256 KB 足够跑几千个 TS 包的同步率统计，
# 又不会为了「判断一下」把 1.8 MB 的分片整片拉下来。
PROBE_BYTES = 262144

# 判定的缓存时长。同一个片源会反复请求清单（播放器、进度条拖动、多端），
# 每次重新探测等于每播一部片子多花一次网络往返，所以缓存住结论。
VERDICT_TTL = 1800
VERDICT_MAX = 512

_STATE = {
    "hijacked": 0,          # 被包住的路由条数
    "routes": [],           # 被包住的路由 path（给健康检查看）
    "app": "",
    "reason": "",
    "hit": 0,               # 命中包装器的请求数
    "wrap": 0,              # 判定为 PNG 壳、改写成自家清单的次数
    "pass": 0,              # 判定为非 PNG、原样放行的次数
    "fail": 0,              # 探测失败而放行的次数
    "last": "",             # 最近一次判定的说明
}

_LOCK = threading.Lock()
_VERDICT = {}               # loc -> (expire_ts, dict)
_ORIG = []                  # [(route, orig_app)]
_PROXY = [None]             # 当前在用的 Proxy 实例（hijack 时装进来）


def state():
    """给 health / 诊断接口看的接管状态。"""
    with _LOCK:
        s = dict(_STATE)
        s["routes"] = list(_STATE["routes"])
    s["cache"] = len(_VERDICT)
    return s


def _bump(key, n=1):
    with _LOCK:
        _STATE[key] = _STATE.get(key, 0) + n


def _note(text):
    with _LOCK:
        _STATE["last"] = text[:300]


# ---------------------------------------------------------------- 判定缓存

def _cache_get(loc):
    with _LOCK:
        item = _VERDICT.get(loc)
    if not item:
        return None
    exp, val = item
    if exp < time.time():
        with _LOCK:
            _VERDICT.pop(loc, None)
        return None
    return val


def _cache_put(loc, val):
    now = time.time()
    with _LOCK:
        if len(_VERDICT) >= VERDICT_MAX:
            # 简单粗暴地清掉过期项，还不够就丢掉最早插入的一批
            dead = [k for k, (exp, _) in _VERDICT.items() if exp < now]
            for k in dead:
                _VERDICT.pop(k, None)
            if len(_VERDICT) >= VERDICT_MAX:
                for k in list(_VERDICT)[:VERDICT_MAX // 4]:
                    _VERDICT.pop(k, None)
        _VERDICT[loc] = (now + VERDICT_TTL, val)


def _token_of(loc):
    """由源地址推出稳定的会话 token。

    稳定很重要：播放器刷新清单、多端同看时都会重新请求，如果每次生成新 token，
    已经发出去的分片地址就全失效了。16 位十六进制足够避免碰撞。
    """
    return hashlib.sha1(loc.encode("utf-8", "replace")).hexdigest()[:16]


# ---------------------------------------------------------------- 探测

def _first_uris(text, base):
    """从媒体清单里挑出「最可能带壳」的候选地址。

    顺序：EXT-X-MAP 的初始化段 → 第一个普通分片。fMP4 源的分片可能不带壳，
    但初始化段带了壳（尤其是伪装成 .png 的），所以两个都探。
    """
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("#ext-x-map"):
            m = re.search(r'URI="([^"]+)"', line)
            if m:
                out.append(_join(base, m.group(1)))
            continue
        if line.startswith("#"):
            continue
        out.append(_join(base, line))
        if len(out) >= 2:
            break
    return [u for u in out if u]


def _join(base, uri):
    import urllib.parse
    try:
        return urllib.parse.urljoin(base, uri)
    except Exception:                               # noqa: BLE001
        return uri


def _probe(loc):
    """判断一个上游 m3u8 的分片是不是 PNG 壳。返回 dict，永不抛。

    注意这里**故意不复用** proxy.register：判定为非壳时会放弃这条源，如果先
    建了会话，媒体库里几千部片子就会白白撑出几千个会话。自己拉一遍清单
    （几十~几百 KB）便宜得多，结论还能缓存。
    """
    import pngu_fetch
    import pngu_unwrap

    val = {"wrapped": False, "why": "", "shell": 0, "kind": "", "seg": ""}
    try:
        blob, ctype, final = pngu_fetch.http_get_ex(loc, timeout=12)
    except Exception as e:                          # noqa: BLE001
        val["why"] = "清单拉取失败：%s: %s" % (type(e).__name__, str(e)[:120])
        return val

    text = blob.decode("utf-8", "replace")
    if "#EXTM3U" not in text:
        val["why"] = "上游返回的不是 m3u8（Content-Type=%s）" % (ctype or "?")
        return val

    if "#EXT-X-STREAM-INF" in text:
        # 多码率主清单：分片不在这一层，本模块保守放行，不去猜。
        val["why"] = "主清单（多码率），保守放行"
        return val

    cands = _first_uris(text, final or loc)
    if not cands:
        val["why"] = "清单里找不到分片地址"
        return val

    for url in cands:
        seg = _fetch_head_bytes(url)
        if not seg:
            continue
        payload, info = pngu_unwrap.unwrap(seg)
        val["seg"] = url
        val["shell"] = int(info.get("shell") or 0)
        val["kind"] = str(info.get("kind") or "")
        if val["shell"] > 0 or info.get("aligned"):
            val["wrapped"] = True
            val["why"] = "首片带壳 %d 字节，剥后是 %s" % (
                val["shell"], val["kind"])
            return val
        if info.get("kind") in ("ts", "mp4"):
            val["why"] = "首片本来就是裸 %s，无需处理" % info["kind"]
            return val
        val["why"] = "首片既不是壳也不是 TS（kind=%s，前 8 字节 %s）" % (
            info.get("kind"), seg[:8].hex())
    return val


def _fetch_head_bytes(url):
    """只取分片开头一段。取不到就返回空，由上层放行。"""
    import pngu_fetch
    try:
        blob, _ctype, _final = pngu_fetch.http_get_ex(
            url, timeout=12, extra={"Range": "bytes=0-%d" % (PROBE_BYTES - 1)})
        return blob
    except Exception as e:                          # noqa: BLE001
        log.info("探测分片失败（放行）：%s %s", url[:90], e)
        return b""


# ---------------------------------------------------------------- ASGI 包装

def _looks_like_playlist(url):
    if not url:
        return False
    try:
        import urllib.parse
        path = urllib.parse.urlsplit(url).path.lower()
    except Exception:                               # noqa: BLE001
        path = url.lower()
    return path.endswith(".m3u8") or ".m3u8?" in path


def _host_base(scope, headers):
    host = headers.get("host") or ""
    scheme = scope.get("scheme") or "http"
    if not host:
        return ""
    return "%s://%s" % (scheme, host)


def _abs_url(scope, headers, loc):
    """Location 可能是相对路径，转成绝对地址再拉。"""
    if loc.lower().startswith(("http://", "https://")):
        return loc
    base = _host_base(scope, headers)
    if not base:
        return loc
    return _join(base + "/", loc)


def _wrap_route_app(proxy, orig_app):
    """包一个路由的 ASGI app。返回新 app（带 `_pngu_origin` 便于还原）。"""

    async def app(scope, receive, send):
        if scope.get("type") != "http":
            return await orig_app(scope, receive, send)

        _bump("hit")

        st = {"hold": False, "start": None, "loc": "", "chunks": [],
              "done": False}

        async def cap(message):
            mtype = message.get("type")

            if mtype == "http.response.start" and not st["hold"]:
                code = int(message.get("status") or 0)
                hdrs = {k.decode("latin-1").lower(): v.decode("latin-1")
                        for k, v in (message.get("headers") or [])}
                loc = hdrs.get("location", "")
                if code in REDIRECT_CODES and _looks_like_playlist(loc):
                    # 先扣住不发，等判定结果
                    st["hold"] = True
                    st["start"] = message
                    scope_headers = {
                        k.decode("latin-1").lower(): v.decode("latin-1")
                        for k, v in (scope.get("headers") or [])}
                    st["loc"] = _abs_url(scope, scope_headers, loc)
                    return
                return await send(message)

            if mtype == "http.response.body" and st["hold"]:
                body = message.get("body") or b""
                if body:
                    st["chunks"].append(body)
                if message.get("more_body"):
                    return
                await _decide_and_send(send, scope, st)
                return

            if st["hold"]:
                # 3xx 正常只有 start + body，其它尾随消息直接吞掉
                return
            return await send(message)

        try:
            await orig_app(scope, receive, cap)
        except Exception as e:                      # noqa: BLE001
            _bump("fail")
            _note("调用原路由异常：%s: %s" % (type(e).__name__, str(e)[:150]))
            log.warning("调用原 STRM 路由异常（交由平台处理）：%s", e)
            raise
        # 极端情况：原路由只发了 start 没发 body。用 done 兜住，
        # 否则「正常发了 start+body」的路径会在下面这里**再发一次响应**。
        if st["hold"] and not st["done"]:
            await _decide_and_send(send, scope, st)

    app._pngu_origin = orig_app
    return app


async def _decide_and_send(send, scope, st):
    """判定 + 输出。任何异常都退化成重放原 302。

    进来的第一件事就是置 done：这个 ASGI 调用只允许产生**一份**响应，
    重复发会让 uvicorn 抛 "Response already started" 或让播放器收到错位数据。
    """
    if st.get("done"):
        return
    st["done"] = True

    loc = st["loc"]
    start_msg = st["start"]

    async def _replay():
        await send(start_msg)
        body = b"".join(st["chunks"])
        await send({"type": "http.response.body", "body": body,
                    "more_body": False})

    val = _cache_get(loc)
    if val is None:
        try:
            val = await asyncio.to_thread(_probe, loc)
            _cache_put(loc, val)
        except Exception as e:                      # noqa: BLE001
            _bump("fail")
            _note("探测异常，放行：%s: %s" % (type(e).__name__, str(e)[:140]))
            return await _replay()

    if not val.get("wrapped"):
        _bump("pass")
        _note("放行 %s（%s）" % (loc[:80], val.get("why", "")))
        return await _replay()

    # —— 确认带壳：接管这条流 ——
    try:
        proxy = _PROXY[0]
        if proxy is None:
            raise RuntimeError("插件代理实例尚未就绪")
        tok = _token_of(loc)
        sess = proxy.session(tok)
        if sess is None:
            proxy.register(loc, referer="", cookie="",
                           prefix=SELF_PREFIX, token=tok)
            sess = proxy.session(tok)
        if sess is None:
            raise RuntimeError("建立会话失败")
        blob = proxy.playlist_bytes(sess, SELF_PREFIX)
    except Exception as e:                          # noqa: BLE001
        _bump("fail")
        _note("改写清单失败，放行：%s: %s" % (type(e).__name__, str(e)[:140]))
        log.warning("改写清单失败（放行原 302）：%s", e)
        return await _replay()

    _bump("wrap")
    _note("接管 %s（%s）" % (loc[:80], val.get("why", "")))
    log.info("接管 STRM 流：%s → 分片改指向 %s/seg/%s/…",
             loc[:100], SELF_PREFIX, tok)

    code = 200
    headers = [
        (b"content-type", b"application/vnd.apple.mpegurl"),
        (b"content-length", str(len(blob)).encode("latin-1")),
        (b"cache-control", b"no-store"),
        (b"access-control-allow-origin", b"*"),
    ]
    if (scope.get("method") or "GET").upper() == "HEAD":
        await send({"type": "http.response.start", "status": code,
                    "headers": headers})
        await send({"type": "http.response.body", "body": b""})
        return
    await send({"type": "http.response.start", "status": code,
                "headers": headers})
    await send({"type": "http.response.body", "body": blob})


# ---------------------------------------------------------------- 安装 / 卸载

def _eligible(route):
    path = getattr(route, "path", "")
    if not isinstance(path, str):
        return False
    if not path.startswith(INCLUDE_PREFIX):
        return False
    if path.startswith(SELF_PREFIX):
        return False
    if not path.endswith(".m3u8"):
        return False
    return getattr(route, "app", None) is not None


def _already_wrapped(route):
    return getattr(getattr(route, "app", None), "_pngu_origin", None) is not None


def hijack(proxy):
    """包住平台所有 STRM 播放入口。返回 (ok, message)，永不抛。"""
    if _ORIG:
        return True, "已接管 %d 条路由" % len(_ORIG)
    try:
        import pngu_mount
        _PROXY[0] = proxy
        apps = pngu_mount.find_apps()
        if not apps:
            _STATE["reason"] = "没在 sys.modules 里找到 FastAPI 应用"
            return False, _STATE["reason"]

        wrapped, last = [], ""
        for name, app in apps:
            router = getattr(app, "router", None)
            routes = getattr(router, "routes", None)
            if not isinstance(routes, list):
                continue
            for route in list(routes):
                if not _eligible(route):
                    continue
                if _already_wrapped(route):
                    continue
                try:
                    orig = route.app
                    route.app = _wrap_route_app(proxy, orig)
                    _ORIG.append((route, orig))
                    wrapped.append(getattr(route, "path", ""))
                except Exception as e:              # noqa: BLE001
                    last = "%s: %s" % (type(e).__name__, e)

        if not _ORIG:
            _STATE["reason"] = last or "没有匹配到 STRM 播放路由"
            return False, _STATE["reason"]

        with _LOCK:
            _STATE.update(hijacked=len(_ORIG), routes=wrapped,
                          app=name, reason="")
        log.info("已接管 %d 条 STRM 路由：%s", len(wrapped), ", ".join(wrapped))
        return True, "已接管 %d 条：%s" % (len(wrapped), ", ".join(wrapped))
    except Exception as e:                          # noqa: BLE001
        _STATE["reason"] = "%s: %s" % (type(e).__name__, e)
        log.warning("接管 STRM 路由异常：%s", _STATE["reason"])
        return False, _STATE["reason"]


def unhijack():
    """把原 app 装回去。"""
    if not _ORIG:
        return
    n = 0
    for route, orig in _ORIG:
        try:
            route.app = orig
            n += 1
        except Exception:                           # noqa: BLE001
            pass
    _ORIG.clear()
    _PROXY[0] = None
    with _LOCK:
        _STATE.update(hijacked=0, routes=[], reason="")
    if n:
        log.info("已还原 %d 条 STRM 路由", n)
