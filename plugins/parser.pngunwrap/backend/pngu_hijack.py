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
import urllib.error
import urllib.parse

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
    "mode": "",             # route = 换路由 app；middleware = 最外层中间件
}

_LOCK = threading.Lock()
_VERDICT = {}               # loc -> (expire_ts, dict)
_ORIG = []                  # [(route, orig_app)]


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
    已经发出去的分片地址就全失效了。前缀 `s` + 15 位十六进制，落在
    `/api/strm/pngu/seg/s1a2b…/<n>`，和 HlsProxy 自己的 token 不会撞。
    """
    return "s" + hashlib.sha1(loc.encode("utf-8", "replace")).hexdigest()[:15]


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
        tok = _token_of(loc)
        sess = sess_get(tok)
        if sess is None:
            sess = await asyncio.to_thread(sess_build, tok, loc)
        blob = sess.playlist.encode("utf-8")
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


# ---------------------------------------------------------------- 自包含会话
# 接管这条链路**故意不依赖 HlsProxy**。剥壳真正需要的只有三件事：拉清单、
# 拉分片、剥壳。复用 HlsProxy 会带来两个真实的坑，都在这台机器上踩过：
#   ① 平台热更新只重载 plugin 模块，内存里的 pngu_proxy 还是旧版类，
#      `HlsProxy(public_base=…)` 直接 TypeError，内建服务起不来；
#   ② 更旧的版本连 `handle_path` 都没有，挂上去的 ASGI 一调就崩。
# 所以这里自带会话表、分片缓存和清单改写，只用 pngu_fetch + pngu_unwrap
# 这两个纯函数模块。18521 内建服务继续保留，但接管不再依赖它。

SEG_TTL = 60                    # 分片缓存秒数
SEG_MAX_BYTES = 96 * 1024 * 1024

_SESS = {}
_SEG = {}
_SEG_BYTES = [0]
_SEG_LOCK = threading.Lock()


class _Sess(object):
    __slots__ = ("tok", "src", "final", "text", "segs", "keys", "maps",
                 "playlist", "touched", "error")

    def __init__(self, tok, src):
        self.tok = tok
        self.src = src
        self.final = src
        self.text = ""
        self.segs = []
        self.keys = []
        self.maps = []
        self.playlist = ""
        self.touched = time.time()
        self.error = ""


def _attr(line):
    i = line.find('URI="')
    if i < 0:
        return ""
    j = line.find('"', i + 5)
    return "" if j < 0 else line[i + 5:j]


def _replace(line, new_uri):
    i = line.find('URI="')
    if i < 0:
        return line
    j = line.find('"', i + 5)
    return line if j < 0 else line[:i + 5] + new_uri + line[j:]


def _is_ours(tok):
    """我们的 token 是 `s` + 15 位十六进制，和 HlsProxy 的 token 不会撞。"""
    if len(tok) != 16 or not tok.startswith("s"):
        return False
    return all(c in "0123456789abcdef" for c in tok[1:])


def sess_get(tok):
    with _SEG_LOCK:
        s = _SESS.get(tok)
    if s is not None:
        s.touched = time.time()
    return s


def _sess_put(sess):
    with _SEG_LOCK:
        _SESS[sess.tok] = sess
        if len(_SESS) > 200:
            old = sorted(_SESS.values(), key=lambda x: x.touched)[:50]
            for s in old:
                _SESS.pop(s.tok, None)


def _render(sess):
    """把上游清单改写成指向本服务。分片用**根相对路径**，不带 host ——
    播放器按清单地址自己补全，局域网 IP / DDNS 域名 / 反代端口都能共用。"""
    out = []
    ki = mi = si = 0
    for raw in sess.text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("#ext-x-key") or low.startswith("#ext-x-session-key"):
            if _attr(line) and ki < len(sess.keys):
                line = _replace(line, "%s/key/%s/%d" % (SELF_PREFIX, sess.tok, ki))
            ki += 1
            out.append(line)
            continue
        if low.startswith("#ext-x-map"):
            if _attr(line) and mi < len(sess.maps):
                line = _replace(line, "%s/key/%s/m%d" % (SELF_PREFIX, sess.tok, mi))
            mi += 1
            out.append(line)
            continue
        if line.startswith("#"):
            out.append(line)
            continue
        out.append("%s/seg/%s/%d" % (SELF_PREFIX, sess.tok, si))
        si += 1
    sess.playlist = "\n".join(out) + "\n"
    return sess.playlist


def sess_build(tok, src):
    """拉清单、解析、渲染。失败抛异常，由调用方决定是否放行。"""
    import pngu_fetch

    blob, _ctype, final = pngu_fetch.http_get_ex(src)
    text = blob.decode("utf-8", "replace")
    if "#EXTM3U" not in text:
        raise RuntimeError("源地址返回的不是 m3u8（前 60 字节：%s）"
                           % text[:60].replace("\n", " "))
    if "#EXT-X-STREAM-INF" in text:
        raise RuntimeError("主清单（多码率），本模块不接管")

    base = final or src
    segs, keys, maps = [], [], []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("#ext-x-key") or low.startswith("#ext-x-session-key"):
            uri = _attr(line)
            if uri:
                keys.append(_join(base, uri))
            continue
        if low.startswith("#ext-x-map"):
            uri = _attr(line)
            if uri:
                maps.append(_join(base, uri))
            continue
        if line.startswith("#"):
            continue
        segs.append(_join(base, line))
    if not segs:
        raise RuntimeError("清单里没有分片")

    sess = _Sess(tok, src)
    sess.final = base
    sess.text = text
    sess.segs = segs
    sess.keys = keys
    sess.maps = maps
    _render(sess)
    _sess_put(sess)
    log.info("接管会话就绪 %s：%d 片，base=%s", tok, len(segs), base[:80])
    return sess


def _fetch_any(url, referer=""):
    """取字节。带 Referer 反而 403 的站很常见（dc.xhscdn / icve 系实测），
    所以默认不发；401/403 再试着补一个。"""
    import pngu_fetch
    try:
        blob, _ct, _f = pngu_fetch.http_get_ex(url, referer=referer, timeout=25)
        return blob
    except urllib.error.HTTPError as e:
        if e.code in (401, 403) and referer:
            blob, _ct, _f = pngu_fetch.http_get_ex(url, timeout=25)
            return blob
        raise


def _seg_put(key, blob):
    now = time.time()
    with _SEG_LOCK:
        old = _SEG.get(key)
        if old:
            _SEG_BYTES[0] -= len(old[1])
        _SEG[key] = (now + SEG_TTL, blob)
        _SEG_BYTES[0] += len(blob)
        if _SEG_BYTES[0] > SEG_MAX_BYTES or len(_SEG) > 4000:
            for k in sorted(_SEG, key=lambda x: _SEG[x][0])[:max(1, len(_SEG) // 4)]:
                _SEG_BYTES[0] -= len(_SEG[k][1])
                _SEG.pop(k, None)


def seg_bytes(tok, idx):
    import pngu_unwrap
    key = (tok, idx)
    now = time.time()
    with _SEG_LOCK:
        item = _SEG.get(key)
    if item and item[0] > now:
        return item[1]
    sess = sess_get(tok)
    if sess is None:
        raise KeyError(tok)
    if not (0 <= idx < len(sess.segs)):
        raise IndexError(idx)

    url = sess.segs[idx]
    try:
        raw = _fetch_any(url, sess.final)
    except urllib.error.HTTPError as e:
        # 上游分片地址有时效。长片看到一半 token 过期，分片就全变 401/403/404。
        # 这时**重新要一次清单**：src 是 T3FAP 门票地址的话，平台会 302 到当次
        # 有效的新上游地址，分片地址随之刷新。只重试一次，不会打转。
        if e.code not in (401, 403, 404):
            raise
        log.info("分片 %d 返回 %s，重取清单刷新上游地址：%s", idx, e.code, url[:80])
        _bump("refresh")
        sess = sess_build(tok, sess.src)
        if idx >= len(sess.segs):
            raise
        new_url = sess.segs[idx]
        if new_url == url:
            raise
        _note("上游地址过期，已刷新清单（片 %d）" % idx)
        raw = _fetch_any(new_url, sess.final)

    payload, info = pngu_unwrap.unwrap(raw)
    if info.get("shell"):
        log.info("剥壳 %s/%d：%d → %d 字节（壳 %s，%s）", tok, idx,
                 len(raw), len(payload), info.get("shell"), info.get("kind"))
    _seg_put(key, payload)
    return payload


def key_bytes(tok, idx):
    sess = sess_get(tok)
    if sess is None:
        raise KeyError(tok)
    if idx.startswith("m"):
        seq, i = sess.maps, int(idx[1:])
    else:
        seq, i = sess.keys, int(idx)
    if not (0 <= i < len(seq)):
        raise IndexError(idx)
    return _fetch_any(seq[i], sess.final)


def serve(path):
    """在挂载的 ASGI 里优先处理我们自己的路径。

    返回 (status, content_type, body)，不是我们的路径返回 None，
    由调用方继续交给原来的 handle_path。
    """
    parts = [p for p in (path or "").split("/") if p]
    if len(parts) < 2:
        # 诊断口即使 pngu_proxy 是旧版也要能用 —— 这里不依赖它。
        if parts and parts[0] in ("__hijack", "__dump"):
            import json
            if parts[0] == "__hijack":
                payload = state()
            else:
                payload = {"hijack": state()}
                try:
                    import pngu_mount
                    payload["mount"] = pngu_mount.diagnose()
                except Exception as e:              # noqa: BLE001
                    payload["mount_error"] = "%s: %s" % (type(e).__name__, e)
            return (200, "application/json; charset=utf-8",
                    json.dumps(payload, ensure_ascii=False, indent=2).encode())
        return None

    head = parts[0]
    if head == "hls" and len(parts) >= 2:
        tok = parts[1].split(".")[0]
        if not _is_ours(tok):
            return None
        sess = sess_get(tok)
        if sess is None:
            return (404, "application/json; charset=utf-8",
                    b'{"ok": false, "error": "session gone"}')
        return 200, "application/vnd.apple.mpegurl", sess.playlist.encode()

    if head == "seg" and len(parts) >= 3:
        tok = parts[1]
        if not _is_ours(tok):
            return None
        try:
            idx = int(parts[2])
        except ValueError:
            return 400, "application/json; charset=utf-8", b'{"ok": false}'
        try:
            return 200, "video/mp2t", seg_bytes(tok, idx)
        except KeyError:
            return (404, "application/json; charset=utf-8",
                    b'{"ok": false, "error": "session gone"}')
        except Exception as e:                      # noqa: BLE001
            _bump("fail")
            msg = "%s: %s" % (type(e).__name__, str(e)[:160])
            _note("取分片失败 %s/%d：%s" % (tok, idx, msg))
            log.warning("取分片失败 %s/%d：%s（上游 %s）", tok, idx, msg,
                        _seg_url(tok, idx))
            return (502, "application/json; charset=utf-8",
                    ('{"ok": false, "error": "%s"}'
                     % msg.replace('"', "'")).encode())

    if head == "key" and len(parts) >= 3:
        tok = parts[1]
        if not _is_ours(tok):
            return None
        try:
            return 200, "application/octet-stream", key_bytes(tok, parts[2])
        except Exception as e:                      # noqa: BLE001
            return (502, "application/json; charset=utf-8",
                    ('{"ok": false, "error": "%s"}'
                     % str(e)[:160].replace('"', "'")).encode())

    return None


def _seg_url(tok, idx):
    sess = sess_get(tok)
    if sess and 0 <= idx < len(sess.segs):
        return sess.segs[idx][:110]
    return "?"


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


def _eligible_route(route):
    """这条路由能不能靠换 `.app` 接管。

    FastAPI 的 APIRoute 一定有 `endpoint`，真正被调用的是 `self.app`；
    Mount 之类没有 `endpoint`，只能整块包住。
    """
    return hasattr(route, "endpoint") and getattr(route, "app", None) is not None


# ---------------------------------------------------------------- 中间件兜底
# 万一路由对象拿不到（302 由中间件产出、路由表被自定义 Router 包了一层、
# 或者平台版本把路由藏进了闭包），还有最后一条路：在应用最外层包一个 ASGI
# 中间件。它同时干两件事 —— 拦 3xx 的 strm 清单请求、自己服务
# `/api/strm/pngu/*`（这样连 mount 都不依赖了）。

MW_FLAG = "_pngu_middleware"


async def _mw_respond(send, code, ctype, blob, method="GET"):
    headers = [(b"content-type", ctype.encode("latin-1")),
               (b"content-length", str(len(blob)).encode("latin-1")),
               (b"cache-control", b"no-store"),
               (b"access-control-allow-origin", b"*")]
    await send({"type": "http.response.start", "status": code,
                "headers": headers})
    await send({"type": "http.response.body",
                "body": b"" if method == "HEAD" else blob})


def _mw_class(proxy):
    """造一个 Starlette 中间件类（Starlette 会以 `cls(app)` 实例化）。"""

    class _PnguMiddleware(object):
        _pngu_middleware = True

        def __init__(self, app):
            self.app = app
            self.wrap = _wrap_route_app(proxy, app)

        async def __call__(self, scope, receive, send):
            if scope.get("type") != "http":
                return await self.app(scope, receive, send)
            path = scope.get("path") or ""
            method = (scope.get("method") or "GET").upper()

            # 1) 自家路径由自己服务，绕开 mount
            if path.startswith(SELF_PREFIX):
                sub = path[len(SELF_PREFIX):] or "/"
                try:
                    hit = serve(sub)
                except Exception as e:              # noqa: BLE001
                    hit = (502, "application/json; charset=utf-8",
                           ('{"ok": false, "error": "%s"}'
                            % str(e)[:160].replace('"', "'")).encode())
                if hit is not None:
                    _bump("hit")
                    return await _mw_respond(send, hit[0], hit[1], hit[2], method)
                return await self.app(scope, receive, send)

            # 2) 只拦 STRM 播放入口，其它请求原样透传（不缓冲不回绕）
            if path.startswith(INCLUDE_PREFIX) and path.endswith(".m3u8"):
                return await self.wrap(scope, receive, send)
            return await self.app(scope, receive, send)

    _PnguMiddleware.__name__ = "PnguStrmMiddleware"
    return _PnguMiddleware


_MW_INSTALLED = []          # [(app, 原 user_middleware 列表快照)]


def install_middleware(proxy):
    """把兜底中间件装到所有找到的应用上。返回 (ok, message)。"""
    try:
        import pngu_mount
    except Exception as e:                          # noqa: BLE001
        return False, "挂载模块不可用：%s" % e

    try:
        from starlette.middleware import Middleware as _MW
    except Exception as e:                          # noqa: BLE001
        return False, "平台没有 starlette（%s），走不了中间件兜底" % e

    apps = pngu_mount.find_apps()
    if not apps:
        return False, "没找到可安装中间件的应用"

    done, last = [], ""
    cls = _mw_class(proxy)
    for name, app in apps:
        mws = getattr(app, "user_middleware", None)
        if not isinstance(mws, list):
            continue
        if any(getattr(getattr(m, "cls", None), MW_FLAG, False) for m in mws):
            done.append(name)
            continue
        try:
            mws.insert(0, _MW(cls))
            _MW_INSTALLED.append((app, mws))
            if getattr(app, "middleware_stack", None) is not None:
                app.middleware_stack = app.build_middleware_stack()
            done.append(name)
        except Exception as e:                      # noqa: BLE001
            last = "%s: %s" % (type(e).__name__, e)

    if not done:
        return False, last or "没有可安装中间件的应用"

    with _LOCK:
        _STATE.update(hijacked=len(done), routes=["(middleware)"],
                      app=done[0], mode="middleware", reason="")
    log.info("已用中间件接管 STRM（%s）", ", ".join(done))
    return True, "中间件接管 %d 个应用：%s" % (len(done), ", ".join(done))


def remove_middleware():
    n = 0
    for app, mws in list(_MW_INSTALLED):
        try:
            for i in range(len(mws) - 1, -1, -1):
                if getattr(getattr(mws[i], "cls", None), MW_FLAG, False):
                    del mws[i]
                    n += 1
            if getattr(app, "middleware_stack", None) is not None:
                app.middleware_stack = app.build_middleware_stack()
        except Exception:                           # noqa: BLE001
            pass
    del _MW_INSTALLED[:]
    return n


def _candidate_routes():
    """枚举要接管的 STRM 路由，返回 [(应用名, 完整路径, 路由对象)]。

    0.4.1 是「遍历 app.router.routes，看 path 是否以 /api/strm/ 开头」——
    真机报「没有匹配到 STRM 播放路由」，可挂载又是成功的，说明找到的 app
    和真正在服务 HTTP 的不是同一层（子应用 / 容器里的 app）。现在按
    **路由归属**反查：谁的路由表里有 `/api/strm/*.m3u8`，就接管谁。
    """
    import pngu_mount
    out = []
    for name, _owner, full, route in pngu_mount.strm_routes():
        out.append((name, full, route))
    return out


def hijack(proxy):
    """包住平台所有 STRM 播放入口。返回 (ok, message)，永不抛。

    两条路：能拿到路由对象就换 `route.app`（最轻、可精确还原）；
    拿不到就退化成最外层 ASGI 中间件（见 `install_middleware`）。
    """
    if _ORIG:
        return True, "已接管 %d 条路由" % len(_ORIG)
    try:
        cands = _candidate_routes()
        if not cands:
            ok, msg = install_middleware(proxy)
            if not ok:
                _STATE["reason"] = "没有匹配到 STRM 播放路由；中间件兜底也失败：%s" % msg
            return ok, _STATE["reason"] or msg

        wrapped, last, app_name = [], "", ""
        for name, full, route in cands:
            if _already_wrapped(route):
                wrapped.append(full)
                app_name = app_name or name
                continue
            try:
                if _eligible_route(route):
                    orig = route.app
                    route.app = _wrap_route_app(proxy, orig)
                else:
                    # Mount / 子应用：整块包住
                    orig = getattr(route, "app", None)
                    if orig is None:
                        raise RuntimeError("路由没有 app 属性")
                    route.app = _wrap_route_app(proxy, orig)
                _ORIG.append((route, orig))
                wrapped.append(full)
                app_name = app_name or name
            except Exception as e:                  # noqa: BLE001
                last = "%s: %s" % (type(e).__name__, e)

        if not _ORIG:
            ok, msg = install_middleware(proxy)
            if ok:
                return ok, msg
            _STATE["reason"] = "路由存在但接管失败（%s）；中间件兜底也失败：%s" % (
                last, msg)
            return False, _STATE["reason"]

        with _LOCK:
            _STATE.update(hijacked=len(_ORIG), routes=wrapped, mode="route",
                          app=app_name, reason="")
        log.info("已接管 %d 条 STRM 路由：%s", len(wrapped), ", ".join(wrapped))
        return True, "已接管 %d 条：%s" % (len(wrapped), ", ".join(wrapped))
    except Exception as e:                          # noqa: BLE001
        _STATE["reason"] = "%s: %s" % (type(e).__name__, e)
        log.warning("接管 STRM 路由异常：%s", _STATE["reason"])
        return False, _STATE["reason"]


def unhijack():
    """把原 app 装回去，并把兜底中间件摘掉。"""
    n = 0
    for route, orig in _ORIG:
        try:
            route.app = orig
            n += 1
        except Exception:                           # noqa: BLE001
            pass
    _ORIG.clear()
    try:
        m = remove_middleware()
    except Exception:                               # noqa: BLE001
        m = 0
    with _LOCK:
        _STATE.update(hijacked=0, routes=[], reason="", mode="")
    if n or m:
        log.info("已还原 %d 条 STRM 路由 / 摘掉 %d 个兜底中间件", n, m)


# 模块自述版本。plugin.py 会拿它和磁盘上的文件比对，不一致就说明平台热更新
# 只重载了 plugin 模块、子模块还留在 sys.modules 里，需要 importlib.reload。
__version__ = "0.4.2"
