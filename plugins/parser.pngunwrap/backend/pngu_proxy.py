# -*- coding: utf-8 -*-
"""内建 HLS 反向代理 —— 插件自己站在播放链路上，负责剥壳。

这是整个方案的关键：平台的 access_mode 只做「带鉴权头的转发」，字节透明，
不会替你剥壳。所以插件必须自己起一个服务，让平台代理（或播放器）来访问它。

路由：
    GET  /hls/<tok>.m3u8    清单：现场拉源清单，把分片/密钥地址改写成本服务地址
    GET  /seg/<tok>/<idx>   分片：拉源分片 → 剥 PNG 壳 → 吐 video/mp2t
    GET  /key/<tok>/<idx>   AES 密钥透传（若有）
    GET  /seg/demo/0        demo 分片（合成 TS，只验证链路）
    GET  /__health          自检 JSON

所有路由都支持 HEAD 与 Range(206) —— 飞牛播放器会先 HEAD，看到
Content-Length: 0 就直接放弃，连 GET 都不发。
"""

from __future__ import annotations

import base64
import json
import logging
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import pngu_fetch
import pngu_unwrap

log = logging.getLogger("pngunwrap")

SEG_EXTINF_DEFAULT = 4.0


class Session(object):
    """一条播放会话：源清单地址 + 拆出来的分片表。"""

    __slots__ = ("token", "src", "referer", "cookie", "segments", "keys",
                 "maps", "playlist", "created", "touched", "error",
                 "raw_text", "render_prefix", "built", "final_src")

    def __init__(self, token, src, referer="", cookie=""):
        self.token = token
        self.src = src
        self.referer = referer
        self.cookie = cookie
        self.segments = []      # 分片绝对 URL
        self.keys = []          # AES 密钥绝对 URL
        self.maps = []          # EXT-X-MAP 绝对 URL
        self.playlist = ""      # 改写后的清单文本
        self.created = time.time()
        self.touched = time.time()
        self.error = ""
        self.raw_text = None    # 源清单原文（None = demo 源）
        self.render_prefix = None   # 上次渲染用的 base，变了就重渲染
        self.built = False
        self.final_src = ""     # 跟随 302 之后的真实清单地址


class SegmentCache(object):
    """分片缓存：字节上限 + TTL 双控，只缓存已交给播放器的分片。"""

    def __init__(self, max_bytes, ttl):
        self.max_bytes = max(4, int(max_bytes)) * 1024 * 1024
        self.ttl = max(5, int(ttl))
        self.data = {}          # key -> (bytes, ts)
        self.order = []         # 插入顺序，用于淘汰
        self.lock = threading.Lock()

    def get(self, key):
        now = time.time()
        with self.lock:
            hit = self.data.get(key)
            if not hit:
                return None
            blob, ts = hit
            if now - ts > self.ttl:
                self.data.pop(key, None)
                return None
            return blob

    def put(self, key, blob):
        now = time.time()
        with self.lock:
            self.data[key] = (blob, now)
            self.order.append(key)
            total = sum(len(v[0]) for v in self.data.values())
            while total > self.max_bytes and self.order:
                old = self.order.pop(0)
                if old == key:
                    continue
                gone = self.data.pop(old, None)
                if gone:
                    total -= len(gone[0])

    def reap(self):
        now = time.time()
        with self.lock:
            dead = [k for k, v in self.data.items() if now - v[1] > self.ttl]
            for k in dead:
                self.data.pop(k, None)
            self.order = [k for k in self.order if k in self.data]

    def stats(self):
        with self.lock:
            total = sum(len(v[0]) for v in self.data.values())
            return {"segs": len(self.data),
                    "bytes": total,
                    "mb": round(total / 1048576.0, 1)}


class DiagLog(object):
    """环形诊断缓冲：记录平台调用进来的每一次请求，供 /__diag 查看。

    排查「插件到底有没有被调用」靠的就是它 —— 平台上什么都不显示的时候，
    这里有没有记录就是唯一证据。
    """

    def __init__(self, maxlen=50):
        self.maxlen = maxlen
        self.items = []
        self.counts = {}
        self.lock = threading.Lock()
        self.started = time.time()

    def bump(self, key, n=1):
        with self.lock:
            self.counts[key] = self.counts.get(key, 0) + n

    def add(self, kind, data):
        with self.lock:
            self.items.append({"t": round(time.time() - self.started, 3),
                               "ev": kind, "data": data})
            if len(self.items) > self.maxlen:
                del self.items[:len(self.items) - self.maxlen]

    def snapshot(self):
        with self.lock:
            return {"uptime_s": round(time.time() - self.started, 1),
                    "counts": dict(self.counts),
                    "recent": list(self.items[-20:])}


DIAG = DiagLog()


class HlsProxy(object):
    """插件内建 HTTP 服务（惰性启动，进程内线程）。"""

    def __init__(self, host="127.0.0.1", port=18521,
                 cache_mb=64, cache_ttl=30, public_base=""):
        self.host = host
        self.port = int(port)
        self.public_base = str(public_base or "").rstrip("/")
        self.cache = SegmentCache(cache_mb, cache_ttl)
        self.sessions = {}
        self.lock = threading.Lock()
        self._httpd = None
        self._thread = None
        self._start_lock = threading.Lock()
        self._seq = 0
        self.error = ""

    # ------------------------------------------------------------ 生命周期

    def start(self):
        """启动服务，返回实际端口；失败抛异常。"""
        with self._start_lock:
            if self._httpd:
                return self.port
            last = ""
            for offset in range(10):
                port = self.port + offset
                try:
                    httpd = ThreadingHTTPServer(
                        (self.host, port), _make_handler(self))
                except OSError as e:
                    last = str(e)
                    continue
                httpd.daemon_threads = True
                self.port = port
                self._httpd = httpd
                self._thread = threading.Thread(
                    target=httpd.serve_forever,
                    kwargs={"poll_interval": 0.5},
                    name="pngunwrap-hls", daemon=True)
                self._thread.start()
                self.error = ""
                log.info("内建 HLS 服务已启动 %s:%d", self.host, self.port)
                self._start_janitor()
                return self.port
            self.error = "端口 %d~%d 都被占用（%s）" % (
                self.port, self.port + 9, last)
            raise RuntimeError(self.error)

    def stop(self):
        with self._start_lock:
            httpd, self._httpd = self._httpd, None
        if httpd:
            try:
                httpd.shutdown()
            except Exception:                       # noqa: BLE001
                pass
            try:
                httpd.server_close()
            except Exception:                       # noqa: BLE001
                pass
        self.sessions.clear()
        log.info("内建 HLS 服务已停止")

    @property
    def running(self):
        return self._httpd is not None

    def _start_janitor(self):
        def loop():
            while self.running:
                time.sleep(15)
                try:
                    self.cache.reap()
                    self._reap_sessions()
                except Exception:                   # noqa: BLE001
                    pass
        threading.Thread(target=loop, name="pngunwrap-janitor",
                         daemon=True).start()

    def _reap_sessions(self, idle=3 * 3600):
        now = time.time()
        with self.lock:
            dead = [k for k, s in self.sessions.items()
                    if now - s.touched > idle]
            for k in dead:
                self.sessions.pop(k, None)

    # ------------------------------------------------------------ 会话

    def register(self, src_url, referer="", cookie="", prefix="", token=None):
        """登记一条源，返回可播放的清单地址。

        token 可指定：`/hls/u/<b64>` 这种自包含入口需要 token 本身带得动
        源地址，这样重启后不需要任何登记记录也能重建会话。
        """
        if not token:
            self._seq += 1
            token = "%x%04x" % (int(time.time()), self._seq & 0xFFFF)
        sess = Session(token, src_url, referer, cookie)
        # 先构建一次，失败也要把会话留住（便于 /__health 看到错误）
        try:
            self._build_playlist(sess, prefix)
        except Exception as e:                      # noqa: BLE001
            sess.error = str(e)[:300]
            log.warning("构建清单失败 %s：%s", token, sess.error)
        with self.lock:
            self.sessions[token] = sess
        if sess.error:
            raise RuntimeError(sess.error)
        return self.playlist_url(token, prefix)

    def playlist_url(self, token, prefix):
        return "%s/hls/%s.m3u8" % (prefix.rstrip("/"), token)

    def session(self, token):
        with self.lock:
            sess = self.sessions.get(token)
        if sess:
            sess.touched = time.time()
        return sess

    # ------------------------------------------------------------ 清单改写

    def _build_playlist(self, sess, prefix):
        # demo 源：不拉远端，直接给内置清单（只用来验证链路能否打通）
        if sess.src.startswith("demo://"):
            sess.raw_text = None
            sess.keys = []
            sess.maps = []
            sess.built = True
            return self._render(sess, prefix)

        # 拿清单时一并取回「最终 URL」：sess.src 可能是 T3FAP 的门票地址
        # （/api/strm/o/<token>，稳定但会 302），分片的相对路径必须按最终
        # 地址解析，否则 urljoin 会以门票地址为 base，拼出一堆死链。
        blob, _ctype, final_url = pngu_fetch.http_get_ex(
            sess.src, referer=sess.referer, cookie=sess.cookie)
        txt = blob.decode("utf-8", "replace")
        if "#EXTM3U" not in txt:
            raise RuntimeError("源地址返回的不是 m3u8（前 80 字节：%s）"
                               % txt[:80].replace("\n", " "))

        base = final_url or sess.src
        if base != sess.src:
            log.info("清单经 302 落到：%s", base[:100])
            sess.final_src = base
        segs, keys, maps = [], [], []
        for raw in txt.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#EXT-X-KEY") or line.startswith("#EXT-X-SESSION-KEY"):
                uri = _attr_uri(line)
                if uri:
                    keys.append(urllib.parse.urljoin(base, uri))
                continue
            if line.startswith("#EXT-X-MAP"):
                uri = _attr_uri(line)
                if uri:
                    maps.append(urllib.parse.urljoin(base, uri))
                continue
            if line.startswith("#"):
                continue
            segs.append(urllib.parse.urljoin(base, line))

        if not segs:
            raise RuntimeError("清单里没有分片")

        sess.raw_text = txt
        sess.segments = segs
        sess.keys = keys
        sess.maps = maps
        sess.built = True
        return self._render(sess, prefix)

    def _render(self, sess, prefix):
        """按「当前客户端实际用的 base」现场生成清单。

        为什么不在建会话时定死：同一个会话会被不同客户端用不同地址访问
        （127.0.0.1 / 局域网 IP / DDNS 域名）。建会话时还看不出客户端会
        从哪进来，写死就会生成 0.0.0.0 或 127.0.0.1 这种播放器打不开的地址。
        prefix 传空串时输出根相对路径（/seg/...），由播放器自己按清单地址补全
        —— 这是最不容易出错的形式。
        """
        base = (prefix or "").rstrip("/")

        if sess.raw_text is None:
            sess.playlist = pngu_fetch.demo_playlist(base)
            sess.segments = ["%s/seg/demo/0" % base]
            sess.render_prefix = base
            return sess.playlist

        out = []
        ki = mi = si = 0
        for raw in sess.raw_text.splitlines():
            line = raw.strip()
            if not line:
                continue

            if line.startswith("#EXT-X-KEY") or line.startswith("#EXT-X-SESSION-KEY"):
                if _attr_uri(line) and ki < len(sess.keys):
                    line = _replace_uri(
                        line, "%s/key/%s/%d" % (base, sess.token, ki))
                ki += 1
                out.append(line)
                continue

            if line.startswith("#EXT-X-MAP"):
                if _attr_uri(line) and mi < len(sess.maps):
                    line = _replace_uri(
                        line, "%s/key/%s/m%d" % (base, sess.token, mi))
                mi += 1
                out.append(line)
                continue

            if line.startswith("#"):
                out.append(line)
                continue

            out.append("%s/seg/%s/%d" % (base, sess.token, si))
            si += 1

        sess.playlist = "\n".join(out) + "\n"
        sess.render_prefix = base
        return sess.playlist

    def playlist_bytes(self, sess, prefix):
        """拿清单字节；没有就现场构建（HEAD 也需要真实长度）。"""
        base = (prefix or "").rstrip("/")
        if not sess.built:
            self._build_playlist(sess, prefix)
        elif sess.render_prefix != base:
            self._render(sess, prefix)
        return (sess.playlist or "").encode("utf-8")

    # ------------------------------------------------------------ 取字节

    def _fetch_segment(self, sess, idx):
        """拉一片，带一层 Referer 策略。

        有些站点的防盗链是「必须带 Referer」（4kvms 系），有些恰恰相反 ——
        「带了就 403」（icve / douyinbit 系，curl 默认不发 Referer 反而能取）。
        所以先按会话配置的 referer 取；没配或失败且是 401/403，再用清单地址
        当 Referer 重试一次，两种站都能过。
        """
        url = sess.segments[idx]
        try:
            return pngu_fetch.http_get(url, referer=sess.referer,
                                       cookie=sess.cookie)
        except urllib.error.HTTPError as e:
            if e.code not in (401, 403):
                raise
            alt = sess.referer or ""
            if alt and alt != sess.src:
                raise
            log.info("分片 403，改用清单地址作 Referer 重试：%s", url[:80])
            return pngu_fetch.http_get(url,
                                       referer=sess.final_src or sess.src,
                                       cookie=sess.cookie)

    def segment_bytes(self, sess, idx):
        key = (sess.token, idx)
        hit = self.cache.get(key)
        if hit is not None:
            return hit
        if idx < 0 or idx >= len(sess.segments):
            raise RuntimeError("分片下标越界 %s" % idx)
        raw, _ = self._fetch_segment(sess, idx)
        payload, info = pngu_unwrap.unwrap(raw)
        if info.get("shell"):
            log.debug("剥壳 %s/%d：%d → %d 字节（%s）",
                      sess.token, idx, len(raw), len(payload), info.get("kind"))
        self.cache.put(key, payload)
        return payload

    def key_bytes(self, sess, idx):
        """AES 密钥 / init 段透传。"""
        if idx.startswith("m"):
            seq = sess.maps
            i = int(idx[1:])
        else:
            seq = sess.keys
            i = int(idx)
        if i < 0 or i >= len(seq):
            raise RuntimeError("密钥下标越界 %s" % idx)
        raw, _ = pngu_fetch.http_get(seq[i], referer=sess.referer or sess.src,
                                     cookie=sess.cookie)
        return raw


# ---------------------------------------------------------------- 工具

def _attr_uri(line):
    """取出 `URI="..."` 里的值，没有就返回空串。"""
    i = line.find('URI="')
    if i < 0:
        return ""
    j = line.find('"', i + 5)
    if j < 0:
        return ""
    return line[i + 5:j]


def _replace_uri(line, new_uri):
    i = line.find('URI="')
    if i < 0:
        return line
    j = line.find('"', i + 5)
    if j < 0:
        return line
    return line[:i + 5] + new_uri + line[j:]


def _range_of(blob, rng, allow_range=True):
    """解析 Range 头，返回 (status, body, extra_headers)。

    抽成纯函数是为了让「独立 HTTP 服务」和「挂到平台 FastAPI 上的 ASGI 路由」
    共用同一套切片逻辑 —— 两条出口的 Range/206/Content-Length 行为必须一致。
    """
    total = len(blob)
    start, end = 0, total - 1
    partial = False
    if allow_range and rng and rng.startswith("bytes=") and total > 0:
        spec = rng[6:].split(",")[0].strip()
        try:
            if spec.startswith("-"):
                n = int(spec[1:])
                start, end = max(0, total - n), total - 1
            else:
                a, _, b = spec.partition("-")
                start = int(a) if a else 0
                end = int(b) if b else total - 1
            start = max(0, min(start, total - 1))
            end = max(start, min(end, total - 1))
            partial = True
        except ValueError:
            start, end, partial = 0, total - 1, False

    body = blob[start:end + 1] if partial else blob
    hdrs = {
        "Accept-Ranges": "bytes" if allow_range else "none",
        "Content-Length": str(len(body)),
        "Cache-Control": "no-store",
    }
    if partial:
        hdrs["Content-Range"] = "bytes %d-%d/%d" % (start, end, total)
    return (206 if partial else 200), body, hdrs


def _serve_bytes(handler, blob, ctype, allow_range=True, code=200):
    """统一的字节输出：支持 HEAD / Range(206) / 正确 Content-Length。

    注意顺序：必须先 send_response（发状态行），再 send_header，否则状态行
    会被塞到响应头后面，客户端直接 BadStatusLine。
    """
    st, body, hdrs = _range_of(blob, handler.headers.get("Range") or "",
                               allow_range)
    if st != 206:
        st = code
    handler.send_response(st)
    handler.send_header("Content-Type", ctype)
    for k, v in hdrs.items():
        handler.send_header(k, v)
    handler.end_headers()
    if handler.command != "HEAD":
        try:
            handler.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def handle_path(proxy, path, query="", prefix=""):
    """把 HTTP 路径翻译成 (status, content_type, body)。

    独立端口（BaseHTTPRequestHandler）和「挂到平台 8521 上的 ASGI 路由」
    共用这一个函数，保证两条出口的行为完全一致 —— 否则很容易出现
    「18521 能播、8521 不能播」这种只在一条路上复现的怪问题。
    """
    parsed = urllib.parse.urlsplit(path)
    parts = [p for p in parsed.path.split("/") if p]
    q = urllib.parse.parse_qs(parsed.query or query)

    if not parts:
        return 200, "application/json; charset=utf-8", json.dumps(
            {"ok": True, "service": "pngunwrap"}, ensure_ascii=False).encode()

    head = parts[0]
    if not head.startswith("__"):
        DIAG.bump("hit_" + head)

    def _json(obj, code=200):
        return code, "application/json; charset=utf-8", json.dumps(
            obj, ensure_ascii=False, indent=2).encode("utf-8")

    if head == "__health":
        return _json(proxy_health(proxy))

    if head == "__diag":
        return _json({"health": proxy_health(proxy), "diag": DIAG.snapshot()})

    def _register(src, ref=""):
        """登记一条源并返回会话；失败抛异常由上层转成 502。"""
        tok = _b64e(src)
        sess = proxy.session(tok)
        if not sess:
            proxy.register(src, referer=ref, prefix=prefix, token=tok)
            sess = proxy.session(tok)
        return sess

    if head == "__test":
        src = (q.get("url") or [""])[0].strip()
        if not src:
            return _json({"ok": False, "error": "用法：/__test?url=<m3u8 地址>"}, 400)
        try:
            sess = _register(src, (q.get("ref") or [""])[0].strip())
        except Exception as e:                      # noqa: BLE001
            return _json({"ok": False, "error": str(e)[:300]}, 502)
        segs = list(sess.segments)
        return _json({
            "ok": True,
            "playlist_url": "%s/hls/u/%s.m3u8" % (prefix.rstrip("/"), sess.token),
            "segments": len(segs),
            "first_segment_url": segs[0] if segs else "",
            "next": "先打开 playlist_url 确认分片地址已被改写成本服务，"
                    "再打开 first_segment_url 确认返回的是 TS 而不是 PNG",
        })

    # 自包含入口：源地址 base64 编在路径里，不依赖任何登记记录
    if head == "hls" and len(parts) >= 3 and parts[1] == "u":
        raw = parts[2].split(".")[0]
        src = _b64d(raw)
        if not src.lower().startswith(("http://", "https://")):
            return _json({"ok": False,
                          "error": "路径里的源地址解不出来（应为 base64url 编码的 "
                                   "m3u8 地址）"}, 400)
        sess = proxy.session(raw)
        if not sess:
            try:
                # 默认**不发 Referer**：icve/douyinbit 这类站点的防盗链恰恰是
                # 「有 Referer 反而 403」，而 curl 默认不发 Referer 能直取。
                proxy.register(src, referer=(q.get("ref") or [""])[0].strip(),
                               prefix=prefix, token=raw)
            except Exception as e:                  # noqa: BLE001
                return _json({"ok": False, "error": str(e)[:300], "src": src}, 502)
            sess = proxy.session(raw)
        return (200, "application/vnd.apple.mpegurl",
                proxy.playlist_bytes(sess, prefix))

    if head == "hls" and len(parts) >= 2:
        tok = parts[1].split(".")[0]
        sess = proxy.session(tok)
        if not sess:
            return _json({"ok": False, "error": "会话不存在或已过期",
                          "token": tok}, 404)
        return (200, "application/vnd.apple.mpegurl",
                proxy.playlist_bytes(sess, prefix))

    if head == "seg" and len(parts) >= 3:
        tok, idx = parts[1], parts[2]
        if tok == "demo":
            return 200, "video/mp2t", pngu_fetch.demo_segment()
        sess = proxy.session(tok)
        if not sess:
            return _json({"ok": False, "error": "会话不存在或已过期",
                          "token": tok}, 404)
        return 200, "video/mp2t", proxy.segment_bytes(sess, int(idx))

    if head == "key" and len(parts) >= 3:
        tok, idx = parts[1], parts[2]
        sess = proxy.session(tok)
        if not sess:
            return _json({"ok": False, "error": "会话不存在或已过期",
                          "token": tok}, 404)
        return 200, "application/octet-stream", proxy.key_bytes(sess, idx)

    return _json({"ok": False, "error": "未知路径 %s" % path}, 404)


def _serve_json(handler, obj, code=200):
    blob = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(blob)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    if handler.command != "HEAD":
        try:
            handler.wfile.write(blob)
        except (BrokenPipeError, ConnectionResetError):
            pass


def _make_handler(proxy):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "pngunwrap/0.1"

        def log_message(self, fmt, *args):          # 安静：只走我们自己的 log
            log.debug("%s - %s", self.address_string(), fmt % args)

        # ---------------------------------------------------------- 路由

        def do_GET(self):
            self._route()

        def do_HEAD(self):
            self._route()

        def _route(self):
            try:
                prefix = _prefix_of(self, proxy)
                code, ctype, blob = handle_path(proxy, self.path, prefix=prefix)
                _serve_bytes(self, blob, ctype, code=code)
            except Exception as e:                  # noqa: BLE001
                log.warning("处理 %s 失败：%s", self.path, e)
                try:
                    _serve_json(self, {"ok": False,
                                       "error": "%s: %s" % (type(e).__name__, e)},
                                502)
                except Exception:                   # noqa: BLE001
                    pass

    return Handler


def _b64e(text):
    """把源地址编码进 URL 路径：base64url、无 padding、无 `/`。"""
    raw = text.encode("utf-8") if isinstance(text, str) else text
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(token):
    """还原。解不出来就返回空串，绝不抛。"""
    try:
        s = token.strip()
        pad = "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s + pad).decode("utf-8")
    except Exception:                               # noqa: BLE001
        return ""


def _prefix_of(handler, proxy):
    """拼给客户端用的 base 前缀。

    顺序：显式 public_base（DDNS / 反代路径场景）> 回环绑定用 127.0.0.1
    （平台代理与插件同容器，稳定可达）> 绑定 0.0.0.0 时用请求自己的 Host
    （direct 模式下播放器拿到的就是它实际访问的地址）。
    """
    if proxy.public_base:
        return proxy.public_base
    if proxy.host in ("127.0.0.1", "localhost"):
        return "http://127.0.0.1:%d" % proxy.port
    host = handler.headers.get("Host") or "127.0.0.1:%d" % proxy.port
    return "http://%s" % host


def proxy_health(proxy):
    return {
        "ok": proxy.running,
        "bind": "%s:%d" % (proxy.host, proxy.port),
        "public_base": proxy.public_base or "(按请求 Host 自动)",
        "sessions": len(proxy.sessions),
        "cache": proxy.cache.stats(),
        "error": proxy.error,
    }


def guess_local_ip():
    """探测本机在局域网里的 IP（不真的发包，只让内核选一次出口地址）。

    绑定 0.0.0.0 时服务端不知道自己在外面该叫什么，用它兜底比写 0.0.0.0 强。
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:                               # noqa: BLE001
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:                           # noqa: BLE001
            return ""
    finally:
        s.close()


def find_free_port(host, start):
    """给「direct 模式」探测一个可用端口。"""
    for port in range(start, start + 20):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((host, port))
            return port
        except OSError:
            continue
        finally:
            s.close()
    return start
