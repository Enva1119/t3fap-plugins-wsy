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

import json
import logging
import os
import socket
import sys
import threading
import time
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
                 "maps", "playlist", "created", "touched", "error")

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


class HlsProxy(object):
    """插件内建 HTTP 服务（惰性启动，进程内线程）。"""

    def __init__(self, host="127.0.0.1", port=18521,
                 cache_mb=64, cache_ttl=30):
        self.host = host
        self.port = int(port)
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

    def register(self, src_url, referer="", cookie="", prefix=""):
        """登记一条源，返回可播放的清单地址。"""
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
            sess.playlist = pngu_fetch.demo_playlist(prefix)
            sess.segments = ["%s/seg/demo/0" % prefix.rstrip("/")]
            sess.keys = []
            sess.maps = []
            return sess.playlist

        txt = pngu_fetch.http_text(sess.src, referer=sess.referer,
                                   cookie=sess.cookie)
        if "#EXTM3U" not in txt:
            raise RuntimeError("源地址返回的不是 m3u8（前 80 字节：%s）"
                               % txt[:80].replace("\n", " "))

        base = sess.src
        out = []
        segs, keys, maps = [], [], []

        for raw in txt.splitlines():
            line = raw.strip()
            if not line:
                continue

            if line.startswith("#EXT-X-KEY") or line.startswith("#EXT-X-SESSION-KEY"):
                uri = _attr_uri(line)
                if uri:
                    keys.append(urllib.parse.urljoin(base, uri))
                    line = _replace_uri(
                        line, "%s/key/%s/%d" % (prefix.rstrip("/"),
                                                sess.token, len(keys) - 1))
                out.append(line)
                continue

            if line.startswith("#EXT-X-MAP"):
                uri = _attr_uri(line)
                if uri:
                    maps.append(urllib.parse.urljoin(base, uri))
                    line = _replace_uri(
                        line, "%s/key/%s/m%d" % (prefix.rstrip("/"),
                                                 sess.token, len(maps) - 1))
                out.append(line)
                continue

            if line.startswith("#"):
                out.append(line)
                continue

            # 普通分片行
            segs.append(urllib.parse.urljoin(base, line))
            out.append("%s/seg/%s/%d" % (prefix.rstrip("/"), sess.token,
                                         len(segs) - 1))

        if not segs:
            raise RuntimeError("清单里没有分片")

        sess.segments = segs
        sess.keys = keys
        sess.maps = maps
        sess.playlist = "\n".join(out) + "\n"
        return sess.playlist

    def playlist_bytes(self, sess, prefix):
        """拿清单字节；没有就现场构建（HEAD 也需要真实长度）。"""
        if not sess.playlist:
            self._build_playlist(sess, prefix)
        return sess.playlist.encode("utf-8")

    # ------------------------------------------------------------ 取字节

    def segment_bytes(self, sess, idx):
        key = (sess.token, idx)
        hit = self.cache.get(key)
        if hit is not None:
            return hit
        if idx < 0 or idx >= len(sess.segments):
            raise RuntimeError("分片下标越界 %s" % idx)
        raw, _ = pngu_fetch.http_get(sess.segments[idx],
                                     referer=sess.referer or sess.src,
                                     cookie=sess.cookie)
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


def _serve_bytes(handler, blob, ctype, allow_range=True):
    """统一的字节输出：支持 HEAD / Range(206) / 正确 Content-Length。

    注意顺序：必须先 send_response（发状态行），再 send_header，否则状态行
    会被塞到响应头后面，客户端直接 BadStatusLine。
    """
    total = len(blob)
    rng = handler.headers.get("Range") or ""

    start, end = 0, total - 1
    partial = False
    if allow_range and rng.startswith("bytes=") and total > 0:
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

    handler.send_response(206 if partial else 200)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Accept-Ranges", "bytes" if allow_range else "none")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(body)))
    if partial:
        handler.send_header(
            "Content-Range", "bytes %d-%d/%d" % (start, end, total))
    handler.end_headers()
    if handler.command != "HEAD":
        try:
            handler.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


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
                parsed = urllib.parse.urlsplit(self.path)
                parts = [p for p in parsed.path.split("/") if p]
                if not parts:
                    return _serve_json(self, {"ok": True,
                                              "service": "pngunwrap"}, 200)
                head = parts[0]

                if head == "__health":
                    return _serve_json(self, proxy_health(proxy))

                if head == "hls" and len(parts) >= 2:
                    tok = parts[1].split(".")[0]
                    sess = proxy.session(tok)
                    if not sess:
                        return _serve_json(
                            self, {"ok": False, "error": "会话不存在或已过期",
                                   "token": tok}, 404)
                    prefix = _prefix_of(self, proxy)
                    blob = proxy.playlist_bytes(sess, prefix)
                    return _serve_bytes(
                        self, blob, "application/vnd.apple.mpegurl")

                if head == "seg" and len(parts) >= 3:
                    tok, idx = parts[1], parts[2]
                    if tok == "demo":
                        return _serve_bytes(self, pngu_fetch.demo_segment(),
                                            "video/mp2t")
                    sess = proxy.session(tok)
                    if not sess:
                        return _serve_json(
                            self, {"ok": False, "error": "会话不存在或已过期",
                                   "token": tok}, 404)
                    blob = proxy.segment_bytes(sess, int(idx))
                    return _serve_bytes(self, blob, "video/mp2t")

                if head == "key" and len(parts) >= 3:
                    tok, idx = parts[1], parts[2]
                    sess = proxy.session(tok)
                    if not sess:
                        return _serve_json(
                            self, {"ok": False, "error": "会话不存在或已过期",
                                   "token": tok}, 404)
                    return _serve_bytes(self, proxy.key_bytes(sess, idx),
                                        "application/octet-stream")

                return _serve_json(self, {"ok": False,
                                          "error": "未知路径 %s" % self.path},
                                   404)
            except Exception as e:                  # noqa: BLE001
                log.warning("处理 %s 失败：%s", self.path, e)
                try:
                    _serve_json(self, {"ok": False,
                                       "error": "%s: %s" % (type(e).__name__, e)},
                                502)
                except Exception:                   # noqa: BLE001
                    pass

    return Handler


def _prefix_of(handler, proxy):
    """拼给客户端用的 base 前缀。

    绑定在回环地址时用 127.0.0.1（平台代理与插件同容器，稳定可达）；
    绑定 0.0.0.0 时用请求自己的 Host，这样 direct 模式下播放器拿到的
    就是它实际访问的地址。
    """
    if proxy.host in ("127.0.0.1", "localhost"):
        return "http://127.0.0.1:%d" % proxy.port
    host = handler.headers.get("Host") or "127.0.0.1:%d" % proxy.port
    return "http://%s" % host


def proxy_health(proxy):
    return {
        "ok": proxy.running,
        "bind": "%s:%d" % (proxy.host, proxy.port),
        "sessions": len(proxy.sessions),
        "cache": proxy.cache.stats(),
        "error": proxy.error,
    }


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
