# -*- coding: utf-8 -*-
"""取流：把「4k 的播放参数」变成「一条可拉的 m3u8 地址」。

分三种来源模式（配置项 source_mode）：
  auto    从 parse_request 的 meta 里取 data_id/secret_key/play_key，走 wasm 签名
  manual  直接用配置里填的 external_m3u8（调试 / 其他来源）
  demo    内置一份写死的清单，只用来验证「平台代理到底认不认 127.0.0.1」

网络层只用标准库 urllib，不引入任何三方依赖。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
WORKER = os.path.join(HERE, "pngu_sign_worker.py")

DEFAULT_BASE = "https://www.4kvms.org"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

SIGN_TIMEOUT = 30
FETCH_TIMEOUT = 20
SIGN_TTL = 3600
M3U8_TTL = 900

_lock = threading.Lock()
_sign_cache = {}
_m3u8_cache = {}


class FetchError(RuntimeError):
    """取流失败，消息直接给用户看。"""


# ---------------------------------------------------------------- 网络

def http_get_ex(url, referer="", timeout=FETCH_TIMEOUT, cookie="", extra=None):
    """同 http_get，但多返回**最终 URL**（跟随 302 之后的那个）。

    T3FAP 的 `/api/strm/o/<token>` 是稳定的门票地址，每次 302 到当次的上游
    m3u8（上游地址带时效）。清单里的分片必须相对**最终地址**解析，否则
    urljoin 会拿门票地址当 base，拼出来的分片地址全是错的。

    extra：额外请求头（dict）。目前用于探测时发 `Range: bytes=0-262143`，
    只取分片开头一段就能判断有没有 PNG 壳，不必整片拉下来。
    """
    req = urllib.request.Request(url)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "*/*")
    if referer:
        req.add_header("Referer", referer)
    if cookie:
        req.add_header("Cookie", cookie)
    for k, v in (extra or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        ctype = resp.headers.get("Content-Type", "")
        final = resp.geturl() or url
    return data, ctype, final


def http_get(url, referer="", timeout=FETCH_TIMEOUT, cookie=""):
    data, ctype, _ = http_get_ex(url, referer, timeout, cookie)
    return data, ctype


def http_text(url, referer="", timeout=FETCH_TIMEOUT, cookie=""):
    data, _ = http_get(url, referer, timeout, cookie)
    return data.decode("utf-8", "replace")


# ---------------------------------------------------------------- wasm 签名

def sign(data_id, secret_key, quality, play_key):
    """在子进程里跑 wasm 签名，返回 `/video/play?...` 相对路径。"""
    key = (str(data_id), str(secret_key), str(quality), str(play_key))
    now = time.time()
    with _lock:
        hit = _sign_cache.get(key)
        if hit and now - hit[0] < SIGN_TTL:
            return hit[1]

    payload = json.dumps({
        "data_id": data_id, "secret_key": secret_key,
        "quality": quality, "play_key": play_key,
    })
    try:
        proc = subprocess.run([sys.executable, WORKER, payload],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=SIGN_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise FetchError("wasm 签名超时（%d 秒），本机执行 wasm 过慢"
                         % SIGN_TIMEOUT)
    except OSError as e:
        raise FetchError("无法启动签名子进程（%s）" % e)

    out = (proc.stdout or b"").decode("utf-8", "replace").strip()
    err = (proc.stderr or b"").decode("utf-8", "replace").strip()
    line = out.splitlines()[-1] if out else ""
    try:
        body = json.loads(line) if line else None
    except ValueError:
        body = None

    rc = proc.returncode
    if rc is not None and rc < 0:
        # 典型：-11 SIGSEGV / -31 SIGSYS（seccomp 拦截 JIT）
        raise FetchError(
            "本机无法执行 wasm 签名（子进程被信号 %d 终止）。"
            "这台机器的容器策略可能禁止 JIT 申请可执行内存，"
            "可改用 source_mode=manual 直接填 m3u8。" % (-rc))
    if rc not in (0, 1, None) and not body:
        raise FetchError("本机无法执行 wasm 签名（子进程异常结束，退出码 %s）"
                         % rc)
    if rc != 0 or not body or not body.get("ok"):
        msg = ((body or {}).get("error") or err[-300:]
               or ("退出码 %s" % rc))
        raise FetchError("wasm 签名失败（%s）" % msg)

    path = body.get("path") or ""
    if not path:
        raise FetchError("wasm 签名返回空路径")
    with _lock:
        _sign_cache[key] = (now, path)
    return path


# ---------------------------------------------------------------- 4k 取流

def _pick_quality(data):
    """优先挑未锁定、非 VIP 的清晰度；全都锁了就取第一个有 url 的。"""
    urls = data.get("quality_urls") or []
    usable = [q for q in urls if q.get("url") not in ("", "1", None)]
    if not usable:
        return None
    for q in usable:
        if not q.get("locked") and not q.get("isvip"):
            return q
    return usable[0]


def resolve_4k(meta, base_url="", quality="1080", cookie=""):
    """从 4k 播放参数解析出 m3u8 地址。返回 (m3u8_url, detail)。"""
    meta = meta or {}
    data_id = meta.get("data_id") or ""
    secret_key = meta.get("secret_key") or ""
    play_key = meta.get("play_key") or ""
    page_url = meta.get("page_url") or ""
    base = (base_url or meta.get("base_url") or DEFAULT_BASE).rstrip("/")

    if not (data_id and secret_key and play_key):
        raise FetchError("4k 播放参数不完整：缺少 data_id / secret_key / "
                         "play_key，无法签名取流")

    cache_key = (str(data_id), str(quality))
    now = time.time()
    with _lock:
        hit = _m3u8_cache.get(cache_key)
        if hit and now - hit[0] < M3U8_TTL:
            return hit[1], {"from": "cache"}

    referer = page_url or (base + "/")
    last = ""
    tried = []
    for q in [quality, "1080", "720"]:
        q = str(q or "").strip()
        if not q or q in tried:
            continue
        tried.append(q)
        path = sign(data_id, secret_key, q, play_key)
        url = base + path if path.startswith("/") else path
        try:
            txt = http_text(url, referer=referer, cookie=cookie)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                last = "HTTP %d（播放令牌不被接受，可能该集需要登录/会员）" % e.code
                continue
            last = "HTTP %d" % e.code
            continue
        except Exception as e:                  # noqa: BLE001
            last = str(e)[:120]
            continue

        try:
            body = json.loads(txt)
        except ValueError:
            last = "返回不是 JSON：%s" % txt[:100]
            continue

        code = body.get("code")
        if code != 200:
            msg = body.get("message") or ("code=%s" % code)
            if code in (401, 403) or "登录" in str(msg) or "VIP" in str(msg):
                raise FetchError("4k 拒绝了取流：%s（该内容需登录/会员）" % msg)
            last = str(msg)
            if code == 400:
                break
            continue

        picked = _pick_quality(body.get("data") or {})
        if not picked:
            last = "该集没有可用的清晰度"
            continue
        link = picked.get("url") or ""
        if not link:
            last = "播放地址为空"
            continue

        with _lock:
            _m3u8_cache[cache_key] = (now, link)
        return link, {"from": "4k", "quality": q,
                      "locked": bool(picked.get("locked"))}

    raise FetchError("4k 取流失败（%s）" % (last or "unknown"))


# ---------------------------------------------------------------- demo 源

DEMO_PLAYLIST = """#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:4
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:4.000,
{prefix}/seg/demo/0
#EXT-X-ENDLIST
"""


def demo_playlist(prefix):
    """一份写死的单分片清单，用来验证平台代理能否拉到插件本地服务。

    分片内容是合成的合法 TS 包（PAT + 空包），播放器可能报没有视频轨，
    但**只要清单和分片都被成功请求到，就证明 127.0.0.1 链路是通的**。
    """
    return DEMO_PLAYLIST.format(prefix=prefix.rstrip("/"))


def demo_segment():
    """合成一个 2 个包的 TS：一个 PAT，一个填充包。"""
    pat = bytearray(188)
    pat[0] = 0x47
    pat[1] = 0x40
    pat[2] = 0x00
    pat[3] = 0x10
    pat[4] = 0x00                 # pointer_field
    pat[5] = 0x00                 # table_id = PAT
    pat[6] = 0xB0
    pat[7] = 0x0D
    pat[8] = 0x00
    pat[9] = 0x01
    pat[10] = 0xC1
    pat[11] = 0x00
    pat[12] = 0x00
    pat[13] = 0x00
    pat[14] = 0x01
    pat[15] = 0xE0
    pat[16] = 0x00
    # CRC 留 0，多数播放器容忍；这里只是链路探针，不是真内容
    fill = bytearray(188)
    fill[0] = 0x47
    fill[1] = 0x1F
    fill[2] = 0xFF
    fill[3] = 0x10
    return bytes(pat) + bytes(fill)
