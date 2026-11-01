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
def worker_script():
    """签名子进程要执行的脚本路径。

    源码包是 `.py`；发布包只放 `.pyc`（不暴露源码）。CPython 能直接执行
    `.pyc`，所以两种布局都能跑 —— 按顺序挑第一个真实存在的。
    """
    for name in ("pngu_sign_worker.py", "pngu_sign_worker.pyc"):
        path = os.path.join(HERE, name)
        if os.path.isfile(path):
            return path
    return os.path.join(HERE, "pngu_sign_worker.pyc")


WORKER = worker_script()

DEFAULT_BASE = "https://www.4kvms.org"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

SIGN_TIMEOUT = 30
FETCH_TIMEOUT = 20
# 签名只是本机 wasm 计算，缓存是为了省 CPU；但签名出来的路径本身带时效，
# 缓存太久会拿着过期路径去打上游（又变成一次「解析失败」）。10 分钟够挡住
# 一次播放里的重复调用，又不会把失效的东西端出去。
SIGN_TTL = 600
M3U8_TTL = 900

# 出站请求的自标记。插件发起的请求如果打到平台自己（门票地址就是），
# 中间件靠这个头认出「这是自己人」，直接透传 302，绝不再探测一遍。
SELF_MARK_HEADER = "X-Pngu-Self"
SELF_MARK_VALUE = "1"

_lock = threading.Lock()
_sign_cache = {}
_m3u8_cache = {}
_m3u8_neg = {}          # 失败结果短缓存：挡住播放器的重试风暴


class FetchError(RuntimeError):
    """取流失败，消息直接给用户看。"""


# ---------------------------------------------------------------- 上游闸门
#
# 因果链：解析失败 → 播放器/平台立刻重试 → 又一次 wasm 签名 + 一次
# `/video/play` → 源站判定「这人在锤我」→ 封 IP → 解析更失败。
#
# 插件唯一能自己控制的一段是**每次解析要发多少个上游请求**。所以所有打 4k
# 站的请求（我们自己的 resolve_4k、官方插件失败后的救场、同源 HLS 线路枚举）
# 全部收进这一个闸门：
#
#   * 失败一次就关一小会儿，连续失败按 20/60/180/600 秒退避；
#   * 403/429/5xx 视为「上游在拒绝」，直接跳到长冷却；
#   * 「登录/VIP/令牌过期」**不冷却** —— 那不是限流，冷却只会让用户白等，
#     而且换令牌就能好，属于要如实报错的那一类；
#   * 关闸期间一个请求都不发，直接抛 UpstreamBusy，让上层如实告诉平台
#     「别重试」（retryable=False）。

_BACKOFF = (20, 60, 180, 600)      # 连续失败 1/2/3/4+ 次的冷却秒数
HARD_CODES = (403, 405, 418, 429, 503)          # 上游拒绝：长冷却
# 这些字样代表「内容权限/令牌」问题，不是限流。命中就不冷却、也不再换画质
# 重试（play_key 一样，换画质只会多发一次请求）。
PERMISSION_MARKERS = ("请先登录", "开通vip", "vip会员", "会员权限",
                      "访问令牌已过期", "令牌已过期", "请登录", "need login")

NEG_TTL = 30          # 失败结果短缓存：重试风暴在这一层被吃掉
MAX_TRIES = 2         # 一次解析最多试几种画质（原来是目标+1080+720 共 3 次）

_GATE = {"fails": 0, "until": 0.0, "reason": "", "since": 0.0,
         "blocked": 0, "hard": 0, "perm": 0}
_GATE_LOCK = threading.Lock()


class UpstreamBusy(FetchError):
    """闸门关着：上游刚失败过，这次直接放弃，一个请求都不发。"""


def gate_open():
    """返回 (能不能发请求, 还要等几秒, 关闸原因)。"""
    now = time.time()
    with _GATE_LOCK:
        left = float(_GATE["until"] or 0.0) - now
        if left > 0:
            _GATE["blocked"] += 1
            return False, int(left + 0.999), str(_GATE["reason"] or "")
        if _GATE["until"]:
            _GATE["until"] = 0.0
        return True, 0, ""


def gate_check():
    """关着就直接抛 UpstreamBusy（调用方不用自己拼句子）。"""
    ok, left, why = gate_open()
    if ok:
        return
    raise UpstreamBusy(
        "上游刚刚拒绝了请求，暂停 %d 秒再试%s。这段时间内不再向源站发任何"
        "请求，避免「越重试越封」。%s" %
        (left, "", ("原因：%s" % why) if why else ""))


def gate_note_ok():
    """上游正常应答：清掉失败计数，闸门完全打开。"""
    with _GATE_LOCK:
        if _GATE["fails"] or _GATE["until"]:
            _GATE["since"] = time.time()
        _GATE["fails"] = 0
        _GATE["until"] = 0.0
        _GATE["reason"] = ""


def gate_note_perm(reason):
    """权限类失败（登录/VIP/令牌过期）：记下来，但**不关闸**。"""
    with _GATE_LOCK:
        _GATE["perm"] += 1
        _GATE["reason"] = str(reason)[:200]


def gate_note_fail(reason, hard=False):
    """记一次失败并起冷却。hard=True 表示上游明确拒绝（403/429/5xx）。"""
    with _GATE_LOCK:
        _GATE["fails"] += 1
        n = int(_GATE["fails"])
        if hard:
            _GATE["hard"] += 1
            idx = max(2, n - 1)                 # 硬失败至少 180 秒
        else:
            idx = n - 1
        wait = _BACKOFF[min(len(_BACKOFF) - 1, max(0, idx))]
        _GATE["until"] = time.time() + wait
        _GATE["reason"] = str(reason)[:200]
        if n == 1:
            _GATE["since"] = time.time()
    return wait


def gate_reset():
    """手动清闸（诊断口用；正常情况下等它自己到点）。"""
    with _GATE_LOCK:
        _GATE.update({"fails": 0, "until": 0.0, "reason": "", "since": 0.0})


def gate_state():
    now = time.time()
    with _GATE_LOCK:
        left = max(0, int((float(_GATE["until"] or 0.0) - now) + 0.999))
        return {"open": left <= 0, "left": left, "fails": int(_GATE["fails"]),
                "reason": str(_GATE["reason"] or ""),
                "blocked": int(_GATE["blocked"]), "hard": int(_GATE["hard"]),
                "perm": int(_GATE["perm"])}


def _looks_permission(text):
    s = str(text or "").lower()
    return any(m.lower() in s for m in PERMISSION_MARKERS)


# ---------------------------------------------------------------- 网络

def http_get_ex(url, referer="", timeout=FETCH_TIMEOUT, cookie="", extra=None,
                method=None, max_bytes=0):
    """同 http_get，但多返回**最终 URL**（跟随 302 之后的那个）。

    T3FAP 的 `/api/strm/o/<token>` 是稳定的门票地址，每次 302 到当次的上游
    m3u8（上游地址带时效）。清单里的分片必须相对**最终地址**解析，否则
    urljoin 会拿门票地址当 base，拼出来的分片地址全是错的。

    extra：额外请求头（dict）。目前用于探测时发 `Range: bytes=0-262143`，
    只取分片开头一段就能判断有没有 PNG 壳，不必整片拉下来。

    method：给了就用它（DELETE 之类）。默认 GET。

    max_bytes：最多读回这么多字节。给 0 表示读完。用途是「只看开头」的
    嗅探：即使对方不认 Range，也不会因为 302 指到一个大文件就把整个文件
    拉进内存。
    """
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "*/*")
    # 给自己做的每个出站请求盖个戳：万一这个地址其实指回平台自己（门票就是
    # 这种情况），中间件见到这个头会**原样透传**，不再做探测/改写。没有它
    # 就会自己请求自己 → 自己又去探测 → 无限自激（实测日志里刷屏的
    # HEAD/GET /api/strm/o/… 302 就是这个循环）。上游 CDN 会忽略这个头。
    req.add_header(SELF_MARK_HEADER, SELF_MARK_VALUE)
    if referer:
        req.add_header("Referer", referer)
    if cookie:
        req.add_header("Cookie", cookie)
    for k, v in (extra or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read(max_bytes) if max_bytes else resp.read()
        ctype = resp.headers.get("Content-Type", "")
        final = resp.geturl() or url
    return data, ctype, final


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不让 urllib 自动跟随 302 —— 我们要的就是那个 Location。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def peek_redirect(url, timeout=8):
    """只发一个请求，把**状态码和 Location** 拿回来，不跟过去。

    门票 `/api/strm/o/<token>.m3u8` 的价值全在 Location 上：平台会按当前
    的解析结果给一个上游地址。`http_get_ex` 会自动跟过去，跟过去就等于
    「拉上游清单」，拿不到跳转目标本身 —— 而「上游清单 404、想知道平台
    还能不能解析出别的地址」恰恰就要这个 Location。

    返回 (status, location, error)。永不抛。
    """
    req = urllib.request.Request(url)
    req.add_header("User-Agent", UA)
    req.add_header("Accept", "*/*")
    req.add_header(SELF_MARK_HEADER, SELF_MARK_VALUE)
    try:
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(req, timeout=timeout) as resp:
            return int(getattr(resp, "status", 0) or 0), \
                   resp.headers.get("Location", "") or "", ""
    except urllib.error.HTTPError as e:
        # 3xx 被我们拦下来时，urllib 会抛 HTTPError —— 这里正是想要的结果
        return int(getattr(e, "code", 0) or 0), \
               (e.headers.get("Location", "") if e.headers else "") or "", ""
    except Exception as e:                          # noqa: BLE001
        return 0, "", "%s: %s" % (type(e).__name__, str(e)[:120])


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
        proc = subprocess.run([sys.executable, worker_script(), payload],
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

def _pick_quality(data, prefer_hls=True):
    """优先挑未锁定、非 VIP 的清晰度；全都锁了就取第一个有 url 的。

    `prefer_hls` 会把清单类地址（`.m3u8`）排到前面。4k 源同一个清晰度下
    可能既给 HLS 又给云盘直链（`.mp4`），直链往往带防盗链、还可能被 CDN
    403，而且没法剥壳、没法改写清单。HLS 永远是更优解，所以默认优先它。
    """
    urls = data.get("quality_urls") or []
    usable = [q for q in urls if q.get("url") not in ("", "1", None)]
    if not usable:
        return None
    if prefer_hls:
        hls = [q for q in usable if ".m3u8" in str(q.get("url") or "").lower()]
        direct = [q for q in usable if q not in hls]
        usable = hls + direct
    for q in usable:
        if not q.get("locked") and not q.get("isvip"):
            return q
    return usable[0]


def _base_from_meta(meta):
    """平台下发的线路里挑了第一个 host 当接口地址。

    官方 4k 插件是 `urljoin(line["host"], path)` —— 也就是说接口域名由
    **平台下发的线路**决定，不是写死的。我们以前一直用 `DEFAULT_BASE`，
    一旦站的域名轮换（.org ↔ .com）就会取流失败。这里对齐官方的做法，
    找不到再退回默认值。
    """
    for line in (meta.get("line_options") or []):
        if isinstance(line, dict):
            host = str(line.get("host") or "").strip()
            if host:
                return host.rstrip("/")
    return ""


def resolve_4k(meta, base_url="", quality="1080", cookie="", prefer_hls=True):
    """从 4k 播放参数解析出 m3u8 地址。返回 (m3u8_url, detail)。

    三道自我约束，都是为了一件事：**别把源站惹毛**。

    1. 缓存键带上 `play_key`。以前是 `(data_id, quality)`，换一集、换一次
       播放令牌都会命中上一集的地址 —— 那个地址多半已经过期，播放器拉不到
       就重试，重试又命中，形成「怎么播都失败」的死循环。
    2. 失败结果短缓存（`NEG_TTL`）。10 秒内重试 8 次只发 1 次请求。
    3. 闸门（`gate_check`）。上游刚拒绝过就一个请求都不发，直接抛
       `UpstreamBusy`，由上层告诉平台「别重试」。
    """
    meta = meta or {}
    data_id = meta.get("data_id") or ""
    secret_key = meta.get("secret_key") or ""
    play_key = meta.get("play_key") or ""
    page_url = meta.get("page_url") or ""
    base = (base_url or meta.get("base_url")
            or _base_from_meta(meta) or DEFAULT_BASE).rstrip("/")

    if not (data_id and secret_key and play_key):
        raise FetchError("4k 播放参数不完整：缺少 data_id / secret_key / "
                         "play_key，无法签名取流")

    # play_key 进 key：同一部片的不同集、以及过期后换的新令牌，结果不能混用
    cache_key = (str(data_id), str(play_key)[-24:], str(quality))
    now = time.time()
    with _lock:
        hit = _m3u8_cache.get(cache_key)
        if hit and now - hit[0] < M3U8_TTL:
            # 手里有货就先给：闸门关着也不该扣住已经解析好的地址。
            return hit[1], {"from": "cache"}

    # 关闸的说法比「上次失败的原因」更准：用户要知道的是「还要等多久」。
    gate_check()

    with _lock:
        neg = _m3u8_neg.get(cache_key)
        if neg and now - neg[0] < NEG_TTL:
            raise FetchError(neg[1])

    referer = page_url or (base + "/")
    last = ""
    tried = []
    tries = 0
    for q in [quality, "1080", "720"]:
        q = str(q or "").strip()
        if not q or q in tried:
            continue
        tried.append(q)
        if tries >= MAX_TRIES:
            break
        tries += 1
        try:
            path = sign(data_id, secret_key, q, play_key)
        except FetchError as e:
            # 签名是本机算的，跟源站无关，不该触发冷却
            last = str(e)
            break
        url = base + path if path.startswith("/") else path
        try:
            txt = http_text(url, referer=referer, cookie=cookie)
        except urllib.error.HTTPError as e:
            msg = "HTTP %d" % e.code
            detail = ""
            try:
                detail = e.read()[:400].decode("utf-8", "replace")
            except Exception:                       # noqa: BLE001
                pass
            if _looks_permission(detail) or e.code in (401,):
                # 令牌/会员问题：换画质没用（play_key 一样），也不该冷却
                reason = ("4k 拒绝了取流（HTTP %d）：内容需要登录/会员，"
                          "或播放令牌已过期" % e.code)
                gate_note_perm(reason)
                _neg_put(cache_key, reason)
                raise FetchError(reason)
            if e.code in HARD_CODES:
                reason = "4k 源站返回 HTTP %d（可能限流或封了本机出口 IP）" % e.code
                gate_note_fail(reason, hard=True)
                _neg_put(cache_key, reason)
                raise FetchError(reason)
            last = msg
            break                                   # 其他错误换画质也没意义
        except UpstreamBusy:
            raise
        except Exception as e:                      # noqa: BLE001
            last = "%s: %s" % (type(e).__name__, str(e)[:100])
            # 连不上/DNS/TLS → 网络层失败，冷却一次，别立刻再试
            gate_note_fail(last)
            break

        try:
            body = json.loads(txt)
        except ValueError:
            last = "返回不是 JSON：%s" % txt[:100]
            gate_note_fail("4k 返回的不是 JSON（疑似被拦截页顶掉）", hard=True)
            break

        code = body.get("code")
        if code != 200:
            msg = str(body.get("message") or ("code=%s" % code))
            if code in (401, 403) or _looks_permission(msg):
                reason = "4k 拒绝了取流：%s（该内容需登录/会员，或令牌已过期）" % msg
                gate_note_perm(reason)
                _neg_put(cache_key, reason)
                raise FetchError(reason)
            last = msg
            if code == 400:
                break
            if code in HARD_CODES:
                reason = "4k 源站返回 code=%s：%s" % (code, msg)
                gate_note_fail(reason, hard=True)
                _neg_put(cache_key, reason)
                raise FetchError(reason)
            continue

        picked = _pick_quality(body.get("data") or {}, prefer_hls=prefer_hls)
        if not picked:
            last = "该集没有可用的清晰度"
            break

        link = picked.get("url") or ""
        if not link:
            last = "播放地址为空"
            break

        with _lock:
            _m3u8_cache[cache_key] = (now, link)
            _m3u8_neg.pop(cache_key, None)
        gate_note_ok()
        return link, {"from": "4k", "quality": q,
                      "locked": bool(picked.get("locked"))}

    reason = "4k 取流失败（%s）" % (last or "unknown")
    _neg_put(cache_key, reason)
    raise FetchError(reason)


def _neg_put(cache_key, msg):
    with _lock:
        _m3u8_neg[cache_key] = (time.time(), str(msg)[:300])


def invalidate_4k(data_id=""):
    """作废解析缓存。门票侧看到上游 4xx 时可以叫我们重来一次。"""
    with _lock:
        if not data_id:
            _m3u8_cache.clear()
            _m3u8_neg.clear()
            return 0
        n = 0
        for k in list(_m3u8_cache):
            if k and str(k[0]) == str(data_id):
                _m3u8_cache.pop(k, None)
                n += 1
        for k in list(_m3u8_neg):
            if k and str(k[0]) == str(data_id):
                _m3u8_neg.pop(k, None)
        return n


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


# 模块自述版本。plugin.py 会拿它和磁盘上的文件比对，不一致就说明平台热更新
# 只重载了 plugin 模块、子模块还留在 sys.modules 里，需要 importlib.reload。
__version__ = "0.5.13"
