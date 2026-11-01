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


def _is_self_call(scope):
    """这个请求是不是插件自己发出去的。

    为什么必须有这道闸：门票地址（`/api/strm/o/<token>.m3u8`）指的其实就是
    平台自己。插件拿门票去拉清单，请求绕一圈又进到同一个中间件里 —— 中间件
    再探测一次，探测又去拉门票…… 结果是日志里 `HEAD/GET /api/strm/o/… 302`
    刷屏，播放器早就关了还在跑。

    `pngu_fetch` 给每个出站请求都盖了 `X-Pngu-Self: 1`，见到就说明是自己人，
    原样交给原来的处理链（平台该 302 就 302），一个字节都不碰。
    """
    for k, _v in (scope.get("headers") or []):
        if k.lower() == b"x-pngu-self":
            return True
    return False

REDIRECT_CODES = (301, 302, 303, 307, 308)

# 探测第一片时取多少字节。
#
# 判定到底需要多少，两个常量说了算（见 pngu_unwrap）：
#   SEARCH_WINDOW = 1024      壳长搜索窗口，1 KB 就够
#   _ts_sync_rate 采 100 点 × 188 字节 ≈ 18.8 KB
# 合计 20 KB 上下，32 KB 已经是两倍余量。
#
# 原来写 256 KB，在实测 100~200 KB/s 的源上，**光这一次 Range 就要
# 1.3~2.6 秒**，而播放器每打开一次都得等它 —— 这就是「起播反应慢」的
# 直接来源。降到 32 KB 后同样的线路只要 0.2~0.3 秒，判定结论不变。
PROBE_BYTES = 32 * 1024

# 判定的缓存时长。同一个片源会反复请求清单（播放器、进度条拖动、多端），
# 每次重新探测等于每播一部片子多花一次网络往返，所以缓存住结论。
VERDICT_TTL = 1800
# 失败的结论只能短暂缓存。踩过的坑：上游刚 404 那一下被判死，结论一存就是
# 30 分钟，期间上游恢复了也不会再探 —— 明明能播的源，插件一直以为它死着，
# 一直放行死地址。成功结论值得记久（省一次探测），失败结论 30 秒就够。
FAIL_TTL = 30
VERDICT_MAX = 512

_STATE = {
    "hijacked": 0,          # 被包住的路由条数
    "routes": [],           # 被包住的路由 path（给健康检查看）
    "app": "",
    "reason": "",
    "hit": 0,               # 命中包装器的请求数（真实播放，不含诊断和自己）
    "diag": 0,              # 诊断口（__inspect/__probe/__speed）的请求数
    "self_skip": 0,         # 插件自己发起的回环请求，被认出后原样放行的次数
    "memo": 0,              # 上游清单失效、用留底顶上的次数
    "rescue": 0,            # 平台自己解析失败（4xx/5xx）、用留底顶上的次数
    "err": 0,               # 平台解析失败且没有留底可救的次数
    "reparse": 0,           # 上游地址死了，尝试「清平台缓存 + 重走门票」的次数
    "reparse_ok": 0,        # 重解析拿到了新的可用地址的次数
    "cache_clear": 0,       # 清平台播放缓存成功的次数
    "wrap": 0,              # 判定为 PNG 壳、改写成自家清单的次数
    "pass": 0,              # 判定为非 PNG、原样放行的次数
    "relay": 0,             # relay_mode=always 时，裸 TS 也强制中转的次数
    "sps_fix": 0,           # 修掉畸形 SPS 的分片数（每片算一次）
    "fail": 0,              # 探测失败而放行的次数
    "last": "",             # 最近一次判定的说明
    "last_status": 0,       # 平台内核最近一次对门票返回的状态码（0=还没请求过）
    "mode": "",             # route = 换路由 app；middleware = 最外层中间件
}

_LOCK = threading.Lock()
_VERDICT = {}               # loc -> (expire_ts, dict)
_ORIG = []                  # [(route, orig_app)]

# ---- 内存回收参数 ----
# NAS 上内存是硬约束（4 GB 机器上还跑着影视转码），插件不能只涨不降。
# 三张表都有上限，另外有个后台清扫线程：**光靠「写入时顺便淘汰」不够**，
# 播放器关掉之后不会再有写入，过期分片会一直留在内存里。
SESS_IDLE = 1800            # 会话闲置多久回收（秒）
SWEEP_SEC = 30              # 后台清扫间隔（秒）
# 会话超过这么久就重新拉一次清单。**这是「过一段再看就播不动」的根治点**：
# 上游分片地址带时效，播放器关掉再打开时如果直接复用旧会话，拿到的还是
# 上一次那批过期地址，分片全 401/403/404。20 秒足够吃掉播放器自己的连续
# 重载（hls.js 会连拉几次清单），又短到能让「续播」一定拿到新地址。
SESS_REFRESH = 20
# 会话被回收后留下的「墓碑」：tok -> (门票地址, 过期时间)。
# 播放器手里那张旧清单里的分片路径不会跟着变，所以只要它还来要分片，
# 就得能凭 tok 找回原始门票地址、重新走一遍 302 拿到新上游。留 24 小时。
TOMB_TTL = 24 * 3600
_REAPER = [None]            # 后台清扫线程（惰性启动，没东西可扫就自己退出）
_WAKE = threading.Event()   # 叫醒清扫线程（停用时立刻退出，不必等满一个周期）
# 最近一次播放入口。诊断口不带参数时分析它。
# 必须同时记 **门票** 和 **302 目标**：门票（`/api/strm/o/…`）每次请求都会
# 被平台重新解析成当前有效的上游地址，而 302 目标本身几分钟就 404。诊断如果
# 直接拿旧的 302 目标去拉，只会得到 "404 Not Found"，误导成「地址过期」。
_LAST = {"entry": "", "loc": "", "ts": 0.0}


def state():
    """给 health / 诊断接口看的接管状态（含内存占用）。"""
    with _LOCK:
        s = dict(_STATE)
        s["routes"] = list(_STATE["routes"])
        verdict = len(_VERDICT)
    # _SEG / _SESS 用 _SEG_LOCK 保护，跟 _LOCK 分开取，避免嵌套死锁
    with _SEG_LOCK:
        seg_n = len(_SEG)
        sess_n = len(_SESS)
        tomb_n = len(_TOMB)
        seg_bytes = _SEG_BYTES[0]
    with _MEMO_LOCK:
        memo_n = len(_MEMO)
    s["cache"] = verdict
    s["last_loc"] = _LAST.get("loc", "")
    s["last_entry"] = _LAST.get("entry", "")
    s["relay_mode"] = RELAY_MODE
    s["sps_fix"] = SPS_FIX
    s["auto_reparse"] = AUTO_REPARSE
    s["repair_cool"] = REPAIR_COOL
    # 三个计数各管一段，别互相污染：
    #   hit        播放器真的来要流了
    #   diag       有人打开 __inspect / __probe / __speed
    #   self_skip  插件自己去拉门票、绕回自己身上（不算播放，也不算故障）
    s["counters"] = {
        "hit": "真实播放请求",
        "diag": "诊断口请求",
        "self_skip": "插件自己发起的回环请求（已放行）",
        "wrap": "判定带壳并改写清单",
        "relay": "relay_mode=always 时强制中转",
        "sps_fix": "修掉畸形 SPS 的分片数（硬解失败常见诱因）",
        "memo": "上游清单 404，用上次的留底顶上",
        "rescue": "平台自己解析失败（4xx/5xx），用留底顶上",
        "err": "平台解析失败且没有留底（这一集从来没成功播过）",
        "reparse": "地址死了，尝试清平台缓存 + 重走门票",
        "reparse_ok": "重解析拿到了新的可用地址",
        "cache_clear": "清平台 drive-playback 缓存成功",
        "pass": "首片是裸 TS，原样放行",
        "fail": "探测失败，退回原 302",
    }
    s["mem"] = {
        "verdict": verdict,
        "segments": seg_n,
        "sessions": sess_n,
        "tombs": tomb_n,
        "memo": memo_n,
        "cache_mb": round(seg_bytes / 1048576.0, 1),
        "cache_max_mb": SEG_MAX_BYTES // 1048576,
        "seg_ttl": SEG_TTL,
        "reaper": bool(_REAPER[0] is not None and _REAPER[0].is_alive()),
    }
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
        _VERDICT[loc] = (now + (VERDICT_TTL if (val or {}).get("playlist")
                                else FAIL_TTL), val)
    _ensure_reaper()


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


def _is_dead(val):
    """这份判定结论是不是「上游已经不可用」。"""
    why = str((val or {}).get("why") or "")
    return ("拉取失败" in why) or ("不是 m3u8" in why) or ("找不到分片" in why)


def _probe(loc, timeout=12):
    """判断一个上游 m3u8 的分片是不是 PNG 壳。返回 dict，永不抛。

    注意这里**故意不复用** proxy.register：判定为非壳时会放弃这条源，如果先
    建了会话，媒体库里几千部片子就会白白撑出几千个会话。自己拉一遍清单
    （几十~几百 KB）便宜得多，结论还能缓存。
    """
    import pngu_fetch
    import pngu_unwrap

    val = {"wrapped": False, "why": "", "shell": 0, "kind": "", "seg": "",
           "playlist": "", "final": "", "bad_sps": 0}
    try:
        blob, ctype, final = pngu_fetch.http_get_ex(loc, timeout=timeout)
    except Exception as e:                          # noqa: BLE001
        val["why"] = "清单拉取失败：%s: %s" % (type(e).__name__, str(e)[:120])
        return val

    text = blob.decode("utf-8", "replace")
    val["playlist"] = text
    val["final"] = final or loc
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
            # 裸流也可能带着**畸形 SPS**。分片本身不用剥，但首片得替播放器
            # 修一下，否则硬解器按坏参数集初始化 surface 会直接失败。
            if info.get("kind") == "ts" and SPS_FIX != "off":
                try:
                    vp = _video_params(seg)
                    n_bad = int(vp.get("sps_invalid") or 0)
                    if n_bad:
                        val["bad_sps"] = n_bad
                        s = vp.get("sps") or {}
                        val["why"] = (
                            "首片是裸 TS，但里面有 %d 组畸形 SPS（%sx%s 不是有效"
                            "画面尺寸），硬解会初始化失败"
                            % (n_bad, s.get("width"), s.get("height")))
                except Exception:                   # noqa: BLE001
                    pass
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


# ---------------------------------------------------------------- 码流体检
# 「同一个链接浏览器能播、电视盒子播不了」基本不是地址问题，而是码流本身：
# 4K HEVC、AC-3 音轨、或者 TS 分片缺 PAT/PMT，这些电视盒子硬解都直接崩，
# 而浏览器的 MSE / FFmpeg 软解能容错。光看日志判断不了，得把码流拆开看。

_TS_STREAM_TYPES = {
    0x01: "MPEG-1 video", 0x02: "MPEG-2 video", 0x03: "MPEG-1 audio",
    0x04: "MPEG-2 audio", 0x0F: "AAC (ADTS)", 0x11: "AAC (LATM)",
    0x1B: "H.264", 0x24: "H.265/HEVC", 0x27: "H.265(3D)",
    0x81: "AC-3", 0x87: "E-AC-3", 0x86: "SCTE-35", 0x15: "ID3 metadata",
    0x06: "private(0x06)",
}


def _ts_section(pkt):
    """取出一个 PSI 包里真正的 section 数据（跳过适配域与 pointer_field）。"""
    if len(pkt) < 5:
        return b""
    af = (pkt[3] >> 4) & 0x03
    off = 4
    if af in (2, 3):
        off = 5 + pkt[4]
    sec = pkt[off:]
    if not sec:
        return b""
    return sec[1 + sec[0]:]


# ---------------------------------------------------------------- H.264 参数集
# 「硬解失败、回退软解」在 1080p H.264 上照样会发生：硬解管线对 level、
# profile、bit depth 都是硬性要求，软解（FFmpeg）什么都吃。光看 stream_type
# 只能说「是 H.264」，说不出「是哪个 level 的 H.264」—— 而卡的往往就是后者。

_H264_PROFILES = {66: "Baseline", 77: "Main", 88: "Extended",
                  100: "High", 110: "High 10", 122: "High 4:2:2",
                  244: "High 4:4:4", 44: "CAVLC 4:4:4"}


def _bitreader(data):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


class _BR(object):
    def __init__(self, data):
        self.it = _bitreader(data)

    def u(self, n):
        v = 0
        for _ in range(n):
            v = (v << 1) | next(self.it)
        return v

    def ue(self):
        zeros = 0
        while next(self.it) == 0:
            zeros += 1
            if zeros > 32:
                raise ValueError("exp-golomb 越界")
        return (1 << zeros) - 1 + (self.u(zeros) if zeros else 0)

    def se(self):
        v = self.ue()
        return (v + 1) // 2 if v % 2 else -(v // 2)


def _unescape(nal):
    """去掉 H.264 的防竞争字节 0x000003。"""
    out = bytearray()
    i = 0
    n = len(nal)
    while i < n:
        if i + 2 < n and nal[i] == 0 and nal[i + 1] == 0 and nal[i + 2] == 3:
            out += nal[i:i + 2]
            i += 3
        else:
            out.append(nal[i])
            i += 1
    return bytes(out)


def _h264_sps(nal):
    """解析 SPS，返回 profile / level / 分辨率 / 位深。"""
    r = _BR(_unescape(nal[1:]))
    prof = r.u(8)
    r.u(8)                                  # constraint_set_flags
    level = r.u(8)
    r.ue()                                  # seq_parameter_set_id
    chroma = 1
    bit_depth = 8
    if prof in (100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135):
        chroma = r.ue()
        if chroma == 3:
            r.u(1)
        bit_depth = r.ue() + 8
        r.ue()                              # bit_depth_chroma_minus8
        r.u(1)                              # qpprime_y_zero_transform_bypass
        if r.u(1):                          # seq_scaling_matrix_present
            for i in range(12 if chroma == 3 else 8):
                if r.u(1):
                    last = nxt = 8
                    for _ in range(16 if i < 6 else 64):
                        if nxt != 0:
                            nxt = (last + r.se() + 256) % 256
                        last = nxt if nxt != 0 else last
    r.ue()                                  # log2_max_frame_num_minus4
    poc = r.ue()
    if poc == 0:
        r.ue()
    elif poc == 1:
        r.u(1)
        r.se()
        r.se()
        for _ in range(r.ue()):
            r.se()
    r.ue()                                  # max_num_ref_frames
    r.u(1)                                  # gaps_in_frame_num_value_allowed
    w_mbs = r.ue() + 1
    h_map = r.ue() + 1
    frame_mbs_only = r.u(1)
    if not frame_mbs_only:
        r.u(1)
    r.u(1)                                  # direct_8x8_inference_flag
    crop_l = crop_r = crop_t = crop_b = 0
    if r.u(1):                              # frame_cropping_flag
        crop_l, crop_r, crop_t, crop_b = r.ue(), r.ue(), r.ue(), r.ue()

    width = w_mbs * 16
    height = h_map * 16 * (2 - frame_mbs_only)
    sub_w = 2 if chroma == 1 else 1
    sub_h = 2 * (2 - frame_mbs_only) if chroma == 1 else (2 - frame_mbs_only)
    width -= (crop_l + crop_r) * sub_w
    height -= (crop_t + crop_b) * sub_h

    # 合理性校验。别省这一步：实测一个真实分片里**有两组 SPS/PPS**，
    # 第一组算出 1920x-280（隔行 + crop 减过头，物理上不存在的画面）。
    # 拿它去下「编码是否超纲」的结论，只会把人带沟里。
    valid = (0 < width <= 8192 and 0 < height <= 4320
             and width % 2 == 0 and height % 2 == 0)
    return {"profile_idc": prof,
            "profile": _H264_PROFILES.get(prof, "未知(%d)" % prof),
            "level_idc": level, "level": "%.1f" % (level / 10.0),
            "width": width, "height": height, "valid": valid,
            "bit_depth": bit_depth, "chroma_format_idc": chroma}


def _video_params(payload):
    """从分片里捞 SPS/PPS，回答「到底是哪个规格的 H.264」。

    一个分片里出现**多组** SPS/PPS 是真实存在的情况（实测某集分片里就有两
    组，其中第一组算出来是 1920x-280 的非法规格）。所以这里不再「拿到第一个
    就收工」，而是全部收下来、挑合理的那个 —— 否则诊断结论会基于垃圾数据。
    """
    out = {"sps": None, "pps": 0, "note": "",
           "sps_total": 0, "sps_invalid": 0}
    try:
        i = 0
        n = min(len(payload), 512 * 1024)      # 扫前 512 KB 足够，别在大分片上白跑
        found = []
        while i < n - 4:
            i = payload.find(b"\x00\x00\x01", i)
            if i < 0 or i + 3 >= n:
                break
            hdr = payload[i + 3]
            nal_type = hdr & 0x1F
            if nal_type == 7:
                end = payload.find(b"\x00\x00\x01", i + 4)
                nal = payload[i + 3:end if end > 0 else i + 3 + 256]
                try:
                    found.append(_h264_sps(nal))
                except Exception as e:          # noqa: BLE001
                    out["note"] = "SPS 解析失败：%s" % e
                if len(found) >= 8:
                    break
            elif nal_type == 8:
                out["pps"] += 1
            i += 3

        good = [s for s in found if s.get("valid")]
        bad = [s for s in found if not s.get("valid")]
        out["sps_total"] = len(found)
        out["sps_invalid"] = len(bad)
        if good:
            out["sps"] = good[0]
            # 同一个分片里既有合法又有非法 SPS —— 这话得留在记录里，
            # 硬解器崩掉最常见的原因之一就是被非法参数集带偏。
            if bad:
                out["note"] = ("同片里有 %d 组合法、%d 组非法 SPS，已取合法那组"
                               % (len(good), len(bad)))
        elif found:
            out["sps"] = found[0]
            out["note"] = "找到 %d 组 SPS，全部不合法" % len(found)
        elif not out["note"]:
            out["note"] = "分片里没找到 SPS —— 参数集只在别的分片里，硬解可能得靠猜"
    except Exception as e:                      # noqa: BLE001
        out["note"] = "%s: %s" % (type(e).__name__, e)
    return out


def _fix_bad_sps(data):
    """把码流里「能解析但尺寸荒谬」的 SPS 就地废掉。返回 (data, 修了几组)。

    实测（2026-10-27，某剧第 N 集首片）里有两组 SPS/PPS：第一组算出
    1920x**-280**（frame_mbs_only=0 的隔行 + crop 减过头，物理上不存在的
    画面），第二组才是真的 1920x1080。硬解器按第一组初始化 surface 会失败，
    而 FFmpeg 软解会跳过坏参数集继续往下找 —— 这就是「硬解必挂、软解能播、
    快进到后面又能播」的完整成因（后面的分片里没有这组坏 SPS）。

    修法只动 **1 个字节**：把 SPS 的 NAL header（0x67）改成 filler data
    （0x0C，nal_ref_idc=0）。解码器见到 type 12 直接丢弃。因为长度不变，
    不用重打包 TS、不用改 PES_packet_length、不用动连续计数器 —— 这是
    能想到的风险最小的修法。

    改之前必须能真的解析出「不合理」，解析失败一律不动：宁可放过，也不能
    把正常码流改坏。
    """
    n = len(data)
    if n < 16:
        return data, 0
    buf = None
    fixed = 0
    pos = 0
    while True:
        pos = data.find(b"\x00\x00\x01\x67", pos)
        if pos < 0 or pos + 4 >= n:
            break
        at = pos + 3
        end = data.find(b"\x00\x00\x01", at + 1)
        nal = data[at:end if end > 0 else min(n, at + 256)]
        if len(nal) < 4:
            pos = at + 1
            continue
        bad = False
        try:
            bad = not _h264_sps(nal).get("valid")
        except Exception:                           # noqa: BLE001
            bad = False
        if bad:
            if buf is None:
                buf = bytearray(data)
            buf[at] = 0x0C
            fixed += 1
            log.info("修掉一组畸形 SPS：偏移 %d，改成 filler NAL", at)
        pos = at + 1
    if buf is None:
        return data, 0
    return bytes(buf), fixed


def _ts_analyse(data):
    """粗解析 TS：同步率、PMT PID、各基本流的 stream_type。

    只回答一个问题：这个流是什么编码。4K HEVC / AC-3 这类在电视盒子上
    硬解不了，是「浏览器能播、TV 播不了」最常见的原因。
    """
    out = {"bytes": len(data), "sync": 0.0, "packets": 0,
           "programs": 0, "pmt_pids": [], "streams": []}
    try:
        import pngu_unwrap
        out["sync"] = round(pngu_unwrap._ts_sync_rate(data), 4)
    except Exception:                               # noqa: BLE001
        pass
    if len(data) < 188:
        return out
    out["packets"] = len(data) // 188

    # 第一遍：PAT → PMT 的 PID
    pmts = []
    for i in range(0, len(data) - 187, 188):
        pkt = data[i:i + 188]
        if pkt[0] != 0x47 or not (pkt[1] & 0x40):
            continue
        if (((pkt[1] & 0x1F) << 8) | pkt[2]) != 0:
            continue
        body = _ts_section(pkt)
        if len(body) < 12 or body[0] != 0x00:
            continue
        seclen = ((body[1] & 0x0F) << 8) | body[2]
        end = min(len(body), 3 + seclen - 4)
        for k in range(8, end - 3, 4):
            prog = (body[k] << 8) | body[k + 1]
            pid = ((body[k + 2] & 0x1F) << 8) | body[k + 3]
            if prog and pid not in pmts:
                pmts.append(pid)
    out["pmt_pids"] = pmts
    out["programs"] = len(pmts)
    if not pmts:
        return out

    # 第二遍：PMT → stream_type
    seen = []
    for i in range(0, len(data) - 187, 188):
        pkt = data[i:i + 188]
        if pkt[0] != 0x47 or not (pkt[1] & 0x40):
            continue
        if (((pkt[1] & 0x1F) << 8) | pkt[2]) not in pmts:
            continue
        body = _ts_section(pkt)
        if len(body) < 16 or body[0] != 0x02:
            continue
        seclen = ((body[1] & 0x0F) << 8) | body[2]
        info_len = ((body[10] & 0x0F) << 8) | body[11]
        k = 12 + info_len
        end = min(len(body), 3 + seclen - 4)
        while k + 4 < end:
            st = body[k]
            pid = ((body[k + 1] & 0x1F) << 8) | body[k + 2]
            es_len = ((body[k + 3] & 0x0F) << 8) | body[k + 4]
            if not any(s["pid"] == pid for s in seen):
                seen.append({"pid": pid, "type": "0x%02X" % st,
                             "codec": _TS_STREAM_TYPES.get(st, "未知")})
            k += 5 + es_len
    out["streams"] = seen
    out["pcr"] = _pcr_quality(data)
    return out


def _pcr_quality(data):
    """量一遍 PCR（节目参考时钟）。

    硬解管线靠 PCR 建时钟，软解（FFmpeg）可以完全无视它 —— 所以
    「硬解必挂、软解能播」最典型的底层原因就是 PCR 缺失或跳变。
    标准要求间隔 < 100ms（DVB 建议 < 40ms）。
    """
    res = {"count": 0, "max_gap_ms": 0, "backward": 0,
           "verdict": ""}
    try:
        vals = []
        for i in range(0, len(data) - 187, 188):
            pkt = data[i:i + 188]
            if pkt[0] != 0x47:
                continue
            afc = (pkt[3] >> 4) & 0x3
            if not (afc & 0x2) or pkt[4] < 7:
                continue
            if not (pkt[5] & 0x10):          # PCR_flag
                continue
            b = pkt[6:12]
            base = ((b[0] << 25) | (b[1] << 17) | (b[2] << 9)
                    | (b[3] << 1) | (b[4] >> 7))
            ext = ((b[4] & 0x01) << 8) | b[5]
            vals.append(base / 90000.0 + ext / 27000000.0)
        res["count"] = len(vals)
        if not vals:
            res["verdict"] = ("流里没有 PCR —— 硬解拿不到时钟基准，"
                              "这种情况基本只能软解")
            return res
        gaps = [vals[i + 1] - vals[i] for i in range(len(vals) - 1)]
        res["max_gap_ms"] = int(max(gaps) * 1000) if gaps else 0
        res["backward"] = len([g for g in gaps if g < -0.001])
        if res["backward"]:
            res["verdict"] = ("PCR 倒退 %d 处，硬解器会以为时钟跳变而放弃"
                              % res["backward"])
        elif res["max_gap_ms"] > 100:
            res["verdict"] = ("PCR 最大间隔 %d ms，超过 100ms 上限，"
                              "硬解容易失锁" % res["max_gap_ms"])
        else:
            res["verdict"] = "PCR 正常（最大间隔 %d ms）" % res["max_gap_ms"]
    except Exception as e:                          # noqa: BLE001
        res["verdict"] = "%s: %s" % (type(e).__name__, e)
    return res


def _inspect(src, timeout=25):
    """一次把「这条流到底是什么」摊开：清单、首片字节、剥壳结果、码流结构。"""
    import pngu_unwrap
    import pngu_fetch

    out = {"ok": False, "src": src, "final": "", "content_type": "",
           "playlist_head": "", "seg": "", "head16": "", "unwrap": {},
           "ts": {}, "error": ""}
    try:
        # 默认 25 秒：如果 src 是门票，这一圈会经过平台 302 + 我们的中间件 +
        # 探测，比直接拉上游慢不少。但走候选链时会传更小的值 —— 见
        # `_diag_sources`，那里宁可快速失败也不要让浏览器干等。
        blob, ctype, final = pngu_fetch.http_get_ex(src, timeout=timeout)
    except Exception as e:                          # noqa: BLE001
        out["error"] = "%s: %s" % (type(e).__name__, str(e)[:160])
        return out

    out["final"] = final or src
    out["content_type"] = ctype or ""
    text = blob.decode("utf-8", "replace")
    out["playlist_head"] = text[:1200]
    if "#EXTM3U" not in text:
        out["error"] = "不是 m3u8（前 60 字节：%s）" % text[:60].replace("\n", " ")
        return out

    cands = _first_uris(text, out["final"])
    if not cands:
        out["error"] = "清单里找不到分片"
        return out
    out["seg"] = cands[0]

    seg = _fetch_head_bytes(cands[0])
    if not seg:
        out["error"] = "首片取不到"
        return out
    out["head16"] = seg[:16].hex()
    payload, info = pngu_unwrap.unwrap(seg)
    out["unwrap"] = info
    out["ts"] = _ts_analyse(payload)
    out["video"] = _video_params(payload)
    sps = out["video"].get("sps")
    if sps:
        # 一句话结论：硬解能不能过，主要看这个
        if not sps.get("valid"):
            out["video"]["verdict"] = (
                "SPS 不合法（%dx%d 不是有效画面尺寸）—— 码流本身有缺陷。"
                "硬解器遇到这种参数集常常直接初始化失败，而 FFmpeg 软解会"
                "跳过它继续找，所以表现就是「硬解挂、软解能播」"
                % (sps["width"], sps["height"]))
        elif sps["bit_depth"] > 8:
            out["video"]["verdict"] = (
                "%d bit 的 H.264：绝大多数电视盒子/手机硬解都不支持 10bit，"
                "只能软解" % sps["bit_depth"])
        elif sps["level_idc"] >= 51 and sps["width"] * sps["height"] > 1920 * 1080:
            out["video"]["verdict"] = (
                "%dx%d H.264 level %s：芯片多半撑不住，会回退软解"
                % (sps["width"], sps["height"], sps["level"]))
        elif sps["profile_idc"] not in (66, 77, 100):
            out["video"]["verdict"] = (
                "profile=%s 少见，部分硬解器直接拒收" % sps["profile"])
        else:
            v = ("%dx%d H.264 %s@L%s %dbit —— 规格本身很标准"
                 % (sps["width"], sps["height"], sps["profile"],
                    sps["level"], sps["bit_depth"]))
            if out["video"].get("sps_invalid"):
                v += ("；但同片里另有 %d 组非法 SPS，硬解器可能先被它带偏"
                      "（这是硬解失败的已知诱因，插件改不了码流）"
                      % out["video"]["sps_invalid"])
            else:
                v += "，硬解失败就别怪编码，往下看网络和封装"
            out["video"]["verdict"] = v
    out["ok"] = True
    return out


# ---------------------------------------------------------------- 诊断候选地址
# 实测踩到的坑（2026-10-25）：飞牛影视跟平台在同一台机器上，请求 STRM 时
# Host 是内网地址 `http://192.168.31.5:8521/…`。插件与平台**同容器**，从容器
# 访问这个内网 IP 会一直等到超时 —— NAS 的防火墙不放行容器网段。于是
# `__inspect` / `__probe` 每次都要干等 25 秒，看着像「诊断口打不开了」。
# 真正通的是 127.0.0.1：同一个监听端口，走回环，不经过防火墙。

_DIAG_TIMEOUT = 6          # 单个候选的预算。宁可快速换下一个，也别让浏览器干等


def _loopback_variants(url):
    """把 URL 的主机换成本机回环，端口和路径不动。

    只给 127.0.0.1 一个候选：`localhost` 在个别容器里会先解析到 ::1，
    而平台只监听 IPv4，那样要多白等一个超时周期才轮到下个候选。
    """
    import urllib.parse
    try:
        parts = urllib.parse.urlsplit(url)
    except Exception:                               # noqa: BLE001
        return []
    if not parts.netloc or not parts.path:
        return []
    try:
        port = parts.port
    except ValueError:
        port = None
    netloc = ("127.0.0.1:%d" % port) if port else "127.0.0.1"
    # 强制 http：容器内部平台就是明文监听，没有 TLS
    return [urllib.parse.urlunsplit(
        ("http", netloc, parts.path, parts.query, parts.fragment))]


# ------------------------------------------------------------ 平台缓存 & 重解析
# 「退出播放器、过一会儿再打开同一个 STRM 就播不了」有两个不同的根：
#   A. 上游清单真的换了/死了，而平台手里还记着旧地址 → 清缓存 + 重走门票能救
#   B. 上游清单死了且平台也解析不出来 → 只能靠留底顶上（_MEMO）
# 这一节干 A 的事。关键接口是平台自己的 `/api/strm/cache/drive-playback`：
# 它记住「这个 STRM 上次解析到哪儿」，地址死了也照念旧地址。不清掉它，
# 重新请求门票只会拿到同一个 404 —— 这就是「怎么重试都播不了」的来源。

REPAIR_COOL = 10            # 同一集 10 秒内只尝试一次重解析
# 10 秒是有讲究的：HLS 播放过程中播放器每 TARGETDURATION（4~10 秒）就会
# 重拉一次清单，那是**播放中**，不该重新解析；而「退出再打开」中间必然
# 超过 10 秒。所以 10 秒刚好把这两件事分开，既不打断播放，也不会让用户
# 打开时还拿到旧地址。
REPAIR_COOL_MAX = 600
AUTO_REPARSE = True         # 地址死了要不要自动「清缓存 + 重走门票」
_REPAIR = {}                # mkey -> 上次尝试的时间戳


def _platform_bases(entry):
    """从门票地址推出可以打平台管理接口的 base，回环排最前。"""
    import urllib.parse
    out = []
    try:
        parts = urllib.parse.urlsplit(entry or "")
    except Exception:                               # noqa: BLE001
        return out
    host = parts.hostname
    if not host:
        return out
    try:
        port = parts.port
    except ValueError:
        port = None
    # 强制 http：容器内部平台就是明文监听，没有 TLS
    for h in ("127.0.0.1", host):
        netloc = ("%s:%d" % (h, port)) if port else h
        base = "http://%s" % netloc
        if base not in out:
            out.append(base)
    return out


def _clear_platform_cache(entry):
    """清平台的 STRM 播放缓存。返回 (ok, 说明)。

    这个路径在 `/api/strm/` 下，和播放器请求门票是同一个**免鉴权**前缀，
    所以插件能直接打。清空只影响「下次请求时重新解析」，不会掐断正在
    播放的流。
    """
    import pngu_fetch

    last = "没有可用的平台地址"
    for base in _platform_bases(entry):
        url = base + "/api/strm/cache/drive-playback"
        try:
            blob, _ctype, _final = pngu_fetch.http_get_ex(
                url, timeout=6, method="DELETE")
            return True, blob[:160].decode("utf-8", "replace")
        except Exception as e:                      # noqa: BLE001
            last = "%s@%s: %s" % (type(e).__name__, base, str(e)[:80])
    return False, last


def _reparse(entry, old_loc, timeout=8):
    """清平台缓存 → 重走门票 → 看平台能不能给出一个**新**的上游地址。

    返回 dict，永不抛：
      ok       拿到了新地址（且和旧的不一样）
      loc      拿到的地址（可能是旧的）
      status   门票返回的状态码
      cleared  平台缓存是否清成功
      detail / error   给诊断看
    """
    import pngu_fetch
    import urllib.parse

    out = {"ok": False, "loc": "", "status": 0, "cleared": False,
           "same": False, "detail": "", "error": ""}
    cleared, detail = _clear_platform_cache(entry)
    out["cleared"] = cleared
    out["detail"] = detail
    if cleared:
        _bump("cache_clear")

    for cand in _loopback_variants(entry) + [entry]:
        status, loc, err = pngu_fetch.peek_redirect(cand, timeout=timeout)
        if err:
            out["error"] = err
            continue
        out["status"] = status
        if loc:
            try:
                out["loc"] = urllib.parse.urljoin(cand, loc)
            except Exception:                       # noqa: BLE001
                out["loc"] = loc
            # 平台给的还是同一个地址 = 它手里没有别的了，再探一遍没意义
            out["ok"] = bool(out["loc"]) and out["loc"] != old_loc
            out["same"] = not out["ok"]
            return out
        if status in REDIRECT_CODES:
            out["error"] = "302 但没有 Location"
            continue
        out["error"] = "HTTP %d" % status
    return out


def _try_repair(mkey, loc, entry):
    """带节流的重解析。返回 _reparse 的结果，或 None（冷却中 / 没有门票）。"""
    if not AUTO_REPARSE or not entry:
        return None
    now = time.time()
    with _LOCK:
        if now - _REPAIR.get(mkey, 0.0) < REPAIR_COOL:
            return None
        _REPAIR[mkey] = now
        # 顺带收敛一下表大小，别跟着媒体库条目无限涨
        if len(_REPAIR) > 2000:
            for k in sorted(_REPAIR, key=lambda k: _REPAIR[k])[:400]:
                _REPAIR.pop(k, None)
    _bump("reparse")
    try:
        return _reparse(entry, loc)
    except Exception as e:                          # noqa: BLE001
        return {"ok": False, "loc": "", "status": 0, "cleared": False,
                "detail": "", "error": "%s: %s" % (type(e).__name__, str(e)[:100])}


def _diag_sources():
    """诊断口该拿哪些地址去试，按「最可能通」排序。"""
    cands = []
    seen = set()
    def add(u):
        if u and u not in seen:
            seen.add(u)
            cands.append(u)

    entry = _LAST.get("entry") or ""
    loc = _LAST.get("loc") or ""
    # 门票在最前面：它能被平台重新解析成**当前有效**的上游地址，
    # 是唯一不怕上游地址轮换的入口。但先换成回环地址，原样排在后面。
    for u in _loopback_variants(entry):
        add(u)
    add(entry)
    add(loc)
    return cands


def _diag_run(kind, cands, timeout=_DIAG_TIMEOUT):
    """按候选顺序试，第一个能拿到清单的就用它。

    返回 (payload, src)。全部失败时 src 是第一候选，payload 里带 tried 列表。
    """
    tried = []
    last = None
    for u in cands:
        payload = (_inspect(u, timeout=timeout) if kind == "__inspect"
                   else _probe(u, timeout=timeout))
        reached = bool(payload.get("final")) if kind == "__inspect" \
            else ("拉取失败" not in str(payload.get("why", "")))
        tried.append({"src": u, "reached": reached,
                      "error": payload.get("error") or payload.get("why") or ""})
        last = payload
        if reached:
            return payload, u, tried
    if last is None:
        last = {"ok": False, "error": "没有可用地址"}
    return last, (cands[0] if cands else ""), tried


def _speed(src, timeout=8):
    """量一遍「从这台 NAS 到上游 CDN 到底能跑多快」。

    App / 电视播不动时最需要的不是猜，而是两个数：分片本身要多少码率、
    这台机器实际能拉到多少。前者从 m3u8 的 #EXTINF 和分片大小算，后者
    实测一次。
    """
    import time as _t
    import pngu_fetch

    out = {"ok": False, "src": src, "final": "", "seg": "", "seg_bytes": 0,
           "seg_sec": 0.0, "need_kbps": 0, "got_kbps": 0,
           "ratio": 0.0, "verdict": "", "error": ""}
    try:
        blob, _ct, final = pngu_fetch.http_get_ex(src, timeout=timeout)
    except Exception as e:                          # noqa: BLE001
        out["error"] = "%s: %s" % (type(e).__name__, str(e)[:160])
        return out
    out["final"] = final or src
    text = blob.decode("utf-8", "replace")
    if "#EXTM3U" not in text:
        out["error"] = "不是 m3u8"
        return out

    dur = 0.0
    url = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#EXTINF:"):
            try:
                dur = float(line.split(":", 1)[1].split(",")[0])
            except ValueError:
                dur = 0.0
        elif line and not line.startswith("#"):
            url = line
            if dur > 0:
                break
    if not url:
        out["error"] = "清单里找不到分片"
        return out
    if not url.lower().startswith(("http://", "https://")):
        url = _join(final or src, url)
    out["seg"] = url

    try:
        t0 = _t.time()
        data, _ct2, _f2 = pngu_fetch.http_get_ex(url, timeout=timeout * 4)
        cost = _t.time() - t0
    except Exception as e:                          # noqa: BLE001
        out["error"] = "分片下载失败：%s: %s" % (type(e).__name__, str(e)[:140])
        return out

    size = len(data)
    out["seg_bytes"] = size
    out["seg_sec"] = round(cost, 2)
    if cost > 0:
        out["got_kbps"] = int(size * 8 / cost / 1000)
    if dur > 0:
        out["need_kbps"] = int(size * 8 / dur / 1000)
    if out["need_kbps"] and out["got_kbps"]:
        out["ratio"] = round(out["got_kbps"] / float(out["need_kbps"]), 2)
        if out["ratio"] >= 3:
            out["verdict"] = "带宽充足（%.1f 倍），播放卡不是因为这里" % out["ratio"]
        elif out["ratio"] >= 1.3:
            out["verdict"] = ("勉强够（%.1f 倍），网络一抖就卡；电视/App 缓冲小，"
                              "多半就卡在这儿" % out["ratio"])
        else:
            out["verdict"] = ("不够（%.1f 倍）：分片要 %d kbps，实测算下来只有 "
                              "%d kbps。这是播放不了的直接原因"
                              % (out["ratio"], out["need_kbps"], out["got_kbps"]))
    out["ok"] = True
    return out


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


def _request_url(scope):
    """当前请求的绝对地址 —— 也就是播放器手里那个「门票」地址。

    记下它是为了续播：门票再去请求一次，平台会 302 到当次有效的上游清单，
    分片地址随之刷新。上游 m3u8 自己过期时，这是唯一能救回来的入口。
    """
    hdrs = {k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in (scope.get("headers") or [])}
    path = scope.get("path") or ""
    qs = (scope.get("query_string") or b"").decode("latin-1")
    if qs:
        path = "%s?%s" % (path, qs)
    return _abs_url(scope, hdrs, path)


def _wrap_route_app(proxy, orig_app):
    """包一个路由的 ASGI app。返回新 app（带 `_pngu_origin` 便于还原）。"""

    async def app(scope, receive, send):
        if scope.get("type") != "http":
            return await orig_app(scope, receive, send)
        # 自己发的请求原样透传（route 模式没有外层中间件时靠这道兜底）
        if _is_self_call(scope):
            _bump("self_skip")
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
                if code >= 400:
                    # **平台自己都没解析出来**。这是「退出播放器、过一会儿再
                    # 打开同一个 STRM 就播不了」最典型的形态：上游 play_key
                    # 过期，4k 插件 parse 失败，平台连 302 都不发，直接回
                    # 4xx/5xx。以前这里原样透传，播放器永远打不开，而插件
                    # 完全不知道发生过什么 —— 留底存了也用不上。
                    # 现在先扣住，能留底就顶上，顶不上再原样发回去。
                    st["hold"] = True
                    st["start"] = message
                    st["err"] = code
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
    # 留个底：平台内核这次对门票到底回了什么。301/302 = 解析成功，
    # 4xx/5xx = 它自己都没解析出来。分开看才知道该修哪一头。
    try:
        with _LOCK:
            _STATE["last_status"] = int(start_msg.get("status") or 0)
    except Exception:                               # noqa: BLE001
        pass
    entry = _request_url(scope)
    # 给 /__inspect 用：门票优先（能拿到新鲜上游地址），旧的 302 目标只做留底
    if loc:
        _LAST["loc"] = loc
    if entry:
        _LAST["entry"] = entry
    _LAST["ts"] = time.time()

    async def _replay():
        await send(start_msg)
        body = b"".join(st["chunks"])
        await send({"type": "http.response.body", "body": body,
                    "more_body": False})

    async def _send_playlist(text):
        body = text.encode("utf-8")
        headers = [
            (b"content-type", b"application/vnd.apple.mpegurl"),
            (b"content-length", str(len(body)).encode("latin-1")),
            (b"cache-control", b"no-store"),
            (b"access-control-allow-origin", b"*"),
        ]
        await send({"type": "http.response.start", "status": 200,
                    "headers": headers})
        await send({"type": "http.response.body",
                    "body": b"" if (scope.get("method") or "GET").upper() == "HEAD"
                    else body})

    async def _redirect_to(url):
        """给播放器一个**新的** 302。

        重解析成功时不能 `_replay()` —— 原 302 指向的是那个已经 404 的死
        地址，原样重放等于什么都没做。这里发自己拼的 Location，行为和平台
        原生的 302 完全一致，播放器看不出区别。
        """
        headers = [(b"location", url.encode("latin-1")),
                   (b"content-length", b"0"),
                   (b"cache-control", b"no-store"),
                   (b"access-control-allow-origin", b"*")]
        await send({"type": "http.response.start", "status": 302,
                    "headers": headers})
        await send({"type": "http.response.body", "body": b""})

    mkey = _memo_key(scope, loc)

    err = int(st.get("err") or 0)

    # ---- 第一步：先判定当前上游地址还活着没有 ----
    val = None
    if not err:
        val = _cache_get(loc)
        if val is None:
            try:
                val = await asyncio.to_thread(_probe, loc)
            except Exception as e:                  # noqa: BLE001
                _bump("fail")
                val = {"wrapped": False,
                       "why": "清单拉取失败：%s: %s"
                              % (type(e).__name__, str(e)[:120])}
            if val.get("playlist") and not val.get("wrapped"):
                # 只给**裸流**留底。带壳的源留底没有意义：顶上之后播放器拿到的
                # 分片还是 PNG 壳，照样播不了（要靠 sess 改写清单，而改写需要
                # 上游活着，那时已经没得救了）。宁可不留，也不要给假希望。
                _memo_put(mkey, val["playlist"], val.get("final"))
            _cache_put(loc, val)

    # ---- 第二步：死了就试着修 —— 清平台缓存 + 重走门票 ----
    # 平台自己的 `/api/strm/cache/drive-playback` 会记住上次解析到的地址，
    # 那个地址死了它照样念。不清掉，重新请求门票只会得到同一个 404。
    repaired = False
    repair_note = ""
    if err or _is_dead(val):
        rep = await asyncio.to_thread(_try_repair, mkey, loc, entry)
        if rep and rep.get("ok") and rep.get("loc"):
            loc2 = rep["loc"]
            val2 = await asyncio.to_thread(_probe, loc2)
            if val2.get("playlist") and not _is_dead(val2):
                repaired = True
                loc, val, err = loc2, val2, 0
                _LAST["loc"] = loc
                _cache_put(loc, val)
                if not val.get("wrapped"):
                    _memo_put(mkey, val["playlist"], val.get("final"))
                _bump("reparse_ok")
                repair_note = "重解析到 %s" % loc[:60]
                _note("平台缓存里是死地址，清掉后重新解析到 %s" % loc[:70])
                log.info("重解析成功 → %s", loc[:90])
            else:
                repair_note = "重解析拿到 %s 但清单仍拉不到" % loc2[:50]
                _note("重解析拿到 %s，但清单仍拉不到（%s）"
                      % (loc2[:60], str(val2.get("why") or "")[:60]))
        elif rep and rep.get("same"):
            repair_note = "重解析后平台仍给同一地址（清缓存%s）" % (
                "成功" if rep.get("cleared") else "失败")
            _note(repair_note)
        elif rep and rep.get("error"):
            repair_note = "重解析失败：%s（清缓存%s）" % (
                rep["error"][:60], "成功" if rep.get("cleared") else "失败")
            _note(repair_note)

    # ---- 第三步：还不行就用留底顶上，或者原样还给播放器 ----
    if err:
        # 平台解析失败（没有 302，直接报错）。清单里的分片是 CDN 绝对地址，
        # 只要分片没过期，播放器照样能播。
        memo = _memo_get(mkey)
        if memo:
            _bump("rescue")
            _note("平台解析失败 %d，用 %.0f 分钟前的留底顶上"
                  % (err, (time.time() - memo[2]) / 60.0))
            log.info("平台返回 %d，用留底救场：%s", err, mkey)
            return await _send_playlist(memo[0])
        _bump("err")
        _note("平台解析失败 %d，且没有留底可救（这一集从未成功播过）" % err)
        log.warning("平台返回 %d 且无留底：%s", err, mkey)
        return await _replay()

    why = str(val.get("why") or "")
    if _is_dead(val):
        # 上游清单挂了（实测常见：同一集的门票 302 到一个已经 404 的地址，
        # 而分片本身在 CDN 上还好好的）。把上次那份原样还回去 —— 播放器
        # 拿到的分片地址仍然有效，这一集就不会整个打不开。
        memo = _memo_get(mkey)
        if memo:
            _bump("memo")
            _note("上游清单失效，用 %.0f 分钟前的留底顶上（%s）"
                  % ((time.time() - memo[2]) / 60.0, why[:60]))
            log.info("清单 404，用留底救场：%s", (loc or "")[:90])
            return await _send_playlist(memo[0])

    # 裸流也可能需要「修」：带畸形 SPS 的源，硬解器一上来就挂。这种源不用
    # 剥壳，但要让我们接管**首片**，把坏参数集改成 filler data。
    needs_fix = bool(val.get("bad_sps")) and SPS_FIX != "off"

    if not val.get("wrapped") and not needs_fix:
        if RELAY_MODE != "always":
            _bump("pass")
            # 把重解析的结论一起写进去：`last` 是「最近一次动作」，
            # 只写「放行」会把刚才做过的事盖掉，排障时看不到关键信息。
            _note("放行 %s（%s）%s" % (
                loc[:80], val.get("why", ""),
                ("；" + repair_note) if repair_note else ""))
            if repaired:
                # 原 302 指向的是死地址，重放它等于什么都没做 —— 必须发
                # 我们自己重解析出来的那个。
                return await _redirect_to(loc)
            return await _replay()
        # relay_mode=always：首片本来就是裸 TS，也照样改写清单，让分片全部
        # 走这台 NAS 中转。用在「播放器直连上游 CDN 太慢 / 不通」的场合 ——
        # 播放器只需要能连上 NAS，剩下的交给 NAS 去拉。
        _bump("relay")
        _note("强制中转 %s（%s）" % (loc[:80], val.get("why", "")))

    # —— 确认带壳：接管这条流 ——
    try:
        tok = _token_of(loc)
        sess = sess_get(tok)
        age = time.time() - (sess.built if sess is not None else 0.0)
        # 只修 SPS、不需要剥壳时，清单里只有首片指向我们 —— 其余分片让
        # 播放器直连 CDN。一集 200 MB 的流量，NAS 只经手开头那 1~2 MB。
        only_first = bool(needs_fix) and not val.get("wrapped") \
            and SPS_FIX == "first"
        if sess is None or age > SESS_REFRESH:
            # 冷启动，或者手里这份清单放久了 —— 重新拉一次。
            # 「关了过一会儿再接着看」就是走这条路：播放器会重新请求门票，
            # 如果这里直接复用旧会话，返回的分片全指向上次那批已经过期的
            # 上游地址，播放器一片都取不到。重拉之后地址是新的，续播才正常。
            try:
                sess = await asyncio.to_thread(sess_build, tok, loc, entry,
                                               only_first)
            except Exception:                       # noqa: BLE001
                if sess is None:
                    raise
                log.info("清单重拉失败，先用 %d 秒前的旧清单兜底", int(age))
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
# 终端的「会话发现」，用来给被回收的会话留一条回家的路。
# 只存 tok -> (门票地址, 过期时间)，一个条目一百来字节，比留整份会话便宜得多。
_TOMB = {}
_SEG_LOCK = threading.Lock()

# 清单留底：loc -> (清单原文, 最终地址, 记下的时间)。
# 上游 m3u8 的地址是有时效的（实测同一集过一阵就 404），但**分片地址往往
# 还活着**（同一个 .ts 路径在 CDN 上照常 206）。所以清单一旦 404，把上次
# 拿到的那份原样还给播放器，它照样能把后面的分片拉下来 —— 这比整个
# 片子打不开强得多。
_MEMO = {}
# 72 小时：用户「今天看了两集、明天接着看」是常态，12 小时太短。
# 一份清单十来 KB，600 条也就几 MB。
_MEMO_TTL = 72 * 3600
_MEMO_MAX = 600
_MEMO_LOCK = threading.Lock()


RELAY_MODE = "auto"     # auto=只接管带壳的流；always=不管有没有壳都走中转
# 畸形 SPS 修复：off=不管；first=只接管首片（默认，最省流量）；
# all=所有分片都过 NAS 再修（首片之外一般没有坏 SPS，除非 first 修不好）
SPS_FIX = "first"


def _memo_key(scope, loc):
    """留底的键：优先用**门票 token**，拿不到才退回上游地址。

    这一点很关键。实测同一集的门票 `/api/strm/o/<token>.m3u8`，不同时间
    302 到不同 md5 的上游清单（`a54547a1` → `4169d05` → `c1f2406`）。如果
    拿 loc 当键，地址一换留底就再也命不中 —— 而「退出播放器再进来」恰恰
    会触发重新解析、换一个新地址。token 是稳定的，用它才对得上。
    """
    path = scope.get("path") or ""
    name = path.rsplit("/", 1)[-1]
    if name.endswith(".m3u8"):
        name = name[:-5]
    if name and "/" not in name:
        return "t:" + name
    return "l:" + (loc or "") if (loc or "") else ""


def _memo_put(loc, text, final=""):
    """记下一份解出来的清单（只留能用的：真有分片地址那种）。"""
    if not loc or not text or "#EXTM3U" not in text:
        return
    if not any(line and not line.startswith("#") for line in text.splitlines()):
        return                                  # 空清单没救的价值
    now = time.time()
    with _MEMO_LOCK:
        if len(_MEMO) >= _MEMO_MAX:
            # 先清过期的，还满就丢最老的一批
            for k in [k for k, v in _MEMO.items() if now - v[2] > _MEMO_TTL]:
                _MEMO.pop(k, None)
            if len(_MEMO) >= _MEMO_MAX:
                for k in sorted(_MEMO, key=lambda k: _MEMO[k][2])[:64]:
                    _MEMO.pop(k, None)
        _MEMO[loc] = (text, final or loc, now)


def _memo_get(loc):
    """取上次能用的清单。过期返回 None。"""
    if not loc:
        return None
    with _MEMO_LOCK:
        item = _MEMO.get(loc)
        if not item:
            return None
        if time.time() - item[2] > _MEMO_TTL:
            _MEMO.pop(loc, None)
            return None
        return item


def configure(cache_mb=None, cache_ttl=None, relay_mode=None,
              auto_reparse=None, sps_fix=None):
    """把插件配置里的缓存上限/保留时长/中转模式/自动重解析/SPS 修复同步过来。

    内建服务（HlsProxy）和接管链路各有一份缓存，用同一组配置才不会出现
    「界面写 64 MB，实际占了 96 MB」这种对不上的情况。
    """
    global SEG_TTL, SEG_MAX_BYTES, RELAY_MODE, AUTO_REPARSE, SPS_FIX
    try:
        if cache_mb:
            SEG_MAX_BYTES = max(8, int(cache_mb)) * 1024 * 1024
        if cache_ttl:
            SEG_TTL = max(10, int(cache_ttl))
    except Exception:                               # noqa: BLE001
        pass
    if relay_mode in ("auto", "always"):
        RELAY_MODE = relay_mode
    if auto_reparse is not None:
        AUTO_REPARSE = bool(auto_reparse)
    if sps_fix in ("off", "first", "all"):
        SPS_FIX = sps_fix
    return {"seg_ttl": SEG_TTL, "seg_max_mb": SEG_MAX_BYTES // 1048576,
            "relay_mode": RELAY_MODE, "auto_reparse": AUTO_REPARSE,
            "sps_fix": SPS_FIX}


def _sweep(now=None, force=False):
    """清掉过期分片、闲置会话、过期判定。返回释放的字节数。

    只扫「已经过期」的项，不动还在用的 —— 播放中途把分片删掉会让播放器
    狂重试。`force=True` 时全清（停用插件/接管卸载时用）。
    """
    now = time.time() if now is None else now
    freed = 0
    with _SEG_LOCK:
        if force:
            for blob in _SEG.values():
                freed += len(blob[1])
            _SEG.clear()
        else:
            dead = [k for k, item in _SEG.items() if item[0] < now]
            for k in dead:
                freed += len(_SEG[k][1])
                _SEG.pop(k, None)
        if force:
            _SESS.clear()
            _TOMB.clear()
        else:
            idle = [t for t, s in _SESS.items()
                    if now - getattr(s, "touched", now) > SESS_IDLE]
            for t in idle:
                _SESS.pop(t, None)
            # 墓碑也要回收，只是留得久一点（默认 24 小时）
            for t in [t for t, (e, exp) in _TOMB.items() if exp < now]:
                _TOMB.pop(t, None)
        # 顺手重算，防止长期增删出现计数漂移
        _SEG_BYTES[0] = sum(len(b) for _e, b in _SEG.values())
    # 清单留底只在「上游挂了」时才被读到，过期就没人要了，跟分片一起扫
    with _MEMO_LOCK:
        if force:
            _MEMO.clear()
        else:
            for k in [k for k, v in _MEMO.items() if now - v[2] > _MEMO_TTL]:
                _MEMO.pop(k, None)
    with _LOCK:
        if force:
            _VERDICT.clear()
        else:
            for k in [k for k, (exp, _v) in _VERDICT.items() if exp < now]:
                _VERDICT.pop(k, None)
    return freed


def _reaper_loop():
    while True:
        # 用 Event 而不是 time.sleep：停用插件时能立刻叫醒它退出，
        # 不用让这个线程干等满一个清扫周期。
        _WAKE.wait(SWEEP_SEC)
        _WAKE.clear()
        try:
            _sweep()
        except Exception as e:                      # noqa: BLE001
            log.warning("内存清扫异常（不影响播放）：%s", e)
        # 三张表都空了才退出，别让线程常驻。墓碑也算「还有事可做」——
        # 它要活到 TOMB_TTL，这期间得有人负责把过期的清掉。
        with _SEG_LOCK:
            empty = not _SEG and not _SESS and not _TOMB
        with _LOCK:
            empty = empty and not _VERDICT
        if empty:
            with _SEG_LOCK:
                if not _SEG and not _SESS:
                    _REAPER[0] = None
                    return


def _ensure_reaper():
    """惰性启动后台清扫线程（有缓存才起，空了就自己退）。"""
    t = _REAPER[0]
    if t is not None and t.is_alive():
        return
    try:
        t = threading.Thread(target=_reaper_loop, name="pngu-reaper", daemon=True)
        _REAPER[0] = t
        t.start()
    except Exception as e:                          # noqa: BLE001
        log.info("清扫线程启动失败（不影响播放）：%s", e)


def release():
    """立刻释放全部分片/会话/判定缓存。停用插件、摘掉接管时调用。"""
    with _SEG_LOCK:
        nseg, nsess = len(_SEG), len(_SESS)
    _sweep(force=True)
    _WAKE.set()                     # 让清扫线程立刻醒来发现「没事可做」并退出
    return {"segments": nseg, "sessions": nsess}


class _Sess(object):
    __slots__ = ("tok", "src", "entry", "final", "text", "segs", "keys", "maps",
                 "playlist", "touched", "built", "error", "only_first")

    def __init__(self, tok, src):
        self.tok = tok
        self.src = src          # 本次实际取清单的地址
        self.entry = src        # 播放器最初请求的门票地址（可用来重新走 302）
        self.final = src
        self.text = ""
        self.segs = []
        self.keys = []
        self.maps = []
        self.playlist = ""
        self.touched = time.time()
        self.built = time.time()    # 清单是什么时候拉的，用于判断新鲜度
        self.error = ""
        self.only_first = False     # True = 清单里只把首片指向本服务


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


def _tomb_put(tok, entry):
    if not entry:
        return
    with _SEG_LOCK:
        _TOMB[tok] = (entry, time.time() + TOMB_TTL)


def _tomb_entry(tok):
    with _SEG_LOCK:
        item = _TOMB.get(tok)
        if not item:
            return ""
        if item[1] < time.time():
            _TOMB.pop(tok, None)
            return ""
        return item[0]


def _sess_put(sess):
    with _SEG_LOCK:
        _SESS[sess.tok] = sess
        if len(_SESS) > 200:
            old = sorted(_SESS.values(), key=lambda x: x.touched)[:50]
            for s in old:
                _SESS.pop(s.tok, None)
        # 墓碑跟着会话走：会话被回收以后，播放器手里那张旧清单还在用
        # `seg/<tok>/<n>` 要分片，得靠它找回门票地址重建。
        _TOMB[sess.tok] = (sess.entry or sess.src,
                           time.time() + TOMB_TTL)
    _ensure_reaper()


def _rebuild(tok, sess=None):
    """重建一份清单，返回新会话；全都失败返回 None。

    优先用**门票地址**（`/api/strm/o/…`）：平台会 302 到当次有效的上游，
    分片地址跟着一起刷新 —— 这是唯一能在上游 m3u8 自身也过期时救回来的路。
    门票拿不到（比如是自包含 `/hls/u/…` 地址）再退回上游地址。
    """
    import pngu_fetch      # noqa: F401  （保持与 sess_build 相同的依赖面）

    entry = (sess.entry if sess else "") or _tomb_entry(tok)
    cands = []
    for url in (entry, sess.src if sess else ""):
        if url and url not in cands:
            cands.append(url)
    for src in cands:
        try:
            return sess_build(tok, src, entry=entry or src)
        except Exception as e:                      # noqa: BLE001
            log.info("重建清单失败（%s）：%s: %s", src[:90],
                     type(e).__name__, str(e)[:120])
    return None


def _resurrect(tok):
    """会话已经被回收，但播放器还在要分片 —— 靠墓碑把它接回来。"""
    entry = _tomb_entry(tok)
    if not entry:
        return None
    log.info("会话 %s 已被回收，按门票地址重建：%s", tok, entry[:90])
    try:
        sess = sess_build(tok, entry, entry=entry)
    except Exception as e:                          # noqa: BLE001
        log.info("按门票地址重建失败：%s: %s", type(e).__name__, str(e)[:120])
        return None
    _note("会话 %s 已按门票地址重建" % tok)
    return sess


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
        if sess.only_first and si > 0:
            # 只修首片：其余分片保持上游绝对地址，播放器直连 CDN，NAS 不参与。
            # 这是「裸流 + 首片畸形 SPS」最省流量的修法 —— 一集 200 MB，
            # NAS 只经手开头那 1~2 MB。
            out.append(sess.segs[si] if si < len(sess.segs) else line)
        else:
            out.append("%s/seg/%s/%d" % (SELF_PREFIX, sess.tok, si))
        si += 1
    sess.playlist = "\n".join(out) + "\n"
    return sess.playlist


def sess_build(tok, src, entry="", only_first=False):
    """拉清单、解析、渲染。失败抛异常，由调用方决定是否放行。

    `src` 是这次真正去取的地址；`entry` 是播放器最初请求的那个门票地址
    （`/api/strm/o/xxx.m3u8`）。两者通常不同：门票会 302 到当次的上游清单，
    而上游地址带时效。把门票记下来，是为了让分片请求在几小时后还能顺着它
    重新走一遍 302，拿到新地址 —— 否则会话一被回收就彻底断线。

    `only_first=True` 时只把**第一个**分片改指向本服务，其余保留上游绝对
    地址。用在「只想修首片的畸形 SPS、不想让整集流量都过 NAS」的场合。
    """
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
    sess.entry = entry or src
    sess.built = time.time()
    sess.final = base
    sess.text = text
    sess.segs = segs
    sess.keys = keys
    sess.maps = maps
    sess.only_first = bool(only_first)
    _render(sess)
    _sess_put(sess)
    log.info("接管会话就绪 %s：%d 片%s，base=%s", tok, len(segs),
             "（只改首片）" if only_first else "", base[:80])
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
            # 先清过期的，再按到期时间丢最早的一批
            now2 = time.time()
            dead = [k for k, item in _SEG.items() if item[0] < now2]
            for k in dead:
                _SEG_BYTES[0] -= len(_SEG[k][1])
                _SEG.pop(k, None)
            if _SEG_BYTES[0] > SEG_MAX_BYTES or len(_SEG) > 4000:
                drop = max(1, len(_SEG) // 4)
                for k in sorted(_SEG, key=lambda x: _SEG[x][0])[:drop]:
                    _SEG_BYTES[0] -= len(_SEG[k][1])
                    _SEG.pop(k, None)
    if len(_SEG) >= 8:
        _ensure_reaper()


def _fetch_seg(sess, idx):
    """取一个分片，地址不新鲜就重建清单再取。返回 (原始字节, 会话)。

    分片地址带时效，而且上游清单自己也会变（分片变多/变少）。所以这里把
    「取失败」当常态处理：401/403/404、越界、网络错误，都重建一次清单再试。
    只有重建后仍然失败才往外抛。
    """
    if 0 <= idx < len(sess.segs):
        try:
            return _fetch_any(sess.segs[idx], sess.final), sess
        except urllib.error.HTTPError as e:
            if e.code not in (401, 403, 404):
                raise
            log.info("分片 %d 返回 %s（上游地址过期），重建清单：%s",
                     idx, e.code, sess.segs[idx][:80])
        except Exception as e:                      # noqa: BLE001
            log.info("分片 %d 取流异常（%s: %s），重建清单后重试",
                     idx, type(e).__name__, str(e)[:100])

    _bump("refresh")
    fresh = _rebuild(sess.tok, sess)
    if fresh is None:
        raise RuntimeError("上游清单已失效，重建失败")
    if not (0 <= idx < len(fresh.segs)):
        raise IndexError(idx)
    _note("分片 %d 的上游地址已刷新" % idx)
    return _fetch_any(fresh.segs[idx], fresh.final), fresh


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
        # 会话被清扫回收了。播放器手里那张清单还没变，分片路径一直是
        # `seg/<tok>/<n>` —— 所以这里不能直接 404，要用墓碑把它接回来。
        sess = _resurrect(tok)
        if sess is None:
            raise KeyError(tok)

    raw, sess = _fetch_seg(sess, idx)

    payload, info = pngu_unwrap.unwrap(raw)
    if info.get("shell"):
        log.info("剥壳 %s/%d：%d → %d 字节（壳 %s，%s）", tok, idx,
                 len(raw), len(payload), info.get("shell"), info.get("kind"))
    # 畸形 SPS 会就地废掉（只改 NAL header 一个字节）。剥壳之后才做 ——
    # 壳里不会有合法的 00 00 01 67，先剥再扫省得误判。
    if SPS_FIX != "off" and info.get("kind") == "ts":
        payload, n_fix = _fix_bad_sps(payload)
        if n_fix:
            _bump("sps_fix")
            _note("分片 %s 修掉 %d 组畸形 SPS" % (idx, n_fix))
    _seg_put(key, payload)
    return payload


def key_bytes(tok, idx):
    sess = sess_get(tok) or _resurrect(tok)
    if sess is None:
        raise KeyError(tok)
    if idx.startswith("m"):
        seq, i = sess.maps, int(idx[1:])
    else:
        seq, i = sess.keys, int(idx)
    if not (0 <= i < len(seq)):
        raise IndexError(idx)
    return _fetch_any(seq[i], sess.final)


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


def _cache_response(arg, scope=""):
    """平台的 STRM 播放缓存：看得见，也能一键清。

    这是「退出播放器再打开就播不了」的第二个源头。平台把上次解析到的地址
    记在 `/api/strm/cache/drive-playback` 里，**地址死了它照样念**。不清掉，
    重新请求门票只会得到同一个 404。

        /api/strm/pngu/__cache          看统计（几条、命中多少）
        /api/strm/pngu/__cache/clear    清空，下次播放会重新解析
    """
    import json
    import pngu_fetch

    entry = _LAST.get("entry") or ""
    action = "clear" if arg in ("clear", "reset", "flush") else "stats"
    out = {"ok": False, "action": action, "entry": entry,
           "bases": _platform_bases(entry), "data": None, "error": ""}
    if not entry:
        out["error"] = "还没有播放请求，推不出平台地址。先播一下再打开这个地址。"
        return (200, "application/json; charset=utf-8",
                json.dumps(out, ensure_ascii=False, indent=2).encode("utf-8"))

    for base in _platform_bases(entry):
        url = base + "/api/strm/cache/drive-playback"
        try:
            if action == "clear":
                blob, _ct, _f = pngu_fetch.http_get_ex(
                    url, timeout=8, method="DELETE")
            else:
                blob, _ct, _f = pngu_fetch.http_get_ex(url, timeout=8)
            out["ok"] = True
            out["url"] = url
            text = blob.decode("utf-8", "replace")
            try:
                out["data"] = json.loads(text)
            except Exception:                       # noqa: BLE001
                out["raw"] = text[:400]
            if action == "clear":
                _bump("cache_clear")
            break
        except Exception as e:                      # noqa: BLE001
            out["error"] = "%s@%s: %s" % (type(e).__name__, base, str(e)[:100])
    return (200 if out["ok"] else 502, "application/json; charset=utf-8",
            json.dumps(out, ensure_ascii=False, indent=2).encode("utf-8"))


def _diag_response(kind, arg):
    """诊断口统一入口（`__inspect` / `__probe`）。

    参数走 path 的 base64url —— 挂在平台应用上的 ASGI 拿到的是纯 path，
    query 早被吃掉了，`/__probe?url=…` 在挂载模式下一律报「参数为空」。
    也允许不带参数：分析**最近一次播放请求**解析出来的上游地址，用户播一下
    再打开这个地址就行，不用自己拼 base64。
    """
    import base64
    import json

    src = ""
    tried = []
    if arg:
        try:
            src = base64.urlsafe_b64decode(arg + "=" * (-len(arg) % 4)) \
                .decode("utf-8", "replace")
        except Exception:                           # noqa: BLE001
            src = ""
        if not src.lower().startswith(("http://", "https://")):
            return (400, "application/json; charset=utf-8",
                    ('{"ok": false, "error": "参数应为 base64url 编码的上游 m3u8 '
                     '地址"}').encode("utf-8"))
        if kind == "__speed":
            return (200, "application/json; charset=utf-8",
                    json.dumps(_speed(src), ensure_ascii=False, indent=2)
                    .encode("utf-8"))
        payload = _inspect(src, timeout=25) if kind == "__inspect" else _probe(src)
    else:
        # 无参模式：按「回环门票 → 原门票 → 上次 302 目标」的顺序试。
        # 门票能让平台重新解析出**当前有效**的上游地址，是唯一不怕地址轮换
        # 的入口；但门票里的主机往往是内网 IP，容器访问会超时 —— 所以先
        # 换成 127.0.0.1 再试，原样留在后面。
        cands = _diag_sources()
        if not cands:
            return (200, "application/json; charset=utf-8",
                    ('{"ok": false, "error": "还没有播放请求。先播一下再打开这个'
                     '地址，或用 /__inspect/<base64url(上游 m3u8)> 指定地址。"}')
                    .encode("utf-8"))
        if kind == "__speed":
            payload, src, tried = None, cands[0], []
            for u in cands:
                payload = _speed(u, timeout=_DIAG_TIMEOUT)
                tried.append({"src": u, "reached": bool(payload.get("final")),
                              "error": payload.get("error") or ""})
                if payload.get("ok"):
                    src = u
                    break
            if not payload.get("ok"):
                src = cands[0]
        else:
            payload, src, tried = _diag_run(kind, cands)

    if not arg:
        age = int(time.time() - _LAST["ts"]) if _LAST.get("ts") else None
        payload["entry"] = _LAST.get("entry", "")
        payload["last_loc"] = _LAST.get("loc", "")
        payload["last_loc_age_sec"] = age
        payload["src_used"] = src
        if tried:
            payload["tried"] = tried
        if payload.get("final") and payload["final"] != src:
            payload["note"] = "已通过门票重新解析到当前上游地址"
    return (200, "application/json; charset=utf-8",
            json.dumps(payload, ensure_ascii=False, indent=2).encode())


def serve(path):
    """在挂载的 ASGI 里优先处理我们自己的路径。

    返回 (status, content_type, body)，不是我们的路径返回 None，
    由调用方继续交给原来的 handle_path。
    """
    parts = [p for p in (path or "").split("/") if p]
    head = parts[0] if parts else ""
    arg = parts[1] if len(parts) >= 2 else ""

    if head.startswith("__"):
        # 诊断口单独计数：否则日志里那串 /api/strm/o/… 分不清是播放器在请求
        # 还是自己在诊断时绕回来的，很容易把「没人播放」误读成「一直在播放」。
        _bump("diag")

    # 诊断口不依赖 pngu_proxy —— 平台热更新后它可能是旧版，这里必须照常可用。
    if head in ("__inspect", "__probe", "__speed"):
        return _diag_response(head, arg)

    if head == "__cache":
        return _cache_response(arg, scope="")

    if head in ("__hijack", "__dump"):
        import json
        if head == "__hijack":
            payload = state()
        else:
            payload = {"hijack": state()}
            try:
                import pngu_mount
                payload["mount"] = pngu_mount.diagnose()
            except Exception as e:                  # noqa: BLE001
                payload["mount_error"] = "%s: %s" % (type(e).__name__, e)
        return (200, "application/json; charset=utf-8",
                json.dumps(payload, ensure_ascii=False, indent=2).encode())

    if head == "hls" and len(parts) >= 2:
        tok = parts[1].split(".")[0]
        if not _is_ours(tok):
            return None
        sess = sess_get(tok) or _resurrect(tok)
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
            # 0) 自己发的请求原样透传 —— 断掉「拉门票 → 又回到自己」的自激环
            if _is_self_call(scope):
                _bump("self_skip")
                return await self.app(scope, receive, send)
            path = scope.get("path") or ""
            method = (scope.get("method") or "GET").upper()

            # 1) 自家路径由自己服务，绕开 mount
            if path.startswith(SELF_PREFIX):
                sub = path[len(SELF_PREFIX):] or "/"
                try:
                    # 必须丢到线程里：serve() 是同步阻塞的（要拉上游清单/分片），
                    # 直接在事件循环里跑会把整个平台卡住。更要命的是诊断口
                    # 会回头请求自己的门票 —— 同步请求 + 同步服务 = 死锁，
                    # 表现就是「127.0.0.1 和 192.168.31.5 一起超时」。
                    hit = await asyncio.to_thread(serve, sub)
                except Exception as e:              # noqa: BLE001
                    hit = (502, "application/json; charset=utf-8",
                           ('{"ok": false, "error": "%s"}'
                            % str(e)[:160].replace('"', "'")).encode())
                if hit is not None:
                    # 诊断口的计数在 serve() 里统一记（mount 和中间件两条路都会
                    # 走到那儿），这里只认真实播放的分片/清单请求。
                    if not sub.lstrip("/").startswith("__"):
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
    # 接管停了就把缓存一起放掉：几 MB 的分片留着没有任何用处
    try:
        freed = release()
    except Exception:                               # noqa: BLE001
        freed = {}
    if n or m or freed.get("segments"):
        log.info("已还原 %d 条路由 / 摘掉 %d 个中间件 / 释放 %d 个分片缓存",
                 n, m, freed.get("segments", 0))


# 模块自述版本。plugin.py 会拿它和磁盘上的文件比对，不一致就说明平台热更新
# 只重载了 plugin 模块、子模块还留在 sys.modules 里，需要 importlib.reload。
__version__ = "0.5.6"
