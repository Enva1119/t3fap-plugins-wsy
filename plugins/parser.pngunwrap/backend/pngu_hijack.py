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
import types
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

# 平台有时**不发 302**，直接把清单正文放在 200 的响应体里。这种正文必须
# 先收下来才能判定，但绝不能无上限地收：万一这个路由哪天回了视频流，
# 无界缓冲会直接变成内存事故。超过这个尺寸就当它不是清单，当场泄洪原样透传。
MAX_INLINE = 1 << 20

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
    "failfast": 0,          # 平台连续失败后短路、根本没去打平台的次数
    "reuse": 0,             # 同一门票在复用窗口内再来、直接回上次清单的次数
                                # （这一项涨 = 省下的平台解析次数，也就省下了 4k 请求）
    "reparse": 0,           # 上游地址死了，尝试「清平台缓存 + 重走门票」的次数
    "reparse_ok": 0,        # 重解析拿到了新的可用地址的次数
    "repair_gated": 0,      # 上游冷却中、跳过重解析的次数（少打一次 4k）
    "cache_clear": 0,       # 清平台播放缓存成功的次数
    "wrap": 0,              # 判定为 PNG 壳、改写成自家清单的次数
    "pass": 0,              # 判定为非 PNG、原样放行的次数
    "unheld": 0,            # 响应形态两类都没命中、原样透传的次数（形态变了才会有）
    "relay": 0,             # relay_mode=always 时，裸 TS 也强制中转的次数
    "sps_fix": 0,           # 修掉畸形 SPS 的分片数（每片算一次）
    "sps_skip": 0,          # 畸形 SPS 但被 PPS 引用、故意没修的分片数
    "fail": 0,              # 探测失败而放行的次数
    "live": 0,              # 上游清单 HEAD 验活通过（说明地址还活着）
    "dead": 0,              # 上游清单 HEAD 验活发现已失效（404/410）
    "last": "",             # 最近一次判定的说明
    "last_status": 0,       # 平台内核最近一次对门票返回的状态码（0=还没请求过）
    "mode": "",             # route = 换路由 app；middleware = 最外层中间件
}

_LOCK = threading.Lock()
_VERDICT = {}               # loc -> (expire_ts, dict)
_ORIG = []                  # [(route, orig_app)]
_SEEN = []                  # 最近几次拦下的响应形态：[ts, status, 说明]
SEEN_MAX = 10


def _seen(code, detail=""):
    """留一份「平台对门票到底回了什么」的尾巴。

    现场最费劲的误判就是「插件到底在不在链路上」。以前只有 hit 计数，
    涨了也不知道那些响应是什么形态 —— 3xx 到清单？200 带正文？还是
    别的什么被原样透传了。这次的数据就是靠 `pass/wrap/fail` 全零才反推
    出「2xx 从来没被处理过」，代价是好几轮往返。留个尾巴，下次看一眼就
    能定性。
    """
    try:
        with _LOCK:
            _SEEN.insert(0, [round(time.time(), 1), int(code),
                             str(detail or "")[:160]])
            del _SEEN[SEEN_MAX:]
    except Exception:                               # noqa: BLE001
        pass

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
        s["recent"] = [list(x) for x in _SEEN]
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
    # 内部平台地址是怎么探出来的、上次重解析成没成 —— 这两项决定「自动恢复」
    # 到底能不能用，比任何猜测都直接。
    s["inner_base"] = _INNER.get("base") or ""
    s["inner_ports"] = _inner_ports(_LAST.get("entry") or "")
    s["repair"] = dict(_REPAIR_LAST)
    # 4k 联动状态。懒导入：pngu_4k 不反向依赖本模块，谁先加载都行。
    try:
        import pngu_4k
        s["fourk"] = pngu_4k.state()
    except Exception as e:                          # noqa: BLE001
        s["fourk"] = {"error": "%s: %s" % (type(e).__name__, e)}
    # 上游闸门：解析和播放两条路径共用同一个出击上限。`gate.open=False`
    # 就说明此刻一个 4k 请求都不会发出去 —— 「解析总失败还一直在打源站」
    # 这件事有没有被摁住，看这一个字段就够了。
    try:
        import pngu_fetch
        s["gate"] = pngu_fetch.gate_state()
    except Exception as e:                          # noqa: BLE001
        s["gate"] = {"error": "%s: %s" % (type(e).__name__, e)}
    # 解析链侧的证据：平台到底有没有把这件事问过我们、问的时候带没带 meta。
    # 「我们的 parse 从来没被调用」和「调用了但 meta 是空的」是两种完全
    # 不同的故障，以前的诊断口看不出来。
    try:
        import pngu_proxy
        d = pngu_proxy.DIAG.snapshot()
        s["parse_diag"] = {"counts": d.get("counts", {}),
                           "recent": (d.get("recent") or [])[-6:]}
    except Exception:                               # noqa: BLE001
        pass
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
        "sps_skip": "畸形 SPS 但被 PPS 引用，故意没修的分片数",
        "memo": "上游清单 404，用上次的留底顶上",
        "rescue": "平台自己解析失败（4xx/5xx），用留底顶上",
        "err": "平台解析失败且没有留底（这一集从来没成功播过）",
        "failfast": "平台连续失败后短路，没再去打平台的次数（防止把重试放大成对上游的连续请求）",
        "reparse": "地址死了，尝试清平台缓存 + 重走门票",
        "reparse_ok": "重解析拿到了新的可用地址",
        "repair_gated": "上游冷却中，跳过重解析（重解析等于再打一次 4k）",
        "cache_clear": "清平台 drive-playback 缓存成功",
        "pass": "首片是裸 TS，原样放行",
        "fail": "探测失败，退回原 302",
        "live": "上游清单 HEAD 验活通过（地址还活着）",
        "dead": "上游清单 HEAD 验活发现已失效（404/410）→ 触发重解析",
        "unheld": "响应形态既不是清单也不是错误，原样透传（含 302 到非清单；"
                  "这数一涨就说明平台换了应答方式，看 recent）",
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


def _cache_drop(loc):
    with _LOCK:
        _VERDICT.pop(loc, None)


# ---------------------------------------------------------------- 存活校验
# 「平台 302 出来的地址早就死了，它还在念」—— 2026-11-01 现场实测：
#
#   门票连请求 6 次，40~86ms 全部 302 到同一个 oss 地址（这么快不可能是
#   现场解析，只能是平台在念 drive-playback 缓存）；
#   那个地址换 5 种 UA / Referer 全部 404「token 不存在或已过期」；
#   播放器 HEAD+GET 每 3 秒重试一轮，插件一路 `pass` 放行，`reparse` 始终 0。
#
# 根因不是探测写错了，是**成功结论缓存了 30 分钟**：第一次探活时地址是好的，
# 后来过期了，插件还拿旧结论放行。平台那边的缓存又会把同一个死地址一直念
# 下去，播放器就永远在重试 —— 用户看到的就是「缓冲一直接不上」。
#
# 所以这里补两件事：
#   ① 结论不能当「现在」用 —— 隔一段时间用一次 HEAD 验活（几十毫秒，几乎
#      不耗流量，比拉清单 + 32KB 分片便宜两个数量级）；
#   ② 同一个地址被反复要 = 播放器在重试 —— 这时候不信缓存，老实拉一遍。
LIVE_CHECK = 25             # 秒。VOD 一集通常只请求一两次清单，这条几乎不触发
STRIKE_WINDOW = 15          # 秒
STRIKE_N = 3                # 窗口内被要这么多次 = 播放器在重试
STRIKE_COOL = 60            # 秒。同一条地址两次「强制验活」的最小间隔

_LIVE = {}                  # loc -> 上次确认还活着的时刻
_STRIKE = {}                # loc -> [请求时刻, ...]
_STRIKE_AT = {}             # loc -> 上次强制验活的时刻


def _head_alive(url):
    """HEAD 一下上游清单：True 活 / False 确定没了 / None 看不出来。

    只看 404 和 410 算死。403 不算 —— 防盗链的源对 HEAD 回 403、对 GET 回
    200 是常见的，按 403 判死会误杀本来能播的片子。判不出来返回 None，
    由上层决定要不要再做一次完整探测。
    """
    import pngu_fetch
    try:
        pngu_fetch.http_get_ex(url, timeout=6, method="HEAD")
        return True
    except urllib.error.HTTPError as e:
        if e.code in (404, 410):
            return False
        return None
    except Exception:                               # noqa: BLE001
        return None


def _strike_hit(loc):
    """这条地址是不是正在被反复索取？是的话返回 True（并占用一次节流名额）。"""
    if not loc:
        return False
    now = time.time()
    with _LOCK:
        q = _STRIKE.setdefault(loc, [])
        q.append(now)
        while q and now - q[0] > STRIKE_WINDOW:
            q.pop(0)
        n = len(q)
        # 顺手收敛表大小：地址是带时效的，旧键攒着没有意义
        if len(_STRIKE) > 500:
            for k in [k for k, v in _STRIKE.items()
                      if not v or now - v[-1] > STRIKE_WINDOW]:
                _STRIKE.pop(k, None)
    if n < STRIKE_N:
        return False
    if now - _STRIKE_AT.get(loc, 0.0) < STRIKE_COOL:
        return False
    _STRIKE_AT[loc] = now
    if len(_STRIKE_AT) > 500:
        for k in list(_STRIKE_AT)[:200]:
            _STRIKE_AT.pop(k, None)
    return True


async def _keep_alive(loc, force=False):
    """验一次上游清单还活着没有。True / False / None（判不出来）。"""
    now = time.time()
    if not force and now - _LIVE.get(loc, 0.0) < LIVE_CHECK:
        return True
    res = await asyncio.to_thread(_head_alive, loc)
    if res is True:
        _LIVE[loc] = now
        _bump("live")
    elif res is False:
        _LIVE.pop(loc, None)
        _bump("dead")
        _note("上游清单已失效（HEAD 404）：%s" % loc[:90])
    return res


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


def probe_url(loc, timeout=12):
    """对外暴露的探测口，给 pngu_4k 用（判定官方解析出来的清单要不要接管）。

    失败不抛：拿不到结论就返回 wrapped=False —— 宁可让官方地址原样过去，
    也不要因为我们探不动就把一条本来能播的流拦下来。
    """
    try:
        return _probe(loc, timeout=timeout)
    except Exception as e:                          # noqa: BLE001
        return {"wrapped": False, "why": "探测失败：%s: %s"
                % (type(e).__name__, str(e)[:120])}


def _probe(loc, timeout=12):
    """判断一个上游 m3u8 的分片是不是 PNG 壳。返回 dict，永不抛。

    注意这里**故意不复用** proxy.register：判定为非壳时会放弃这条源，如果先
    建了会话，媒体库里几千部片子就会白白撑出几千个会话。自己拉一遍清单
    （几十~几百 KB）便宜得多，结论还能缓存。
    """
    import pngu_fetch

    try:
        blob, ctype, final = pngu_fetch.http_get_ex(loc, timeout=timeout)
    except Exception as e:                          # noqa: BLE001
        val = _blank_verdict()
        val["why"] = "清单拉取失败：%s: %s" % (type(e).__name__, str(e)[:120])
        return val
    return _judge_text(blob.decode("utf-8", "replace"), final or loc,
                       ctype, loc)


def _blank_verdict():
    return {"wrapped": False, "why": "", "shell": 0, "kind": "", "seg": "",
            "playlist": "", "final": "", "bad_sps": 0}


def _judge_text(text, base, ctype="", loc=""):
    """给**一段已经在手里的清单正文**下判定。

    为什么单独拎出来：平台对门票有两种完全不同的应答形态，两个都得处理。

      * `302` 到上游清单 —— 我们自己去拉（`_probe`）；
      * **`200` + 清单正文** —— 平台把清单直接吐给播放器，**没有 302**。

    第二种以前完全没处理（见 `_decide_inline` 的说明），而它恰恰是
    「平台解析成功、分片还是 PNG」的那一类源的真实形态。两边必须共用
    同一套判定，否则同一个源走 302 和走 200 会得出不同结论，排障时对不上。

    `base` 决定相对分片地址怎么补全，**必须用播放器将来会用的那个**：
    302 场景是上游清单的最终地址，200 内联场景是门票地址本身。
    """
    import pngu_unwrap

    val = _blank_verdict()
    val["playlist"] = text
    val["final"] = base or loc
    if "#EXTM3U" not in text:
        val["why"] = "上游返回的不是 m3u8（Content-Type=%s）" % (ctype or "?")
        return val

    if "#EXT-X-STREAM-INF" in text:
        # 多码率主清单：分片不在这一层，本模块保守放行，不去猜。
        val["why"] = "主清单（多码率），保守放行"
        return val

    cands = _first_uris(text, val["final"])
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
                    # 只有按 TS/PES 分层拿到的结论才可信。退回原始字节硬扫时
                    # 会把 AAC 载荷里的随机字节当成 SPS，据此去改码流等于自残。
                    if n_bad and vp.get("trusted"):
                        val["bad_sps"] = n_bad
                        s = vp.get("sps") or {}
                        val["why"] = (
                            "首片是裸 TS，但视频流里有 %d 组畸形 SPS（%sx%s 不是"
                            "有效画面尺寸），硬解会初始化失败"
                            % (n_bad, s.get("width"), s.get("height")))
                    elif n_bad:
                        val["why"] = ("首片是裸 TS；参数集没能按 TS/PES 分层取出，"
                                      "不做处理（避免误改字节）")
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
    sps_id = r.ue()                         # 要它：判断「废掉这组 SPS 会不会让 PPS 悬空」
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
            "sps_id": sps_id,
            "width": width, "height": height, "valid": valid,
            "bit_depth": bit_depth, "chroma_format_idc": chroma}


def _h264_pps_sps_id(nal):
    """PPS 只取两个字段：它自己的 id，以及它引用的 SPS id。

    用途单一但关键：要废掉一组 SPS 之前，得先知道有没有 PPS 指着它。
    指着还废，那个 PPS 就悬空了，解码器可能比原来还要更早报错。
    """
    r = _BR(_unescape(nal[1:]))
    return {"pps_id": r.ue(), "sps_id": r.ue()}


# ------------------------------------------------------- TS → PES → ES 分层
# 教训（2026-10-27）：**直接在整段 TS 字节上找 `00 00 01 67` 是不可靠的**。
# AAC 的 ADTS 载荷没有防竞争字节保护，随机字节撞出 `00 00 01 xx` 很常见，
# 撞上 `xx & 0x1F == 7` 的概率是 1/32 —— 于是凭空多出一组「SPS」，解析出来
# 自然是 1666x-280 这种荒唐尺寸。拿它当「码流有畸形参数集」的证据去改码流，
# 改的就是**真实媒体数据里的一个字节**，等于自己把流改坏。
#
# 正确做法：先走 PAT → PMT 找到视频 PID，再把该 PID 的 PES 载荷拼成 ES，
# 只在 ES 里找起始码。H.264 的 ES 内部有防竞争字节，起始码是可信的。

_VIDEO_TYPES = (0x01, 0x02, 0x1B, 0x24, 0x27)


def _psi_tables(data):
    """走一遍 PAT → PMT，返回 (pmt_pids, [(pid, stream_type)])。

    只看带 PUSI 的 PSI 包，不做跨包 section 拼接 —— 为了「看一眼编码」去
    拼 PSI 没必要，一个 PMT 装不下时也还有别的包能命中。
    """
    pmts, streams = [], []
    n = len(data)
    if n < 376:
        return pmts, streams
    step = 188
    for i in range(0, n - 187, step):
        pkt = data[i:i + step]
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
    if not pmts:
        return pmts, streams
    for i in range(0, n - 187, step):
        pkt = data[i:i + step]
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
            if (pid, st) not in streams:
                streams.append((pid, st))
            k += 5 + es_len
    return pmts, streams


def _video_pids(data):
    """挑出视频基本流的 PID。取不到 PMT 就返回空 —— 由调用方决定要不要兜底。"""
    try:
        _pmts, streams = _psi_tables(data)
    except Exception:                               # noqa: BLE001
        return []
    return [pid for pid, st in streams if st in _VIDEO_TYPES]


def _es_map(data, pids, limit=512 * 1024):
    """把指定 PID 的 PES 载荷拼成 ES，并记住每段在文件里的位置。

    返回 (es_bytes, spans)，spans = [(es_start, file_start, length)]。有了
    spans 才能把「ES 里第几个字节」映射回「TS 原文件里的偏移」，改字节时
    才不会改错地方。

    `limit` 是拼接上限：参数集都出现在分片开头，没必要为一个 5 MB 的分片
    复制出整条 5 MB 的 ES。拼到上限就停，尾部被切断的 NAL 由 _es_nals 丢弃。
    """
    es = bytearray()
    spans = []
    want = set(pids)
    for i in range(0, len(data) - 187, 188):
        pkt = data[i:i + 188]
        if pkt[0] != 0x47:
            continue
        pid = ((pkt[1] & 0x1F) << 8) | pkt[2]
        if pid not in want:
            continue
        afc = (pkt[3] >> 4) & 0x03
        off = 4
        if afc in (2, 3):
            off = 5 + pkt[4]
        if off >= 188:                  # 只有适配域（填充包），没有载荷
            continue
        pay = pkt[off:]
        skip = 0
        if pkt[1] & 0x40:               # PUSI：这一段开头是 PES 头
            if len(pay) > 9 and pay[:3] == b"\x00\x00\x01":
                skip = 9 + pay[8]       # 9 = 起始码3 + stream_id1 + len2 + flags2 + hdrlen1
                if skip >= len(pay):
                    continue
        payload = pay[skip:]
        if not payload:
            continue
        spans.append((len(es), i + off + skip, len(payload)))
        es += payload
        if len(es) >= limit:
            break
    return bytes(es), spans


def _file_off(spans, es_pos):
    """ES 偏移 → 文件偏移。落在空隙里（跨包断点）就返回 -1。"""
    lo, hi, best = 0, len(spans) - 1, None
    while lo <= hi:
        mid = (lo + hi) // 2
        s, f, ln = spans[mid]
        if s <= es_pos:
            best = (s, f, ln)
            lo = mid + 1
        else:
            hi = mid - 1
    if best is None:
        return -1
    s, f, ln = best
    if es_pos >= s + ln:
        return -1
    return f + (es_pos - s)


def _es_nals(data, pids, types=(7, 8), limit=512 * 1024):
    """只在视频 ES 里找完整的 NAL。返回 [(nal_type, file_offset, nal_bytes)]。

    尾部截断的 NAL 直接丢弃：探测只取前 32 KB，最后一个 NAL 往往被切断，
    拿着半截数据去解析只会得出荒唐结论（这正是误判的来源之一）。
    """
    if not pids:
        return []
    try:
        es, spans = _es_map(data, pids, limit)
    except Exception:                               # noqa: BLE001
        return []
    if not es:
        return []
    out = []
    n = min(len(es), limit)
    i = 0
    while True:
        i = es.find(b"\x00\x00\x01", i)
        if i < 0 or i + 4 >= n:
            break
        nxt = es.find(b"\x00\x00\x01", i + 3)
        if nxt < 0:                     # 后面没有起始码 = 被截断，不可信
            break
        t = es[i + 3] & 0x1F
        if t in types:
            fo = _file_off(spans, i + 3)
            if fo > 0:
                out.append((t, fo, es[i + 3:nxt]))
        i = nxt
    return out


def _raw_nals(payload, types=(7, 8), limit=512 * 1024):
    """兜底：拼不出 ES 时才在原始字节上硬扫。

    结果必须标记成不确定 —— 这条路会在 AAC 载荷里误抓 SPS，不能作为
    「码流有缺陷」的证据，更不能据此去改码流。
    """
    out = []
    n = min(len(payload), limit)
    i = 0
    while i < n - 4:
        i = payload.find(b"\x00\x00\x01", i)
        if i < 0 or i + 3 >= n:
            break
        end = payload.find(b"\x00\x00\x01", i + 3)
        if end < 0:
            break
        t = payload[i + 3] & 0x1F
        if t in types:
            out.append((t, i + 3, payload[i + 3:end]))
        i = end
    return out



def _video_params(payload):
    """从分片里捞 SPS/PPS，回答「到底是哪个规格的 H.264」。

    按 TS/PES 分层之后，得到的才是**视频 ES 里真实存在的**参数集。`trusted`
    为 False 表示退回了原始字节硬扫 —— 那种结果可能把 AAC 载荷里的随机字节
    当成 SPS，只能参考，不能拿来下结论、更不能据此改码流。
    """
    out = {"sps": None, "pps": 0, "note": "", "sps_total": 0, "sps_invalid": 0,
           "sps_list": [], "pps_refs": [], "source": "", "video_pids": [],
           "trusted": False}
    try:
        pids = _video_pids(payload)
        out["video_pids"] = pids
        if pids:
            nals = _es_nals(payload, pids, types=(7, 8))
            out["source"] = "ts/es"
            out["trusted"] = True
        else:
            nals = _raw_nals(payload, types=(7, 8))
            out["source"] = "raw"
        if not nals:
            out["note"] = ("视频包里还没有参数集（首片前段未出现 SPS）" if pids
                           else "取不到 PMT，无法定位视频流")
            return out

        found = []
        for t, fo, nal in nals:
            if t == 7:
                try:
                    s = _h264_sps(nal)
                    s["offset"] = fo
                    s["bytes"] = len(nal)
                    found.append(s)
                except Exception as e:              # noqa: BLE001
                    out["note"] = "SPS 解析失败：%s" % e
            else:
                try:
                    out["pps_refs"].append(_h264_pps_sps_id(nal))
                except Exception:                   # noqa: BLE001
                    pass
        out["pps"] = len(out["pps_refs"])
        out["sps_list"] = [{"sps_id": s.get("sps_id"), "width": s["width"],
                            "height": s["height"], "valid": s["valid"],
                            "offset": s["offset"]} for s in found]

        good = [s for s in found if s.get("valid")]
        bad = [s for s in found if not s.get("valid")]
        out["sps_total"] = len(found)
        out["sps_invalid"] = len(bad)
        if good:
            out["sps"] = good[0]
            if bad:
                out["note"] = ("同片里有 %d 组合法、%d 组非法 SPS，已取合法那组"
                               % (len(good), len(bad)))
        elif found:
            out["sps"] = found[0]
            out["note"] = "找到 %d 组 SPS，全部不合法" % len(found)
        if not out["trusted"]:
            out["note"] = ("（未按 TS/PES 分层，原始字节硬扫的结果可能混入音频数据"
                           "里的假起始码，仅供参考）" + (out["note"] or ""))
    except Exception as e:                          # noqa: BLE001
        out["note"] = "%s: %s" % (type(e).__name__, e)
    return out


def _fix_bad_sps(data):
    """把视频 ES 里「能解析但尺寸荒谬」的 SPS 就地废掉。

    返回 (data, 修了几组, 跳过几组)。

    修法只动 **1 个字节**：把 SPS 的 NAL header（0x67）改成 filler data
    （0x0C，nal_ref_idc=0）。解码器见到 type 12 直接丢弃。长度不变，所以
    不用重打包 TS、不用改 PES_packet_length、不用动连续计数器。

    但「改」有一个必须守住的底线：**不能让 PPS 悬空**。如果某个 PPS 还指着
    这组 SPS 的 id，把它改成 filler 之后那个 PPS 就找不到参数集了，解码器
    可能比原来更早报错。所以只在两种情况下动手：
      1) 同一个 sps_id 另有一组合法的 SPS 顶替（后出现的会覆盖，安全）；
      2) 没有任何 PPS 引用这个 sps_id（改掉不影响别人）。
    其余情况一律跳过并记日志 —— 宁可修不好，也不能改坏。
    """
    n = len(data)
    if n < 376:
        return data, 0, 0
    pids = _video_pids(data)
    if not pids:
        # 拿不到 PMT，就无法确定某个 00 00 01 67 到底是视频还是音频里的巧合。
        # 这种时候动手改字节等于赌，直接放弃。
        return data, 0, 0
    nals = _es_nals(data, pids, types=(7, 8))
    if not nals:
        return data, 0, 0

    parsed = []
    refs = set()
    for t, fo, nal in nals:
        if t == 7:
            try:
                parsed.append((_h264_sps(nal), fo))
            except Exception:                       # noqa: BLE001
                continue
        else:
            try:
                refs.add(_h264_pps_sps_id(nal)["sps_id"])
            except Exception:                       # noqa: BLE001
                continue

    good_ids = set(s.get("sps_id") for s, _fo in parsed if s.get("valid"))
    buf = None
    fixed = skipped = 0
    for s, fo in parsed:
        if s.get("valid"):
            continue
        sid = s.get("sps_id")
        if sid in good_ids:
            why = "同 id 有合法 SPS 顶替"
        elif sid not in refs:
            why = "没有 PPS 引用它"
        else:
            skipped += 1
            log.info("跳过畸形 SPS（sps_id=%s 仍被 PPS 引用，改掉会让 PPS 悬空）："
                     "偏移 %d，尺寸 %sx%s", sid, fo, s.get("width"), s.get("height"))
            continue
        if buf is None:
            buf = bytearray(data)
        buf[fo] = 0x0C
        fixed += 1
        log.info("修掉畸形 SPS（%s）：偏移 %d，%sx%s → filler NAL",
                 why, fo, s.get("width"), s.get("height"))
    if buf is None:
        return data, 0, skipped
    return bytes(buf), fixed, skipped


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

# 门票里写的是**对外**端口，平台在容器里监听的往往是另一个（现场 2026-11-01：
# 门票是 `blz.cc.cd:8525`，容器里 `127.0.0.1:8525` 直接 Connection refused，
# 真实监听是 8521）。按门票端口拼回环地址，等于把「清平台缓存」「重走门票」
# 这两条内部通道全部废掉 —— 而它们正是自动修复的全部依靠。
INNER_PORT_HINTS = (8521, 8525, 18521, 8000, 8080)
_INNER = {"base": "", "ts": 0.0}       # 探通过的内部 base，记住省得每次重试


def _listen_ports():
    """从 /proc/net/tcp{,6} 里捞出本机处于 LISTEN 的端口。

    比硬编码端口表可靠：平台换成 9000 还是别的，这里都能捞到。拿不到
    （非 Linux / 权限受限）就返回空表，由调用方退回候选端口。
    """
    ports = []
    for fn in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(fn, "r") as f:
                f.readline()                        # 表头
                for line in f:
                    cols = line.split()
                    if len(cols) < 4 or cols[3] != "0A":   # 0A = LISTEN
                        continue
                    try:
                        ports.append(int(cols[1].rsplit(":", 1)[1], 16))
                    except Exception:               # noqa: BLE001
                        pass
        except Exception:                           # noqa: BLE001
            continue
    return ports


def _inner_ports(entry):
    """内部可达的端口候选，按「最可能对」排序。"""
    import urllib.parse
    out = []

    def add(p):
        try:
            p = int(p)
        except Exception:                           # noqa: BLE001
            return
        if 0 < p < 65536 and p not in out:
            out.append(p)

    try:
        add(urllib.parse.urlsplit(entry or "").port)
    except Exception:                               # noqa: BLE001
        pass
    # 常见端口排在 /proc 前面：/proc 里什么都有（数据库、SSH），挨个试很贵
    for p in INNER_PORT_HINTS:
        add(p)
    for p in _listen_ports():
        if p >= 1024:
            add(p)
    return out[:6]


def _probe_port(port, timeout=0.4):
    """0.4 秒内能不能连上。只做 TCP 连接，不问 HTTP —— 便宜。"""
    import socket
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.close()
        return True
    except Exception:                               # noqa: BLE001
        return False


def _pick_inner_base(entry, force=False):
    """找出容器里平台真正监听的那个端口，返回 `http://127.0.0.1:<port>`。

    为什么要挑而不是挨个试：挨个试的代价是**每个候选一个超时**，六个候选
    能把一次重解析拖到二十几秒，播放器那边早重试好几轮了。这里先用 0.4 秒
    的 TCP 连接筛一遍，只对真正在 listen 的端口发一次 HTTP 探测。

    结果缓存起来（负结果只缓存 2 分钟，免得端口后来起来了还一直用旧的）。
    """
    import pngu_fetch

    now = time.time()
    if not force and _INNER["base"] and now - _INNER["ts"] < 900:
        return _INNER["base"]
    if not force and not _INNER["base"] and now - _INNER["ts"] < 120:
        return ""

    for port in _inner_ports(entry):
        if not _probe_port(port):
            continue
        base = "http://127.0.0.1:%d" % port
        url = base + "/api/strm/cache/drive-playback"
        try:
            pngu_fetch.http_get_ex(url, timeout=2)
            _INNER.update(base=base, ts=time.time())
            return base
        except urllib.error.HTTPError as e:
            if e.code in (401, 403, 404, 405):
                # 有 HTTP 服务在答，就是它（要登录也对 —— 至少地址是对的）
                _INNER.update(base=base, ts=time.time())
                return base
        except Exception:                           # noqa: BLE001
            continue
    _INNER.update(base="", ts=time.time())
    return ""


def _loopback_variants(url):
    """把 URL 的主机换成本机回环，端口换成**容器内**真正在听的端口。

    只给 127.0.0.1 一种主机：`localhost` 在个别容器里会先解析到 ::1，
    而平台只监听 IPv4，那样每个候选都要多白等一个超时周期。
    """
    import urllib.parse
    try:
        parts = urllib.parse.urlsplit(url)
    except Exception:                               # noqa: BLE001
        return []
    if not parts.netloc or not parts.path:
        return []

    bases = []
    base = _pick_inner_base(url)
    if base:
        bases.append(base)
    else:
        # 探不出来就退回门票端口试一次 —— 有些部署确实是直通的
        try:
            port = parts.port
        except ValueError:
            port = None
        bases.append("http://127.0.0.1:%d" % port if port else "http://127.0.0.1")

    out = []
    for b in bases:
        try:
            out.append(urllib.parse.urlunsplit(
                ("http", b[len("http://"):], parts.path, parts.query,
                 parts.fragment)))
        except Exception:                           # noqa: BLE001
            continue
    # 强制 http：容器内部平台就是明文监听，没有 TLS
    return out




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
_REPAIR_LAST = {"at": 0.0, "ok": False, "cleared": False, "same": False,
                "status": 0, "detail": ""}


def _platform_bases(entry):
    """能打平台管理接口的 base：内部回环排最前，对外主机只做兜底。"""
    import urllib.parse
    out = []
    base = _pick_inner_base(entry)
    if base:
        out.append(base)
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
    netloc = ("%s:%d" % (host, port)) if port else host
    pub = "http://%s" % netloc
    if pub not in out:
        out.append(pub)
    return out


def _clear_platform_cache(entry):
    """清平台的 STRM 播放缓存。返回 (ok, 说明)。

    清空只影响「下次请求时重新解析」，不会掐断正在播放的流。

    两个坑都踩过：① 门票给的是对外端口，容器里那个端口根本没人听，必须
    换成真实监听端口（见 `_inner_ports`）；② 这个接口**不是**免鉴权的 ——
    外网请求一律 401「请先登录后继续」，伪造 X-Forwarded-For / Host 六种
    组合都没用。所以内部 HTTP 打不通时，退一步在进程里直接调那条路由的
    endpoint（鉴权是 Depends，直接调用根本不会求解）。
    """
    import pngu_fetch

    last = "没有可用的平台地址"
    need_auth = False
    for base in _platform_bases(entry):
        url = base + "/api/strm/cache/drive-playback"
        try:
            blob, _ctype, _final = pngu_fetch.http_get_ex(
                url, timeout=4, method="DELETE")
            _INNER.update(base=base, ts=time.time())
            return True, blob[:160].decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                need_auth = True
                last = "平台接口要登录态（%s@%s）" % (e.code, base)
            else:
                last = "HTTP %s@%s" % (e.code, base)
        except Exception as e:                      # noqa: BLE001
            last = "%s@%s: %s" % (type(e).__name__, base, str(e)[:60])

    ok, why = _clear_cache_inproc()
    if ok:
        return True, why
    if need_auth:
        return False, "%s；进程内也没成功：%s" % (last, why)
    return False, "%s；进程内：%s" % (last, why)


def _endpoint_kwargs(ep):
    """给平台那条路由的 endpoint 凑参数；凑不齐返回 None（宁可不动）。

    只认 Request / Response 两个类型 —— 鉴权依赖是 Depends，直接调用
    endpoint 时根本不会被求解，这正是我们要的效果。
    """
    import inspect

    try:
        sig = inspect.signature(ep)
    except Exception:                               # noqa: BLE001
        return None
    kwargs = {}
    for name, p in sig.parameters.items():
        if name in ("self", "cls"):
            continue
        ann = str(getattr(p, "annotation", "") or "")
        if p.default is not inspect.Parameter.empty:
            continue
        if "Request" in ann:
            kwargs[name] = _fake_request()
        elif "Response" in ann:
            kwargs[name] = _fake_response()
        elif name in ("request", "req"):
            kwargs[name] = _fake_request()
        elif name in ("response", "resp"):
            kwargs[name] = _fake_response()
        else:
            return None                             # 认不出来就别瞎传
    return kwargs


class _StubRequest(object):
    """starlette 不可用时的最小替身。

    正常容器里平台就是 FastAPI，starlette 一定在；但把「清缓存」这件事
    押在「恰好能 import starlette」上没有必要 —— 平台那条 endpoint 真正
    用到的只有 request.method / headers 这些最普通的字段。
    """

    def __init__(self):
        self.method = "DELETE"
        self.scheme = "http"
        self.headers = {}
        self.cookies = {}
        self.query_params = {}
        self.path_params = {}
        self.client = ("127.0.0.1", 0)
        self.url = types.SimpleNamespace(
            path="/api/strm/cache/drive-playback", query="", scheme="http")


class _StubResponse(object):
    status_code = 200
    body = b""
    headers = {}


def _fake_request():
    try:
        from starlette.requests import Request
        return Request({
            "type": "http", "http_version": "1.1", "method": "DELETE",
            "path": "/api/strm/cache/drive-playback",
            "raw_path": b"/api/strm/cache/drive-playback",
            "root_path": "", "scheme": "http", "query_string": b"",
            "headers": [], "client": ("127.0.0.1", 0),
            "server": ("127.0.0.1", 0),
        })
    except Exception:                               # noqa: BLE001
        return _StubRequest()


def _fake_response():
    try:
        from starlette.responses import JSONResponse
        return JSONResponse({"ok": True})
    except Exception:                               # noqa: BLE001
        return _StubResponse()


def _run_coro(coro, timeout=20):
    """在一个**没有事件循环**的线程里跑协程；万一就在循环里，就换线程跑。"""
    import concurrent.futures

    try:
        asyncio.get_running_loop()
        in_loop = True
    except RuntimeError:
        in_loop = False
    if not in_loop:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(1) as ex:
        return ex.submit(asyncio.run, coro).result(timeout=timeout)


_INPROC = {"at": 0.0, "ok": False, "why": ""}


def _clear_cache_inproc():
    """在进程里直接调平台「清播放缓存」那条路由，绕过鉴权中间件。

    失败要节流：这条路第一次就要扫一遍 `sys.modules` + `gc.get_objects()`
    才能找到平台应用，NAS 上那一下能到一两秒；而「重解析失败 → 播放器继续
    重试 → 又重解析」是常态。不节流的话，光扫对象就能把播放拖垮。
    """
    now = time.time()
    if not _INPROC["ok"] and now - _INPROC["at"] < 300:
        return False, _INPROC["why"]

    try:
        import pngu_mount
        apps = pngu_mount.find_apps()
    except Exception as e:                          # noqa: BLE001
        _INPROC.update(at=now, ok=False, why="mount 不可用：%s" % str(e)[:60])
        return False, _INPROC["why"]

    ok, why = _do_inproc(apps)
    _INPROC.update(at=time.time(), ok=ok, why=why)
    return ok, why


def _do_inproc(apps):
    import inspect

    for _name, app in apps:
        try:
            routes = list(getattr(getattr(app, "router", None), "routes", []) or [])
        except Exception:                           # noqa: BLE001
            continue
        for route in routes:
            if getattr(route, "path", "") != "/api/strm/cache/drive-playback":
                continue
            ep = getattr(route, "endpoint", None)
            if ep is None:
                continue
            try:
                kwargs = _endpoint_kwargs(ep)
            except Exception as e:                  # noqa: BLE001
                return False, "那个路由的参数认不全（%s）" % type(e).__name__
            if kwargs is None:
                return False, "那个路由的参数认不全，不敢在进程里调用"
            try:
                res = ep(**kwargs)
                if inspect.isawaitable(res):
                    res = _run_coro(res)
                return True, "已在进程内清掉平台播放缓存（%s）" % type(res).__name__
            except Exception as e:                  # noqa: BLE001
                return False, "进程内调用失败：%s: %s" % (
                    type(e).__name__, str(e)[:80])
    return False, "进程里没找到清缓存的库由"



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

    # 内部候选的预算收窄到 3 秒：回环上被拒是**瞬间**返回的，真会等满 3 秒的
    # 多半是「端口开着但不是 HTTP」。6 个候选 × 8 秒会把重解析拖到一分钟，
    # 播放器那边早就重试了十几次。
    cands = [(u, 3) for u in _loopback_variants(entry)] + [(entry, timeout)]
    for cand, to in cands:
        status, loc, err = pngu_fetch.peek_redirect(cand, timeout=to)
        if err:
            out["error"] = err
            continue
        out["status"] = status
        if loc:
            try:
                out["loc"] = urllib.parse.urljoin(cand, loc)
            except Exception:                       # noqa: BLE001
                out["loc"] = loc
            if cand != entry:
                # 回环能打到票 = 这个内部端口是对的，记下来给下次用
                _INNER.update(base=cand.split("/api/")[0], ts=time.time())
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
    # 「重解析」在平台侧等于「再跑一次 4k 插件 parse」，也就是又一次 wasm 签名
    # + 一次上游请求。上游正在拒绝时重解析毫无意义，只是在帮播放器锤源站 ——
    # 所以这里跟解析层共用同一个闸门。
    try:
        import pngu_fetch
        ok, left, _why = pngu_fetch.gate_open()
        if not ok:
            _bump("repair_gated")
            _note("上游冷却中（还剩 %d 秒），跳过重解析" % left)
            return None
    except Exception:                               # noqa: BLE001
        pass
    _bump("reparse")
    try:
        rep = _reparse(entry, loc)
    except Exception as e:                          # noqa: BLE001
        rep = {"ok": False, "loc": "", "status": 0, "cleared": False,
               "detail": "", "same": False,
               "error": "%s: %s" % (type(e).__name__, str(e)[:100])}
    # 把这次重解析的结局留下来：下次用户问「为什么没自动恢复」，
    # 看 `__hijack.repair` 就够了，不用再靠猜。
    try:
        with _LOCK:
            _REPAIR_LAST.update(
                at=round(time.time(), 1),
                ok=bool(rep.get("ok")),
                cleared=bool(rep.get("cleared")),
                same=bool(rep.get("same")),
                status=int(rep.get("status") or 0),
                detail=str(rep.get("detail") or rep.get("error") or "")[:160])
    except Exception:                               # noqa: BLE001
        pass
    return rep


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
    # 回环候选最多 4 个：诊断口是给人点开的，不能让浏览器干等一分钟。
    for u in _loopback_variants(entry)[:4]:
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


def _is_self_url(url):
    """这条地址是不是指向我们自己挂的服务（挂上去的清单/分片）。"""
    if not url:
        return False
    try:
        import urllib.parse
        path = urllib.parse.urlsplit(url).path
    except Exception:                               # noqa: BLE001
        path = url
    return str(path or "").startswith(SELF_PREFIX + "/")


# 嗅探只取开头这么多字节就够了：m3u8 的第一行必然是 `#EXTM3U`。
SNIFF_BYTES = 2048


def _sniff_playlist(url, timeout=6):
    """一次 2 KB 的 Range 请求，判断这条地址后面到底是不是 m3u8。

    为什么不靠后缀判断：实测有源给的清单地址长这样 ——

        https://lf26-imcloud-file-sign.bytetos.com/tos-cn-…/89bde80f…?x-expires=…&x-signature=…

    **路径里根本没有 `.m3u8`**。按后缀判断会把这一整类源原样放过去：现场
    22 次播放请求里 19 次落在 `unheld`，`wrap`/`pass`/`fail` 一个都没动 ——
    播放器拿到的永远是平台那份没改写的清单，分片还是 PNG 壳。

    取流时带 `max_bytes`，就算对方不认 Range 也只读 2 KB，不会因为一个
    302 指到大文件就把整部片子拖下来。

    返回 True / False；探不动（网络错误、对方拒绝）返回 None，由上层按
    老路子原样放行 —— 探不动不等于不是清单，只是我们没证据动它。
    """
    import pngu_fetch
    try:
        blob, _ctype, _final = pngu_fetch.http_get_ex(
            url, timeout=timeout,
            extra={"Range": "bytes=0-%d" % (SNIFF_BYTES - 1)},
            max_bytes=SNIFF_BYTES)
    except Exception as e:                          # noqa: BLE001
        log.info("嗅探清单失败（原样放行）：%s %s", str(url)[:80], e)
        return None
    head = blob[:SNIFF_BYTES]
    if head[:3] == b"\xef\xbb\xbf":                 # 带 BOM 的清单也见过
        head = head[3:]
    return head.lstrip()[:7] == b"#EXTM3U"


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


# ------------------------------------------------------------ 失败短路（熔断）
# 实测（2026-10-27）：上游整体不可用时，平台对门票一律 502。播放器不会等，
# 它每秒重试一次 —— 计数器上 `hit` 从 32 涨到 209，也就是**平台被打了 209 次**，
# 每次都要走一遍 4k 签名解析。上游既然在限流，这样只会让它更晚恢复。
#
# 所以：同一张门票连续失败 3 次之后，20 秒内直接回 503 + Retry-After，连平台
# 都不去碰。这样播放器的重试风暴就止在我们这儿，上游能喘口气；等冷却结束
# 自然放一次探测，成功即恢复。**熔断绝不吞掉成功**：平台一旦给出 302 就清零。
FAIL_OPEN = 3               # 连续失败几次后开始短路
FAIL_COOL = 20              # 短路多少秒
_FAILCOOL = {}              # mkey -> (连续失败次数, 短路截止时间戳)


def _failcool_left(mkey):
    """还要短路多少秒。0 = 不短路。

    注意 `until == 0` 表示「还在累计失败次数」，**不是过期**。早期版本在这里
    一律按过期处理并 pop，结果每次都在第 1 次就清零，连续失败永远攒不到
    FAIL_OPEN，熔断形同虚设（实测播放器把平台锤了 209 次都没短路）。
    """
    if not mkey:
        return 0.0
    with _LOCK:
        item = _FAILCOOL.get(mkey)
        if not item:
            return 0.0
        until = item[1]
        if not until:
            return 0.0
        left = until - time.time()
        if left <= 0:
            _FAILCOOL.pop(mkey, None)
            return 0.0
        return left


def _failcool_mark(mkey, ok):
    """记一次成败。平台只要答了 302 就立刻清零 —— 别把熔断留在成功之后。"""
    if not mkey:
        return
    with _LOCK:
        if ok:
            _FAILCOOL.pop(mkey, None)
            return
        n = (_FAILCOOL.get(mkey) or (0, 0.0))[0] + 1
        until = time.time() + FAIL_COOL if n >= FAIL_OPEN else 0.0
        if len(_FAILCOOL) > 128:            # 上限保护，别为这事涨内存
            _FAILCOOL.clear()
        _FAILCOOL[mkey] = (n, until)


async def _send_plain_playlist(send, text, scope):
    """直接回一份 m3u8。给熔断路径用（那里没有 _decide_and_send 的闭包可用）。"""
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


async def _fail_fast(send, wait, scope):
    """平台连续失败期间的快速应答。不碰平台、不碰上游，立刻回。"""
    secs = int(wait + 0.999)
    body = ('{"ok":false,"error":"upstream unavailable",'
            '"retry_after":%d}' % secs).encode()
    headers = [(b"content-type", b"application/json"),
               (b"content-length", str(len(body)).encode("latin-1")),
               (b"retry-after", str(secs).encode("latin-1")),
               (b"cache-control", b"no-store")]
    await send({"type": "http.response.start", "status": 503,
                "headers": headers})
    await send({"type": "http.response.body",
                "body": b"" if (scope.get("method") or "GET").upper() == "HEAD"
                else body})


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

        # 门票级复用：清单刚改写好的这 20 秒内，同一张门票再来就直接给，
        # 连平台都不碰 —— 播放器失败重试是每秒一次的，让它每次都去触发一遍
        # 「wasm 签名 + 4k 上游接口」正是被限流的源头。
        reuse_text = _reuse_playlist(scope)
        if reuse_text:
            _bump("reuse")
            return await _send_plain_playlist(send, reuse_text, scope)

        # 平台连续失败期间先短路：播放器每秒重试，我们不能让它变成对上游的
        # 连续锤击（见 FAIL_OPEN 的说明）。诊断口不经过这里，照常可用。
        mkey0 = _memo_key(scope, "")
        left = _failcool_left(mkey0)
        if left:
            # 但短路不能把**留底**一起短路掉：那正是「退出再打开」要靠的东西。
            # 有留底就照旧顶上，没有才快速失败。
            memo0 = _memo_get(mkey0)
            if memo0:
                _bump("rescue")
                _note("平台连续失败，用 %.0f 分钟前的留底顶上（%d 秒内不再打平台）"
                      % ((time.time() - memo0[2]) / 60.0, int(left + 0.999)))
                return await _send_plain_playlist(send, memo0[0], scope)
            _bump("failfast")
            return await _fail_fast(send, left, scope)

        st = {"hold": False, "start": None, "loc": "", "chunks": [],
              "done": False, "mode": "", "ctype": "", "err": 0}

        async def cap(message):
            mtype = message.get("type")

            if mtype == "http.response.start" and not st["hold"]:
                code = int(message.get("status") or 0)
                hdrs = {k.decode("latin-1").lower(): v.decode("latin-1")
                        for k, v in (message.get("headers") or [])}
                loc = hdrs.get("location", "")
                if code in REDIRECT_CODES and loc and not _is_self_url(loc):
                    # **先扣住，再判断它是不是清单**。
                    # 以前这里要求 `_looks_like_playlist(loc)`（路径以 .m3u8
                    # 结尾）。实测有源给的清单是签名地址，路径里没有 .m3u8：
                    # 19 次请求全落进 `unheld` 原样透传，分片仍是 PNG 壳。
                    # 现在一律扣住，到 `_decide_and_send` 里用一次 2 KB Range
                    # 嗅出真身；不是清单就原封不动重放这个 302，行为与以前
                    # 完全一致（登录页跳转之类不会被误伤）。
                    st["hold"] = True
                    st["mode"] = "302"
                    st["start"] = message
                    scope_headers = {
                        k.decode("latin-1").lower(): v.decode("latin-1")
                        for k, v in (scope.get("headers") or [])}
                    st["loc"] = _abs_url(scope, scope_headers, loc)
                    _seen(code, st["loc"])
                    return
                if code >= 400:
                    # **平台自己都没解析出来**。这是「退出播放器、过一会儿再
                    # 打开同一个 STRM 就播不了」最典型的形态：上游 play_key
                    # 过期，4k 插件 parse 失败，平台连 302 都不发，直接回
                    # 4xx/5xx。以前这里原样透传，播放器永远打不开，而插件
                    # 完全不知道发生过什么 —— 留底存了也用不上。
                    # 现在先扣住，能留底就顶上，顶不上再原样发回去。
                    st["hold"] = True
                    st["mode"] = "err"
                    st["start"] = message
                    st["err"] = code
                    _seen(code, "平台自己解析失败")
                    return
                if 200 <= code < 300:
                    # **平台直接把清单吐在响应体里，没有 302。**
                    # 这是 0.5.9 补的盲区：以前这里是无条件 `send(message)`
                    # 原样透传，于是这一类源从上到下**没有任何一次处置** ——
                    # 播放器拿到的永远是平台那份没改写的清单，分片还是 PNG
                    # 壳，而诊断里 `hit` 一直涨、`pass`/`wrap`/`fail` 全是 0，
                    # 看上去像插件根本没工作。现场两次数据都是这个形状
                    # （hit 209 / 59，三个判定计数全零），当时误判成「平台
                    # 没解析成功」，其实是解析成功了、只是没用 302 递过来。
                    st["hold"] = True
                    st["mode"] = "inline"
                    st["start"] = message
                    st["ctype"] = hdrs.get("content-type", "")
                    st["loc"] = _request_url(scope)
                    _seen(code, "200 内联 %s" % (st["ctype"] or "?"))
                    return
                _bump("unheld")
                _seen(code, loc or hdrs.get("content-type", ""))
                return await send(message)

            if mtype == "http.response.body" and st["hold"]:
                body = message.get("body") or b""
                if body:
                    st["chunks"].append(body)
                if st["mode"] == "inline" and \
                        sum(len(c) for c in st["chunks"]) > MAX_INLINE:
                    # 不可能是清单了。把已经扣住的吐回去，后面原样透传 ——
                    # 宁可多绕一次 send，也不能让一个无界缓冲留在内存里。
                    _bump("unheld")
                    st["hold"] = False
                    await send(st["start"])
                    for c in st["chunks"]:
                        await send({"type": "http.response.body",
                                    "body": c, "more_body": True})
                    st["chunks"] = []
                    st["start"] = None
                    return
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


async def _decide_inline(send, scope, st, replay, send_playlist):
    """平台回了 `200 + 清单正文`：没有 302 可改写，直接在正文上动手。

    补的是 0.5.9 之前最致命的一个盲区（来龙去脉见 `cap` 里的注释）。处置
    语义和 302 分支保持一致，否则同一个源走两种形态会得到不同结果：

      * 分片是裸流 → 把平台那份原样还回去（`pass`）；
      * 分片带 PNG 壳 → 现场建会话、返回我们改写过的清单（`wrap`）。

    base 用**门票地址**而不是别处：平台是把这份清单直接放在门票 URL 上给
    播放器的，播放器解析相对分片地址时用的也是它。两边必须一致，否则我们
    算出来的分片地址和播放器眼里的不是同一个。
    """
    text = b"".join(st["chunks"]).decode("utf-8", "replace")
    entry = st.get("loc") or _request_url(scope)
    if "#EXTM3U" not in text:
        _bump("unheld")
        _note("平台返回 200 但不是清单（Content-Type=%s），原样放行"
              % (st.get("ctype") or "?"))
        return await replay()

    val = _cache_get(entry)
    if val is None:
        val = _judge_text(text, entry, st.get("ctype") or "")
        _cache_put(entry, val)

    mkey = _memo_key(scope, "")

    if not val.get("wrapped"):
        _memo_put(mkey, val.get("playlist") or text, val.get("final"))
        _bump("pass")
        _note("平台直接返回清单（无 302），%s —— 原样放行"
              % (val.get("why") or ""))
        return await replay()

    try:
        tok = _token_of(entry)
        sess = await asyncio.to_thread(
            sess_build, tok, entry, entry, False, text, entry)
    except Exception as e:                          # noqa: BLE001
        _bump("fail")
        _note("内联清单改写失败，原样放行：%s: %s"
              % (type(e).__name__, str(e)[:120]))
        log.warning("内联清单改写失败（放行平台原文）：%s", e)
        return await replay()

    _bump("wrap")
    _note("平台直接返回清单（无 302），首片带壳（%s），已换成我们的清单"
          % (val.get("why") or ""))
    log.info("内联清单接管 %s：%d 片",
             tok, len(getattr(sess, "segs", []) or []))
    return await send_playlist(sess.playlist)


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

    # ---- 分支：平台把清单内联在 200 里，压根没发 302 ----
    # 这类根本就没有「上游地址」可探、可留底、可重解析 —— 清单已经在手里。
    if st.get("mode") == "inline":
        return await _decide_inline(send, scope, st, _replay, _send_playlist)

    # ---- 分支：302 的目标不以 .m3u8 结尾（签名地址那一类）----
    # 先用一次 2 KB Range 闻一下真身。是清单就继续往下判定（和 .m3u8 完全
    # 同一条路径）；不是清单就**原封不动重放这个 302** —— 登录页跳转、
    # 直链分片这些都不该被我们碰。探不动（None）也按放行处理。
    if st.get("mode") == "302" and not _looks_like_playlist(loc):
        sniff = await asyncio.to_thread(_sniff_playlist, loc)
        if not sniff:
            _bump("unheld")
            _note("302 到 %s —— 闻着不是清单，原样透传" % (loc or "")[:80])
            return await _replay()
        _note("302 到签名地址、无 .m3u8 后缀，但确实是清单：%s" % (loc or "")[:70])

    # ---- 第一步：先判定当前上游地址还活着没有 ----
    val = None
    # 这次探测如果是**现拉的**，清单正文就在手里，建会话时不必再拉一遍。
    # 对 4k 这类源这一点不是省流量的问题：清单地址常常带一次性签名，
    # 多拉一次就多一次被限流的机会。
    fresh_text, fresh_base = "", ""
    if not err:
        val = _cache_get(loc)
        force = _strike_hit(loc)
        if val is not None and not _is_dead(val):
            # 有结论 ≠ 现在还是活的。平台会把很久以前解析出来的地址一直念
            # （drive-playback 缓存），上游清单却几分钟就过期。所以隔一阵用
            # 一次 HEAD 验活：几十毫秒、几乎不耗流量。
            alive = await _keep_alive(loc, force=force)
            if alive is False:
                _cache_drop(loc)
                val = None
            elif alive is None and force:
                # 探不出来，但播放器已经在反复要这个地址 —— 老实拉一遍
                val = None
        if val is None:
            try:
                val = await asyncio.to_thread(_probe, loc)
                if val.get("playlist"):
                    fresh_text = val["playlist"]
                    fresh_base = val.get("final") or loc
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
            if not _is_dead(val):
                _LIVE[loc] = time.time()

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
                fresh_text = val2["playlist"]
                fresh_base = val2.get("final") or loc2
                _LAST["loc"] = loc
                _cache_put(loc, val)
                _LIVE[loc] = time.time()
                if not val.get("wrapped"):
                    _memo_put(mkey, val["playlist"], val.get("final"))
                _bump("reparse_ok")
                # 重解析拿到能拉的清单 = 上游这会儿是通的。失败计数在这里
                # 清零，下次偶发失败才会从 20 秒重新起算，不会被前面攒下的
                # 次数直接推到 600 秒。
                try:
                    import pngu_fetch
                    pngu_fetch.gate_note_ok()
                except Exception:                   # noqa: BLE001
                    pass
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
        _failcool_mark(mkey, False)
        _note("平台解析失败 %d，且没有留底可救（这一集从未成功播过）" % err)
        log.warning("平台返回 %d 且无留底：%s", err, mkey)
        return await _replay()

    # 走到这里说明平台答了 302：它就是活的，熔断立刻清零。
    _failcool_mark(mkey, True)

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
                                               only_first,
                                               fresh_text or None,
                                               fresh_base if fresh_text else "")
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

# ---------------------------------------------------------------- 门票级复用
# 播放器打不开时的行为是**每秒重试一次**，每次重试都打门票，于是每次都触发
# 平台重新解析一遍：官方 4k 插件 parse() = wasm 现场签名 + 一个上游接口请求。
# 一分钟就是几十次，一小时上千次 —— 源站限流、封 IP 基本都是这么来的。
#
# 可这份清单本来就已经改写好了（会话就在内存里），没有任何理由再让平台算一遍。
# 所以：同一张门票在上次接管后 REUSE_WINDOW 秒内再来，直接把手里那份还回去，
# 平台和上游一次都不碰。窗口取 20 秒足够盖住「连点几下 / 播放器快速重试」，
# 又不至于让已经过期的分片地址被反复喂给播放器。
REUSE_WINDOW = 20
_REUSE = {}                 # 门票 key -> 会话 token
_REUSE_MAX = 512


def _entry_key(url):
    """门票 key：只取路径最后一段，和 `_memo_key` 同一套口径。"""
    path = (url or "").split("?", 1)[0]
    name = path.rsplit("/", 1)[-1]
    if name.endswith(".m3u8"):
        name = name[:-5]
    return name if name and "/" not in name else ""


def _reuse_put(entry, tok):
    # 只登记真正的平台门票（`/api/strm/o/<tok>.m3u8`）。自包含地址
    # （`/hls/u/…`）的最后一段可能都叫同一个名字，登记进来会让不同源
    # 互相串台，宁可不用。
    if "/strm/" not in (entry or "") or ".m3u8" not in (entry or ""):
        return
    key = _entry_key(entry)
    if not key or not tok:
        return
    with _SEG_LOCK:
        _REUSE[key] = tok
        if len(_REUSE) > _REUSE_MAX:
            for k in list(_REUSE)[:128]:
                _REUSE.pop(k, None)


def _reuse_drop(tok):
    with _SEG_LOCK:
        for k in [k for k, v in _REUSE.items() if v == tok]:
            _REUSE.pop(k, None)


def _reuse_playlist(scope):
    """同一张门票马上又来一次：把上次改写好的清单直接还回去。

    只认 `.m3u8` 结尾的门票路径，`/seg/`、`/key/` 这些不在这里拦。
    会话不在、清单空的、超过窗口的，一律返回空串走原来的流程。
    """
    method = (scope.get("method") or "GET").upper()
    if method not in ("GET", "HEAD"):
        return ""
    path = scope.get("path") or ""
    if not path.endswith(".m3u8"):
        return ""
    key = _entry_key(path)
    if not key:
        return ""
    with _SEG_LOCK:
        tok = _REUSE.get(key)
    if not tok:
        return ""
    sess = sess_get(tok)            # 它自己会取 _SEG_LOCK，必须在锁外调用
    if sess is None or not getattr(sess, "playlist", ""):
        return ""
    if time.time() - getattr(sess, "built", 0.0) > REUSE_WINDOW:
        return ""
    return sess.playlist


RELAY_MODE = "auto"     # auto=只接管带壳的流；always=不管有没有壳都走中转
# 畸形 SPS 修复：off=不管（默认）；first=只接管首片；all=所有分片都过 NAS 再修。
# 默认 off 的理由见 _fix_bad_sps 的注释：0.5.6 的误判（把 TS 包头掺进 SPS）
# 会把正常参数集改成 filler，代价太大。真需要时在配置页打开。
SPS_FIX = "off"


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
    _reuse_put(sess.entry, sess.tok)
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


def sess_build(tok, src, entry="", only_first=False, text=None, base=""):
    """拉清单、解析、渲染。失败抛异常，由调用方决定是否放行。

    `src` 是这次真正去取的地址；`entry` 是播放器最初请求的那个门票地址
    （`/api/strm/o/xxx.m3u8`）。两者通常不同：门票会 302 到当次的上游清单，
    而上游地址带时效。把门票记下来，是为了让分片请求在几小时后还能顺着它
    重新走一遍 302，拿到新地址 —— 否则会话一被回收就彻底断线。

    `only_first=True` 时只把**第一个**分片改指向本服务，其余保留上游绝对
    地址。用在「只想修首片的畸形 SPS、不想让整集流量都过 NAS」的场合。

    `text` / `base` 给「清单正文已经在手里」的场景用（平台 200 内联清单）：
    这时再按 `src` 去拉一遍纯属浪费 —— 对 4k 这类源，每拉一次都是
    wasm 签名 + 上游接口，拉多了一次就可能被限流。
    """
    import pngu_fetch

    if text is None:
        blob, _ctype, final = pngu_fetch.http_get_ex(src)
        text = blob.decode("utf-8", "replace")
        base = final or src
    if "#EXTM3U" not in text:
        raise RuntimeError("源地址返回的不是 m3u8（前 60 字节：%s）"
                           % text[:60].replace("\n", " "))
    if "#EXT-X-STREAM-INF" in text:
        raise RuntimeError("主清单（多码率），本模块不接管")

    base = base or src
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
    # 壳里不会有合法的 00 00 01 67，先剥再扫省得误判。改之前会先确认没有
    # PPS 依赖这组 SPS，宁可修不好也不让参数集悬空。
    if SPS_FIX != "off" and info.get("kind") == "ts":
        payload, n_fix, n_skip = _fix_bad_sps(payload)
        if n_fix:
            _bump("sps_fix")
            _note("分片 %s 修掉 %d 组畸形 SPS" % (idx, n_fix))
        if n_skip:
            _bump("sps_skip")
            _note("分片 %s 有 %d 组畸形 SPS 因被 PPS 引用而未修" % (idx, n_skip))
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
__version__ = "0.5.14"
