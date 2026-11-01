# -*- coding: utf-8 -*-
"""和官方 4k 解析插件（parser.thirdparty.4k）联动。

为什么需要这一层
----------------
我们自己的 `parse()` 解析 4k 用的是**同一套协议**（同一个 wasm 签名 + 同一个
`/video/play` 接口），区别只在于「解析出来的清单由谁改写」。问题出在解析链的
兜底顺序上：

  * 我们的插件排在 4k 前面（priority 20 < 25），正常情况下我们先被问到；
    一旦我们因为「没拿到 meta / 上游暂时拒了」返回失败，平台就会去问 4k；
  * 4k 一旦解析成功，它返回的是**上游原始 m3u8 地址**，平台 302 过去之后，
    播放器手里就是那份没改写的清单 —— 分片全是 PNG 壳，照样播不了。

所以这里把官方插件的 `parse` 包一层，做到两件事：

1. **成功也接管**：它解析出来的清单，先探一下首片是不是带壳。带壳就用我们的
   内建服务重新登记一遍（返回我们自己的清单地址），分片才会经过剥壳；裸流
   原样返回，不白白多走一趟 NAS。
2. **失败就接手**：它抛异常或返回 ok=false 时，用同一次调用里拿到的 meta
   自己重新解析（走我们自己的 cookie / 画质配置），成功就按成功返回。
   这样「官方插件取不到流」不会再直接变成平台的 502。

安全边界
--------
* 只碰 `parser.thirdparty.4k` 这一个类，找不到就安静地什么都不做；
* 全程 try/except，任何异常都原样交还给官方实现，绝不改变它的失败语义；
* 只改返回值里 `streams[0].url` 这一个字段，其它字段（headers、line_id、
  proxy_subresources…）原封不动；
* `uninstall()` 能把原方法装回去，插件停用即摘干净。
"""

from __future__ import annotations

import logging
import sys
import time

log = logging.getLogger("pngunwrap.4k")

PLUGIN_ID = "parser.thirdparty.4k"
CLASS_NAME = "FourKParserPlugin"

# 找了多久还没找到就先歇一会儿再找（插件加载顺序不保证）
RETRY_SEC = 60.0

_STATE = {
    "hooked": False,
    "target": "",           # 打到了哪个类（模块名.类名）
    "reason": "",
    "calls": 0,             # 官方 parse 被调用的次数
    "ok": 0,                # 官方自己成功了
    "fail": 0,              # 官方失败（抛异常或 ok=false）
    "wrapped": 0,           # 我们判定带壳、把地址换成我们自己的次数
    "shell": 0,             # 判定带壳的次数（不论有没有真的替换地址）
    "rescued": 0,           # 官方失败后由我们重新解析成功的次数
    "bare": 0,              # 官方成功但首片是裸 TS，原样放行
    "direct": 0,            # 官方选中了「直链」（mp4 之类）而不是 HLS 清单
    "hls_switch": 0,        # 直链换成了同源的 HLS 线路（真正有用的那一步）
    "hls_line": "",         # 换到了哪条线路
    "hls_note": "",         # 换线路这件事的说明（不会被后面的动作覆盖）
    "error": 0,             # 我们自己这层出错的次数
    "gated": 0,             # 上游冷却中、官方 parse 被我们直接短路掉的次数
    "last": "",             # 最近一次动作（中文，排障用）
    "last_meta": {},        # 最近一次看到的 meta（已脱敏）
}

_ATTEMPTS = [0]
_LAST_TRY = [0.0]
_HANDLER = [None]
_META = []                  # 最近的 meta，排障用（最多 5 条）


# ---------------------------------------------------------------- 工具

def _bump(key, n=1):
    try:
        _STATE[key] = int(_STATE.get(key) or 0) + n
    except Exception:                               # noqa: BLE001
        pass


def _note(text):
    """记「这次到底做了什么」。

    一次调用里可能连着做两件事（先把直链换成同源 HLS，再判首片），后面的
    说明不能把前面那件更重要的事盖掉 —— 现场只看 `last` 一行，看到「裸流
    放行」就以为我们没干活，看不到它测的其实已经是换过来的 HLS 线路。
    """
    text = str(text)[:300]
    prev = _STATE.get("hls_note") or ""
    if prev and prev not in text:
        text = (prev + "；" + text)[:300]
    _STATE["last"] = text


def _mask(v):
    """只留前 6 位 + 总长度。data_id 要能对得上，密钥不能还原。"""
    s = str(v or "")
    if not s:
        return ""
    return s[:6] + ("…(%d)" % len(s) if len(s) > 6 else "")


def _remember(target_url, meta):
    """记下这次调用带的 meta。脱敏后再暴露给诊断接口。"""
    try:
        item = {
            "at": round(time.time(), 1),
            "target": str(target_url or "")[:200],
            "page_url": str(meta.get("page_url") or "")[:200],
            "data_id": _mask(meta.get("data_id")),
            "secret_key": _mask(meta.get("secret_key")),
            "play_key": _mask(meta.get("play_key")),
            "has_keys": all(meta.get(k) for k in
                            ("data_id", "secret_key", "play_key")),
            "provider": str(meta.get("provider") or ""),
        }
        _META.insert(0, item)
        del _META[5:]
        _STATE["last_meta"] = item
    except Exception:                               # noqa: BLE001
        pass


def _meta_of(parse_request):
    """从 parse_request 里把 (target_url, meta) 抠出来，怎么变结构都能兜住。"""
    try:
        req = parse_request or {}
        target = None
        if isinstance(req, dict):
            target = req.get("play_target") or req.get("target") or {}
            meta = target.get("meta") if isinstance(target, dict) else None
            if not isinstance(meta, dict):
                meta = req.get("meta") or {}
        else:
            target = getattr(req, "play_target", None) or getattr(req, "target", None)
            meta = getattr(target, "meta", None) if target is not None else None
            if not isinstance(meta, dict):
                meta = getattr(req, "meta", None) or {}
        if not isinstance(meta, dict):
            meta = {}
        if isinstance(target, dict):
            url = target.get("url") or target.get("page_url") or ""
        else:
            url = getattr(target, "url", "") if target is not None else ""
        return str(url or ""), meta
    except Exception:                               # noqa: BLE001
        return "", {}


def _failed(out):
    if out is None:
        return True
    if isinstance(out, dict):
        return out.get("ok") is False
    try:
        return getattr(out, "ok", True) is False
    except Exception:                               # noqa: BLE001
        return False


def _first_stream(out):
    """取第一条 stream，返回 (容器, 取 url 的函数式)。dict / 模型都能处理。"""
    try:
        streams = out.get("streams") if isinstance(out, dict) else getattr(out, "streams", None)
        if not streams:
            return None
        first = streams[0]
        if isinstance(first, dict):
            return first
        return {"url": str(getattr(first, "url", "") or "")}
    except Exception:                               # noqa: BLE001
        return None


def _url_of(out):
    st = _first_stream(out)
    return str((st or {}).get("url") or "")


def _set_url(out, url):
    """只替换 streams[0].url，别的一个字段都不动。"""
    try:
        streams = out.get("streams") if isinstance(out, dict) else getattr(out, "streams", None)
        if not streams:
            return False
        first = streams[0]
        if isinstance(first, dict):
            first["url"] = url
            return True
        setattr(first, "url", url)
        return True
    except Exception:                               # noqa: BLE001
        return False


def _is_ours(url):
    """已经指向我们内建服务的地址不要再包一层，否则清单会被自己套两次。"""
    u = str(url or "").lower()
    return ("/api/strm/pngu/" in u) or ("/pngu/hls/" in u) or ("/hls/u/" in u)


def _is_hls(url):
    """是不是 HLS 清单。

    判据故意和官方插件保持一致（`'.m3u8' in url.lower()`），否则两边对
    「这算不算 m3u8」的判断不一致，会来回换地址、谁都不服谁。
    """
    return ".m3u8" in str(url or "").lower()


def _brief(url):
    """一行以内的地址摘要，写进诊断用：「域名/文件名」。"""
    try:
        import urllib.parse
        p = urllib.parse.urlsplit(str(url or ""))
        tail = p.path.rsplit("/", 1)[-1][:44]
        return "%s%s" % (p.netloc[:44], ("/" + tail) if tail else "")
    except Exception:                               # noqa: BLE001
        return str(url or "")[:60]


def _selected_line_id(out):
    """官方在 diagnostics 里记了它最终选了哪条线路。"""
    try:
        diag = (out.get("diagnostics") if isinstance(out, dict)
                else getattr(out, "diagnostics", None))
        if isinstance(diag, dict):
            return str(diag.get("selected_line_id") or "")
    except Exception:                               # noqa: BLE001
        pass
    return ""


def _try_hls_line(inst, meta, skip_id="", limit=3):
    """官方选中了直链：遍历同一份 line_options，找一条 m3u8 回来。

    为什么必须这么做
    ----------------
    官方 `parse()` 是「按线路顺序逐条试，**第一条成功的就返回**」。4k 源的
    线路里既有 HLS（CDN 上的 ts 分片），也有云盘直链（xxx.mp4，天翼云之类）。
    一旦排在前面的线路给的是 mp4，官方就返回 mp4 —— 后面那些能播的 HLS
    线路根本没机会被用到。现场表现就是：网页播放器拉 ts 分片好好的，平台
    却 302 到一个打不开的 mp4。

    这里直接复用官方自己的签名实现（`_ordered_lines` + `_resolve_stream`），
    不另写一套协议，避免和它的 wasm 签名细节跑偏。

    `limit` 是硬上限：每试一条都是一次真实的上游请求（wasm 签名 + /video/play），
    试太多既慢又容易触发限流。`skip_id` 跳过官方已经选中过的那条。

    默认 2 而不是 3：官方刚成功（说明上游还通），我们紧接着再连打 3 条就是
    「一次播放 4 个请求」。两条已经是「主线路 + 一条备用」的合理上限。
    """
    if inst is None or not meta:
        return ""
    if limit > 2:
        limit = 2
    try:
        mod = sys.modules.get(type(inst).__module__)
        ordered = getattr(mod, "_ordered_lines", None) if mod else None
        resolver = getattr(inst, "_resolve_stream", None)
    except Exception:                               # noqa: BLE001
        return ""
    if not callable(ordered) or not callable(resolver):
        return ""

    page_url = str(meta.get("page_url") or "")
    try:
        lines = list(ordered(meta) or [])
    except Exception as e:                          # noqa: BLE001
        log.info("4k 线路枚举失败：%s", e)
        return ""

    tried = 0
    for line in lines:
        try:
            lid = str(line.get("id") or "")
        except Exception:                           # noqa: BLE001
            lid = ""
        if skip_id and lid and lid == skip_id:
            continue
        if tried >= limit:
            break
        gok, left, gwhy = _gate_of(_HANDLER[0])
        if not gok:
            _bump("gated")
            _note("线路枚举中途上游开始拒绝（还剩 %d 秒），停止继续试" % left)
            break
        tried += 1
        try:
            u = resolver(page_url, meta, line)
        except Exception as e:                      # noqa: BLE001
            log.info("4k 线路 %s 解析失败：%s", lid or "?", str(e)[:120])
            continue
        if u and _is_hls(u):
            _STATE["hls_line"] = lid or "?"
            log.info("4k 换到 HLS 线路 %s：%s", lid or "?", str(u)[:100])
            return str(u)
    return ""


# ---------------------------------------------------------------- 找目标

def _find_classes():
    """在 sys.modules 里找官方 4k 插件类。

    不按模块名硬匹配 —— 平台装插件的目录名可能是 `plugins.installed.xxx`
    也可能是别的布局。只认「类名是 FourKParserPlugin」或「类属性
    plugin_id == parser.thirdparty.4k」，并且类自身定义了 parse。
    """
    out = []
    for name, mod in list(sys.modules.items()):
        if mod is None:
            continue
        try:
            items = list(vars(mod).items())
        except Exception:                           # noqa: BLE001
            continue
        for key, val in items:
            if not isinstance(val, type):
                continue
            if key != CLASS_NAME:
                try:
                    if str(getattr(val, "plugin_id", "") or "") != PLUGIN_ID:
                        continue
                except Exception:                   # noqa: BLE001
                    continue
                # 光有 plugin_id 还不够：任何模块里只要有个同名属性类都可能撞上。
                # 再加一道「模块名里带 4k」的约束，避免在无关模块上瞎打补丁。
                if "4k" not in str(name).lower():
                    continue
            if "parse" not in getattr(val, "__dict__", {}):
                continue
            out.append((name, val))
    return out


def _gate_of(handler):
    """问 handler 上游闸门开不开。拿不到就当开着（绝不因自己出错而阻断解析）。"""
    try:
        fn = getattr(handler, "fourk_gate", None)
        if callable(fn):
            r = fn()
            if isinstance(r, tuple) and len(r) == 3:
                return bool(r[0]), int(r[1] or 0), str(r[2] or "")
    except Exception:                               # noqa: BLE001
        pass
    return True, 0, ""


def _gate_ok(handler):
    try:
        fn = getattr(handler, "fourk_gate_ok", None)
        if callable(fn):
            fn()
    except Exception:                               # noqa: BLE001
        pass


def _gate_fail(handler, reason, hard=False):
    try:
        fn = getattr(handler, "fourk_gate_fail", None)
        if callable(fn):
            return int(fn(reason, hard=hard) or 0)
    except Exception:                               # noqa: BLE001
        pass
    return 0


def _gate_perm(handler, reason):
    try:
        fn = getattr(handler, "fourk_gate_perm", None)
        if callable(fn):
            fn(reason)
    except Exception:                               # noqa: BLE001
        pass


_PERM_MARKS = ("登录", "vip", "会员", "令牌", "token", "过期")
_HARD_MARKS = ("403", "429", "502", "503", "504", "http 5", "forbidden",
               "too many", "限流", "封")


def _classify(reason):
    """把官方给的失败原因粗分成三类。

    分错方向的代价不一样：把「令牌过期」当成限流去冷却，用户要白等十分钟；
    把「被封 IP」当成普通失败不冷却，就是继续锤源站。所以权限字样优先判。
    """
    s = str(reason or "").lower()
    if any(k in s for k in _PERM_MARKS):
        return "perm"
    if any(k in s for k in _HARD_MARKS):
        return "hard"
    return "soft"


def _mark_fail(handler, reason):
    """官方失败时给闸门记账。

    soft（比如「这集没有可用线路」）**不冷却** —— 那是内容问题，冷却只会让
    用户换别的集也播不了。只有权限类（记下不关闸）和明确拒绝类（关闸）才动。
    """
    if not reason:
        return
    kind = _classify(reason)
    if kind == "perm":
        _gate_perm(handler, reason)
    elif kind == "hard":
        _gate_fail(handler, reason, hard=True)


def _patch(cls, handler):
    orig = cls.__dict__.get("parse")
    if orig is None or getattr(orig, "_pngu4k", False):
        return False

    def parse(self, parse_request):
        _bump("calls")
        target_url, meta = _meta_of(parse_request)
        if meta:
            _remember(target_url, meta)

        # 第一道关：上游刚拒绝过就别再打了。
        # 官方 parse 自己也要跑一次 wasm 签名 + `/video/play`，跟我们的解析
        # 走同一个出口 IP —— 闸门不覆盖它，封 IP 这件事就拦不住。
        gok, left, gwhy = _gate_of(handler)
        if not gok:
            _bump("gated")
            _note("上游冷却中（还剩 %d 秒），本次不解析：%s" % (left, gwhy))
            raise RuntimeError(
                "4k 源站刚拒绝过请求，%d 秒内不再解析（避免越重试越封）。"
                "原因：%s" % (left, gwhy or "上游限流/封禁"))

        try:
            out = orig(self, parse_request)
        except Exception as e:                      # noqa: BLE001
            _bump("fail")
            why = "%s: %s" % (type(e).__name__, str(e)[:160])
            _note("官方解析抛出 %s" % why)
            _mark_fail(handler, str(e))
            res = _rescue(handler, meta, str(e)[:160])
            if res is not None:
                return res
            raise

        if _failed(out):
            _bump("fail")
            why = _why(out)
            _note("官方解析返回失败：%s" % (why or "无说明"))
            _mark_fail(handler, why)
            res = _rescue(handler, meta, why)
            if res is not None:
                return res
            return out

        _bump("ok")
        _gate_ok(handler)
        return _wrap_official(handler, out, meta, self)

    parse._pngu4k = True
    parse.pngu_orig = orig
    try:
        cls.parse = parse
    except Exception as e:                          # noqa: BLE001
        log.warning("替换 %s.parse 失败：%s", cls.__name__, e)
        return False
    return True


def _why(out):
    try:
        if isinstance(out, dict):
            for k in ("error", "message", "reason"):
                if out.get(k):
                    return str(out[k])[:160]
            diag = out.get("diagnostics")
            if isinstance(diag, dict):
                return str(diag.get("message") or diag)[:160]
            return ""
        return str(getattr(out, "error", "") or "")[:160]
    except Exception:                               # noqa: BLE001
        return ""


# ---------------------------------------------------------------- 两个动作

def _wrap_official(handler, out, meta, inst=None):
    """官方解析成功了：先看它给的是不是 HLS，再探一眼，最后决定动不动它。

    这里有三道关，顺序不能反：

    1. **它选的是直链还是 HLS**。官方 `parse()` 取第一条成功线路就收工，
       而 4k 源的线路里混着云盘直链（`.mp4`，常见于天翼云家庭云）和 HLS。
       选到直链时后面能播的 HLS 线路就永远用不上 —— 现场表现是「网页播放器
       能播 ts 分片，平台却 302 到一个打不开的 mp4」。所以先用官方自己的
       签名实现把同源 HLS 线路找出来换过去（`hls_switch`）。
    2. **首片带不带 PNG 壳**。带壳才需要我们的中转。
    3. **能不能交出一个对外地址**。见下。

    ⚠️ 0.5.8 这里是无条件把地址换成我们自己的清单，结果把平台打成了 502。
    我们交出去的是「探测出来的局域网 IP + 8521」，而平台跑在容器里：容器
    访问宿主机 LAN IP 会被防火墙挡（实测只有 `127.0.0.1:<同端口>` 通）。
    平台拿到一个自己拉不到的地址，解析就直接失败 —— 现场数据正是这个形状：
    `fourk.ok`/`fourk.wrapped` 一直涨，门票侧却全是 502，`pass`/`wrap` 全零。

    所以现在只有**能确定一个平台和播放器都够得着的对外地址**时（配了
    `public_base`，或平台注入了自己的对外地址环境变量）才替换地址；否则
    只做判定、如实报结论，真正的改写交给门票侧 —— 那边 302 和 200 内联
    两种形态都能处理，且播放器用的永远是它自己已经在用的那个域名。
    """
    try:
        _STATE["hls_note"] = ""          # 说明只描述本次调用，别串到下一次
        url = _url_of(out)
        if not url or _is_ours(url):
            return out
        if not handler.fourk_enabled():
            return out

        # ---- 第一道：直链（mp4）先换同源 HLS 线路 ----
        if not _is_hls(url):
            _bump("direct")
            want_hls = True
            try:
                want_hls = bool(handler.fourk_prefer_hls())
            except Exception:                       # noqa: BLE001
                pass
            alt = _try_hls_line(inst, meta, _selected_line_id(out)) if want_hls else ""
            if alt:
                if _set_url(out, alt):
                    _bump("hls_switch")
                    msg = ("官方选中了直链（%s），同源有 HLS 线路（%s），已换过去"
                           % (_brief(url), _STATE.get("hls_line") or "?"))
                    _STATE["hls_note"] = msg
                    _note(msg)
                    url = alt
            else:
                msg = ("官方选中了直链（%s），同源没找到可用的 HLS 线路，"
                       "原样返回（直链能不能播取决于源站有没有防盗链）"
                       % _brief(url))
                _STATE["hls_note"] = msg
                _note(msg)
                return out

        info = handler.fourk_probe(url)
        if not info.get("wrapped"):
            _bump("bare")
            note = str(info.get("why") or "")[:100]
            _note("官方解析成功，首片是裸 TS，原样放行（%s）" % note)
            return out

        _bump("shell")
        if not handler.fourk_can_substitute():
            _note("官方解析成功但首片带壳（%s）；按配置不动它的地址"
                  "（改写交给门票侧，`fourk.wrapped` 不会涨是正常的）"
                  % str(info.get("why") or "")[:70])
            return out

        referer = str(meta.get("page_url") or "")
        new = handler.fourk_wrap(url, referer, meta)
        if not new:
            return out
        if _set_url(out, new):
            _bump("wrapped")
            _note("官方解析成功但首片带壳（%s），已换成我们的清单"
                  % str(info.get("why") or "")[:80])
            log.info("官方 4k 解析结果已接管剥壳：%s → %s", url[:80], new[:80])
        return out
    except Exception as e:                          # noqa: BLE001
        _bump("error")
        _note("包官方解析结果时出错（已原样放行）：%s: %s"
              % (type(e).__name__, str(e)[:120]))
        return out


def _rescue(handler, meta, why):
    """官方失败了：拿同一次调用里的 meta 自己解析一遍。失败返回 None。"""
    try:
        _STATE["hls_note"] = ""
        if not handler.fourk_enabled():
            return None
        if not (meta.get("data_id") and meta.get("secret_key")
                and meta.get("play_key")):
            _STATE["reason"] = "官方失败且没有 meta，无法自己解析"
            return None

        # 官方刚失败往往正说明上游在拒绝。我们再打一次就是第二次请求 ——
        # 救场本来是好事，但「官方失败 → 我们再解析」叠加重试就是双倍锤击。
        gok, left, gwhy = _gate_of(handler)
        if not gok:
            _bump("gated")
            _note("上游冷却中（还剩 %d 秒），不救场：%s" % (left, gwhy))
            return None

        referer = str(meta.get("page_url") or "")
        link = handler.fourk_resolve(meta)       # 抛异常就走下面的 except
        if not link:
            return None

        final = link
        # 只有 HLS 才值得探首片。直链（mp4）没有「分片」这回事，探了也白探，
        # 还多一次上游请求。
        if _is_hls(link):
            info = handler.fourk_probe(link)
            if info.get("wrapped"):
                _bump("shell")
                if handler.fourk_can_substitute():
                    wrapped = handler.fourk_wrap(link, referer, meta)
                    if wrapped:
                        final = wrapped
                        _bump("wrapped")

        res = handler.fourk_result(final, meta)
        _bump("rescued")
        _note("官方解析失败（%s），我们用自己的配置解析成功"
              % (str(why or "无说明")[:80]))
        log.info("4k 兜底解析成功：%s", final[:90])
        return res
    except Exception as e:                          # noqa: BLE001
        _bump("error")
        _STATE["reason"] = "%s: %s" % (type(e).__name__, str(e)[:160])
        _note("我们自己解析也失败：%s" % _STATE["reason"])
        log.info("4k 兜底解析失败：%s", _STATE["reason"])
        return None


# ---------------------------------------------------------------- 安装 / 卸载

def install(handler, force=False):
    """给官方 4k 插件的类打补丁。返回 (ok, message)，永不抛。"""
    _HANDLER[0] = handler
    if _STATE["hooked"]:
        return True, "已接管 %s" % _STATE["target"]

    now = time.time()
    if not force and now - _LAST_TRY[0] < RETRY_SEC:
        return False, "还没找到 4k 插件，%d 秒后再试" % int(
            RETRY_SEC - (now - _LAST_TRY[0]))
    _LAST_TRY[0] = now
    _ATTEMPTS[0] += 1

    try:
        found = _find_classes()
        if not found:
            _STATE["reason"] = "sys.modules 里没有 parser.thirdparty.4k（可能还没加载）"
            return False, _STATE["reason"]

        done = []
        for mod_name, cls in found:
            if _patch(cls, handler):
                done.append("%s.%s" % (mod_name, cls.__name__))

        if not done:
            # 平台热更新只重载 plugin，子模块可能被 reload 过 —— 这时类上挂着的
            # 还是「旧模块定义的」补丁函数（它按模块字典查全局名，所以拨的是新
            # 代码），不能因为 _patch 返回 False 就判失败，否则状态永远显示未接管。
            already = ["%s.%s" % (m, c.__name__) for m, c in found
                       if getattr(c.__dict__.get("parse"), "_pngu4k", False)]
            if already:
                _STATE.update(hooked=True, target=already[0],
                              reason="沿用已有补丁（子模块 reload 过）")
                return True, "已有补丁，继续沿用 %s" % already[0]
            _STATE["reason"] = "找到 4k 插件但没打上补丁（可能已被别处接管）"
            return False, _STATE["reason"]

        _STATE.update(hooked=True, target=done[0], reason="")
        log.info("已接管官方 4k 解析：%s", ", ".join(done))
        return True, "已接管 %s" % ", ".join(done)
    except Exception as e:                          # noqa: BLE001
        _STATE["reason"] = "%s: %s" % (type(e).__name__, e)
        log.warning("接管 4k 插件失败：%s", _STATE["reason"])
        return False, _STATE["reason"]


def uninstall():
    """把原方法装回去。"""
    try:
        for _mod_name, cls in _find_classes():
            cur = cls.__dict__.get("parse")
            orig = getattr(cur, "pngu_orig", None)
            if orig is not None:
                cls.parse = orig
        _STATE["hooked"] = False
        _STATE["target"] = ""
    except Exception as e:                          # noqa: BLE001
        log.warning("摘除 4k 补丁失败：%s", e)


def tick(handler=None):
    """还没接管就借一次调用顺手再找一遍（带冷却，别每个请求都扫 sys.modules）。"""
    if _STATE["hooked"]:
        return
    install(handler or _HANDLER[0], force=False)


def state():
    s = dict(_STATE)
    s["recent_meta"] = list(_META)
    s["attempts"] = _ATTEMPTS[0]
    h = _HANDLER[0]
    try:
        fn = getattr(h, "fourk_gate", None)
        if callable(fn):
            ok, left, why = fn()
            s["gate"] = {"open": bool(ok), "left": int(left or 0),
                         "reason": str(why or "")}
    except Exception:                               # noqa: BLE001
        pass
    return s

__version__ = "0.5.13"
