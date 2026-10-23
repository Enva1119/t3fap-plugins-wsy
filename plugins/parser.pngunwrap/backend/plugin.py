# -*- coding: utf-8 -*-
"""T3FAP 插件入口：PNG 壳分片剥离。

设计目标（也是「删了就干净」的前提）：
  * 只读现有插件，不写 —— wasm 用自己的副本，不引用、不修改 4k 插件文件
  * 不碰数据库、不注册任何 UI（menus/settings_sections/task_templates 全空）
  * 优先级只在内存排序里生效，删插件后解析链自动回落到 4k(25)
  * 内建 HTTP 服务是**进程内线程**，不是守护进程，平台重启即消失
  * 提供 enabled 软开关：关掉就完全让路给 4k，不用卸载

任何一步出问题都只影响本插件，返回明确失败，不抛到平台主流程。
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

log = logging.getLogger("pngunwrap")
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter(
        "%(asctime)s [pngunwrap] %(levelname)s %(message)s"))
    log.addHandler(_h)
    log.setLevel(logging.INFO)

# ---------------------------------------------------------------- SDK 导入

try:
    from core.sdk import (BasePlugin, ConfigField, HealthReport,
                          ParseResult, ParseStream)
    _SDK = True
except Exception as _e:                             # noqa: BLE001
    _SDK = False
    _SDK_ERR = str(_e)

    class BasePlugin(object):                       # 本地跑测试时的占位
        pass

    def ConfigField(**kw):
        return dict(kw)

    def HealthReport(**kw):
        # 桩也要按 Literal 校验，否则本地测试拦不住 "warning" 这类错误 ——
        # 0.2.0 装不上就是这么漏过去的。
        st = kw.get("status")
        if st not in ("ok", "degraded", "error", "unknown"):
            raise ValueError("HealthReport status 非法：%r" % (st,))
        return dict(kw)

    class _Model(object):
        """本地无 SDK 时的占位，行为尽量贴近 pydantic：属性可读、可 dump。"""

        def __init__(self, **kw):
            self._kw = dict(kw)
            for k, v in kw.items():
                setattr(self, k, v)

        def model_dump(self, **_ignored):
            return dict(self._kw)

    ParseResult = ParseStream = _Model

import pngu_fetch
import pngu_proxy


# ---------------------------------------------------------------- 常量

DEFAULTS = {
    "enabled": True,
    "supports_mode": "4k",          # 4k / any（any 仅排查用）
    "source_mode": "auto",          # auto / manual / demo
    "external_m3u8": "",
    "base_url": pngu_fetch.DEFAULT_BASE,
    "play_quality": "1080",
    "cookie": "",
    "access_mode": "proxy",         # proxy / direct
    "bind_host": "127.0.0.1",
    "listen_port": "18521",
    "public_base": "",
    "cache_mb": "64",
    "cache_ttl": "30",
}


def _snap(obj, limit=1500):
    """把平台传进来的结构压成一行日志 —— 排查就靠它。"""
    try:
        s = json.dumps(obj, ensure_ascii=False, default=str, sort_keys=True)
    except Exception:                               # noqa: BLE001
        s = repr(obj)
    return s[:limit]


# HealthReport.status 是 Literal 校验。写错一个词（比如 "warning"）会让平台在
# 安装阶段直接 pydantic validation error，插件装不上 —— 所以这里白名单 + 兜底。
_HEALTH_STATUS = ("ok", "degraded", "error", "unknown")


def _health(status, message, details=None):
    st = status if status in _HEALTH_STATUS else "unknown"
    try:
        return HealthReport(status=st, message=message, details=details or {})
    except Exception as e:                          # noqa: BLE001
        log.warning("HealthReport 构造失败，降级成 dict：%s", e)
        return {"status": st, "message": message, "details": details or {}}


def _as_bool(v, default=True):
    """`int(x or default)` 会把 0 吞成默认值 —— 这里显式处理。"""
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on", "y", "是")


def _as_int(v, default, lo=None, hi=None):
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        n = default
    if lo is not None:
        n = max(lo, n)
    if hi is not None:
        n = min(hi, n)
    return n


# ---------------------------------------------------------------- 插件

class Plugin(BasePlugin):
    plugin_id = "parser.pngunwrap"
    plugin_name = "PNG 壳分片剥离"
    plugin_version = "0.2.2"

    def __init__(self):
        self._cfg = dict(DEFAULTS)
        self._proxy = None
        self._disabled = False
        self._seen_sig = set()
        self._last_log = 0.0

    # ------------------------------------------------------------ 配置

    def set_runtime_config(self, config):
        cfg = dict(DEFAULTS)
        data = self._as_mapping(config)
        if isinstance(data, dict):
            for k, v in data.items():
                # 只接受已知键；允许空字符串（用户主动清空某一项）
                if k in DEFAULTS and v is not None:
                    cfg[k] = v
        self._cfg = cfg
        log.info("配置已更新：source_mode=%s access_mode=%s bind=%s:%s "
                 "enabled=%s supports_mode=%s", cfg["source_mode"],
                 cfg["access_mode"], cfg["bind_host"], cfg["listen_port"],
                 cfg["enabled"], cfg["supports_mode"])

    @staticmethod
    def _as_mapping(obj):
        """平台可能传 dict，也可能传 pydantic 模型 / dataclass。

        以前只认 dict，一旦平台换成模型对象，配置会被**整份静默忽略**
        （全部回落到默认值），排查起来极难。这里统一成 dict。
        """
        if obj is None or isinstance(obj, dict):
            return obj
        for attr in ("model_dump", "dict", "_asdict"):
            fn = getattr(obj, attr, None)
            if callable(fn):
                try:
                    got = fn()
                    if isinstance(got, dict):
                        return got
                except Exception:                   # noqa: BLE001
                    pass
        try:
            return dict(obj)
        except Exception:                           # noqa: BLE001
            return None

    def get_runtime_config_schema(self):
        return [
            ConfigField(key="enabled", label="启用本插件",
                        type="boolean", default=True,
                        description="关掉后立刻完全让路给原来的 4k 解析插件，"
                                    "不需要卸载。",
                        group="总开关"),
            ConfigField(key="supports_mode", label="接管范围", type="select",
                        default="4k",
                        description="4k = 只接管 4k 影视来源（推荐）；"
                                    "any = 任何 m3u8 解析请求都接管，"
                                    "仅用于排查平台是否真的调用了本插件。",
                        group="总开关",
                        options=[
                            {"value": "4k", "label": "只接管 4k 来源"},
                            {"value": "any", "label": "全部接管（排查用）"},
                        ]),
            ConfigField(key="source_mode", label="取流模式", type="select",
                        default="auto",
                        description="auto = 用 4k 播放参数自动签名取流；"
                                    "manual = 直接用下面填的 m3u8；"
                                    "demo = 内置测试清单，只验证链路。",
                        group="取流",
                        options=[
                            {"value": "auto", "label": "自动（4k 签名取流）"},
                            {"value": "manual", "label": "手动 m3u8"},
                            {"value": "demo", "label": "内置测试（验证链路）"},
                        ]),
            ConfigField(key="external_m3u8", label="手动 m3u8 地址", type="text",
                        default="",
                        description="source_mode=manual 时使用，可直接填一条"
                                    "PNG 壳分片的 m3u8 用于调试。",
                        group="取流"),
            ConfigField(key="base_url", label="4k 站点地址", type="text",
                        default=pngu_fetch.DEFAULT_BASE,
                        description="留空用默认；站点换域名时改这里。",
                        group="取流"),
            ConfigField(key="play_quality", label="优先画质", type="select",
                        default="1080",
                        description="取不到时按 1080 → 720 依次回退。",
                        group="取流",
                        options=[{"value": "2160", "label": "2160p"},
                                 {"value": "1080", "label": "1080p"},
                                 {"value": "720", "label": "720p"}]),
            ConfigField(key="cookie", label="4k Cookie", type="text",
                        default="", secret=True,
                        description="可选；登录态能拿到更高画质。",
                        group="取流"),
            ConfigField(key="access_mode", label="交给平台的方式", type="select",
                        default="proxy",
                        description="proxy（默认，推荐）：平台在容器内自己来拉流，"
                                    "对外仍然只有 T3FAP 的统一端口，不需要端口映射，"
                                    "也不影响其它平台播放。direct：让播放器直接访问"
                                    "插件端口，才需要额外映射端口，且删插件后要重建 STRM。",
                        group="服务",
                        options=[
                            {"value": "proxy",
                             "label": "proxy：平台代理转发（走统一端口，推荐）"},
                            {"value": "direct",
                             "label": "direct：播放器直连（需额外端口）"},
                        ]),
            ConfigField(key="bind_host", label="监听地址", type="select",
                        default="127.0.0.1",
                        description="这是插件内建服务的监听地址，不是 T3FAP 的端口。"
                                    "默认 127.0.0.1 只允许容器内部访问，不占对外端口、"
                                    "不需要映射、不影响 8521。只有选了 direct 才需要改成 "
                                    "0.0.0.0（0.0.0.0 也能被 127.0.0.1 访问，只是多暴露"
                                    "了一个接口）。",
                        group="服务",
                        options=[{"value": "127.0.0.1",
                                  "label": "127.0.0.1（仅容器内，推荐）"},
                                 {"value": "0.0.0.0",
                                  "label": "0.0.0.0（direct 方案用）"}]),
            ConfigField(key="listen_port", label="监听端口", type="text",
                        default="18521",
                        description="插件内建服务的端口，只在容器内部使用，"
                                    "和 T3FAP 的 8521 互不影响。被占用时自动往后顺延。",
                        group="服务"),
            ConfigField(key="public_base", label="对外地址", type="text",
                        default="",
                        description="仅在 direct 模式、或经过 DDNS/反代需要指定对外地址时填写，"
                                    "例如 http://192.168.1.10:18521。留空则按请求的实际 Host 生成。",
                        group="服务"),
            ConfigField(key="cache_mb", label="分片缓存上限（MB）", type="text",
                        default="64",
                        description="按字节封顶，不会因为片数多而吃爆内存。",
                        group="缓存"),
            ConfigField(key="cache_ttl", label="分片保留秒数", type="text",
                        default="30",
                        description="播放过的分片超过这个时间就回收。",
                        group="缓存"),
        ]

    # ------------------------------------------------------------ 生命周期

    def install(self, ctx=None):
        log.info("install")
        return True

    def register(self, ctx=None):
        return True

    def enable(self, ctx=None):
        self._disabled = False
        log.info("enable")
        return True

    def disable(self, ctx=None):
        """软停用：立刻停服务、清会话，完全让路给 4k 插件。"""
        self._disabled = True
        self._shutdown()
        log.info("disable：内建服务已停止，解析让路给 4k")
        return True

    def uninstall(self, ctx=None):
        """卸载前清理：停服务、清缓存、清临时状态。"""
        self._disabled = True
        self._shutdown()
        log.info("uninstall：已清理内建服务与缓存")
        return True

    def _shutdown(self):
        proxy, self._proxy = self._proxy, None
        if proxy:
            try:
                proxy.stop()
            except Exception as e:                  # noqa: BLE001
                log.warning("停止内建服务失败：%s", e)

    def health(self, ctx=None):
        # 整体兜底：health 抛异常会让平台判插件不可用甚至装不上，
        # 所以这里任何意外都转成 degraded 文本返回。
        try:
            problems = []
            if not _SDK:
                problems.append("core.sdk 导入失败：%s" % _SDK_ERR)
            if not self._enabled():
                problems.append("插件在配置里被关闭（enabled=false）")

            wasm = os.path.join(HERE, "vendor", pngu_sign_filename())
            if not os.path.isfile(wasm):
                problems.append("缺少 wasm 模块：vendor/%s" % pngu_sign_filename())

            proxy = self._proxy
            details = {
                "enabled": self._enabled(),
                "supports_mode": self._cfg.get("supports_mode"),
                "source_mode": self._cfg.get("source_mode"),
                "access_mode": self._cfg.get("access_mode"),
                "service": proxy_health_of(proxy),
                "wasm": os.path.isfile(wasm),
                "sdk": _SDK,
                "diag": pngu_proxy.DIAG.snapshot(),
            }
            if problems:
                return _health("degraded", "；".join(problems), details)
            return _health("ok", "PNG 壳剥离已就绪。", details)
        except Exception as e:                      # noqa: BLE001
            log.warning("health 异常：%s: %s", type(e).__name__, e)
            return _health("degraded", "自检异常：%s: %s" % (type(e).__name__, e))

    def health_score(self):
        """T3FAP 解析链用它对插件排序/过滤（rules.md §4.6 要求实现）。

        返回 0.0 会被当成不可用直接跳过，所以只要没被关掉就给高分。
        """
        if not self._enabled():
            return 0.0
        if not _SDK:
            return 0.3
        return 0.95

    # ------------------------------------------------------------ 协议

    def supports(self, target):
        """只在「确实该我们管」的时候返回 True。

        判定很保守：来源必须是 4k（provider=4k 或地址属于 4k 家族），
        且能拿到播放参数。其余一律放行，退回给别的解析插件。

        每次调用都会留痕（PNGU-supports 日志 + /__diag），因为「插件到底有没有
        被平台问过」是排查的第一现场。
        """
        if self._disabled or not self._enabled():
            pngu_proxy.DIAG.bump("supports_skipped")
            return False

        pngu_proxy.DIAG.bump("supports_calls")
        self._note_target("supports", target)

        mode = str(self._cfg.get("supports_mode") or "4k").lower()
        try:
            if isinstance(target, dict):
                if mode == "any":
                    ok = bool(target.get("url") or target.get("page_url")
                              or target.get("play_url") or target.get("meta"))
                    pngu_proxy.DIAG.bump("supports_true" if ok
                                         else "supports_false")
                    return ok
                provider = str(target.get("provider") or "").strip().lower()
                if provider and provider != "4k":
                    pngu_proxy.DIAG.bump("supports_false")
                    return False
                meta = target.get("meta") or {}
                if isinstance(meta, dict):
                    if (meta.get("data_id") and meta.get("secret_key")
                            and meta.get("play_key")):
                        pngu_proxy.DIAG.bump("supports_true")
                        return True
                    if meta.get("data_id") and meta.get("play_key"):
                        pngu_proxy.DIAG.bump("supports_true")
                        return True
                url = str(target.get("url") or target.get("page_url") or "")
                ok = self._looks_4k(url)
                pngu_proxy.DIAG.bump("supports_true" if ok else "supports_false")
                return ok
            if isinstance(target, str):
                ok = (mode == "any" and bool(target)) or self._looks_4k(target)
                pngu_proxy.DIAG.bump("supports_true" if ok else "supports_false")
                return ok
        except Exception as e:                      # noqa: BLE001
            log.warning("supports 判定异常：%s", e)
            pngu_proxy.DIAG.add("supports_error", {"error": str(e)[:200]})
        pngu_proxy.DIAG.bump("supports_false")
        return False

    def _note_target(self, kind, target):
        """留痕：先塞进环形缓冲，再按「签名去重 + 2 秒节流」打日志。"""
        sig = _snap(target, 300)
        now = time.time()
        try:
            pngu_proxy.DIAG.add(kind, {"target": _snap(target)})
        except Exception:                           # noqa: BLE001
            pass
        fresh = sig not in self._seen_sig
        if fresh and len(self._seen_sig) < 40:
            self._seen_sig.add(sig)
        if fresh or now - self._last_log > 2.0:
            self._last_log = now
            log.info("PNGU-%s 收到：%s", kind, _snap(target))

    @staticmethod
    def _looks_4k(url):
        u = str(url or "").lower()
        if not u:
            return False
        return any(k in u for k in ("4kvms", "nbmovie", "4kys", "4kvm"))

    def parse(self, parse_request):
        pngu_proxy.DIAG.bump("parse_calls")
        self._note_target("parse", parse_request)
        try:
            return self._parse(parse_request)
        except pngu_fetch.FetchError as e:
            pngu_proxy.DIAG.bump("parse_fail")
            pngu_proxy.DIAG.add("parse_fail", {"error": str(e)[:300]})
            return self._fail(str(e), retryable=True)
        except Exception as e:                      # noqa: BLE001
            pngu_proxy.DIAG.bump("parse_fail")
            pngu_proxy.DIAG.add("parse_fail",
                                {"error": "%s: %s" % (type(e).__name__, e)})
            log.warning("parse 失败：%s: %s", type(e).__name__, e)
            return self._fail("%s: %s" % (type(e).__name__, e), retryable=True)


    # ------------------------------------------------------------ 内部

    def _parse(self, req):
        req = req or {}
        target = req.get("play_target") or req.get("target") or {}
        if not isinstance(target, dict):
            target = {"url": str(target)}
        meta = target.get("meta") or req.get("meta") or {}
        if not isinstance(meta, dict):
            meta = {}

        src, referer, detail = self._resolve_source(meta, target)
        proxy = self._ensure_proxy()
        prefix = self._client_prefix(proxy)

        try:
            url = proxy.register(src, referer=referer,
                                 cookie=self._cfg.get("cookie") or "",
                                 prefix=prefix)
        except Exception as e:                      # noqa: BLE001
            raise pngu_fetch.FetchError(
                "内建服务没能生成可播放清单：%s" % e)

        mode = str(self._cfg.get("access_mode") or "proxy").lower()
        if mode not in ("proxy", "direct"):
            mode = "proxy"

        log.info("解析完成：token 就绪，mode=%s，源=%s，%s",
                 mode, src[:80], detail)
        return self._ok(url, mode, meta)

    def _resolve_source(self, meta, target):
        """按 source_mode 决定这条流从哪来。"""
        mode = str(self._cfg.get("source_mode") or "auto").lower()

        if mode == "demo":
            return ("demo://builtin", "", {"from": "demo"})

        if mode == "manual":
            url = str(self._cfg.get("external_m3u8") or "").strip()
            if not url:
                raise pngu_fetch.FetchError(
                    "source_mode=manual 但没有填「手动 m3u8 地址」")
            return (url, str(meta.get("page_url") or ""), {"from": "manual"})

        # auto：先看平台有没有直接把最终 m3u8 交过来（STRM 二次解析就是这样），
        # 有就直接用，省掉一次签名；没有才走 4k 签名取流。
        url = str(target.get("url") or target.get("play_url") or "")
        has_keys = bool(meta.get("data_id") and meta.get("play_key"))
        if not has_keys and url.lower().split("?")[0].endswith((".m3u8", ".m3u")):
            return (url, str(meta.get("page_url") or ""), {"from": "target"})
        if not meta:
            raise pngu_fetch.FetchError(
                "没拿到 4k 播放参数（meta 为空，target 里也没有 m3u8 地址）。"
                "如果这是手动调试，请把 source_mode 改成 manual 并填 m3u8 地址。")

        link, detail = pngu_fetch.resolve_4k(
            meta,
            base_url=self._cfg.get("base_url") or "",
            quality=self._cfg.get("play_quality") or "1080",
            cookie=self._cfg.get("cookie") or "",
        )
        referer = str(meta.get("page_url") or "")
        return (link, referer, detail)

    def _ensure_proxy(self):
        if self._proxy and self._proxy.running:
            return self._proxy
        host = str(self._cfg.get("bind_host") or "127.0.0.1").strip()
        port = _as_int(self._cfg.get("listen_port"), 18521, 1024, 65535)
        proxy = pngu_proxy.HlsProxy(
            host=host,
            port=port,
            cache_mb=_as_int(self._cfg.get("cache_mb"), 64, 4, 4096),
            cache_ttl=_as_int(self._cfg.get("cache_ttl"), 30, 5, 3600),
            public_base=str(self._cfg.get("public_base") or "").strip(),
        )
        try:
            proxy.start()
        except Exception as e:                      # noqa: BLE001
            raise pngu_fetch.FetchError(
                "内建服务启动失败（%s:%d）：%s" % (host, port, e))
        self._proxy = proxy
        return proxy

    def _client_prefix(self, proxy):
        """返回给平台的「流地址」用的绝对 base。

        优先级：public_base > 绑定地址（非通配）> direct 模式探测本机局域网 IP
        > 127.0.0.1。
        注意这只决定**清单地址本身**；清单里分片的地址由每个请求自己的 Host
        头现场决定（见 pngu_proxy._prefix_of / _render），所以局域网 IP 和
        DDNS 域名可以共用同一份会话。
        """
        public = str(self._cfg.get("public_base") or "").strip().rstrip("/")
        if public:
            return public

        host = str(proxy.host or "").strip()
        if host and host not in ("0.0.0.0", "::"):
            return "http://%s:%d" % (host, proxy.port)

        mode = str(self._cfg.get("access_mode") or "proxy").lower()
        if mode == "direct":
            ip = pngu_proxy.guess_local_ip()
            if ip:
                return "http://%s:%d" % (ip, proxy.port)
        return "http://127.0.0.1:%d" % proxy.port

    def _enabled(self):
        return _as_bool(self._cfg.get("enabled"), True)

    # ------------------------------------------------------------ 返回构造

    def _ok(self, url, access_mode, meta):
        stream = self._stream(url, access_mode, meta)
        pngu_proxy.DIAG.bump("parse_ok")
        pngu_proxy.DIAG.add("parse_ok", {"url": url,
                                         "access_mode": access_mode})
        return self._dump({
            "success": True,
            "provider_plugin_id": self.plugin_id,
            "streams": [stream],
            "confidence": 1.0,
            "retryable": True,
            "selected_source_name": "4k影视（PNG 壳剥离）",
            "diagnostics": {
                "access_mode": access_mode,
                "source_mode": self._cfg.get("source_mode"),
                "service": "http://%s:%d" % (
                    (self._proxy.host if self._proxy else "127.0.0.1"),
                    (self._proxy.port if self._proxy else 0)),
            },
        })

    def _stream(self, url, access_mode, meta):
        kw = {
            "stream_id": "pngunwrap-main",
            "url": url,
            "media_type": "m3u8",
            "access_mode": access_mode,
            "headers": {},
            "extra": {
                "line_id": str((meta or {}).get("line_id") or "line-1"),
                "source_name": "4k影视",
                "pngunwrap": True,
                "plugin_version": self.plugin_version,
            },
        }
        try:
            return ParseStream(**kw)
        except Exception:                           # noqa: BLE001
            # 退化：只给最核心字段
            try:
                return ParseStream(stream_id=kw["stream_id"], url=url,
                                   media_type="m3u8",
                                   access_mode=access_mode)
            except Exception:                       # noqa: BLE001
                return kw

    def _fail(self, message, retryable=True):
        log.warning("解析失败：%s", message)
        return self._dump({
            "success": False,
            "provider_plugin_id": self.plugin_id,
            "streams": [],
            "retryable": bool(retryable),
            "diagnostics": {"message": str(message)[:500],
                            "plugin_version": self.plugin_version},
        })

    @staticmethod
    def _dump(payload):
        """尽量走 ParseResult + model_dump，失败就逐级降级。

        关键：诊断信息不能丢 —— 平台和用户都要能看到「为什么失败」。
        """
        core = {
            "success": payload["success"],
            "provider_plugin_id": payload["provider_plugin_id"],
            "streams": payload.get("streams") or [],
            "confidence": payload.get("confidence", 1.0),
            "retryable": payload.get("retryable", True),
        }
        extra = {}
        for k in ("selected_source_name", "diagnostics", "non_retryable"):
            if k in payload:
                extra[k] = payload[k]

        # 1) 完整字段
        try:
            return ParseResult(**dict(core, **extra)).model_dump(mode="json")
        except Exception:                           # noqa: BLE001
            pass
        # 2) 去掉可选字段
        try:
            return ParseResult(**core).model_dump(mode="json")
        except Exception:                           # noqa: BLE001
            pass
        # 3) 纯 dict 兜底（带上诊断，至少人能看懂）
        return dict(core, **extra)


def pngu_sign_filename():
    try:
        import pngu_sign
        return pngu_sign.WASM_FILENAME
    except Exception:                               # noqa: BLE001
        return "nbmovie_wasm_bg.wasm"


def proxy_health_of(proxy):
    if not proxy:
        return {"running": False}
    try:
        return pngu_proxy.proxy_health(proxy)
    except Exception:                               # noqa: BLE001
        return {"running": proxy.running}


plugin = Plugin()
