"""parser.video_vip — 把 video_vip 油猴脚本的解析能力移植为 T3FAP 解析插件。

契约对齐依据（对照镜像内 official/ 解析插件反汇编还原）：
  - 入口：`supports(target: dict) -> bool` / `parse(parse_request: dict) -> dict` / `health_score() -> float`
  - `parse()` 返回 `ParseResult(...).model_dump(mode="json")`，即 **dict**，不是对象
  - `ParseStream(stream_id, url, media_type, headers, access_mode, quality, extra)`
  - `media_type`: **仅** m3u8 / mp4 / unknown（Literal，传 "page" 会 ValidationError）
  - `access_mode`: proxy（需平台代理拉取，m3u8 走这条）/ redirect（直接跳转，mp4、播放页走这条）
  - `parse_request` 关键字段：play_target（含 url / kind / headers）、auth_context、action
  - `play_target["kind"] == "direct_url"` 时解析插件应直接放弃（已拿到直链，无需再解析）

脚本能力映射：
  readVideoTitle()          →  _resolve_title()      服务端抓 og:title / <title>
  wsyzyCleanTitle()         →  _clean_title()        片名清洗与站点名剥离
  searchList()/suggest      →  _search_suggest()     联想搜索拿 vod id
  rankCandidates()          →  _rank_candidates()    精确 > 前缀 > 包含 > 反向包含
  getEpisodes()/parseEps()  →  _parse_play_url()     vod_play_url 分线路分集
  curEpNum()                →  _episode_from_request()  URL/标题推断集号
  PLAYER + m3u8             →  access_mode="proxy"    返回真实 m3u8 直链
  videoParseList + type     →  access_mode="redirect" 第三方解析页兜底

未移植：UI 接管、displayNodes 清理、广告压制、媒体静音——服务端没有页面可操作。
"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse

from core.sdk import BasePlugin, HealthReport, OperationResult, ParserProvider

try:  # 官方解析插件从 contracts 取契约（3q/4k 均如此），sdk 作为兜底
    from core.contracts.parser import ParseResult, ParseStream
except ImportError:  # pragma: no cover
    from core.sdk import ParseResult, ParseStream  # type: ignore[no-redef]

try:  # 统一 HTTP 出口；不同 core 版本签名可能不同
    from core.services.resource_http import ResourceHttpError, fetch_json, fetch_text
except ImportError:  # pragma: no cover
    from core.services.resource_http import ResourceHttpError, fetch_json  # type: ignore[no-redef]

    fetch_text = None  # type: ignore[assignment]


DEFAULT_SITE = "https://wsyzy.cc"
DEFAULT_API = "https://api.wsyzy.net/api.php/provide/vod/"
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# 脚本 videoParseList 里除「无损云解析」外的 6 条 jx 线路
DEFAULT_PARSE_SITES: list[dict[str, str]] = [
    {"name": "LX解析", "url": "https://jx.lxyy.club/index.php?url=", "type": "1,3"},
    {"name": "七哥解析", "url": "https://jx.202617.xyz/tv.php?url=", "type": "1,3"},
    {"name": "TXNQ解析", "url": "https://bfq.txnp.cn/player?url=", "type": "1,3"},
    {"name": "789解析", "url": "https://jiexi.789jiexi.com/?url=", "type": "1,3"},
    {"name": "冰豆解析", "url": "https://bd.jx.cn/?url=", "type": "1,3"},
    {"name": "麒麟解析", "url": "https://free.maccms.xyz/?url=", "type": "1,3"},
]

# 支持解析的站点：域名后缀 → 展示名（对应脚本 @include 与 playerContainers.host）
SUPPORTED_SITES: dict[str, str] = {
    "qq.com": "腾讯视频",
    "iqiyi.com": "爱奇艺",
    "iq.com": "爱奇艺国际",
    "youku.com": "优酷",
    "mgtv.com": "芒果TV",
    "tudou.com": "土豆网",
    "sohu.com": "搜狐视频",
    "bilibili.com": "哔哩哔哩",
    "pptv.com": "PPTV",
    "wasu.cn": "华数TV",
    "le.com": "乐视视频",
    "acfun.cn": "AcFun",
    "1905.com": "1905电影网",
    "miguvideo.com": "咪咕视频",
    "ixigua.com": "西瓜视频",
    "fun.tv": "风行网",
}

SITE_NAMES = (
    "爱奇艺|腾讯视频|腾讯|优酷|芒果TV|芒果|哔哩哔哩|bilibili|B站|搜狐视频|搜狐|"
    "乐视视频|乐视|PPTV聚力|PPTV|1905电影网|1905|土豆网|土豆|风行网|风行|"
    "西瓜视频|咪咕视频|咪咕|AcFun"
)
_SITE_NAME_RE = re.compile(r"(?:^|[\s\-_：:|｜，,。·]+)(?:" + SITE_NAMES + r")(?=$|[\s\-_：:|｜，,。·]+)", re.I)
_SITE_LEAD_RE = re.compile(r"^(?:" + SITE_NAMES + r")+", re.I)
_SITE_TAIL_RE = re.compile(r"(?:[\s\-_：:|｜]+|^)(?:" + SITE_NAMES + r")$", re.I)
_SITE_WORD_RE = re.compile(r"^(?:" + SITE_NAMES + r")$", re.I)
_NOISE_RE = re.compile(r"在线观看|高清正版|免费观看|完整版|正片|预告|全集")
_TITLE_SPLIT_RE = re.compile(r"[-_\s（(|｜]")
_EP_IN_NAME_RE = re.compile(r"第.+[集季部]")

_OG_TITLE_RES = [
    re.compile(r'<meta[^>]+property=["\']og:title["\'][^>]*content=["\']([^"\']+)', re.I),
    re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*property=["\']og:title["\']', re.I),
    re.compile(r'<meta[^>]+name=["\']title["\'][^>]*content=["\']([^"\']+)', re.I),
]
_DOC_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

# 脚本 curEpNum() 的 URL 规则，按优先级排列
_EP_URL_RES = [
    re.compile(r"[?&](?:ep|episode|p|e|cur)=(\d{1,5})(?!\d)", re.I),
    re.compile(r"/p(\d{1,5})\.html", re.I),
    re.compile(r"/ep(\d{1,5})(?!\d)", re.I),
    re.compile(r"第?\s*(\d{1,8})\s*[集期话]"),
]


class VideoVipParserPlugin(BasePlugin, ParserProvider):
    plugin_id = "parser.video_vip"
    plugin_name = "全网VIP视频解析（video_vip）"
    plugin_version = "0.2.1"

    def __init__(self) -> None:
        # 导入期不发请求、不建连接
        self._runtime_config: dict[str, Any] = {}

    # ------------------------------------------------------------------ 生命周期

    def set_runtime_config(self, config: dict[str, Any]) -> None:
        self._runtime_config = dict(config or {})

    def validate_config(self, config: dict[str, Any]) -> OperationResult:
        merged = dict(config or {})
        errors: list[str] = []
        direct = self._as_bool(merged.get("enable_direct"), True)
        fallback = self._as_bool(merged.get("enable_page_fallback"), True)
        if direct and not str(merged.get("wsyzy_api") or DEFAULT_API).strip():
            errors.append("启用直连时 wsyzy_api 不能为空")
        if not direct and not fallback:
            errors.append("直连与解析页回退同时关闭，插件将无法产出任何播放地址")
        if errors:
            return OperationResult(success=False, message="解析插件配置校验失败。", errors=errors)
        return OperationResult(success=True, message="解析插件配置校验通过。", data=merged)

    validate_runtime_config = validate_config

    def health(self, ctx: dict[str, Any]) -> HealthReport:
        direct = self._as_bool(self._cfg("enable_direct"), True)
        fallback = self._as_bool(self._cfg("enable_page_fallback"), True)
        sites = self._parse_sites(self._cfg("parse_sites"))
        return HealthReport(
            status="ok" if (direct or fallback) else "degraded",
            message=(
                f"解析插件就绪：直连={'开' if direct else '关'}，"
                f"解析页线路={len(sites)} 条。"
            ),
            details={
                "supports_sites": len(SUPPORTED_SITES),
                "direct_enabled": direct,
                "page_fallback_enabled": fallback,
                "page_sites": len(sites),
                "score": self.health_score(),
            },
        )

    def health_score(self) -> float:
        """官方 health_score 返回 float；轻量评分，不发网络请求。"""
        direct = self._as_bool(self._cfg("enable_direct"), True)
        fallback = self._as_bool(self._cfg("enable_page_fallback"), True)
        if direct and fallback:
            return 0.9
        if direct:
            return 0.85
        if fallback:
            return 0.65
        return 0.2

    # ------------------------------------------------------------------ 协议入口

    def supports(self, target: Any) -> bool:
        if not isinstance(target, dict):
            return False
        # 已拿到直链的目标不需要解析插件（与 3q 同一判断）
        if str(target.get("kind") or "").strip().lower() == "direct_url":
            return False
        url = str(target.get("url") or "").strip()
        if not url.lower().startswith(("http://", "https://")):
            return False
        return bool(self._site_of(url)[0])

    def parse(self, parse_request: Any) -> dict[str, Any]:
        request = parse_request if isinstance(parse_request, dict) else {}
        play_target = request.get("play_target") or request.get("target") or {}
        if not isinstance(play_target, dict):
            play_target = {}
        resource = request.get("resource") if isinstance(request.get("resource"), dict) else {}
        action = str(request.get("action") or "").strip().lower()

        official_url = str(play_target.get("url") or play_target.get("official_url") or "").strip()
        if not official_url:
            return self._fail("缺少待解析的播放地址（play_target.url）。", retryable=False, non_retryable=True)

        site_key, site_label = self._site_of(official_url)
        if not site_key:
            return self._fail(
                f"暂不支持该站点：{self._host_of(official_url)}",
                retryable=False,
                non_retryable=True,
            )

        title = self._pick_title(request, play_target, resource)
        episode_hint = self._pick_episode(request, play_target, resource)
        diagnostics: dict[str, Any] = {
            "site": site_label,
            "action": action,
            "official_url": official_url,
            "episode_hint": episode_hint,
            "direct_enabled": self._as_bool(self._cfg("enable_direct"), True),
            "page_fallback_enabled": self._as_bool(self._cfg("enable_page_fallback"), True),
        }

        if diagnostics["direct_enabled"]:
            try:
                result = self._parse_direct(official_url, title=title, episode_hint=episode_hint)
                if result is not None:
                    streams, meta = result
                    diagnostics.update(meta)
                    return ParseResult(
                        success=True,
                        provider_plugin_id=self.plugin_id,
                        retryable=False,
                        non_retryable=False,
                        confidence=0.9,
                        message=f"video_vip 解析成功：{meta.get('vod_name') or title}",
                        streams=streams,
                        diagnostics=diagnostics,
                    ).model_dump(mode="json")
                diagnostics["direct_error"] = "直连未命中片源"
            except ResourceHttpError as exc:
                diagnostics["direct_error"] = f"上游请求失败：{exc}"
            except Exception as exc:  # noqa: BLE001 - 解析链路必须收敛
                diagnostics["direct_error"] = f"{type(exc).__name__}: {exc}"

        if diagnostics["page_fallback_enabled"]:
            page_streams = self._build_page_streams(official_url)
            if page_streams:
                diagnostics["fallback"] = "page"
                return ParseResult(
                    success=True,
                    provider_plugin_id=self.plugin_id,
                    retryable=False,
                    non_retryable=False,
                    confidence=0.45,
                    message=f"{site_label} 直连未命中，已回退第三方解析页",
                    streams=page_streams,
                    diagnostics=diagnostics,
                ).model_dump(mode="json")

        return self._fail(
            diagnostics.get("direct_error") or "未取到可用播放地址。",
            retryable=True,
            diagnostics=diagnostics,
        )

    # ------------------------------------------------------------------ 直连链路

    def _parse_direct(
        self, url: str, *, title: str, episode_hint: int
    ) -> tuple[list[ParseStream], dict[str, Any]] | None:
        resolved_title = self._clean_title(title) or self._resolve_title(url)
        if not resolved_title:
            return None

        site_root = str(self._cfg("wsyzy_site") or DEFAULT_SITE).rstrip("/")
        candidates = self._search_suggest(site_root, resolved_title)
        if not candidates:
            cleaned = self._clean_title(resolved_title)
            if cleaned and cleaned != resolved_title:
                candidates = self._search_suggest(site_root, cleaned)
        if not candidates:
            return None

        api = str(self._cfg("wsyzy_api") or DEFAULT_API)
        max_candidates = self._as_int(self._cfg("max_candidates"), 3, minimum=1, maximum=10)
        preferred_line = self._as_int(self._cfg("preferred_line"), 0, minimum=0, maximum=9)
        wanted_episode = episode_hint or self._episode_from_request(url, resolved_title)

        for candidate in self._rank_candidates(candidates, resolved_title)[:max_candidates]:
            vod_id = str(candidate.get("id") or "").strip()
            if not vod_id:
                continue
            detail = self._fetch_detail(api, vod_id)
            if not detail:
                continue
            episodes = self._parse_play_url(detail.get("vod_play_url"), preferred_line)
            if not episodes:
                continue

            by_line: dict[int, list[dict[str, Any]]] = {}
            for entry in episodes:
                by_line.setdefault(entry["line"], []).append(entry)

            vod_name = str(detail.get("vod_name") or candidate.get("name") or resolved_title)
            headers = self._media_headers()
            streams: list[ParseStream] = []
            for line_no in sorted(by_line):
                line_episodes = by_line[line_no]
                line_index = self._match_episode(line_episodes, wanted_episode)
                entry = line_episodes[line_index]
                media_type = "m3u8" if self._looks_like_m3u8(entry["url"]) else "mp4"
                streams.append(
                    ParseStream(
                        stream_id="default" if not streams else f"line{line_no + 1}",
                        url=entry["url"],
                        media_type=media_type,
                        headers=dict(headers),
                        # m3u8 需平台代理并重写分片地址；mp4 直接 302
                        access_mode="proxy" if media_type == "m3u8" else "redirect",
                        quality="",
                        extra={
                            "provider": self.plugin_id,
                            "vod_id": vod_id,
                            "vod_name": vod_name,
                            "episode": entry["name"],
                            "episode_index": line_index + 1,
                            "total_episodes": len(line_episodes),
                            "line": line_no,
                            "official_url": url,
                        },
                    )
                )
            if not streams:
                continue

            meta = {
                "vod_id": vod_id,
                "vod_name": vod_name,
                "matched_name": candidate.get("name"),
                "episode_index": streams[0].extra.get("episode_index"),
                "total_episodes": streams[0].extra.get("total_episodes"),
                "lines": len(streams),
                "api_fields": sorted(detail.keys())[:20],
            }
            return streams, meta
        return None

    def _resolve_title(self, url: str) -> str:
        """服务端版 readVideoTitle：抓 og:title / <title> 后清洗。"""
        try:
            html = self._fetch_text(url)
        except Exception:  # noqa: BLE001 - 抓不到就交给上游联想
            return ""
        if not html:
            return ""
        for pattern in _OG_TITLE_RES:
            matched = pattern.search(html)
            if matched:
                cleaned = self._clean_title(matched.group(1))
                if cleaned:
                    return cleaned
        doc = _DOC_TITLE_RE.search(html)
        if doc:
            return self._clean_title(doc.group(1))
        return ""

    def _search_suggest(self, site_root: str, keyword: str) -> list[dict[str, Any]]:
        """脚本 searchList()：官网联想偶发抖动，空结果重试一次。"""
        keyword = str(keyword or "").strip()
        if not keyword:
            return []
        endpoint = f"{site_root}/index.php/ajax/suggest"
        for _attempt in range(2):
            payload = self._get_json(endpoint, {"mid": "1", "wd": keyword})
            raw_list = (payload or {}).get("list") if isinstance(payload, dict) else None
            items = [
                entry
                for entry in (raw_list or [])
                if isinstance(entry, dict) and entry.get("id") and entry.get("name")
            ]
            if items:
                return items
        return []

    def _fetch_detail(self, api: str, vod_id: str) -> dict[str, Any]:
        payload = self._get_json(api, {"ac": "detail", "ids": vod_id})
        if not isinstance(payload, dict):
            return {}
        entries = payload.get("list") or []
        if not isinstance(entries, list) or not entries:
            return {}
        first = entries[0]
        return first if isinstance(first, dict) else {}

    # ------------------------------------------------------------------ 兜底链路

    def _build_page_streams(self, url: str) -> list[ParseStream]:
        sites = self._parse_sites(self._cfg("parse_sites"))
        streams: list[ParseStream] = []
        for index, site in enumerate(sites):
            streams.append(
                ParseStream(
                    stream_id="default" if index == 0 else f"page{index + 1}",
                    url=f"{site['url']}{url}",
                    # 契约只接受 m3u8/mp4/unknown；解析页不是媒体流，只能是 unknown
                    media_type="unknown",
                    headers={"User-Agent": str(self._cfg("user_agent") or DEFAULT_UA)},
                    # 播放页只能跳转，平台无法代理其内部播放器
                    access_mode="redirect",
                    quality="",
                    extra={
                        "provider": self.plugin_id,
                        "line_name": site["name"],
                        "target_types": site["type"],
                        "fallback": "page",
                        "official_url": url,
                    },
                )
            )
        return streams

    # ------------------------------------------------------------------ 纯函数移植

    def _clean_title(self, text: Any) -> str:
        """移植 wsyzyCleanTitle()。"""
        value = str(text or "")
        value = re.sub(r"[《》【】「」]", "", value)
        value = _SITE_NAME_RE.sub(" ", value)
        value = _SITE_LEAD_RE.sub("", value)
        value = _SITE_TAIL_RE.sub("", value)
        value = _NOISE_RE.sub("", value)
        parts = [
            _EP_IN_NAME_RE.sub("", segment).strip()
            for segment in _TITLE_SPLIT_RE.split(value)
        ]
        parts = [segment for segment in parts if segment]
        for segment in parts:
            if (
                len(segment) >= 2
                and not _SITE_WORD_RE.match(segment)
                and not re.search(r"第\d{1,8}[集期话季]", segment)
            ):
                return segment
        return parts[0] if parts else ""

    @staticmethod
    def _rank_candidates(candidates: list[dict[str, Any]], title: str) -> list[dict[str, Any]]:
        """移植 rankCandidates()：精确 4 / 前缀 3 / 包含 2 / 反向包含 1 / 其他 0。"""

        def score(entry: dict[str, Any]) -> int:
            name = str(entry.get("name") or "")
            if not name:
                return 0
            if name == title:
                return 4
            if name.startswith(title):
                return 3
            if title and title in name:
                return 2
            # 单字片名不做反向包含，避免播错片（脚本原注释）
            if len(title) >= 2 and name in title:
                return 1
            return 0

        ranked = sorted(candidates, key=score, reverse=True)
        matched = [entry for entry in ranked if score(entry) > 0]
        return matched or ranked

    @staticmethod
    def _parse_play_url(value: Any, preferred_line: int = 0) -> list[dict[str, Any]]:
        """移植 parseEps()：vod_play_url 形如 `第1集$url#第2集$url$$$线路二`。"""
        text = str(value or "").strip()
        if not text:
            return []
        lines = text.split("$$$")
        episodes: list[dict[str, Any]] = []
        order = list(range(len(lines)))
        if 0 <= preferred_line < len(lines):
            order.remove(preferred_line)
            order.insert(0, preferred_line)
        for line_index in order:
            for raw in lines[line_index].split("#"):
                segment = raw.strip()
                if not segment:
                    continue
                separator = segment.find("$")
                if separator > 0:
                    name = segment[:separator].strip()
                    link = segment[separator + 1:].strip()
                else:
                    name, link = "", segment
                if not re.match(r"^https?://", link, re.I):
                    continue
                episodes.append({"name": name, "url": link, "line": line_index})
        return episodes

    @staticmethod
    def _match_episode(episodes: list[dict[str, Any]], wanted: int) -> int:
        """按集号匹配；匹配不到退回第一集。"""
        if wanted <= 0:
            return 0
        for index, entry in enumerate(episodes):
            matched = re.search(r"\d{1,8}", str(entry.get("name") or ""))
            if matched and int(matched.group(0)) == wanted:
                return index
        return 0

    @staticmethod
    def _episode_from_request(url: str, title: str) -> int:
        """移植 curEpNum()：服务端没有 document.title，用传入标题 + URL 代替。"""
        target = f"{url} {title}"
        for pattern in _EP_URL_RES:
            matched = pattern.search(target)
            if matched:
                return int(matched.group(1))
        return 0

    # ------------------------------------------------------------------ 入参解析

    def _pick_title(self, request: dict[str, Any], play_target: dict[str, Any], resource: dict[str, Any]) -> str:
        # 真实解析链由 ParserService 传 {play_target, target}，片名在 play_target.meta 里
        # （官方 3q 插件同样从 meta 取 title），所以要一并展开 meta。
        sources: list[dict[str, Any]] = []
        for source in (play_target, request, resource):
            if not isinstance(source, dict):
                continue
            sources.append(source)
            meta = source.get("meta")
            if isinstance(meta, dict):
                sources.append(meta)
        for source in sources:
            for key in ("title", "name", "vod_name", "keyword", "media_title", "display_name"):
                value = source.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return ""

    def _pick_episode(self, request: dict[str, Any], play_target: dict[str, Any], resource: dict[str, Any]) -> int:
        sources: list[dict[str, Any]] = []
        for source in (play_target, request, resource):
            if not isinstance(source, dict):
                continue
            sources.append(source)
            meta = source.get("meta")
            if isinstance(meta, dict):
                sources.append(meta)
        for source in sources:
            for key in ("episode", "episode_index", "episode_number", "ep", "index"):
                value = source.get(key)
                if isinstance(value, bool):
                    continue
                if isinstance(value, int) and value > 0:
                    return value
                if isinstance(value, str) and value.strip().isdigit():
                    return int(value.strip())
        return 0

    # ------------------------------------------------------------------ 工具函数

    def _fail(
        self, message: str, *, retryable: bool = True, non_retryable: bool = False,
        diagnostics: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return ParseResult(
            success=False,
            provider_plugin_id=self.plugin_id,
            retryable=retryable,
            non_retryable=non_retryable,
            message=message,
            streams=[],
            diagnostics=dict(diagnostics or {}),
        ).model_dump(mode="json")

    def _cfg(self, key: str) -> Any:
        return self._runtime_config.get(key)

    def _get_json(self, url: str, params: dict[str, Any]) -> Any:
        timeout = self._as_int(self._cfg("timeout_seconds"), 8, minimum=3, maximum=60)
        headers = {"User-Agent": str(self._cfg("user_agent") or DEFAULT_UA)}
        try:
            return fetch_json(url, params=params, headers=headers, timeout=timeout)
        except TypeError:  # 老版本 core 的 fetch_json 不接受 timeout/headers
            return fetch_json(url, params=params)

    def _fetch_text(self, url: str) -> str:
        timeout = self._as_int(self._cfg("timeout_seconds"), 8, minimum=3, maximum=60)
        headers = {"User-Agent": str(self._cfg("user_agent") or DEFAULT_UA)}
        if fetch_text is None:  # 老版本 core 没有 fetch_text，降级 urllib
            from urllib.request import Request, urlopen

            request = Request(url, headers=headers)
            with urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8", errors="replace")
        try:
            return fetch_text(url, headers=headers, timeout=timeout)
        except TypeError:
            return fetch_text(url, headers=headers)

    def _media_headers(self) -> dict[str, str]:
        return {
            "User-Agent": str(self._cfg("user_agent") or DEFAULT_UA),
            "Referer": "https://wsyzy.vip/",
        }

    def _parse_sites(self, raw: Any) -> list[dict[str, str]]:
        """解析线路配置：留空用内置；支持 JSON 数组或每行「名称|前缀|类型」。"""
        text = str(raw or "").strip()
        if not text:
            return list(DEFAULT_PARSE_SITES)
        if text.startswith("["):
            try:
                entries = json.loads(text)
            except json.JSONDecodeError:
                return list(DEFAULT_PARSE_SITES)
            sites: list[dict[str, str]] = []
            for entry in entries if isinstance(entries, list) else []:
                if isinstance(entry, dict) and str(entry.get("url") or "").strip():
                    sites.append(
                        {
                            "name": str(entry.get("name") or "解析线路").strip(),
                            "url": str(entry.get("url")).strip(),
                            "type": str(entry.get("type") or "1,3"),
                        }
                    )
            return sites or list(DEFAULT_PARSE_SITES)

        sites = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [part.strip() for part in line.split("|")]
            if len(parts) < 2 or not parts[1]:
                continue
            sites.append(
                {
                    "name": parts[0] or "解析线路",
                    "url": parts[1],
                    "type": parts[2] if len(parts) > 2 and parts[2] else "1,3",
                }
            )
        return sites or list(DEFAULT_PARSE_SITES)

    @staticmethod
    def _host_of(url: str) -> str:
        try:
            return (urlparse(url).netloc or "").lower().split(":")[0]
        except ValueError:
            return ""

    def _site_of(self, url: str) -> tuple[str, str]:
        host = self._host_of(url)
        if not host:
            return "", ""
        for suffix, label in SUPPORTED_SITES.items():
            if host == suffix or host.endswith("." + suffix):
                return suffix, label
        return "", ""

    @staticmethod
    def _looks_like_m3u8(url: str) -> bool:
        return ".m3u8" in str(url).lower()

    @staticmethod
    def _as_bool(value: Any, default: bool) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            text = value.strip().lower()
            if text in ("1", "true", "yes", "on"):
                return True
            if text in ("0", "false", "no", "off"):
                return False
        if isinstance(value, (int, float)):
            return bool(value)
        return default

    @staticmethod
    def _as_int(value: Any, default: int, *, minimum: int, maximum: int) -> int:
        try:
            number = int(str(value).strip())
        except (TypeError, ValueError):
            return default
        return max(minimum, min(maximum, number))


plugin = VideoVipParserPlugin()
