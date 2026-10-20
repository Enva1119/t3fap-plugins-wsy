# 全网VIP视频解析（parser.video_vip）

把 [video_vip](https://blog.88lin.eu.org/article/46) 油猴脚本的解析能力移植为 T3FAP 解析插件，让 T3FAP 能直接调用解析能力获取可播放地址。

协议实现对照镜像内 `official/parser.thirdparty.*` 反汇编还原的真实契约（详见工作区《T3FAP镜像解析插件运行方式分析.md》）。

## 与油猴脚本的映射关系

脚本跑在浏览器里，靠 DOM 读标题、靠 iframe 播放；插件跑在服务端，所以**只保留"拿到可播放地址"这条主链路**，UI 接管、广告屏蔽、媒体静音、播放器布局全部丢弃。

| 脚本函数 | 插件方法 | 说明 |
|---|---|---|
| `readVideoTitle()` | `_resolve_title()` | 服务端抓 `og:title` / `<title>` 后清洗 |
| `wsyzyCleanTitle()` | `_clean_title()` | 剥离平台名、去"在线观看/高清正版"等噪音 |
| `searchList()` | `_search_suggest()` | `index.php/ajax/suggest` 联想搜索拿 vod id |
| `rankCandidates()` | `_rank_candidates()` | 精确 > 前缀 > 包含 > 反向包含 |
| `getEpisodes()` + `parseEps()` | `_parse_play_url()` | `vod_play_url` 按 `$$$` 分线路、`#` 分集 |
| `curEpNum()` | `_episode_from_request()` | 4 条 URL 正则推断集号 |
| `PLAYER + m3u8` | `media_type="m3u8"` + `access_mode="proxy"` | 返回真实 m3u8，交给平台代拉 |
| `videoParseList` + `type` | `media_type="unknown"` + `access_mode="redirect"` | 第三方解析页兜底（契约不允许 `page`）|

## 两条解析链路

### 1. 直连（默认）

```
play_target.url + 标题
      ↓  优先用 play_target/request/resource 里的 title；没有才抓 og:title
   片名清洗
      ↓  GET https://wsyzy.cc/index.php/ajax/suggest?mid=1&wd=<片名>
   候选 vod id 列表 → 排序取前 N 个
      ↓  GET https://api.wsyzy.net/api.php/provide/vod/?ac=detail&ids=<id>
   vod_play_url → 解析出每集 m3u8
      ↓  按集号匹配（URL/标题有集号则精确命中，否则第一集）
   ParseStream(media_type="m3u8", access_mode="proxy", headers=..., extra=...)
```

`vod_play_url` 实际格式（真实数据）：

```
第01集$https://v4.wsyzym3u8.com/202308/27/fKUemb3exp1/video/index.m3u8#第02集$https://...#...
$$$第01集$https://另一条线路/...
```

`$$$` 前后是不同线路。每条线路各产出一个 `ParseStream`，`stream_id` 依次为 `default`、`line2`、`line3`……`preferred_line` 只影响线路顺序。

### 2. 解析页兜底

直连拿不到片源时，返回 6 条第三方解析页：

```python
ParseStream(stream_id="default", url="https://jx.lxyy.club/index.php?url=<原始播放页>",
            media_type="unknown", access_mode="redirect", extra={"line_name": "LX解析"})
```

> 两条链路性质完全不同：直连给的是**可直接进 STRM / 下载 / 播放器的 m3u8**（`access_mode="proxy"`）；兜底给的是**第三方网页**（`media_type="unknown"` + `redirect`），只能跳转，取不到流。

## 协议实现

```python
class VideoVipParserPlugin(BasePlugin, ParserProvider):
    plugin_id = "parser.video_vip"
    plugin_version = "0.2.0"

    def set_runtime_config(self, config: dict) -> None
    def validate_config(self, config: dict) -> OperationResult   # validate_runtime_config 为别名
    def health(self, ctx: dict) -> HealthReport
    def supports(self, target: dict) -> bool
    def parse(self, parse_request: dict) -> dict
    def health_score(self) -> float                              # 0~1
```

### `supports(target)`

```python
if target.get("kind") == "direct_url":   return False   # 已是直链，无需解析
if not url.startswith(("http://","https://")): return False
return url 的域名属于支持的 16 个站点
```

只对自己能处理的站点返回 `True`，避免在解析链里抢跑。

### `parse(parse_request)` → dict

入参按官方结构取值，并对不规范的调用做兼容：

```python
play_target = parse_request.get("play_target") or parse_request.get("target") or {}
url     = play_target.get("url") or play_target.get("official_url")
title   = play_target.title / request.title / resource.title / 抓页面
episode = play_target.episode / request.episode / resource.episode_index / URL 推断
action  = parse_request.get("action")        # play / strm，本插件不改行为
```

返回 `ParseResult(...).model_dump(mode="json")`：

```python
{
  "success": True,
  "provider_plugin_id": "parser.video_vip",
  "retryable": False,
  "non_retryable": False,
  "confidence": 0.9,
  "message": "video_vip 解析成功：漫长的季节",
  "streams": [{
      "stream_id": "default",
      "url": "https://v8.wsyzym3u8.com/202311/04/jCpHMnQknX1/video/index.m3u8",
      "media_type": "m3u8",              # 仅 m3u8 / mp4 / unknown（Literal）
      "headers": {"User-Agent": "...", "Referer": "https://wsyzy.vip/"},
      "access_mode": "proxy",            # proxy = 平台代拉并重写；redirect = 直接跳转
      "quality": "",
      "extra": {
          "provider": "parser.video_vip", "vod_id": "48127", "vod_name": "漫长的季节",
          "episode": "第07集", "episode_index": 7, "total_episodes": 12,
          "line": 0, "official_url": "..."
      }
  }],
  "diagnostics": {"site": "腾讯视频", "vod_id": "48127", "lines": 1, ...}
}
```

失败分两种语义，与官方一致：

| 场景 | retryable | non_retryable | message |
|---|---|---|---|
| 缺 `play_target.url` | False | True | 缺少待解析的播放地址（play_target.url）。 |
| 站点不支持 | False | True | 暂不支持该站点：xxx |
| 直连没搜到 + 兜底也关闭 | True | False | 直连未命中片源 |

`diagnostics.direct_error` 会记录上游异常原因，便于排查。

## 配置项

| key | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `enabled` | boolean | `true` | 插件总开关 |
| `enable_direct` | boolean | `true` | 关闭后只走解析页 |
| `enable_page_fallback` | boolean | `true` | 直连失败是否回退解析页 |
| `wsyzy_site` | text | `https://wsyzy.cc` | 联想搜索站点（脚本 `SITE`） |
| `wsyzy_api` | text | `https://api.wsyzy.net/api.php/provide/vod/` | 苹果CMS V10 采集接口（脚本 `API`） |
| `preferred_line` | integer | `0` | 优先线路序号 |
| `max_candidates` | integer | `3` | 候选片源尝试上限 |
| `parse_sites` | json | `[]` | 空=内置 6 条；元素 `{"name","url","type"}` |
| `timeout_seconds` | integer | `8` | 单次上游超时（对应脚本 8000ms） |
| `user_agent` | text | Chrome UA | 抓标题与调接口用的 UA |

清单里 `resource.priority = 60`——排在官方 `bubu(25)` 之后、`3q(100)` 之前。

## 安装（飞牛 / Docker）

插件只能落在镜像的 `/app/plugins/official` 或 `/app/plugins/market`（路径写死在 `core.settings`，没有环境变量可改）。

```
parser.video_vip/
├── plugin.json
└── backend/plugin.py
```

**推荐**：挂载插件目录，避免容器重建后丢失。

```yaml
services:
  t3fap:
    volumes:
      - /vol2/1000/docker/t3fap/plugins:/app/plugins/market
```

宿主机 `/vol2/1000/docker/t3fap/plugins/parser.video_vip/` 放上面两个文件即可。

**或**自建镜像固化：`COPY parser.video_vip /app/plugins/market/parser.video_vip`。

启动后还要做两件事：

1. 在插件页把本插件**启用**（新发现的插件 `enabled=False`，不启用不会被激活）；
2. 若未绑定 QQ 会员，`parser.default_vip`（priority=5）会返回 `non_retryable` 并**中止整条解析链**——先在插件页把它禁用，或把本插件 `resource.priority` 调到 4 排到它前面。

## 本地验证

```bash
# 离线冒烟（mock 上游 + mock 页面，校验协议字段与枚举）
python3 devkit/smoke_test.py repo/plugins/parser.video_vip

# 真机联调（真实上游，验证能否拿到 m3u8）
python3 devkit/live_check.py "漫长的季节" 7
python3 devkit/live_check.py "" 0 "https://v.qq.com/x/cover/xxx.html"   # 走页面抓标题

# 镜像内验收（用镜像自带的 core 跑真实加载器 + 真实解析链，不需要 Docker）
python3 devkit/pull_image.py --out /tmp/t3fap/rootfs
cp -R repo/plugins/parser.video_vip /tmp/t3fap/rootfs/app/plugins/market/
python3 devkit/fnos_verify.py /tmp/t3fap/rootfs/app parser.video_vip --title "漫长的季节" --episode 7
```

实测（2026-10-20）：

| 用例 | 结果 |
|---|---|
| `supports({url: v.qq.com})` / `{url: example.com}` / `{kind: direct_url}` | True / False / False |
| 繁花1990（单集"全集"） | success，1 条 m3u8，`proxy` |
| 漫长的季节 `episode=7` | success，`第07集`，7/12 |
| 漫长的季节 URL `/p9.html` | 自动推断第 9 集，9/12 |
| 不传 title（v.qq.com 真实页面） | 抓到的 `<title>` 是"腾讯视频"→ 清洗为空 → 回退 6 条解析页，`confidence=0.45` |
| m3u8 直链访问 | HTTP 200，`application/vnd.apple.mpegurl` |
| 关闭直连 | 6 条 `media_type=unknown` / `redirect` |
| `parse({})` | success=False，`non_retryable=True` |
| 镜像内 `ParserService.parse()`（v2.2.1 真实 core） | success，`m3u8 / proxy`，链内第 5/7 位 |

镜像内验收（2026-10-20，`devkit/fnos_verify.py`）7/7 PASS：发现 → 加载 → `ParserProvider` 协议 → 兜底契约 → 直连 m3u8 → 进链 → 调度成功。

## 已知限制

1. **片名来自 `play_target.meta`**。平台真实链路 `ParserService.parse()` 只传 `{play_target, target}`，片名在 `target["meta"]` 里（官方 3q 也从这里取），插件已展开 `meta` 读 `title`/`episode`。只有在**完全拿不到片名**时才回退抓页面标题，而 `v.qq.com` 的 `<title>` 是占位"腾讯视频"、bilibili 直接反爬，此时会回退解析页。
2. `_clean_title()` 按 `- _ 空格 （ | ｜` 切分后取第一段（忠实移植脚本行为），"漫长 的季节" 会被切成 "漫长"。
3. **部分片源是"全集"单条**（`全集$https://.../index.m3u8`），此时集号匹配失效，返回完整正片。
4. **依赖上游存活**。`wsyzy.cc` / `api.wsyzy.net` / m3u8 CDN 都是第三方服务，随时可能失效；失效时 `diagnostics.direct_error` 会记录原因并回退解析页。
5. **未实现资源上报**：官方 czzy/dushe/3q 会把验证过、可长期播放的 m3u8 上报回资源站，本插件没有接这个机制（需要在 core 侧有对应接口）。
6. **未做缓存**：官方 default_vip 用 `resource_ttl_cache` 缓存 play_target 结果，本插件每次都真实请求上游（单次约 2 个 HTTP 请求）。
7. 脚本里的 `playerContainers`、`displayNodes`、`cleanupNodes` 等 DOM 清理规则没有移植——服务端没有页面可清理。

## 合规提示

本插件仅做地址解析与转发，不存储、不分发任何视频内容。上游服务的可用性与合法性由使用者自行判断，使用前请确认所在地区法规与平台服务条款。
