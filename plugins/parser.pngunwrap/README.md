# PNG 壳分片剥离（parser.pngunwrap）

T3FAP 解析插件。把「伪装成 PNG 的 HLS 分片」剥回可播放的 TS，让飞牛影视 / Emby / Jellyfin
能正常播放 4k影视这类站点。

**不改动任何现有插件。** 它靠 `resource.priority = 26`（高于 4k 解析插件的 25）接管解析链，
删掉就自动回落。

---

## 一、它解决什么问题

4kvms 一类站点的 HLS 分片不是裸 TS，而是在真正的 MPEG-TS 前面套了一段伪装成 PNG 的壳
（让 CDN、防盗链、`<img>` 预检以为是图片）。播放器看到 PNG 魔数直接放弃，表现就是
**一直转圈、只显示封面**。

本插件在自己的进程里起一个 HLS 反代：

```
播放器 → 平台代理 → 插件反代(127.0.0.1:18521) → 源站
                        ├─ /hls/<tok>.m3u8   改写分片地址
                        └─ /seg/<tok>/<n>    拉分片 → 剥 126 字节壳 → video/mp2t
```

平台的 `access_mode=proxy` 只做「带鉴权头转发」，字节透明，不会替你剥壳 —— 所以剥壳
必须由插件自己做。

**实测数据**：三个真实分片样本剥掉 **126 字节**后，长度都能被 188 整除，同步率 `1.0000`。

---

## 二、安装

把 `parser.pngunwrap/` 整个目录放到 T3FAP 的插件目录下（与现有插件同级），例如：

```
plugins/market/parser.pngunwrap/
├── plugin.json
└── backend/
    ├── __init__.py
    ├── plugin.py
    ├── pngu_unwrap.py
    ├── pngu_proxy.py
    ├── pngu_fetch.py
    ├── pngu_sign.py
    ├── pngu_sign_worker.py
    └── vendor/nbmovie_wasm_bg.wasm
```

然后重启 T3FAP，在插件列表里应能看到「PNG 壳分片剥离」。

> `vendor/nbmovie_wasm_bg.wasm` 是从 `parser.thirdparty.4k` 复制的一份**副本**，
> 不引用也不修改原插件文件。

---

## 三、三步验证（按顺序，别跳）

### 第 1 步：验链路（30 秒）

```json
{ "source_mode": "demo" }
```

播一次任意 4k 内容。这一模式返回内置写死清单，分片是合成的合法 TS 包 ——
**画面可能是黑的、播放器可能报没有视频轨，这都正常。**

判断标准只有一个：**清单和分片有没有被成功请求到**。

- 平台日志里能看到 `/hls/...m3u8` 和 `/seg/...` 的请求 → **127.0.0.1 链路通，方案成立**
- 报 502 / 超时 / SSRF 拦截 → 平台代理不放行内网，改走「第 4 节 B 方案」

也可以直接访问自检接口：

```
http://127.0.0.1:18521/__health
```

### 第 2 步：验剥壳（1 分钟）

```json
{ "source_mode": "manual", "external_m3u8": "https://你的源/a.m3u8" }
```

填一条已知是 PNG 壳分片的清单地址，播一次。这次应该有画面。
如果第 2 步能播、第 1 步不通，说明是平台代理的问题，不是插件的问题。

### 第 3 步：走自动

```json
{ "source_mode": "auto", "play_quality": "1080" }
```

插件从 `parse_request.meta` 里取 `data_id / secret_key / play_key`，
用 wasm 在**子进程**里签名，拿 `/video/play` 的 JSON，挑一个清晰度，交给反代。

---

## 四、配置

| 键 | 默认 | 说明 |
|---|---|---|
| `enabled` | `true` | **软开关**。关掉立即完全让路给 4k 插件，不用卸载 |
| `source_mode` | `auto` | `auto` / `manual` / `demo` |
| `external_m3u8` | 空 | `manual` 时用 |
| `base_url` | `https://www.4kvms.org` | 站点换域名改这里 |
| `play_quality` | `1080` | 取不到按 1080 → 720 回退 |
| `cookie` | 空 | 可选，登录态能拿更高画质 |
| `access_mode` | `proxy` | `proxy`=平台代拉（推荐）；`direct`=播放器直连 |
| `bind_host` | `127.0.0.1` | `direct` 模式要改 `0.0.0.0` |
| `listen_port` | `18521` | 被占用自动顺延最多 10 个 |
| `public_base` | 空 | 仅 `direct` 模式需要 |
| `cache_mb` | `64` | 分片缓存字节上限 |
| `cache_ttl` | `30` | 播放后保留秒数 |

### B 方案：平台代理不放行内网时

```yaml
# compose.yaml
services:
  t3fap:
    ports:
      - "8521:8521"
      - "18521:18521"
```

配置改成：

```json
{ "access_mode": "direct", "bind_host": "0.0.0.0",
  "public_base": "http://你的NAS地址:18521" }
```

此时 STRM 里存的是插件地址，**卸载插件后需要重新生成 STRM**（见 5.3）。

---

## 五、卸载与回滚

### 5.1 不想用了，先关软开关

```json
{ "enabled": false }
```

`supports()` 第一行就返回 `False`，解析链立刻回落 4k。插件还在，但完全不参与。

### 5.2 真删

| 方式 | 效果 | 代价 |
|---|---|---|
| 平台界面停用 | 立即恢复 | 无 |
| 平台界面卸载 | 恢复 | 钩子里停服务、清缓存 |
| 直接删目录 | 恢复 | **需重启一次 T3FAP** |

第三种要重启，是因为内建 HTTP 服务跑在**平台进程内的线程**里（不是守护进程），
平台一重启就必然消失，不会留孤儿进程。

### 5.3 为什么删了不会破坏原有环境

1. 只读现有插件 —— wasm 用自己的副本，原文件时间戳都不变
2. 不碰数据库 —— 只有 `config_schema` 的值会留在平台 DB 里（几 KB 孤儿数据，无害）
3. `menus / settings_sections / task_templates` 全空 —— 界面零新增，删了没有空壳菜单
4. 优先级只在内存排序里生效 —— 删后自动回落 `4k(25)`
5. 缓存写在插件自己目录 —— 删目录即删缓存

**唯一要注意的**：`proxy` 模式下 STRM 存的是平台地址，删插件后平台会重新解析并回落 4k，
回到「能拉到清单但播不了」的原点；`direct` 模式下 STRM 存的是插件地址，删了会 404，
**必须重新生成 STRM**。所以推荐 `proxy`。

---

## 六、排障

| 现象 | 原因 | 处理 |
|---|---|---|
| 插件列表里不出现 | 目录层级不对 / 没重启 | 确认 `plugin.json` 与 `backend/` 同级 |
| `core.sdk 导入失败` | 平台版本不匹配 | 检查 `core_version` 与平台版本 |
| `wasm 签名失败` | 子进程崩 / 缺 wasmtime | 看日志；容器禁 JIT 时改 `source_mode=manual` |
| `内建服务启动失败` | 端口全被占 | 改 `listen_port` |
| 有画面但卡顿 | 首片未预热 | 反代已内置缓存，确认 `cache_mb` 不是 0 |
| 平台报 502 | 代理不放行 127.0.0.1 | 走第 4 节 B 方案 |

自检：

```
curl http://127.0.0.1:18521/__health
```

返回 `ok / bind / sessions / cache / error`。

---

## 七、已知限制

- 只接管 4k 来源（`provider=4k` 或域名属于 4kvms 家族），其他来源一律放行
- 需要容器里有 `wasmtime`（4k 插件本来就依赖它）
- 4K 画质取决于源站是否给该片 2160 流
- 需要登录/会员的集，换令牌也救不回来，会返回明确错误
- 分片是「拉一片、剥一片、缓存一片」，不做整集预下载

---

## 八、版本

**0.1.0** —— 首版。剥壳、清单改写、AES 密钥透传、Range/206、HEAD 真实长度、
字节上限缓存、demo/manual/auto 三模式、生命周期钩子齐备。

剥壳规则实测自三个真实分片样本（同步率 1.0）。
