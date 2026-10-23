# -*- coding: utf-8 -*-
"""PNG 壳分片剥离。

4kvms 一类站点的 HLS 分片并不是裸 TS，而是在真正的 TS 前面套了一段
伪装成 PNG 的壳（让 CDN / 防盗链 / 浏览器 <img> 预检以为是图片）。
壳头固定 73 字节，其后是完整的 MPEG-TS（188 字节定长包）。

本模块只做一件事：把壳剥掉，交还真实的媒体字节。

设计原则：**幂等且无害**。
  - 不是壳的内容原样返回，绝不破坏
  - 认不出来也原样返回
所以即使上游误判、把普通分片送进来，播放也不会坏。
"""

from __future__ import annotations

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
TS_PACKET = 188
TS_SYNC = 0x47

# 已知的壳头长度（只是「优先试探」，真正的判定靠同步率，见下）：
#   126 —— 4kvms 三份真实样本（_seg_1012130_0 等）实测
#    61 —— icve/douyinbit 系（8 签名字节 + 25 IHDR + 28 IDAT，无 IEND）
#    73 —— 早期的历史值，部分站点仍在使用
SHELL_SIZES = (126, 61, 73, 0)

# 允许在头部多大范围内滑动搜索同步字节
SEARCH_WINDOW = 1024

# 同步率阈值。真 TS 每 188 字节必有一个 0x47，实测 1.0000；
# 随机字节（含真 PNG 图片）命中率约 1/256 ≈ 0.004，两者差三个数量级，
# 0.85 足够把「壳后 TS」和「真图片」分开，同时容忍偶发丢包。
SYNC_MIN = 0.85


def _ts_sync_rate(body: bytes, n: int = 100) -> float:
    """从第 0 字节起每 188 字节采一个，统计 0x47 命中率。

    **不能用「长度 % 188 == 0」来判断**：这个判据在真实数据上会把正确的
    偏移直接跳过 —— icve 系分片末尾有 12 字节残包（最后一个 TS 包被截断），
    剥掉 61 字节后长度 4,671,812 不整除 188，老代码因此认定「不是 TS」，
    原样把 PNG 吐给播放器。同步率对残包免疫，这也是 fpkvip 里
    `_locate_ts` 用的办法。
    """
    if not body or len(body) < TS_PACKET * 2:
        return 0.0
    samples = body[::TS_PACKET][:n]
    if len(samples) < 2:
        return 0.0
    return samples.count(TS_SYNC) / float(len(samples))


def _is_ts(body: bytes) -> bool:
    """首字节是同步字节，且后续 188 步进几乎全是同步字节。

    容许末尾残包（最后一个包被 CDN 截断），这也是真实分片的常态。
    """
    if not body or body[0] != TS_SYNC:
        return False
    return _ts_sync_rate(body) >= SYNC_MIN


def _is_mp4(body: bytes) -> bool:
    """fMP4 分片：第 4~8 字节是 box 类型 ftyp / styp / moof / sidx。"""
    if len(body) < 12:
        return False
    box = body[4:8]
    return box in (b"ftyp", b"styp", b"moof", b"sidx", b"mdat")


def _align_ts(body: bytes) -> bytes:
    """在 SEARCH_WINDOW 内找第一个「其后每 188 字节都是 0x47」的位置。

    顺序扫描天然取到最小偏移 —— 最前面几个包是 PAT/PMT，往后剥会把节目表
    丢掉，播放器找不到 PMT 就黑屏。
    """
    limit = min(len(body), SEARCH_WINDOW)
    for off in range(limit):
        if body[off] != TS_SYNC:
            continue
        tail = body[off:]
        if _ts_sync_rate(tail) >= SYNC_MIN:
            return tail
    return b""


def unwrap(data: bytes):
    """剥壳。

    返回 (payload, info)：
      payload  —— 可直接交给播放器的字节
      info     —— 诊断信息 dict，含 shell（剥掉多少字节）、kind（ts/mp4/raw）
    """
    if not data:
        return data, {"shell": 0, "kind": "empty", "png": False}

    info = {"shell": 0, "kind": "raw", "png": data.startswith(PNG_MAGIC)}

    # 1) 已经是裸 TS / fMP4，直接放行（幂等）
    if _is_ts(data):
        info["kind"] = "ts"
        return data, info
    if _is_mp4(data):
        info["kind"] = "mp4"
        return data, info

    # 2) 按已知壳长逐个尝试
    for size in SHELL_SIZES:
        if size == 0 or size >= len(data):
            continue
        body = data[size:]
        if _is_ts(body):
            info.update(shell=size, kind="ts")
            return body, info
        if _is_mp4(body):
            info.update(shell=size, kind="mp4")
            return body, info

    # 3) 兜底：滑动搜索 TS 同步字节
    body = _align_ts(data)
    if body:
        info.update(shell=len(data) - len(body), kind="ts", aligned=True)
        return body, info

    # 4) 认不出来 —— 原样返回，宁可不处理也不能破坏
    info["kind"] = "raw"
    return data, info


def describe(data: bytes) -> dict:
    """只诊断不处理，用于自检接口。"""
    _, info = unwrap(data)
    info["bytes"] = len(data)
    info["head_hex"] = data[:16].hex()
    return info


# 模块自述版本。plugin.py 会拿它和磁盘上的文件比对，不一致就说明平台热更新
# 只重载了 plugin 模块、子模块还留在 sys.modules 里，需要 importlib.reload。
__version__ = "0.4.3"
