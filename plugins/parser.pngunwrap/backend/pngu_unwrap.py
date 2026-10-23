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

# 已知的壳头长度。126 是 4kvms 的实测值 —— 三个真实分片样本
# (_seg_1012130_0 / _seg_1016642_134 / _seg_845374_1) 剥掉 126 字节后
# 长度都能被 188 整除，且同步率 1.0000。73 作为历史值保留。
SHELL_SIZES = (126, 73, 0)

# 允许在头部多大范围内滑动搜索同步字节
SEARCH_WINDOW = 1024


def _is_ts(body: bytes) -> bool:
    """首字节是同步字节，且长度能被 188 整除（允许末尾残包）。"""
    if not body or body[0] != TS_SYNC:
        return False
    if len(body) < TS_PACKET * 2:
        return False
    return len(body) % TS_PACKET == 0


def _is_mp4(body: bytes) -> bool:
    """fMP4 分片：第 4~8 字节是 box 类型 ftyp / styp / moof / sidx。"""
    if len(body) < 12:
        return False
    box = body[4:8]
    return box in (b"ftyp", b"styp", b"moof", b"sidx", b"mdat")


def _align_ts(body: bytes) -> bytes:
    """在 SEARCH_WINDOW 内找第一个能把长度整除 188 的同步字节位置。"""
    limit = min(len(body), SEARCH_WINDOW)
    for off in range(limit):
        if body[off] != TS_SYNC:
            continue
        tail = len(body) - off
        if tail >= TS_PACKET * 2 and tail % TS_PACKET == 0:
            return body[off:]
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
