# -*- coding: utf-8 -*-
"""流探针：判断一条 m3u8 / 分片到底是不是 PNG 壳，以及里面是什么编码。

用法（不需要装任何第三方库）：
    python probe_stream.py "https://.../index.m3u8"
    python probe_stream.py "https://.../seg_0.ts"
    python probe_stream.py D:\\path\\seg_0.bin

它会回答三个问题：
    1. 分片开头是不是 PNG 壳？壳有多长？
    2. 剥壳后是不是标准 TS（188 字节包、同步率多少）？
    3. 视频轨是什么编码 / 什么像素格式（如果本机有 ffprobe）。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
TS_PACKET = 188
TS_SYNC = 0x47


def fetch(url, timeout=20, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(), dict(r.headers), r.status


def head_headers(url, timeout=20):
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers)
    except Exception as e:                          # noqa: BLE001
        return None, {"error": str(e)}


def find_shell_offset(buf):
    """找 PNG 壳后面第一个 TS 同步位置。

    规则：从 8 字节起滑动，要求 (len - off) 能被 188 整除，且该处为 0x47，
    并且后面连续 3 个包也是 0x47。命中就返回 off。
    """
    if not buf or buf[0] != 0x89:
        return 0
    n = len(buf)
    for off in range(8, min(2048, n)):
        if (n - off) % TS_PACKET:
            continue
        if buf[off] != TS_SYNC:
            continue
        good = all(buf[off + i * TS_PACKET] == TS_SYNC
                   for i in range(1, 4)
                   if off + i * TS_PACKET < n)
        if good:
            return off
    return 0


def sync_rate(buf):
    if not buf:
        return 0.0
    n = len(buf) // TS_PACKET
    if not n:
        return 0.0
    ok = sum(1 for i in range(n) if buf[i * TS_PACKET] == TS_SYNC)
    return ok / n


def probe_bytes(buf, label):
    out = {"样本": label, "字节数": len(buf),
           "前16字节": buf[:16].hex() if buf else ""}
    shell = find_shell_offset(buf)
    body = buf[shell:] if shell else buf
    if buf.startswith(PNG_MAGIC):
        out["PNG壳"] = "是（壳长 %d）" % shell if shell else "是（但没找到对齐边界）"
    else:
        out["PNG壳"] = "否"
    out["壳长度"] = shell
    out["剥壳后字节数"] = len(body)
    out["能被188整除"] = (len(body) % TS_PACKET == 0)
    out["TS同步率"] = round(sync_rate(body), 4)
    out["首包PID"] = (((body[1] & 0x1F) << 8) | body[2]) if len(body) > 3 else None
    out["判定"] = _verdict(shell, body)
    return out, body


def _verdict(shell, body):
    r = sync_rate(body)
    if r > 0.99 and len(body) % TS_PACKET == 0:
        return ("PNG壳 + 标准TS（硬解会被壳卡住，剥壳后才能硬解）"
                if shell else "标准TS，无需剥壳")
    if body[:4] in (b"\x00\x00\x00\x18", b"\x00\x00\x00\x20") or b"ftyp" in body[:32]:
        return "fMP4，不需要剥壳"
    return "既不像标准TS也不像fMP4，可能是加密或其它格式"


def ffprobe_info(body, ext=".ts"):
    """有 ffprobe 就顺手看一眼编码，没有就算了。"""
    path = None
    try:
        fd, path = tempfile.mkstemp(suffix=ext)
        with os.fdopen(fd, "wb") as f:
            f.write(body)
        p = subprocess.run(
            ["ffprobe", "-v", "error", "-show_streams",
             "-print_format", "json", path],
            capture_output=True, timeout=25)
        if p.returncode != 0:
            return {"ffprobe": (p.stderr or b"").decode("utf-8", "ignore")[:200]}
        doc = json.loads(p.stdout.decode("utf-8", "ignore") or "{}")
        rows = []
        for s in doc.get("streams", []):
            rows.append({
                "类型": s.get("codec_type"),
                "编码": s.get("codec_name"),
                "profile": s.get("profile"),
                "像素格式": s.get("pix_fmt"),
                "分辨率": ("%sx%s" % (s.get("width"), s.get("height"))
                           if s.get("width") else None),
            })
        return {"ffprobe": rows}
    except FileNotFoundError:
        return {"ffprobe": "本机没有 ffprobe，跳过编码检查"}
    except Exception as e:                          # noqa: BLE001
        return {"ffprobe": "调用失败：%s" % e}
    finally:
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    target = sys.argv[1].strip().strip('"')
    print("目标：%s\n" % target)

    headers = {"User-Agent": UA, "Accept": "*/*"}
    seg_url = target
    playlist_text = ""
    body = b""

    if os.path.isfile(target):
        with open(target, "rb") as f:
            body = f.read()
        seg_url = target
    else:
        status, _ = head_headers(target)
        if status:
            print("HEAD：HTTP %d" % status)
        raw, hdrs, code = fetch(target, headers=headers)
        ctype = (hdrs.get("Content-Type") or "").lower()
        print("GET ：HTTP %d  Content-Type=%s  长度=%d" % (code, ctype, len(raw)))
        if b"#EXTM3U" in raw[:2048] or "mpegurl" in ctype:
            playlist_text = raw.decode("utf-8", "ignore")
            print("\n---- 清单前 20 行 ----")
            print("\n".join(playlist_text.splitlines()[:20]))
            first = _first_segment(playlist_text)
            if not first:
                print("\n清单里没有分片")
                return 1
            seg_url = urllib.parse.urljoin(target, first)
            print("\n首个分片：%s" % seg_url)
            body, hdrs, code = fetch(seg_url, headers=headers)
            print("分片：HTTP %d  Content-Type=%s  长度=%d"
                  % (code, hdrs.get("Content-Type"), len(body)))
        else:
            body = raw

    info, unwrapped = probe_bytes(body, os.path.basename(seg_url)[:60])
    print("\n---- 分片体检 ----")
    for k, v in info.items():
        print("  %-12s %s" % (k, v))

    if playlist_text:
        keys = [ln for ln in playlist_text.splitlines() if "EXT-X-KEY" in ln]
        if keys:
            print("\n  加密        有（%s）" % keys[0][:80])

    print("\n---- 编码（剥壳后内容）----")
    for k, v in ffprobe_info(unwrapped).items():
        print("  %-12s %s" % (k, v))

    print("\n结论：%s" % info["判定"])
    return 0


def _first_segment(text):
    for line in text.splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            return s
    return ""


if __name__ == "__main__":
    sys.exit(main())
