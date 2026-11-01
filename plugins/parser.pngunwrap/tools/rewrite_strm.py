#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把媒体库里已有的 .strm 批量改成走插件的地址。

背景
----
T3FAP 的 `/api/strm/o/<token>.m3u8` 是**内核直接 302 到上游地址**，播放器跟着
跳完就出了 T3FAP，插件（哪怕挂在 8521 上）根本没有机会改写清单。所以要让剥壳
生效，只能把 `.strm` 文件里那一行换成插件的自包含地址。

本工具只做这一件事，默认**只看不改**。

用法
----
    # 1) 先看会改哪些（默认 dry-run，不动文件）
    python rewrite_strm.py --dir "D:/media/影视" --host 192.168.31.5

    # 2) 确认无误后真正写入（自动备份成 .strm.bak）
    python rewrite_strm.py --dir "D:/media/影视" --host 192.168.31.5 --apply

    # 3) 想回滚
    python rewrite_strm.py --dir "D:/media/影视" --restore

    # 走独立端口而不是 8521
    python rewrite_strm.py --dir "..." --host 192.168.31.5 --port 18521 --path /hls
"""

import argparse
import base64
import os
import re
import sys

# 平台门票地址（要换掉的目标）
TICKET_RE = re.compile(
    r"^https?://[^/\s]+/api/strm/o/([A-Za-z0-9_\-]+)\.m3u8\s*$", re.I)
# 已经是插件地址的，跳过
PLUGIN_RE = re.compile(r"/hls/u/[A-Za-z0-9_\-]+\.m3u8\s*$")
# 上游直链（不是门票），也支持换，但可能有时效
UPSTREAM_RE = re.compile(r"^https?://[^\s]+\.m3u8\s*$", re.I)

BAK = ".bak"


def b64e(text):
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


def read_text(path):
    """按原编码读，并返回写回时该用的编码（原来是 UTF-8 无 BOM 就别加 BOM）。"""
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", "replace"), "utf-8-sig"
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        return raw.decode("gbk"), "gbk"
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace"), "utf-8"


def build_url(src, host, port, path, https=False):
    scheme = "https" if https else "http"
    base = "%s://%s:%s%s" % (scheme, host, port, path.rstrip("/"))
    return "%s/hls/u/%s.m3u8" % (base, b64e(src))


def iter_strm(root):
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if not d.startswith(".")]
        for fn in fns:
            if fn.lower().endswith(".strm"):
                yield os.path.join(dp, fn)


def do_restore(root):
    n = 0
    for p in iter_strm(root):
        bak = p + BAK
        if os.path.isfile(bak):
            with open(bak, "rb") as f:
                data = f.read()
            with open(p, "wb") as f:
                f.write(data)
            os.remove(bak)
            n += 1
            print("已还原 %s" % p)
    print("\n共还原 %d 个文件" % n)
    return 0


def main():
    ap = argparse.ArgumentParser(description="批量把 .strm 改成插件地址")
    ap.add_argument("--dir", required=True, help="媒体库根目录（会递归）")
    ap.add_argument("--host", default="192.168.31.5", help="NAS 的局域网 IP 或域名")
    ap.add_argument("--port", default="8521", help="8521=平台统一端口，18521=独立端口")
    ap.add_argument("--path", default="", help="URL 路径前缀；8521 用 /api/strm/pngu，18521 留空")
    ap.add_argument("--https", action="store_true", help="用 https")
    ap.add_argument("--apply", action="store_true", help="真正写入（默认只看不改）")
    ap.add_argument("--restore", action="store_true", help="从 .strm.bak 还原")
    ap.add_argument("--limit", type=int, default=0, help="最多处理多少个文件（排查用）")
    args = ap.parse_args()

    root = args.dir
    if not os.path.isdir(root):
        print("目录不存在：%s" % root, file=sys.stderr)
        return 2

    if args.restore:
        return do_restore(root)

    if not args.path:
        args.path = "/api/strm/pngu" if args.port == "8521" else ""

    files = list(iter_strm(root))
    print("扫描到 %d 个 .strm 文件\n" % len(files))

    todo, skip_plugin, skip_other = [], 0, 0
    for p in files[:args.limit or None]:
        try:
            txt, enc = read_text(p)
        except Exception as e:                      # noqa: BLE001
            print("读不了 %s：%s" % (p, e), file=sys.stderr)
            continue
        src = txt.strip()
        if not src:
            skip_other += 1
            continue
        if PLUGIN_RE.search(src):
            skip_plugin += 1
            continue
        if TICKET_RE.match(src) or UPSTREAM_RE.match(src):
            todo.append((p, src, enc))
        else:
            skip_other += 1

    print("需要改：%d    已是插件地址：%d    其它格式：%d\n"
          % (len(todo), skip_plugin, skip_other))
    for p, src, _ in todo[:10]:
        print("  %s\n    %s\n    → %s" % (
            os.path.basename(p), src,
            build_url(src, args.host, args.port, args.path, args.https)))
    if len(todo) > 10:
        print("  ... 还有 %d 个" % (len(todo) - 10))

    if not args.apply:
        print("\n【预演】没有改动任何文件。确认无误后加 --apply 真正写入。")
        return 0

    ok = fail = 0
    for p, src, enc in todo:
        try:
            bak = p + BAK
            if not os.path.isfile(bak):
                with open(p, "rb") as f:
                    data = f.read()
                with open(bak, "wb") as f:
                    f.write(data)
            new = build_url(src, args.host, args.port, args.path, args.https)
            with open(p, "w", encoding=enc, newline="\n") as f:
                f.write(new + "\n")
            ok += 1
        except Exception as e:                      # noqa: BLE001
            fail += 1
            print("写失败 %s：%s" % (p, e), file=sys.stderr)

    print("\n写入成功 %d，失败 %d" % (ok, fail))
    print("回滚：python rewrite_strm.py --dir \"%s\" --restore" % root)
    print("改完记得在飞牛影视里**重新扫描该媒体库**，否则播放的还是旧地址。")
    return 0 if not fail else 1


if __name__ == "__main__":
    sys.exit(main())
