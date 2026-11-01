#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""追一条播放地址的完整链路：302 跳到哪、最终清单谁给的、分片是不是 PNG 壳。

用法：
    python trace_chain.py "http://192.168.31.5:8521/api/strm/o/ZxQfw9NP0Y7.m3u8"
    python trace_chain.py "https://blz.cc.cd:18090/p/wGhMd4dE.m3u8"

只读，不会修改任何东西。默认最多跟 8 跳，每跳都打印状态码、Location、
Content-Type、Content-Length，最后探第一个分片。
"""

import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "T3FAP-trace/1.0"
TS_PACKET = 188
TS_SYNC = 0x47
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MAX_HOPS = 8


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """不自动跟随，我们自己跟，好把每一跳看清楚。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(NoRedirect)


def fetch(url, method="GET", referer="", timeout=12, limit=None):
    """返回 (status, headers, body)。不抛 302，不抛 4xx。"""
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", UA)
    if referer:
        req.add_header("Referer", referer)
    if method == "GET":
        req.add_header("Range", "bytes=0-%d" % ((limit or 262144) - 1))
    try:
        r = _opener.open(req, timeout=timeout)
        body = r.read()
        return r.getcode(), dict(r.headers), body
    except urllib.error.HTTPError as e:
        body = b""
        try:
            body = e.read()
        except Exception:                       # noqa: BLE001
            pass
        return e.code, dict(e.headers), body
    except Exception as e:                      # noqa: BLE001
        return 0, {"x-error": "%s: %s" % (type(e).__name__, e)}, b""


def short(u, n=96):
    return u if len(u) <= n else u[:n] + "…"


def unwrap_shell(buf):
    """返回 (去掉壳后的字节, 壳长)。认不出就当裸流。"""
    if not buf:
        return buf, 0
    if buf[:8] == PNG_MAGIC:
        # PNG 壳：最后一个 IDAT 之后就是 TS
        i = buf.find(b"IEND")
        if i > 0:
            tail = buf[i + 8:]
            sync = _align(tail)
            if sync is not None:
                return tail[sync:], i + 8 + sync
        sync = _align(buf)
        if sync is not None:
            return buf[sync:], sync
    sync = _align(buf)
    if sync is not None and sync > 0:
        return buf[sync:], sync
    return buf, 0


def _align(buf):
    """在头部 2048 字节内找第一个能让 (len-off) % 188 == 0 的 0x47。"""
    if not buf:
        return None
    for off in range(0, min(len(buf), 2048)):
        if buf[off] != TS_SYNC:
            continue
        if (len(buf) - off) % TS_PACKET == 0:
            return off
    # 长度不整齐（截断）时退化成「连续 5 个包同步」
    for off in range(0, min(len(buf), 2048)):
        if buf[off] != TS_SYNC:
            continue
        ok = True
        for k in range(1, 6):
            p = off + k * TS_PACKET
            if p < len(buf) and buf[p] != TS_SYNC:
                ok = False
                break
        if ok:
            return off
    return None


def sync_rate(buf):
    n = len(buf) // TS_PACKET
    if not n:
        return 0.0
    return sum(1 for i in range(n) if buf[i * TS_PACKET] == TS_SYNC) / n


def probe_segment(url, referer):
    """拉第一片，判断是不是 PNG 壳。"""
    code, hdrs, body = fetch(url, referer=referer, limit=196608)
    out = {"url": url, "status": code, "ctype": hdrs.get("Content-Type", ""),
           "bytes": len(body)}
    if code not in (200, 206) or not body:
        out["verdict"] = "分片拉不到（HTTP %s）" % code
        return out
    body_clean, shell = unwrap_shell(body)
    is_png_head = body[:8] == PNG_MAGIC
    out.update({
        "png_magic": is_png_head,
        "shell": shell,
        "sync_raw": round(sync_rate(body), 4),
        "sync_clean": round(sync_rate(body_clean), 4),
    })
    if is_png_head:
        out["verdict"] = "PNG 壳（壳长 %d）→ 硬解会被壳卡住" % shell
    elif shell:
        out["verdict"] = "无 PNG 魔数但对齐偏移 %d（疑似壳）" % shell
    elif out["sync_raw"] > 0.99:
        out["verdict"] = "裸 TS，正常"
    else:
        out["verdict"] = "非 TS（可能是 fMP4 或加密数据）"
    return out


def first_segment(playlist, base):
    keys = []
    for line in playlist.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("#EXT-X-KEY") and "URI=" in s:
            u = s.split("URI=")[1].split('"')[1]
            keys.append(urllib.parse.urljoin(base, u))
            continue
        if s.startswith("#"):
            continue
        return urllib.parse.urljoin(base, s), keys
    return "", keys


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    url = sys.argv[1].strip()
    print("=" * 78)
    print("起点：", url)
    print("=" * 78)

    chain = []
    cur = url
    referer = ""
    final_body = b""
    final_hdrs = {}
    for hop in range(MAX_HOPS):
        code, hdrs, body = fetch(cur, referer=referer, limit=65536)
        loc = hdrs.get("Location") or hdrs.get("location") or ""
        chain.append({"n": hop + 1, "url": cur, "status": code,
                      "ctype": hdrs.get("Content-Type", ""),
                      "len": hdrs.get("Content-Length", ""),
                      "loc": loc})
        print("\n[%d] %s" % (hop + 1, short(cur, 110)))
        print("    状态      : %s" % code)
        if hdrs.get("Content-Type"):
            print("    Content-Type: %s" % hdrs.get("Content-Type"))
        if hdrs.get("Content-Length"):
            print("    Content-Length: %s" % hdrs.get("Content-Length"))
        if code == 0:
            print("    错误      : %s" % hdrs.get("x-error"))
            break
        if code in (301, 302, 303, 307, 308) and loc:
            print("    → 302 去  : %s" % loc)
            # 302 说明这一层只是「转发器」，不产生内容
            if not urllib.parse.urlparse(loc).netloc:
                loc = urllib.parse.urljoin(cur, loc)
            referer = cur
            cur = loc
            continue
        final_body, final_hdrs = body, hdrs
        print("    → 终点    : 这一层返回内容（%d 字节）" % len(body))
        break

    if not final_body:
        print("\n没有拿到内容，链路在上面中断了。")
        return 1

    txt = ""
    try:
        txt = final_body.decode("utf-8", "replace")
    except Exception:                           # noqa: BLE001
        pass

    print("\n" + "-" * 78)
    if "#EXTM3U" in txt:
        lines = [l.strip() for l in txt.splitlines() if l.strip()]
        segs = [l for l in lines if not l.startswith("#")]
        print("终点是 m3u8：共 %d 行，%d 个分片" % (len(lines), len(segs)))
        seg_url, keys = first_segment(txt, cur)
        if keys:
            print("AES 密钥   : %s" % short(keys[0], 100))
        if seg_url:
            host = urllib.parse.urlparse(seg_url).netloc
            print("第一片     : %s" % short(seg_url, 110))
            print("分片域名   : %s" % host)
            if "/p/" in seg_url or "/seg/" in seg_url:
                print("判定       : 分片经过自有反代（清单已被改写）")
            else:
                print("判定       : 分片直连上游（清单未改写）")
            info = probe_segment(seg_url, referer=cur)
            print("\n分片探测：")
            print("  状态        : %s  %s  %d 字节"
                  % (info.get("status"), info.get("ctype", ""), info.get("bytes", 0)))
            if "shell" in info:
                print("  PNG 魔数    : %s" % ("是" if info["png_magic"] else "否"))
                print("  壳长        : %d" % info["shell"])
                print("  同步率 原始 : %.4f" % info["sync_raw"])
                print("  同步率 剥后 : %.4f" % info["sync_clean"])
            print("  结论        : %s" % info.get("verdict"))
    elif final_body[:8] == PNG_MAGIC:
        print("终点直接是一片 PNG（不是 m3u8）")
        info = probe_segment(cur, referer="")
        print("  壳长 %s / 结论：%s" % (info.get("shell"), info.get("verdict")))
    else:
        print("终点不是 m3u8（前 60 字节：%r）"
              % final_body[:60])

    print("\n" + "=" * 78)
    print("链路：")
    for c in chain:
        arrow = "  --%s-->" % c["status"] if c["status"] in (301, 302, 303, 307, 308) else "   [内容]"
        print("  %d %s%s" % (c["n"], short(c["url"], 78), arrow))
    print()
    print("判读要点：")
    print("  · 如果 302 的目标在 T3FAP 之外（别的端口/别的域名），")
    print("    那么之后所有请求都不再经过 T3FAP 的解析链，解析类插件不会被调用。")
    print("  · 如果终点 m3u8 的分片是上游地址且带 PNG 壳，")
    print("    说明中间没有任何一层做了剥壳，硬解必然失败。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
