#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成一行可以直接写进 .strm 的播放地址。

插件从 0.2.3 起支持「自包含入口」：把源地址 base64url 编进路径，
不需要任何登记、不需要数据库，插件重启也能重建会话。

用法：
    python mk_strm.py "https://blz.cc.cd:8525/api/strm/o/cJgiJC-iQ4dT.m3u8" --host 192.168.31.5
    python mk_strm.py "<源地址>" --host 192.168.31.5 --write "D:/movies/影片.strm"

推荐传 T3FAP 的「门票地址」（/api/strm/o/...），因为它 token 稳定：
插件每次现跟 302 去取当次的上游清单，上游地址换了也不用改 STRM。
传上游 m3u8 直链也能用，但那个地址有时效，过期就得重写。
"""

import argparse
import base64
import sys


def b64e(text):
    raw = text.encode("utf-8") if isinstance(text, str) else text
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64d(token):
    s = token.strip()
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode("utf-8")


def main():
    ap = argparse.ArgumentParser(description="生成 .strm 播放地址")
    ap.add_argument("source", help="源地址（T3FAP 的 /api/strm/o/... 或上游 m3u8）")
    ap.add_argument("--host", default="127.0.0.1", help="播放器访问的地址")
    ap.add_argument("--port", default="", help="端口：默认平台模式 8521、独立模式 18521")
    ap.add_argument("--platform", action="store_true",
                    help="走 T3FAP 统一端口 8521（插件挂在 /api/strm/pngu 上）")
    ap.add_argument("--prefix", default="/api/strm/pngu",
                    help="平台模式下的挂载前缀，默认 /api/strm/pngu")
    ap.add_argument("--write", help="直接写入这个 .strm 文件")
    ap.add_argument("--decode", help="反向：给一个 /hls/u/<b64>.m3u8，解回源地址")
    ap.add_argument("--https", action="store_true", help="用 https 前缀")
    args = ap.parse_args()

    if args.decode:
        tok = args.decode.rsplit("/", 1)[-1].split(".")[0]
        try:
            print(b64d(tok))
            return 0
        except Exception as e:                      # noqa: BLE001
            print("解不出来：%s" % e, file=sys.stderr)
            return 2

    src = args.source.strip()
    if not src.lower().startswith(("http://", "https://")):
        print("源地址必须以 http:// 或 https:// 开头", file=sys.stderr)
        return 2

    scheme = "https" if args.https else "http"
    port = args.port or ("8521" if args.platform else "18521")
    base = "%s://%s:%s" % (scheme, args.host, port)
    if args.platform:
        base += args.prefix.rstrip("/")
    url = "%s/hls/u/%s.m3u8" % (base, b64e(src))

    print(url)
    if args.write:
        with open(args.write, "w", encoding="utf-8", newline="\n") as f:
            f.write(url + "\n")
        print("\n已写入：%s" % args.write, file=sys.stderr)

    print("\n--- 说明 ---", file=sys.stderr)
    print("源地址      : %s" % src, file=sys.stderr)
    print("编码后长度  : %d 字符（.strm 里就这一行）" % len(b64e(src)), file=sys.stderr)
    if args.host in ("127.0.0.1", "localhost"):
        print("警告：host 是回环地址，只有本机能播。"
              "播放器在别的设备上时用 NAS 的局域网 IP。", file=sys.stderr)
    if args.platform:
        print("模式        : 走 T3FAP 统一端口（8521），无需端口映射", file=sys.stderr)
        print("前提        : 插件配置里「挂到平台统一端口」保持开启；"
              "日志搜「挂到平台 8521 成功」确认", file=sys.stderr)
    else:
        print("模式        : 播放器直连插件端口，需要 bind_host=0.0.0.0 并映射 %s 端口"
              % port, file=sys.stderr)
    print("自检：curl -I \"%s\"  应返回 200 + application/vnd.apple.mpegurl"
          % url, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
