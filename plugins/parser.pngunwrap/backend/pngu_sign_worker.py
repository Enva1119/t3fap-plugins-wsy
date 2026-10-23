# -*- coding: utf-8 -*-
"""wasm 签名子进程入口。

用法：
    python pngu_sign_worker.py '<json>'
    echo '<json>' | python pngu_sign_worker.py

输入：{"data_id": "...", "secret_key": "...", "quality": "1080", "play_key": "..."}
输出：{"ok": true, "path": "/video/play?..."}  或  {"ok": false, "error": "..."}

这个文件被 plugin.py 用 subprocess 拉起，**永远不要在主进程里 import**。
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def main():
    raw = sys.argv[1] if len(sys.argv) > 1 else sys.stdin.read()
    try:
        req = json.loads(raw or "{}")
    except ValueError as e:
        print(json.dumps({"ok": False,
                          "error": "子进程入参不是 JSON（%s）" % e}))
        return 2

    try:
        import pngu_sign
        builder = pngu_sign.Builder()
        path = builder.build(req.get("data_id"), req.get("secret_key"),
                             req.get("quality") or "1080",
                             req.get("play_key"))
    except Exception as e:                          # noqa: BLE001
        print(json.dumps({"ok": False,
                          "error": "%s: %s" % (type(e).__name__, e)}))
        return 1

    print(json.dumps({"ok": True, "path": path, "env": sys.executable}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
