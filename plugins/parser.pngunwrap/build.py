# -*- coding: utf-8 -*-
"""把插件打成两个包：一个带源码的，一个只有 .pyc 的。

用法
----
    python build.py                      # 用自动找到的 3.11 编译并打包
    python build.py --py311 D:/py311/python.exe
    python build.py --work D:/tmp/build  # 指定构建目录（默认系统临时目录）

一次跑出两个包，版本号取自 plugin.json：

    parser.pngunwrap-0.4.6.zip        源码包 —— 留着改代码用，也能直接装
    parser.pngunwrap-0.4.6.pyc.zip    发布包 —— 只有 .pyc，不暴露源码

改完源码直接重跑这个脚本，两个包一起更新，不用记步骤。

为什么要专门用 3.11 编译
------------------------
pyc 是**和解释器版本绑定**的。T3FAP 官方插件包里的 pyc magic 是
`0x0DA7`(3495)，对应 **CPython 3.11**；开发机上是 3.13（magic `0x0DF3`）。
拿 3.13 编出来的 pyc 丢进容器，导入时会直接 `bad magic number`。
所以这里强制用 3.11 的解释器编译，并在打包前把 magic 逐个校验一遍。

布局也有讲究
------------
`sourceless import` 只认「和源码同目录、同名」的 `xxx.pyc`，
**不认** `__pycache__/xxx.cpython-311.pyc`（那个必须有 .py 配套才会被用）。
所以用 `compileall -b`（legacy 布局），编译完把 .py 全删掉。
"""

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile

NAME = "parser.pngunwrap"
HERE = os.path.dirname(os.path.abspath(__file__))
MAGIC_311 = 3495            # CPython 3.11 的 pyc magic

SKIP_DIRS = {"__pycache__", ".git", ".idea", ".vscode"}
SKIP_FILES = {".DS_Store", "build.py", "pack_pngu.py"}
SKIP_EXT = (".pyc", ".zip", ".pyz", ".bak")

# 源码包的排除规则不一样：它要**带上** build.py（用户改完源码得能重新打包）
# 和全部 .py，只把缓存与产物排掉。
SRC_SKIP_FILES = {".DS_Store", "pack_pngu.py"}
SRC_SKIP_EXT = (".pyc", ".zip", ".pyz", ".bak")


def log(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


def find_py311(explicit=""):
    """找一个能用的 CPython 3.11。找不到就报清楚该怎么办。"""
    cands = []
    if explicit:
        cands.append(explicit)
    if os.environ.get("PY311"):
        cands.append(os.environ["PY311"])
    cands += [
        os.path.join(HERE, "py311", "python.exe"),
        "D:/t3work/py311/python.exe",
        "/usr/bin/python3.11",
        "/usr/local/bin/python3.11",
        "python3.11",
    ]
    for c in cands:
        if not c:
            continue
        exe = c if os.path.isfile(c) else shutil.which(c)
        if not exe:
            continue
        try:
            out = subprocess.run(
                [exe, "-c", "import sys,importlib.util,struct;"
                            "print(sys.version_info[0],sys.version_info[1],"
                            "struct.unpack('<H',importlib.util.MAGIC_NUMBER[:2])[0])"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
            parts = (out.stdout or b"").decode().split()
            if len(parts) >= 3 and parts[0] == "3" and parts[1] == "11":
                log("用解释器：%s（magic %s）" % (exe, parts[2]))
                return exe
        except (OSError, subprocess.SubprocessError):
            continue
    raise SystemExit(
        "没找到 CPython 3.11。pyc 必须和目标解释器同版本，3.12/3.13 编出来的\n"
        "在容器里会 bad magic number。装一个 3.11（或下载\n"
        "https://mirrors.huaweicloud.com/python/3.11.9/python-3.11.9-embed-amd64.zip\n"
        "解压即用），再用 --py311 指过来。")


def read_version():
    with open(os.path.join(HERE, "plugin.json"), "r", encoding="utf-8") as f:
        return json.load(f)["version"]


def stage(dst):
    """把源码树复制到构建目录（不带 pyc / 缓存 / 构建脚本）。"""
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    os.makedirs(dst)
    count = 0
    for dp, dns, fns in os.walk(HERE):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        rel_dir = os.path.relpath(dp, HERE)
        out_dir = dst if rel_dir == "." else os.path.join(dst, rel_dir)
        if not os.path.isdir(out_dir):
            os.makedirs(out_dir)
        for fn in fns:
            if fn in SKIP_FILES or fn.endswith(SKIP_EXT):
                continue
            shutil.copy2(os.path.join(dp, fn), os.path.join(out_dir, fn))
            count += 1
    return count


def compile_all(py311, root):
    """用 3.11 把 backend/ 和 tools/ 编成同目录的 .pyc。"""
    targets = [os.path.join(root, d) for d in ("backend", "tools")
               if os.path.isdir(os.path.join(root, d))]
    cmd = [py311, "-m", "compileall", "-b", "-q", "-f",
           "--invalidation-mode", "unchecked-hash"] + targets
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = (proc.stdout or b"").decode("utf-8", "replace").strip()
    if proc.returncode != 0:
        raise SystemExit("compileall 失败：\n%s" % out)
    if out:
        log("compileall 输出：\n" + out)


def drop_sources(root):
    """删掉所有 .py —— 这一步之后包里就没有可读源码了。"""
    gone = []
    for dp, _dns, fns in os.walk(root):
        for fn in fns:
            if fn.endswith(".py"):
                path = os.path.join(dp, fn)
                os.remove(path)
                gone.append(os.path.relpath(path, root).replace("\\", "/"))
    return gone


def check_magic(root):
    """逐个 pyc 校验 magic，顺便统计。"""
    bad, ok = [], 0
    for dp, _dns, fns in os.walk(root):
        for fn in fns:
            if not fn.endswith(".pyc"):
                continue
            path = os.path.join(dp, fn)
            with open(path, "rb") as f:
                head = f.read(4)
            magic = struct.unpack("<H", head[:2])[0] if len(head) >= 2 else -1
            if magic != MAGIC_311:
                bad.append((os.path.relpath(path, root).replace("\\", "/"), magic))
            else:
                ok += 1
    return ok, bad


def check_import(py311, root):
    """真的 import 一次：sourceless 布局能不能加载，版本自检对不对。"""
    code = r"""
import importlib, os, sys
sys.path.insert(0, sys.argv[1])
plug = importlib.import_module("backend.plugin")
import pngu_unwrap, pngu_fetch, pngu_hijack, pngu_mount, pngu_proxy, pngu_sign
mods = [pngu_unwrap, pngu_fetch, pngu_hijack, pngu_mount, pngu_proxy, pngu_sign]
vers = {m.__name__: getattr(m, "__version__", "") for m in mods}
disk = {n: plug._disk_version(plug._module_file(m, n)) for n, m in zip(vers, mods)}
inst = plug.Plugin()
stale = inst._stale_modules()
worker = pngu_fetch.worker_script()
print("plugin file  :", plug.__file__)
print("mem  versions:", vers)
print("disk versions:", disk)
print("stale        :", stale)
print("worker       :", worker, "exists =", os.path.isfile(worker))
print("Plugin()     :", type(inst).__name__, "ok")
ok = (not stale
      and all(vers[k] == disk[k] for k in vers)
      and worker.endswith(".pyc")
      and str(plug.__file__).endswith(".pyc"))
print("RESULT:", "OK" if ok else "BAD")
sys.exit(0 if ok else 3)
"""
    proc = subprocess.run([py311, "-c", code, root],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return proc.returncode, (proc.stdout or b"").decode("utf-8", "replace").strip()


def make_zip(root, ver, out_dir, suffix=""):
    """打一个 zip。`suffix` 决定包名尾巴：pyc 包是 ".pyc"。

    两种包名：
        源码包  parser.pngunwrap-0.4.6.zip
        pyc 包  parser.pngunwrap-0.4.6.pyc.zip
    """
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    out = os.path.join(out_dir, "%s-%s%s.zip" % (NAME, ver, suffix))
    files = []
    for dp, _dns, fns in os.walk(root):
        for fn in fns:
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            files.append((full, rel))
    files.sort(key=lambda x: x[1])
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for full, rel in files:
            z.write(full, NAME + "/" + rel)
    return out, files


def make_src_zip(ver, out_dir):
    """源码包：直接打源目录，保留 .py 和 build.py。

    留着它是为了以后还能改 —— 源码包解压后改完，跑 `python build.py`
    就会同时产出新的源码包和 pyc 包。
    """
    files = []
    for dp, dns, fns in os.walk(HERE):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            if fn in SRC_SKIP_FILES or fn.endswith(SRC_SKIP_EXT):
                continue
            full = os.path.join(dp, fn)
            rel = os.path.relpath(full, HERE).replace("\\", "/")
            files.append((full, rel))
    files.sort(key=lambda x: x[1])
    if not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    out = os.path.join(out_dir, "%s-%s.zip" % (NAME, ver))
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for full, rel in files:
            z.write(full, NAME + "/" + rel)
    return out, files


def main():
    ap = argparse.ArgumentParser(description="把插件编译成只有 pyc 的发布包")
    ap.add_argument("--py311", default="", help="CPython 3.11 解释器路径")
    ap.add_argument("--work", default="", help="构建目录（默认系统临时目录）")
    ap.add_argument("--out", default="", help="输出目录（默认上级 dist/）")
    args = ap.parse_args()

    py311 = find_py311(args.py311)
    ver = read_version()
    work = args.work or os.path.join(tempfile.gettempdir(), "pngunwrap_build")
    out_dir = args.out or os.path.join(os.path.dirname(HERE), "dist")
    log("== 打包 %s %s（pyc 版）" % (NAME, ver))

    build = os.path.join(work, NAME)
    log("已复制 %d 个文件到 %s" % (stage(build), build))

    compile_all(py311, build)
    gone = drop_sources(build)
    log("已编译并删除 %d 个源码文件" % len(gone))

    ok, bad = check_magic(build)
    log("pyc magic 校验：%d 个正常，%d 个异常" % (ok, len(bad)))
    if bad:
        raise SystemExit("magic 不对（应为 %d）：%s" % (MAGIC_311, bad))

    code, out = check_import(py311, build)
    log("== 真导入验证（Python 3.11）==\n" + out)
    if code != 0:
        raise SystemExit("导入验证失败，退出码 %d" % code)

    out_zip, files = make_zip(build, ver, out_dir, ".pyc")
    log("\n产物（pyc）：%s" % out_zip)
    log("大小：%.1f KB，%d 个文件"
        % (os.path.getsize(out_zip) / 1024.0, len(files)))

    leftovers = [r for _f, r in files if r.endswith(".py")]
    log("包内 .py 残留：%s" % (leftovers or "无"))

    src_zip, src_files = make_src_zip(ver, out_dir)
    log("\n产物（源码）：%s" % src_zip)
    log("大小：%.1f KB，%d 个文件"
        % (os.path.getsize(src_zip) / 1024.0, len(src_files)))
    log("包内含 build.py：%s"
        % any(r == "build.py" for _f, r in src_files))

    for _f, rel in files:
        log("   " + NAME + "/" + rel)
    return 0 if not leftovers else 4


sys.exit(main())
