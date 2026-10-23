# -*- coding: utf-8 -*-
"""nbmovie_wasm_bg.wasm 的最小宿主 —— **只在子进程里使用**。

为什么必须隔离进程：
  wasmtime 是 ~29MB 的原生库，初始化时要申请可执行内存（JIT）。在部分
  NAS 内核 / 容器 seccomp 策略下这一步会直接把进程打死（SIGSEGV/SIGSYS），
  Python 的 try/except 兜不住。如果跑在 T3FAP 主进程里，崩的就是整个平台。
  所以签名一律走 pngu_sign_worker.py 子进程，崩也只崩这一集。

主进程（plugin.py）永远不 import 本模块，也不 import wasmtime。
"""

from __future__ import annotations

import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
WASM_FILENAME = "nbmovie_wasm_bg.wasm"


def wasm_path() -> str:
    """优先用插件自带的副本，其次复用 4k 插件目录里的同名文件。"""
    local = os.path.join(HERE, "vendor", WASM_FILENAME)
    if os.path.isfile(local):
        return local
    sibling = os.path.join(HERE, "..", "..", "parser.thirdparty.4k",
                           "backend", WASM_FILENAME)
    sibling = os.path.abspath(sibling)
    if os.path.isfile(sibling):
        return sibling
    return local


class Builder(object):
    """wasm-bindgen ABI 的最小宿主。

    只需要三类操作：把字符串写进线性内存 → 调用导出函数 → 从返回指针读字符串。
    document / nb-st / nb-plt 那几个 import 实测不参与签名（换任何值结果都不变），
    全部给空实现即可。
    """

    _err = ""

    def __init__(self, path=None):
        self.wasm_path = path or wasm_path()
        self._ready = False

    # ---------------------------------------------------------------- 初始化

    def _ensure(self):
        if self._ready:
            return True
        err = self._load()
        if err:
            Builder._err = err
            return False
        return True

    def _load(self):
        try:
            import wasmtime
        except Exception as e:                      # noqa: BLE001
            return "wasmtime 未就绪（%s）" % e
        if not os.path.isfile(self.wasm_path):
            return "缺少 wasm 模块文件 %s" % WASM_FILENAME
        try:
            from wasmtime import (Engine, Store, Linker, Module, Func,
                                  FuncType, ValType, Config)
        except Exception as e:                      # noqa: BLE001
            return "wasmtime 版本不兼容（%s）" % e

        I32, F64 = ValType.i32(), ValType.f64()
        MOD = "./nbmovie_wasm_bg.js"
        engine = self._engine(Engine, Config)
        store = Store(engine)
        module = Module.from_file(engine, self.wasm_path)
        linker = Linker(engine)
        self.store = store

        holder = {}

        def _throw(ptr, length):
            mem = holder.get("m")
            raw = bytes(mem.read(store, ptr, ptr + length)) if mem else b""
            raise RuntimeError(raw.decode("utf-8", "replace") or "wasm error")

        def defn(name, params, results, fn):
            linker.define(store, MOD, name,
                          Func(store, FuncType(params, results), fn))

        defn("__wbg___wbindgen_is_undefined_52709e72fb9f179c", [I32], [I32],
             lambda a: 0)
        defn("__wbindgen_object_drop_ref", [I32], [], lambda a: None)
        defn("__wbg_static_accessor_GLOBAL_8adb955bd33fac2f", [], [I32],
             lambda: 1)
        defn("__wbg_static_accessor_GLOBAL_THIS_ad356e0db91c7913", [], [I32],
             lambda: 1)
        defn("__wbg_static_accessor_WINDOW_bb9f1ba69d61b386", [], [I32],
             lambda: 1)
        defn("__wbg_static_accessor_SELF_f207c857566db248", [], [I32],
             lambda: 1)
        defn("__wbindgen_object_clone_ref", [I32], [I32], lambda a: a)
        defn("__wbg_instanceof_Window_23e677d2c6843922", [I32], [I32],
             lambda a: 0)
        defn("__wbg_document_c0320cd4183c6d9b", [I32], [I32], lambda a: 0)
        defn("__wbg_getElementById_d1f25d287b19a833", [I32, I32, I32], [I32],
             lambda a, b, c: 0)
        defn("__wbg_instanceof_HtmlMetaElement_07f78901e9785572", [I32], [I32],
             lambda a: 0)
        defn("__wbg_content_4373268a6f34e443", [I32, I32], [],
             lambda retptr, obj: None)
        defn("__wbg_now_16f0c993d5dd6c27", [], [F64],
             lambda: float(int(time.time() * 1000)))
        defn("__wbg___wbindgen_throw_6ddd609b62940d55", [I32, I32], [], _throw)

        inst = linker.instantiate(store, module)
        ex = inst.exports(store)
        mem = ex["memory"]
        holder["m"] = mem
        self.inst = inst
        self.mem = mem
        self.malloc = ex["__wbindgen_export"]
        self.stack = ex["__wbindgen_add_to_stack_pointer"]
        self.build_fn = ex["build_play_url"]
        self._ready = True
        return ""

    def _engine(self, Engine, Config):
        """保守的 Engine 配置。

        默认每块线性内存预留 4GB 虚拟地址（静态内存 + guard page），在
        NAS 容器或 ulimit -v 受限环境里最容易失败。wasm 只有 57KB，
        预留 16MB 绰绰有余。
        """
        try:
            cfg = Config()
            cfg.memory_reservation = 16 * 1024 * 1024
            cfg.memory_guard_size = 64 * 1024
            return Engine(cfg)
        except Exception:                           # noqa: BLE001
            return Engine()

    # ---------------------------------------------------------------- 调用

    def _put(self, text):
        data = str(text).encode("utf-8")
        ptr = self.malloc(self.store, len(data), 1)
        self.mem.write(self.store, data, ptr)
        return ptr, len(data)

    def _read(self, ptr, length):
        return bytes(self.mem.read(self.store, ptr, ptr + length))

    def build(self, data_id, secret_key, quality, play_key):
        """返回 `/video/play?...` 这样的相对路径。"""
        if not self._ensure():
            raise RuntimeError(Builder._err or "wasm 初始化失败")
        p0, l0 = self._put(data_id)
        p1, l1 = self._put(secret_key)
        p2, l2 = self._put(quality)
        p3, l3 = self._put(play_key)
        retptr = self.stack(self.store, -16)
        try:
            self.build_fn(self.store, retptr,
                          p0, l0, p1, l1, p2, l2, p3, l3)
            r0 = int.from_bytes(self._read(retptr, 4), "little")
            r1 = int.from_bytes(self._read(retptr + 4, 4), "little")
            return self._read(r0, r1).decode("utf-8", "replace")
        finally:
            self.stack(self.store, 16)


# 模块自述版本。plugin.py 会拿它和磁盘上的文件比对，不一致就说明平台热更新
# 只重载了 plugin 模块、子模块还留在 sys.modules 里，需要 importlib.reload。
__version__ = "0.4.1"
