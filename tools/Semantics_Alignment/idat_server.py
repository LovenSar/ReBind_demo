#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
idat_server.py

在 IDA 的文本界面（idat）中运行的轻量级 HTTP 服务：
- 支持函数重命名、全局变量重命名、类型应用；
- 支持 Ctrl+C 优雅退出，自动保存数据库（避免残留 .id0/.id1 文件）；
- 支持远程 save_and_exit 指令。

启动方式：
    idat64 -A -S"path/to/idat_server.py" target.exe
"""

from __future__ import annotations

import http.server
import json
import socketserver
import sys
import signal
import os
import builtins
import inspect
from pathlib import Path
import re

import ida_auto
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_pro
import idc
import ida_loader  # [关键] 用于显式保存数据库
import ida_typeinf
import ida_funcs
import idautils

PORT = 12345

_RUNNING = True  # 控制主循环是否继续
_CLEANED_UP = False  # 确保清理逻辑只执行一次


def _install_print_with_location() -> None:
    """Prefix every print with absolute file path and line number."""
    if getattr(builtins, "_original_print", None):
        return

    builtins._original_print = builtins.print  # type: ignore[attr-defined]

    def _print_with_location(*args, **kwargs):
        frame = inspect.currentframe()
        if frame and frame.f_back:
            caller = frame.f_back
            path = Path(caller.f_code.co_filename).resolve()
            lineno = caller.f_lineno
            prefix = f"{path}:{lineno} "
        else:
            prefix = ""
        message = " ".join(str(a) for a in args)
        builtins._original_print(f"{prefix}{message}", **kwargs)

    builtins.print = _print_with_location  # type: ignore[assignment]


_install_print_with_location()


def init_hexrays() -> bool:
    """确保 Hex-Rays 已加载，可用于反编译。"""
    try:
        ok = ida_hexrays.init_hexrays_plugin()
    except Exception:
        ok = False
    if not ok:
        print("[IDAT-Server] Hex-Rays decompiler is NOT available.")
        return False
    print("[IDAT-Server] Hex-Rays initialized.")
    return True


# ==========================================
#  [关键] 优雅退出与清理逻辑
# ==========================================
def perform_cleanup_and_exit(signum=None, frame=None):
    """
    执行保存和退出操作。
    解决直接强制退出导致的 .id0/.id1 文件残留问题。
    """
    global _RUNNING, _CLEANED_UP
    # 幂等：清理只执行一次
    if _CLEANED_UP:
        return

    _CLEANED_UP = True
    _RUNNING = False
    
    print("\n" + "="*50)
    if signum is not None:
        print(f"[IDAT-Server] Caught Signal: {signum} (Ctrl+C). Preparing to exit...")
    else:
        print("[IDAT-Server] Shutdown requested via Logic/API.")

    # 1. 保存数据库 (这是避免临时文件残留的核心)
    # 使用 ida_loader.save_database 而不是 process_ui_action，更稳定
    print("[IDAT-Server] Saving database to .i64 file...")
    try:
        # 参数1: None 表示覆盖原数据库文件
        # 参数2: 0 表示默认标志 (DBFL_COMP 等)
        ida_loader.save_database(None, 0)
        print("[IDAT-Server] Database saved successfully.")
    except Exception as e:
        print(f"[IDAT-Server] ERROR saving database: {e}")

    # 2. 退出 IDA
    # qexit(0) 会触发 IDA 的清理流程，如果数据库已保存，它会合并临时文件
    print("[IDAT-Server] Exiting IDA now (cleaning up .id0/.id1 files)...")
    try:
        ida_pro.qexit(0)
    except Exception as e:
        print(f"[IDAT-Server] Error calling qexit: {e}")
        sys.exit(0)


class IDATRequestHandler(http.server.BaseHTTPRequestHandler):
    """处理来自外部脚本的 HTTP 请求。"""

    server_version = "IDATSync/1.0"

    def log_message(self, format: str, *args) -> None:
        # 静默输出
        return

    def do_POST(self) -> None:
        length_str = self.headers.get("Content-Length") or "0"
        try:
            length = int(length_str)
        except ValueError:
            length = 0

        body = self.rfile.read(length) if length > 0 else b""

        status_code = 500
        resp: dict = {"status": "error", "msg": "unknown error"}

        try:
            payload = json.loads(body.decode("utf-8") or "{}")
            action = payload.get("action")

            if action == "rename_and_sync":
                result = self._execute_in_main_thread(self._handle_rename_and_sync, payload)
                resp = result or {"status": "error", "msg": "no result"}
                status_code = 200
            elif action == "rename_global":
                result = self._execute_in_main_thread(self._handle_rename_global, payload)
                resp = result or {"status": "error", "msg": "no result"}
                status_code = 200
            elif action == "rename_lvar":
                result = self._execute_in_main_thread(self._handle_rename_lvar, payload)
                resp = result or {"status": "error", "msg": "no result"}
                status_code = 200
            elif action == "save_database":
                result = self._execute_in_main_thread(self._handle_save_database, payload)
                resp = result or {"status": "error", "msg": "no result"}
                status_code = 200
            elif action == "get_pseudocode":
                result = self._execute_in_main_thread(self._handle_get_pseudocode, payload)
                resp = result or {"status": "error", "msg": "no result"}
                status_code = 200
            elif action == "get_function_info":
                result = self._execute_in_main_thread(self._handle_get_function_info, payload)
                resp = result or {"status": "error", "msg": "no result"}
                status_code = 200
            elif action == "get_sub_functions":
                result = self._execute_in_main_thread(self._handle_get_sub_functions, payload)
                resp = result or {"status": "error", "msg": "no result"}
                status_code = 200
            elif action == "ping":
                resp = {"status": "ok", "msg": "pong"}
                status_code = 200
            elif action == "save_and_exit":
                # 处理远程退出指令
                self._handle_save_and_exit_request(payload)
                resp = {"status": "ok", "msg": "Server is saving and shutting down..."}
                status_code = 200
            else:
                resp = {"status": "error", "msg": f"unknown action: {action!r}"}
                status_code = 400
        except Exception as exc:
            resp = {"status": "error", "msg": f"{exc}"}
            status_code = 500

        # 发送响应
        try:
            data = json.dumps(resp).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception:
            pass

    # =========================
    # 线程调度辅助
    # =========================

    def _execute_in_main_thread(self, func, *args, **kwargs):
        class _Ctx:
            result = None
        ctx = _Ctx()
        def wrapper():
            ctx.result = func(*args, **kwargs)
            return 1
        ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_WRITE)
        return ctx.result

    # =========================
    # 业务逻辑处理
    # =========================

    def _handle_rename_and_sync(self, payload: dict) -> dict:
        ea = payload.get("ea")
        name = payload.get("name") or ""
        comment = payload.get("comment") or ""

        if ea is None:
            return {"status": "error", "msg": "missing 'ea'"}
        if isinstance(ea, str):
            try:
                ea = int(ea, 16)
            except ValueError:
                return {"status": "error", "msg": f"invalid ea: {ea!r}"}
        ea = int(ea)
        
        res: dict = {"status": "ok", "ea": ea}

        # 1) 重命名
        if name:
            safe = "".join(c if (c.isalnum() or c == "_") else "_" for c in str(name))
            if not safe:
                safe = f"func_{ea:X}"
            idc.set_name(ea, safe, idc.SN_NOWARN | idc.SN_NOCHECK)
            print(f"[IDAT-Server] Renamed 0x{ea:X} -> {safe}")
            res["new_name"] = safe

        # 2) 注释
        if comment:
            try:
                idc.set_func_cmt(ea, str(comment), 1)
            except Exception:
                pass

        # 3) 重新反编译
        updated_code: str | None = None
        try:
            if init_hexrays():
                try:
                    ida_hexrays.clear_cached_cfuncs()
                except Exception:
                    pass
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    lines = []
                    for pline in cfunc.get_pseudocode():
                        try:
                            text = ida_lines.tag_remove(pline.line)
                        except Exception:
                            text = str(pline.line)
                        lines.append(text)
                    updated_code = "\n".join(lines)
                    print(f"[IDAT-Server] Decompilation refreshed for 0x{ea:X}")
        except Exception as exc:
            print(f"[IDAT-Server] Decompile error for 0x{ea:X}: {exc}")

        res["updated_pseudocode"] = updated_code
        return res

    def _handle_rename_global(self, payload: dict) -> dict:
        """
        处理全局变量重命名和类型应用。
        使用更健壮的方式来解决 ida_typeinf.parse_decl 的参数兼容性问题。
        """
        ea = payload.get("ea")
        name = payload.get("name") or ""
        type_str = payload.get("type") or ""

        if ea is None:
            return {"status": "error", "msg": "missing 'ea'"}

        # 允许十六进制字符串或十进制字符串
        if isinstance(ea, str):
            s = ea.strip()
            try:
                if s.lower().startswith("0x"):
                    ea = int(s, 16)
                else:
                    ea = int(s)
            except ValueError:
                return {"status": "error", "msg": f"invalid ea: {ea!r}"}
        ea = int(ea)

        res: dict = {"status": "ok", "ea": ea}

        # 1) 重命名
        safe_name = ""
        if name:
            safe_name = "".join(
                c if (c.isalnum() or c == "_") else "_" for c in str(name)
            )
            if not safe_name:
                safe_name = f"g_{ea:X}"
            idc.set_name(ea, safe_name, idc.SN_NOWARN | idc.SN_NOCHECK)
            print(f"[IDAT-Server] Global renamed 0x{ea:X} -> {safe_name}")
            res["new_name"] = safe_name

        # 2) 应用类型（若提供）
        if type_str:
            success = False
            try:
                til = ida_typeinf.get_idati()
                tinfo = ida_typeinf.tinfo_t()

                # 策略 A：尝试作为已命名类型（int / bool / FARPROC / HANDLE 等）
                if tinfo.get_named_type(til, type_str):
                    if ida_typeinf.apply_tinfo(
                        ea, tinfo, ida_typeinf.TINFO_DEFINITE
                    ):
                        success = True

                # 策略 B：复杂类型（函数指针、struct 指针等），使用 idc.parse_decl
                if not success:
                    # 构造完整声明，例如 "int (*dummy_var_for_parse)(void);"
                    decl_str = f"{type_str} dummy_var_for_parse;"
                    parsed = idc.parse_decl(decl_str, 0)
                    # 现代 IDA：parse_decl 返回 (name, tinfo, fields)
                    if parsed and len(parsed) >= 2 and isinstance(
                        parsed[1], ida_typeinf.tinfo_t
                    ):
                        tinfo2 = parsed[1]
                        if ida_typeinf.apply_tinfo(
                            ea, tinfo2, ida_typeinf.TINFO_DEFINITE
                        ):
                            success = True
            except Exception as exc:
                print(
                    f"[IDAT-Server] Exception applying type '{type_str}' at 0x{ea:X}: {exc}"
                )

            if success:
                res["applied_type"] = type_str
                print(f"[IDAT-Server] Applied type '{type_str}' at 0x{ea:X}")
            else:
                print(
                    f"[IDAT-Server] Failed to apply type '{type_str}' at 0x{ea:X} "
                    "(all strategies failed)"
                )

        try:
            ida_hexrays.clear_cached_cfuncs()
        except Exception:
            pass

        return res

    def _handle_rename_lvar(self, payload: dict) -> dict:
        """
        处理局部变量重命名请求。
        改进版：更健壮的变量查找与应用。
        """
        ea = payload.get("ea")
        renames = payload.get("renames") or {}

        if ea is None:
            return {"status": "error", "msg": "missing 'ea'"}

        # 转换 ea
        if isinstance(ea, str):
            s = ea.strip()
            try:
                if s.lower().startswith("0x"):
                    ea = int(s, 16)
                else:
                    ea = int(s)
            except ValueError:
                return {"status": "error", "msg": f"invalid ea: {ea!r}"}
        ea = int(ea)

        if not isinstance(renames, dict) or not renames:
            # 如果 renames 为空，可能是 LLM 觉得无需修改，直接返回 ok
            return {"status": "ok", "ea": ea, "applied": {}}

        if not init_hexrays():
            return {"status": "error", "msg": "Hex-Rays decompiler not available"}

        res: dict = {"status": "ok", "ea": ea, "applied": {}}

        try:
            func = ida_funcs.get_func(ea)
            if not func:
                return {"status": "error", "msg": f"no function at 0x{ea:X}"}

            # 刷新缓存
            try:
                ida_hexrays.clear_cached_cfuncs()
            except Exception:
                pass

            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                return {"status": "error", "msg": f"decompile failed at 0x{func.start_ea:X}"}

            # 建立 name -> lvar 映射
            lvars = cfunc.get_lvars()
            lvars_by_name = {lv.name: lv for lv in lvars}

            # 同时也建立 stripped_name -> lvar 映射 (例如 "v1" -> lvar)
            # 用于处理可能的后缀差异 (LLM 说 v1, IDA 实际上是 v1_1)
            lvars_fuzzy = {}
            for lv in lvars:
                # 简单清洗名字，去掉末尾的 _数字
                base = re.sub(r"_\d+$", "", lv.name)
                if base not in lvars_fuzzy:
                    lvars_fuzzy[base] = lv
                lvars_fuzzy[lv.name] = lv  # 原始名字优先

            applied: dict = {}
            modified = False

            for old_name, new_name in renames.items():
                if not isinstance(old_name, str) or not isinstance(new_name, str):
                    continue

                # 1. 精确查找
                lvar = lvars_by_name.get(old_name)

                # 2. 模糊查找 (尝试去掉 LLM 可能忽略的后缀)
                if not lvar:
                    lvar = lvars_fuzzy.get(old_name)

                if not lvar:
                    print(
                        f"[IDAT-Server] Lvar '{old_name}' not found in 0x{ea:X}. "
                        f"Available: {list(lvars_by_name.keys())[:5]}..."
                    )
                    continue

                # 清洗新名字
                raw_new = new_name.strip()
                safe_new = "".join(c if (c.isalnum() or c == "_") else "_" for c in raw_new)
                if not safe_new:
                    continue
                if safe_new[0].isdigit():
                    safe_new = "v_" + safe_new

                if safe_new == lvar.name:
                    continue

                try:
                    # 关键修改：直接修改 lvar 对象并保存
                    print(
                        f"[IDAT-Server] Applying lvar rename 0x{ea:X}: "
                        f"{lvar.name} -> {safe_new}"
                    )

                    # 1. 尝试使用高层 API (如果可用)
                    if hasattr(ida_hexrays, "rename_lvar"):
                        ida_hexrays.rename_lvar(func.start_ea, lvar.name, safe_new)

                    # 2. 无论上面是否成功，直接操作 lvar_t 并调用 set_user_name
                    lvar.name = safe_new
                    lvar.set_user_name()

                    applied[old_name] = safe_new
                    modified = True

                except Exception as exc:
                    print(f"[IDAT-Server] Error setting lvar name {old_name}: {exc}")

            if modified:
                # 必须调用 save_user_lvars 才能持久化到数据库
                try:
                    cfunc.save_user_lvars()
                    # 再次刷新以确保生效
                    ida_hexrays.clear_cached_cfuncs()
                    cfunc = ida_hexrays.decompile(func.start_ea)
                except Exception as exc:
                    print(f"[IDAT-Server] save_user_lvars failed: {exc}")
                    return {"status": "error", "msg": f"save failed: {exc}"}

            res["applied"] = applied

            # 返回最新的伪代码供 knowledge_propagation.py 更新本地 DB
            updated_code: str | None = None
            if cfunc:
                try:
                    lines = []
                    for pline in cfunc.get_pseudocode():
                        try:
                            text = ida_lines.tag_remove(pline.line)
                        except Exception:
                            text = str(pline.line)
                        lines.append(text)
                    updated_code = "\n".join(lines)
                except Exception:
                    updated_code = None

            res["updated_pseudocode"] = updated_code
            return res

        except Exception as exc:
            import traceback

            traceback.print_exc()
            return {"status": "error", "msg": str(exc)}

    def _handle_save_database(self, payload: dict) -> dict:
        """单独触发一次数据库保存，避免退出。"""
        try:
            ida_loader.save_database(None, 0)
            print("[IDAT-Server] Database saved (manual request).")
            return {"status": "ok", "msg": "saved"}
        except Exception as exc:
            print(f"[IDAT-Server] save_database failed: {exc}")
            return {"status": "error", "msg": str(exc)}

    def _handle_get_pseudocode(self, payload: dict) -> dict:
        """返回指定函数的最新伪代码，用于重命名后的确认。"""
        ea = payload.get("ea")
        if ea is None:
            return {"status": "error", "msg": "missing 'ea'"}

        if isinstance(ea, str):
            s = ea.strip()
            try:
                if s.lower().startswith("0x"):
                    ea = int(s, 16)
                else:
                    ea = int(s)
            except ValueError:
                return {"status": "error", "msg": f"invalid ea: {ea!r}"}
        ea = int(ea)

        if not init_hexrays():
            return {"status": "error", "msg": "Hex-Rays decompiler not available"}

        try:
            func = ida_funcs.get_func(ea)
            if not func:
                return {"status": "error", "msg": f"no function at 0x{ea:X}"}

            try:
                ida_hexrays.clear_cached_cfuncs()
            except Exception:
                pass

            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                return {"status": "error", "msg": f"decompile failed at 0x{func.start_ea:X}"}

            lines = []
            for pline in cfunc.get_pseudocode():
                try:
                    text = ida_lines.tag_remove(pline.line)
                except Exception:
                    text = str(pline.line)
                lines.append(text)

            code = "\n".join(lines)
            return {"status": "ok", "ea": func.start_ea, "pseudocode": code}
        except Exception as exc:
            print(f"[IDAT-Server] get_pseudocode failed: {exc}")
            return {"status": "error", "msg": str(exc)}

    def _handle_get_function_info(self, payload: dict) -> dict:
        """返回指定函数的当前名称与伪代码。"""
        ea = payload.get("ea")
        if ea is None:
            return {"status": "error", "msg": "missing 'ea'"}

        if isinstance(ea, str):
            s = ea.strip()
            try:
                if s.lower().startswith("0x"):
                    ea = int(s, 16)
                else:
                    ea = int(s)
            except ValueError:
                return {"status": "error", "msg": f"invalid ea: {ea!r}"}
        ea = int(ea)

        name = idc.get_func_name(ea) or ""

        if not init_hexrays():
            return {"status": "error", "msg": "Hex-Rays decompiler not available"}

        try:
            func = ida_funcs.get_func(ea)
            if not func:
                return {"status": "error", "msg": f"no function at 0x{ea:X}"}

            try:
                ida_hexrays.clear_cached_cfuncs()
            except Exception:
                pass

            cfunc = ida_hexrays.decompile(func.start_ea)
            if not cfunc:
                return {"status": "error", "msg": f"decompile failed at 0x{func.start_ea:X}"}

            lines = []
            for pline in cfunc.get_pseudocode():
                try:
                    text = ida_lines.tag_remove(pline.line)
                except Exception:
                    text = str(pline.line)
                lines.append(text)

            code = "\n".join(lines)
            return {
                "status": "ok",
                "ea": func.start_ea,
                "name": name,
                "pseudocode": code,
            }
        except Exception as exc:
            print(f"[IDAT-Server] get_function_info failed: {exc}")
            return {"status": "error", "msg": str(exc)}

    def _handle_get_sub_functions(self, payload: dict) -> dict:
        """
        返回当前 IDB 中所有仍为默认 sub_ 前缀的函数列表。
        结果格式:
            {
                "status": "ok",
                "sub_functions": { ea(int): name(str), ... }
            }
        """
        pattern = re.compile(r"^sub_[0-9A-Fa-f]+$")
        result: dict[int, str] = {}

        try:
            for ea in idautils.Functions():
                try:
                    name = idc.get_func_name(ea) or ""
                except Exception:
                    name = ""
                name = name.strip()
                if not name:
                    continue
                if pattern.fullmatch(name):
                    result[int(ea)] = name
        except Exception as exc:
            print(f"[IDAT-Server] get_sub_functions failed: {exc}")
            return {"status": "error", "msg": str(exc)}

        return {"status": "ok", "sub_functions": result}

    def _handle_save_and_exit_request(self, payload: dict):
        """
        处理远程的 save_and_exit 请求。
        直接触发清理，避免遗漏。
        """
        global _RUNNING
        print("[IDAT-Server] Received remote save_and_exit command.")
        _RUNNING = False
        perform_cleanup_and_exit()
        

def _run_server():
    """
    主循环：设置超时以便能响应 Ctrl+C
    """
    global _RUNNING
    socketserver.TCPServer.allow_reuse_address = True
    
    with socketserver.TCPServer(("127.0.0.1", PORT), IDATRequestHandler) as httpd:
        # [关键] 设置超时，否则 handle_request 会无限阻塞，导致 Ctrl+C 无法被 Python 及时捕获
        httpd.timeout = 1.0 
        print(f"[IDAT-Server] Listening on http://127.0.0.1:{PORT} ...")
        print(f"[IDAT-Server] Press Ctrl+C to save and exit safely.")
        
        while _RUNNING:
            try:
                # handle_request 会处理一个请求，或者超时(1秒)返回
                httpd.handle_request()
            except KeyboardInterrupt:
                # 如果在 handle_request 期间捕获到中断，跳出循环
                break
            except Exception:
                pass
    
    print("[IDAT-Server] HTTP loop exited.")


def main():
    # 1. 注册信号处理，拦截 Ctrl+C
    signal.signal(signal.SIGINT, perform_cleanup_and_exit)
    signal.signal(signal.SIGTERM, perform_cleanup_and_exit)

    print("[IDAT-Server] Waiting for auto-analysis to finish...")
    try:
        ida_auto.auto_wait()
    except Exception:
        pass
    print("[IDAT-Server] Auto-analysis finished.")

    init_hexrays()

    print(f"[IDAT-Server] Server running. PID: {os.getpid()}")
    print("[IDAT-Server] Use Ctrl+C or POST {'action': 'save_and_exit'} to stop.")

    try:
        _run_server()
    except KeyboardInterrupt:
        pass
    
    # 2. 无论是因为 _RUNNING=False 退出，还是异常跳出，最后都尝试执行清理
    perform_cleanup_and_exit()


if __name__ == "__main__":
    main()
