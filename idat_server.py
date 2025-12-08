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

import ida_auto
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_pro
import idc
import ida_loader  # [关键] 用于显式保存数据库
import ida_typeinf
import ida_funcs

PORT = 12345

_RUNNING = True  # 控制主循环是否继续


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
    global _RUNNING
    # 如果已经正在退出中，避免重复执行
    if not _RUNNING and signum is None:
        return
    
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
        处理局部变量重命名请求：
        使用直接修改 lvar_t 对象并保存用户命名的方式，
        避免依赖 ida_hexrays.rename_lvar 等高层 API 在不同版本下的签名差异。
        """
        ea = payload.get("ea")
        renames = payload.get("renames") or {}

        if ea is None:
            return {"status": "error", "msg": "missing 'ea'"}

        # 转换 ea（支持十六进制和十进制字符串）
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
            return {"status": "error", "msg": "missing or invalid 'renames' dict"}

        if not init_hexrays():
            return {"status": "error", "msg": "Hex-Rays decompiler not available"}

        res: dict = {"status": "ok", "ea": ea, "applied": {}}

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
                return {
                    "status": "error",
                    "msg": f"decompile failed at 0x{func.start_ea:X}",
                }

            # 建立 name -> lvar 映射
            lvars = cfunc.get_lvars()
            lvars_by_name = {lv.name: lv for lv in lvars}

            applied: dict = {}
            modified = False

            for old_name, new_name in renames.items():
                if not isinstance(old_name, str) or not isinstance(new_name, str):
                    continue

                # 先按原名查找，若失败且不以 v 开头，尝试 v+old_name
                lvar = lvars_by_name.get(old_name)
                if not lvar and not old_name.startswith("v"):
                    lvar = lvars_by_name.get("v" + old_name)
                if not lvar:
                    continue

                # 清洗新名字，保持 C 风格
                raw_new = new_name.strip()
                safe_new = "".join(
                    c if (c.isalnum() or c == "_") else "_" for c in raw_new
                )
                if not safe_new:
                    continue
                if safe_new[0].isdigit():
                    safe_new = "v_" + safe_new

                if safe_new == lvar.name:
                    continue

                try:
                    # 直接修改 lvar_t 名字，并标记为用户命名
                    lvar.name = safe_new
                    if hasattr(lvar, "set_user_name"):
                        try:
                            lvar.set_user_name()
                        except Exception:
                            pass

                    applied[old_name] = safe_new
                    lvars_by_name[safe_new] = lvar
                    if old_name in lvars_by_name:
                        del lvars_by_name[old_name]

                    modified = True
                    print(
                        f"[IDAT-Server] Lvar rename at 0x{func.start_ea:X}: "
                        f"{old_name} -> {safe_new}"
                    )
                except Exception as exc:
                    print(f"[IDAT-Server] Error setting lvar name: {exc}")

            if modified:
                # 尝试保存局部变量用户设置
                if hasattr(cfunc, "save_user_lvars"):
                    try:
                        cfunc.save_user_lvars()
                    except Exception as exc:
                        print(f"[IDAT-Server] save_user_lvars failed: {exc}")
                        return {"status": "error", "msg": f"save failed: {exc}"}

                # 为了获取最新伪代码，可再次反编译
                try:
                    cfunc = ida_hexrays.decompile(func.start_ea)
                except Exception:
                    pass

            res["applied"] = applied

            # 获取最新伪代码
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

    def _handle_save_and_exit_request(self, payload: dict):
        """
        处理远程的 save_and_exit 请求。
        只设置标志位，实际的保存和退出交给主循环结束后的 cleanup 逻辑，
        或者通过 execute_sync 触发。
        """
        global _RUNNING
        print("[IDAT-Server] Received remote save_and_exit command.")
        _RUNNING = False
        # 我们这里不直接调用 qexit，而是让 handle_request 循环结束，
        # 然后在 main 函数最后统一调用 perform_cleanup_and_exit
        

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
