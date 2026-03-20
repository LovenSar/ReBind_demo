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
import http.client
import json
import socketserver
import sys
import signal
import os
import atexit
import time
import builtins
import inspect
from pathlib import Path
import re

import ida_auto
import idaapi
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

# 逐行伪代码注释缓存：ea -> {line_no(1-based): comment}
_PSEUDOCODE_LINE_COMMENTS: dict[int, dict[int, str]] = {}
# 逐行伪代码行号到“代表性 EA”的缓存：func_ea -> {line_no(1-based): ea}
# 用于将行号注释转换为 Hex-Rays treeloc_t(ea, itp) 注释。
_PSEUDOCODE_LINE_EAS: dict[int, dict[int, int]] = {}

_RUNNING = True  # 控制主循环是否继续
_CLEANED_UP = False  # 确保清理逻辑只执行一次


def _install_print_with_location() -> None:
    """Prefix every print with absolute file path and line number.

    注意：该函数与 kp/kp_utils.py 中的 install_print_with_location 逻辑相同。
    因为 idat_server.py 在 IDA 内部环境（ida_hexrays/idc 等 SDK）中运行，
    无法依赖外部 kp 包，故在此保留独立副本。
    """
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

# Regex helpers for type normalization: split "A or B" and convert "[]"
_TYPE_VARIANT_SPLIT_RE = re.compile(r"\s+or\s+", re.IGNORECASE)
_ARRAY_BRACKETS_RE = re.compile(r"\[\s*\]")


def _generate_type_variants(type_str: str) -> list[str]:
    """
    Produce normalized type candidates (split `A or B`, expand array notation) for parsing attempts.
    """
    cleaned = type_str.strip().rstrip(";")
    if not cleaned:
        return []
    parts = _TYPE_VARIANT_SPLIT_RE.split(cleaned)
    seen: list[str] = []
    for part in parts:
        normalized = " ".join(part.split())
        if not normalized:
            continue
        if normalized not in seen:
            seen.append(normalized)
        if _ARRAY_BRACKETS_RE.search(normalized):
            pointer_variant = _ARRAY_BRACKETS_RE.sub("*", normalized)
            pointer_variant = " ".join(pointer_variant.split())
            if pointer_variant and pointer_variant not in seen:
                seen.append(pointer_variant)
    return seen


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


def _post_json(port: int, payload: dict, timeout_s: float = 1.5) -> tuple[int | None, str | None]:
    """向本机 IDAT-Server 发起 POST，返回 (status_code, response_text)。"""
    try:
        body = json.dumps(payload).encode("utf-8")
        conn = http.client.HTTPConnection("127.0.0.1", int(port), timeout=timeout_s)
        conn.request(
            "POST",
            "/",
            body=body,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "Content-Length": str(len(body)),
            },
        )
        resp = conn.getresponse()
        data = resp.read()
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = None
        return int(resp.status), text
    except Exception as exc:
        return None, str(exc)
    finally:
        try:
            conn.close()  # type: ignore[name-defined]
        except Exception:
            pass


def _request_remote_save_and_exit(port: int) -> bool:
    """若已有旧实例占用端口，尝试请求其 save_and_exit。"""
    status, text = _post_json(int(port), {"action": "save_and_exit"}, timeout_s=1.5)
    if status is None:
        # 旧版本可能在返回 HTTP 响应前就 qexit，导致连接被重置；这种情况下仍然很可能已触发退出
        msg = (text or "").lower()
        if any(k in msg for k in ("connection reset", "broken pipe", "connection aborted", "reset by peer")):
            print(f"[IDAT-Server] save_and_exit connection dropped (likely exiting): {text}")
            return True
        print(f"[IDAT-Server] save_and_exit request failed: {text}")
        return False
    ok = 200 <= status < 300
    if not ok:
        print(f"[IDAT-Server] save_and_exit request returned HTTP {status}: {text}")
    return ok


class _ReusableTCPServer(socketserver.TCPServer):
    # macOS 上端口回收更敏感：显式开启地址复用
    allow_reuse_address = True


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
            elif action == "set_pseudocode_line_comments":
                result = self._execute_in_main_thread(
                    self._handle_set_pseudocode_line_comments, payload
                )
                resp = result or {"status": "error", "msg": "no result"}
                status_code = 200
            elif action == "set_pseudocode_ea_comments":
                result = self._execute_in_main_thread(
                    self._handle_set_pseudocode_ea_comments, payload
                )
                resp = result or {"status": "error", "msg": "no result"}
                status_code = 200
            elif action == "get_sub_functions":
                result = self._execute_in_main_thread(self._handle_get_sub_functions, payload)
                resp = result or {"status": "error", "msg": "no result"}
                status_code = 200
            elif action == "get_functions":
                result = self._execute_in_main_thread(self._handle_get_functions, payload)
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

    def _parse_ea(self, payload: dict) -> int | None:
        ea = payload.get("ea")
        if ea is None:
            return None
        if isinstance(ea, str):
            s = ea.strip()
            try:
                if s.lower().startswith("0x"):
                    return int(s, 16)
                return int(s)
            except ValueError:
                return None
        try:
            return int(ea)
        except Exception:
            return None

    def _append_line_comments_to_pseudocode(
        self, ea: int, lines: list[str]
    ) -> list[str]:
        cmts = _PSEUDOCODE_LINE_COMMENTS.get(int(ea)) or {}
        if not cmts:
            return lines

        out: list[str] = []
        for idx, ln in enumerate(lines, 1):
            c = (cmts.get(int(idx)) or "").strip()
            if not c:
                out.append(ln)
                continue

            s = ln.rstrip("\r\n")
            ss = s.rstrip()
            if not ss or ss in ("{", "}"):
                out.append(ln)
                continue

            if "//" in ss:
                out.append(s + " | " + c)
            else:
                out.append(s + "  // " + c)
        return out

    def _try_apply_hexrays_line_comments(
        self,
        func_ea: int,
        line_comments: dict[int, str],
        line_eas: dict[int, int] | None = None,
    ) -> tuple[int, str]:
        """尽力将“伪代码行号->注释”写入 Hex-Rays。

        说明：IDA/Hex-Rays 的 Python API 在不同版本上存在差异，这里采用多种方式尝试。
        返回 (applied_count, method_name)。
        """

        if not init_hexrays():
            return 0, "no_hexrays"

        func = ida_funcs.get_func(func_ea)
        if not func:
            return 0, "no_func"

        try:
            ida_hexrays.clear_cached_cfuncs()
        except Exception:
            pass

        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
        except Exception:
            cfunc = None
        if not cfunc:
            return 0, "decompile_failed"

        # 方式 A（IDA 9.2 / Hex-Rays 推荐）：cfunc.set_user_cmt(treeloc_t, text)
        # 参考最小示例：
        #   tl = hx.treeloc_t(); tl.ea = ea; tl.itp = idaapi.ITP_SEMI
        #   cfunc.set_user_cmt(tl, comment); cfunc.save_user_cmts(); cfunc.refresh_func_ctext()
        if hasattr(ida_hexrays, "treeloc_t") and hasattr(cfunc, "set_user_cmt"):
            applied = 0
            for lnnum, text in sorted(line_comments.items()):
                comment = (text or "").strip()
                if not comment:
                    continue
                try:
                    tl = ida_hexrays.treeloc_t()  # type: ignore[attr-defined]

                    # 关键：用“该伪代码行代表的 EA”来定位 treeloc。
                    # 若缺失映射，则退回函数起始地址（可能会导致注释聚集到同一行）。
                    line_ea = None
                    if line_eas is not None:
                        try:
                            line_ea = int(line_eas.get(int(lnnum)) or 0)
                        except Exception:
                            line_ea = None
                    if not line_ea:
                        line_ea = int(func.start_ea)

                    try:
                        tl.ea = int(line_ea)
                    except Exception:
                        pass

                    # 常用：行尾注释
                    try:
                        tl.itp = idaapi.ITP_SEMI
                    except Exception:
                        # 兼容：某些环境下常量可从 idaapi/ida_lines 等导入；失败就不设置
                        pass

                    cfunc.set_user_cmt(tl, comment)
                    applied += 1
                except Exception:
                    continue

            if applied > 0:
                try:
                    if hasattr(cfunc, "save_user_cmts"):
                        cfunc.save_user_cmts()
                    if hasattr(cfunc, "refresh_func_ctext"):
                        cfunc.refresh_func_ctext()
                    ida_kernwin.refresh_idaview_anyway()
                except Exception:
                    pass
                return applied, "cfunc.set_user_cmt"

        # 方式 B：set_user_cmt(cfunc, treeloc_t, text)（旧式全局函数）
        if hasattr(ida_hexrays, "set_user_cmt") and hasattr(ida_hexrays, "treeloc_t"):
            applied = 0
            for lnnum, text in sorted(line_comments.items()):
                comment = (text or "").strip()
                if not comment:
                    continue
                try:
                    tl = ida_hexrays.treeloc_t()  # type: ignore[attr-defined]
                    line_ea = None
                    if line_eas is not None:
                        try:
                            line_ea = int(line_eas.get(int(lnnum)) or 0)
                        except Exception:
                            line_ea = None
                    if not line_ea:
                        line_ea = int(func.start_ea)

                    if hasattr(tl, "ea"):
                        try:
                            tl.ea = int(line_ea)
                        except Exception:
                            pass

                    try:
                        tl.itp = idaapi.ITP_SEMI
                    except Exception:
                        pass

                    ida_hexrays.set_user_cmt(cfunc, tl, comment)  # type: ignore[attr-defined]
                    applied += 1
                except Exception:
                    continue
            if applied > 0:
                try:
                    ida_kernwin.refresh_idaview_anyway()
                except Exception:
                    pass
                return applied, "ida_hexrays.set_user_cmt"

        # 方式 B：user_cmts_t + restore/save
        if (
            hasattr(ida_hexrays, "user_cmts_t")
            and hasattr(ida_hexrays, "restore_user_cmts")
            and hasattr(ida_hexrays, "save_user_cmts")
            and hasattr(ida_hexrays, "treeloc_t")
        ):
            try:
                cmts = ida_hexrays.user_cmts_t()  # type: ignore[attr-defined]
                ida_hexrays.restore_user_cmts(cfunc, cmts)  # type: ignore[attr-defined]

                applied = 0
                for lnnum, text in sorted(line_comments.items()):
                    comment = (text or "").strip()
                    if not comment:
                        continue
                    try:
                        tl = ida_hexrays.treeloc_t()  # type: ignore[attr-defined]
                        for attr, val in (
                            ("ea", int(func.start_ea)),
                            ("lnnum", int(lnnum)),
                            ("line", int(lnnum)),
                        ):
                            try:
                                if hasattr(tl, attr):
                                    setattr(tl, attr, val)
                            except Exception:
                                pass

                        if hasattr(cmts, "__setitem__"):
                            cmts[tl] = comment  # type: ignore[index]
                            applied += 1
                        elif hasattr(cmts, "add"):
                            cmts.add(tl, comment)  # type: ignore[attr-defined]
                            applied += 1
                    except Exception:
                        continue

                ida_hexrays.save_user_cmts(cfunc, cmts)  # type: ignore[attr-defined]
                if applied > 0:
                    try:
                        ida_kernwin.refresh_idaview_anyway()
                    except Exception:
                        pass
                    return applied, "user_cmts"
            except Exception:
                pass

        return 0, "unsupported"

    def _try_apply_hexrays_ea_comments(
        self,
        func_ea: int,
        ea_comments: dict[int, str],
    ) -> tuple[int, str]:
        """尽力将“EA->注释”写入 Hex-Rays（treeloc_t.ea 定位）。"""

        if not init_hexrays():
            return 0, "no_hexrays"

        func = ida_funcs.get_func(func_ea)
        if not func:
            return 0, "no_func"

        try:
            ida_hexrays.clear_cached_cfuncs()
        except Exception:
            pass

        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
        except Exception:
            cfunc = None
        if not cfunc:
            return 0, "decompile_failed"

        if hasattr(ida_hexrays, "treeloc_t") and hasattr(cfunc, "set_user_cmt"):
            applied = 0
            for ea, text in sorted(ea_comments.items()):
                # 仅对该函数范围内的 EA 写注释，避免产生大量“Orphan comments”
                try:
                    iea = int(ea)
                except Exception:
                    continue
                try:
                    if iea < int(func.start_ea) or iea >= int(func.end_ea):
                        continue
                except Exception:
                    pass

                comment = (text or "").strip()
                if not comment:
                    continue
                try:
                    tl = ida_hexrays.treeloc_t()  # type: ignore[attr-defined]
                    try:
                        tl.ea = int(iea)
                    except Exception:
                        pass
                    try:
                        tl.itp = idaapi.ITP_SEMI
                    except Exception:
                        pass
                    cfunc.set_user_cmt(tl, comment)
                    applied += 1
                except Exception:
                    continue

            if applied > 0:
                try:
                    if hasattr(cfunc, "save_user_cmts"):
                        cfunc.save_user_cmts()
                    if hasattr(cfunc, "refresh_func_ctext"):
                        cfunc.refresh_func_ctext()
                    ida_kernwin.refresh_idaview_anyway()
                except Exception:
                    pass
                return applied, "cfunc.set_user_cmt"

        return 0, "unsupported"

    def _handle_rename_and_sync(self, payload: dict) -> dict:
        ea = payload.get("ea")
        name = payload.get("name") or ""
        comment = payload.get("comment") or ""
        emit_pseudocode = bool(payload.get("emit_pseudocode", True))

        if ea is None:
            return {"status": "error", "msg": "missing 'ea'"}
        if isinstance(ea, str):
            try:
                ea = int(ea, 16)
            except ValueError:
                return {"status": "error", "msg": f"invalid ea: {ea!r}"}
        ea = int(ea)
        
        res: dict = {"status": "ok", "ea": ea}
        set_type_func = getattr(idc, "set_type", None)
        set_type_name = "set_type"
        if not set_type_func:
            set_type_func = getattr(idc, "SetType", None)
            set_type_name = "SetType" if set_type_func else None
        set_type_missing_logged = False

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
                if emit_pseudocode:
                    try:
                        ida_hexrays.clear_cached_cfuncs()
                    except Exception:
                        pass
                cfunc = ida_hexrays.decompile(ea)
                if emit_pseudocode and cfunc:
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
        set_type_func = getattr(idc, "set_type", None)
        set_type_name = "set_type"
        if not set_type_func:
            set_type_func = getattr(idc, "SetType", None)
            set_type_name = "SetType" if set_type_func else None
        set_type_missing_logged = False

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
            applied_variant = None
            candidates = _generate_type_variants(type_str)
            if not candidates:
                candidates = [type_str.strip()]

            try:
                til = ida_typeinf.get_idati()
            except Exception as exc:
                til = None
                print(
                    f"[IDAT-Server] Exception getting til for '{type_str}' at 0x{ea:X}: {exc}"
                )

            for candidate in candidates:
                candidate = candidate.strip()
                if not candidate:
                    continue

                candidate_success = False
                try:
                    tinfo = ida_typeinf.tinfo_t()
                    if til and tinfo.get_named_type(til, candidate):
                        if ida_typeinf.apply_tinfo(
                            ea, tinfo, ida_typeinf.TINFO_DEFINITE
                        ):
                            candidate_success = True

                    if not candidate_success:
                        decl_str = f"{candidate} dummy_var_for_parse;"
                        parsed = idc.parse_decl(decl_str, 0)
                        if parsed and len(parsed) >= 2 and isinstance(
                            parsed[1], ida_typeinf.tinfo_t
                        ):
                            tinfo2 = parsed[1]
                            if ida_typeinf.apply_tinfo(
                                ea, tinfo2, ida_typeinf.TINFO_DEFINITE
                            ):
                                candidate_success = True
                except Exception as exc:
                    print(
                        f"[IDAT-Server] Exception applying variant '{candidate}' "
                        f"for '{type_str}' at 0x{ea:X}: {exc}"
                    )

                if not candidate_success:
                    if set_type_func:
                        try:
                            if set_type_func(ea, candidate):
                                candidate_success = True
                        except Exception as exc:
                            func_name = set_type_name or "set_type/SetType"
                            print(
                                f"[IDAT-Server] {func_name} failed for variant '{candidate}' "
                                f"from '{type_str}' at 0x{ea:X}: {exc}"
                            )
                    elif not set_type_missing_logged:
                        set_type_missing_logged = True
                        print(
                            "[IDAT-Server] idc.set_type/SetType is unavailable in this build; "
                            "skipping the legacy fallback."
                        )

                if candidate_success:
                    success = True
                    applied_variant = candidate
                    break

            if success:
                applied_log = applied_variant or type_str
                res["applied_type"] = applied_log
                print(
                    f"[IDAT-Server] Applied type '{applied_log}' at 0x{ea:X} "
                    f"(requested '{type_str}')"
                )
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
        emit_pseudocode = bool(payload.get("emit_pseudocode", True))
        persist_database = bool(payload.get("persist_database", True))

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

                # 避免将全局地址样式的名字当作局部变量改名
                if re.match(r"^(qword|dword|byte|word|off|asc|unk|stru|loc)_", old_name):
                    print(
                        f"[IDAT-Server] Skip global-like name '{old_name}' in 0x{ea:X}"
                    )
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
                    print(
                        f"[IDAT-Server] Applying lvar rename 0x{ea:X}: "
                        f"{lvar.name} -> {safe_new}"
                    )

                    rename_done = False

                    # 1. 优先使用官方高层 API（会尝试持久化）
                    if hasattr(ida_hexrays, "rename_lvar"):
                        try:
                            rename_done = bool(
                                ida_hexrays.rename_lvar(func.start_ea, lvar.name, safe_new)
                            )
                        except Exception as exc:
                            print(f"[IDAT-Server] ida_hexrays.rename_lvar failed: {exc}")

                    # 2. 兼容旧版：直接修改 lvar_t 并标记用户名称
                    if not rename_done:
                        lvar.name = safe_new
                        lvar.set_user_name()
                        rename_done = True

                    if rename_done:
                        applied[old_name] = safe_new
                        modified = True

                except Exception as exc:
                    print(f"[IDAT-Server] Error setting lvar name {old_name}: {exc}")

            if modified:
                # 尝试持久化：新版 API 可直接保存，旧版依赖 save_user_lvars
                try:
                    if hasattr(cfunc, "save_user_lvars"):
                        cfunc.save_user_lvars()
                except Exception as exc:
                    print(f"[IDAT-Server] save_user_lvars failed: {exc}")

                if emit_pseudocode:
                    try:
                        ida_hexrays.clear_cached_cfuncs()
                    except Exception:
                        pass

                try:
                    idc.mark_position(func.start_ea, 1, 0, 0, 0, "")
                except Exception:
                    pass

                if persist_database:
                    try:
                        ida_loader.save_database(None, 0)
                    except Exception as exc:
                        print(f"[IDAT-Server] save_database failed: {exc}")

                if emit_pseudocode:
                    try:
                        cfunc = ida_hexrays.decompile(func.start_ea)
                    except Exception:
                        cfunc = None
                else:
                    cfunc = None

            res["applied"] = applied

            # 返回最新的伪代码供 knowledge_propagation.py 更新本地 DB
            updated_code: str | None = None
            if emit_pseudocode and cfunc:
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

            lines: list[str] = []
            pseudocode_lines: list[dict] = []
            line_eas: dict[int, int] = {}
            for idx, pline in enumerate(cfunc.get_pseudocode(), 1):
                try:
                    text = ida_lines.tag_remove(pline.line)
                except Exception:
                    text = str(pline.line)

                pea = None
                try:
                    pea = int(getattr(pline, "ea", 0) or 0)
                except Exception:
                    pea = None
                if pea:
                    line_eas[int(idx)] = int(pea)

                lines.append(text)
                pseudocode_lines.append({"no": int(idx), "ea": int(pea or 0), "text": text})

            # 缓存 line_no->ea 映射，便于后续 set_pseudocode_line_comments 精准落点
            if line_eas:
                _PSEUDOCODE_LINE_EAS[int(func.start_ea)] = dict(line_eas)

            # 若已设置逐行注释，则在返回文本中附带行尾注释（便于外部脚本刷新 DB）
            lines = self._append_line_comments_to_pseudocode(int(func.start_ea), lines)

            code = "\n".join(lines)
            return {
                "status": "ok",
                "ea": int(func.start_ea),
                "pseudocode": code,
                "pseudocode_lines": pseudocode_lines,
                "line_eas": {str(k): int(v) for k, v in line_eas.items()},
            }
        except Exception as exc:
            print(f"[IDAT-Server] get_pseudocode failed: {exc}")
            return {"status": "error", "msg": str(exc)}

    def _handle_get_function_info(self, payload: dict) -> dict:
        """返回指定函数的当前名称与伪代码。"""
        include_disasm = bool(payload.get("include_disasm") or False)
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

            lines: list[str] = []
            pseudocode_lines: list[dict] = []
            line_eas: dict[int, int] = {}
            for idx, pline in enumerate(cfunc.get_pseudocode(), 1):
                try:
                    text = ida_lines.tag_remove(pline.line)
                except Exception:
                    text = str(pline.line)

                pea = None
                try:
                    pea = int(getattr(pline, "ea", 0) or 0)
                except Exception:
                    pea = None
                if pea:
                    line_eas[int(idx)] = int(pea)

                lines.append(text)
                pseudocode_lines.append({"no": int(idx), "ea": int(pea or 0), "text": text})

            # 缓存 line_no->ea 映射，便于后续 set_pseudocode_line_comments 精准落点
            if line_eas:
                _PSEUDOCODE_LINE_EAS[int(func.start_ea)] = dict(line_eas)

            lines = self._append_line_comments_to_pseudocode(int(func.start_ea), lines)

            code = "\n".join(lines)

            disasm_lines: list[dict] = []
            if include_disasm:
                try:
                    for insn_ea in idautils.FuncItems(func.start_ea):
                        try:
                            dtext = idc.generate_disasm_line(insn_ea, 0) or ""
                        except Exception:
                            try:
                                dtext = idc.GetDisasm(insn_ea) or ""
                            except Exception:
                                dtext = ""
                        if dtext:
                            disasm_lines.append({"ea": int(insn_ea), "text": dtext})
                except Exception:
                    disasm_lines = []

            return {
                "status": "ok",
                "ea": int(func.start_ea),
                "name": name,
                "pseudocode": code,
                "pseudocode_lines": pseudocode_lines,
                "line_eas": {str(k): int(v) for k, v in line_eas.items()},
                "disassembly": disasm_lines,
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

    def _handle_get_functions(self, payload: dict) -> dict:
        """
        返回当前 IDB 中所有函数的列表（包括地址和名称）。
        结果格式:
            {
                "status": "success",
                "functions": { ea(int): name(str), ... }
            }
        """
        result: dict[int, str] = {}

        try:
            for ea in idautils.Functions():
                try:
                    name = idc.get_func_name(ea) or ""
                except Exception:
                    name = ""
                name = name.strip()
                if name:
                    result[int(ea)] = name
        except Exception as exc:
            print(f"[IDAT-Server] get_functions failed: {exc}")
            return {"status": "error", "message": str(exc)}

        return {"status": "success", "functions": result}

    def _handle_set_pseudocode_line_comments(self, payload: dict) -> dict:
        """为指定函数设置“伪代码行注释”。

                payload:
                    - ea: 函数地址
                    - line_comments: {"1": "...", "2": "..."}
                    - line_eas (optional): {"1": 268... , "2": 268...}  # 行号对应的代表性 EA

        注意：不同 IDA/Hex-Rays 版本对“行注释”的支持能力不同。
        - 若可写入 Hex-Rays user comments，会尽力应用并 refresh
        - 无法写入时仍会缓存，供 get_pseudocode 返回带注释文本
        """

        ea = self._parse_ea(payload)
        if ea is None:
            return {"status": "error", "msg": "missing/invalid 'ea'"}

        raw = payload.get("line_comments")
        if not isinstance(raw, dict):
            return {"status": "error", "msg": "missing/invalid 'line_comments'"}

        raw_line_eas = payload.get("line_eas")
        parsed_line_eas: dict[int, int] = {}
        if isinstance(raw_line_eas, dict):
            for k, v in raw_line_eas.items():
                try:
                    idx = int(str(k).strip())
                    vea = int(str(v).strip(), 16) if isinstance(v, str) and str(v).strip().lower().startswith("0x") else int(v)
                except Exception:
                    continue
                if idx <= 0:
                    continue
                if vea <= 0:
                    continue
                parsed_line_eas[int(idx)] = int(vea)

        normalized: dict[int, str] = {}
        for k, v in raw.items():
            try:
                idx = int(str(k).strip())
            except Exception:
                continue
            if idx <= 0:
                continue
            text = (str(v) if v is not None else "").strip()
            if not text:
                continue
            # 简单裁剪，避免单行注释过长导致视图很难读
            if len(text) > 200:
                text = text[:200] + "..."
            normalized[idx] = text

        if not normalized:
            return {"status": "ok", "ea": int(ea), "applied": 0, "method": "none"}

        # 始终缓存一份（用于 get_pseudocode 返回行尾注释文本）
        # 注意：这里要“合并”而不是覆盖，支持分块增量提交。
        existing_cmts = _PSEUDOCODE_LINE_COMMENTS.get(int(ea)) or {}
        existing_cmts.update(normalized)
        _PSEUDOCODE_LINE_COMMENTS[int(ea)] = dict(existing_cmts)

        # 同步缓存一份 line_no->ea 映射（优先使用 payload 传入的；否则沿用最近一次反编译缓存）
        # 同样使用合并，支持多次提交逐步补全映射。
        if parsed_line_eas:
            existing_eas = _PSEUDOCODE_LINE_EAS.get(int(ea)) or {}
            existing_eas.update(parsed_line_eas)
            _PSEUDOCODE_LINE_EAS[int(ea)] = dict(existing_eas)
            parsed_line_eas = existing_eas
        else:
            parsed_line_eas = _PSEUDOCODE_LINE_EAS.get(int(ea)) or {}

        applied, method = self._try_apply_hexrays_line_comments(
            int(ea),
            normalized,
            line_eas=parsed_line_eas or None,
        )
        return {
            "status": "ok",
            "ea": int(ea),
            "applied": int(applied),
            "cached": len(normalized),
            "method": method,
        }

    def _handle_set_pseudocode_ea_comments(self, payload: dict) -> dict:
        """为指定函数设置“按汇编地址(EA)定位”的伪代码行注释。

        payload:
            - ea: 函数地址
            - ea_comments: {"0x140001000": "...", "140001234": "..."}

        说明：这里直接按 EA 构造 treeloc_t(ea, ITP_SEMI) 写入 Hex-Rays user comments。
        """

        func_ea = self._parse_ea(payload)
        if func_ea is None:
            return {"status": "error", "msg": "missing/invalid 'ea'"}

        raw = payload.get("ea_comments")
        if not isinstance(raw, dict):
            return {"status": "error", "msg": "missing/invalid 'ea_comments'"}

        normalized: dict[int, str] = {}
        for k, v in raw.items():
            try:
                s = str(k).strip()
                ea = int(s, 16) if s.lower().startswith("0x") else int(s)
            except Exception:
                continue
            if ea <= 0:
                continue
            text = (str(v) if v is not None else "").strip()
            if not text:
                continue
            # 与 line_comments 一致：避免过长、避免以 // 开头
            text = re.sub(r"^\s*//+\s*", "", text)
            text = text.replace("\r", " ").replace("\n", " ").strip()
            if len(text) > 200:
                text = text[:200] + "..."

            # 同一 EA 多次提交时做合并，避免覆盖丢信息
            prev = normalized.get(ea)
            if prev and text and text != prev:
                normalized[ea] = prev + " | " + text
            else:
                normalized[ea] = text

        if not normalized:
            return {"status": "ok", "ea": int(func_ea), "applied": 0, "method": "none"}

        applied, method = self._try_apply_hexrays_ea_comments(int(func_ea), normalized)
        return {
            "status": "ok",
            "ea": int(func_ea),
            "applied": int(applied),
            "count": len(normalized),
            "method": method,
        }

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

    with _ReusableTCPServer(("127.0.0.1", PORT), IDATRequestHandler) as httpd:
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


def _run_server_with_port_recovery(
    max_attempts: int = 6,
    base_wait_s: float = 0.8,
    after_exit_wait_s: float = 2.0,
) -> None:
    """启动服务；若遇到 Errno 48，则请求旧实例 save_and_exit 后重试。"""
    for attempt in range(1, max_attempts + 1):
        try:
            _run_server()
            return
        except OSError as exc:
            # macOS: 48, Linux: 98, Windows: 10048
            err = getattr(exc, "errno", None)
            if err not in (48, 98, 10048):
                raise

            print(
                f"[IDAT-Server] [Errno {err}] Address already in use on 127.0.0.1:{PORT} "
                f"(attempt {attempt}/{max_attempts})."
            )

            requested = _request_remote_save_and_exit(PORT)
            if requested:
                print("[IDAT-Server] Requested existing server to save_and_exit; waiting...")
                time.sleep(after_exit_wait_s)
            else:
                # 可能不是我们的服务占用，或旧实例已卡死；等待后继续重试
                time.sleep(base_wait_s * attempt)

    raise RuntimeError(f"[IDAT-Server] Failed to bind port {PORT} after {max_attempts} attempts")


def main():
    # 1. 注册信号处理，拦截 Ctrl+C
    signal.signal(signal.SIGINT, perform_cleanup_and_exit)
    signal.signal(signal.SIGTERM, perform_cleanup_and_exit)

    # 2. 无论何种退出路径（异常/脚本结束），都触发与 Ctrl+C 相同的安全清理流程
    atexit.register(perform_cleanup_and_exit)

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
        _run_server_with_port_recovery()
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        # 这里不能直接抛出，否则会导致 IDA 以异常路径退出而不清理临时文件
        print(f"[IDAT-Server] Fatal error: {exc}")
    finally:
        # 无论是因为 _RUNNING=False 退出，还是异常跳出，最后都尝试执行清理
        perform_cleanup_and_exit()


if __name__ == "__main__":
    main()
