"""kp_ida.py

IDA(idat_server) 交互层：封装 HTTP 调用、在线探测与常用操作。

目标：让 pipeline/phase 代码只关心“做什么”，不关心 requests/超时/错误处理细节。
"""

from __future__ import annotations

import logging
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None


logger = logging.getLogger(__name__)


def wait_for_ida_server(ida_url: str) -> None:
    """检查与 idat_server 的连接情况。"""
    if requests is None:
        return

    while True:
        try:
            resp = requests.post(
                ida_url,
                json={"action": "ping"},
                timeout=3.0,
            )
            if resp.status_code == 200:
                return
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            msg = (
                f"[IDA-Sync] 无法连接到 IDA 服务器 {ida_url}: {exc}。"
                " 将在 30 秒后自动重试，按回车可立即重试，Ctrl+C 终止。"
            )
            print(msg)
            logger.warning("%s", msg)

            user_triggered: List[Optional[bool]] = [None]

            def _wait_input() -> None:
                try:
                    input()
                    user_triggered[0] = True
                except EOFError:
                    user_triggered[0] = False

            t: Optional[threading.Thread] = None
            if sys.stdin and sys.stdin.isatty():
                t = threading.Thread(target=_wait_input, daemon=True)
                t.start()

            start = time.time()
            while True:
                if user_triggered[0] is not None:
                    break
                if time.time() - start >= 30.0:
                    break
                time.sleep(0.2)


class IDAService:
    """封装与 idat_server 的 HTTP 通信与错误处理。"""

    def __init__(self, url: Optional[str], enabled: bool = False):
        self.url = (url or "").strip() or "http://127.0.0.1:12345"
        self.enabled = bool(enabled) and (requests is not None) and bool(self.url)
        self._checked_online = False

    def ensure_online(self) -> None:
        if not self.enabled:
            return
        if self._checked_online:
            return
        try:
            wait_for_ida_server(self.url)
            self._checked_online = True
        except Exception:
            self._checked_online = False

    def request(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
        timeout: float = 10.0,
        ensure_online: bool = True,
    ) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        if ensure_online:
            self.ensure_online()

        full_payload: Dict[str, Any] = {"action": action}
        if payload:
            full_payload.update(payload)

        try:
            resp = requests.post(self.url, json=full_payload, timeout=float(timeout))  # type: ignore[union-attr]
        except Exception as exc:
            self._checked_online = False
            logger.error("[IDA-Sync] %s failed: %s", action, exc)
            return None

        if resp.status_code != 200:
            logger.error(
                "[IDA-Sync] %s HTTP %s: %s",
                action,
                resp.status_code,
                (resp.text or "")[:200],
            )
            return None

        try:
            data = resp.json()
        except Exception as exc:
            logger.error(
                "[IDA-Sync] %s invalid JSON: %s; body=%s",
                action,
                exc,
                (resp.text or "")[:200],
            )
            return None

        if not isinstance(data, dict) or data.get("status") != "ok":
            logger.warning("[IDA-Sync] %s remote error: %s", action, data)
            return None

        return data

    def rename_global(self, ea: int, name: str, type_str: str = "") -> Optional[Dict[str, Any]]:
        return self.request("rename_global", {"ea": int(ea), "name": name, "type": type_str or ""})

    def rename_and_sync(self, ea: int, name: str, comment: str) -> Tuple[Optional[str], Optional[str]]:
        data = self.request(
            "rename_and_sync",
            {"ea": int(ea), "name": name, "comment": comment},
            timeout=10.0,
        )
        if not data:
            return None, None
        return (data.get("new_name") or name), (data.get("updated_pseudocode") or None)

    def save_database(self, timeout: float = 15.0) -> bool:
        return bool(self.request("save_database", timeout=timeout))

    def get_pseudocode(self, ea: int, timeout: float = 10.0) -> Optional[str]:
        data = self.request("get_pseudocode", {"ea": int(ea)}, timeout=timeout)
        if not data:
            return None
        code = data.get("pseudocode")
        return code if isinstance(code, str) else None

    def get_function_info(
        self, ea: int, include_disasm: bool = True, timeout: float = 10.0
    ) -> Optional[Dict[str, Any]]:
        return self.request(
            "get_function_info",
            {"ea": int(ea), "include_disasm": bool(include_disasm)},
            timeout=timeout,
        )

    def get_sub_functions(self, timeout: float = 30.0) -> Optional[Dict[str, Any]]:
        return self.request("get_sub_functions", timeout=timeout)

    def rename_lvar(self, ea: int, renames: Dict[str, str], timeout: float = 10.0) -> Optional[str]:
        data = self.request(
            "rename_lvar",
            {"ea": int(ea), "renames": renames},
            timeout=timeout,
        )
        if not data:
            return None
        updated_code = data.get("updated_pseudocode")
        return updated_code if isinstance(updated_code, str) and updated_code.strip() else None

    def set_pseudocode_line_comments(
        self,
        ea: int,
        comments: Dict[str, str],
        line_eas: Dict[str, int],
        timeout: float = 10.0,
    ) -> bool:
        return bool(
            self.request(
                "set_pseudocode_line_comments",
                {"ea": int(ea), "line_comments": comments, "line_eas": line_eas},
                timeout=timeout,
            )
        )

    def set_pseudocode_ea_comments(
        self,
        ea: int,
        ea_comments: Dict[str, str],
        timeout: float = 10.0,
    ) -> bool:
        return bool(
            self.request(
                "set_pseudocode_ea_comments",
                {"ea": int(ea), "ea_comments": ea_comments},
                timeout=timeout,
            )
        )

    def save_and_exit(self, timeout: float = 2.0) -> None:
        if not self.enabled:
            return
        requests.post(self.url, json={"action": "save_and_exit"}, timeout=float(timeout))  # type: ignore[union-attr]
