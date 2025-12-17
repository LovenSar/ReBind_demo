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


def wait_for_ida_server(
    ida_url: str,
    *,
    retry_interval_s: float = 30.0,
    ping_timeout_s: float = 3.0,
    max_wait_seconds: Optional[float] = None,
) -> bool:
    """检查与 idat_server 的连接情况。

    - 默认无限重试（保持历史行为）。
    - 若设置 max_wait_seconds，则在超时后返回 False，避免流水线永久卡住。
    - 在非交互 stdin 环境，不显示“按回车立即重试”的提示。
    """

    if requests is None:
        return False

    interactive = bool(sys.stdin and getattr(sys.stdin, "isatty", lambda: False)())
    started = time.time()

    while True:
        try:
            resp = requests.post(
                ida_url,
                json={"action": "ping"},
                timeout=float(ping_timeout_s),
            )
            if resp.status_code == 200:
                return True
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            elapsed = time.time() - started
            if max_wait_seconds is not None and elapsed >= float(max_wait_seconds):
                msg = (
                    f"[IDA-Sync] 无法连接到 IDA 服务器 {ida_url}: {exc}。"
                    f" 已等待 {elapsed:.1f}s，超过 max_wait_seconds={float(max_wait_seconds):.1f}s，停止等待。"
                )
                print(msg)
                logger.error("%s", msg)
                return False

            if interactive:
                msg = (
                    f"[IDA-Sync] 无法连接到 IDA 服务器 {ida_url}: {exc}。"
                    f" 将在 {float(retry_interval_s):.0f} 秒后自动重试，按回车可立即重试，Ctrl+C 终止。"
                )
            else:
                msg = (
                    f"[IDA-Sync] 无法连接到 IDA 服务器 {ida_url}: {exc}。"
                    f" 将在 {float(retry_interval_s):.0f} 秒后自动重试，Ctrl+C 终止。"
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

            if interactive:
                threading.Thread(target=_wait_input, daemon=True).start()

            # 等待到：用户触发 / 到达 retry_interval / 达到 max_wait
            per_round_start = time.time()
            while True:
                if user_triggered[0] is not None:
                    break

                now = time.time()
                if now - per_round_start >= float(retry_interval_s):
                    break

                if max_wait_seconds is not None and (now - started) >= float(max_wait_seconds):
                    return False

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
            ok = wait_for_ida_server(self.url)
            self._checked_online = bool(ok)
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

    def rename_lvar(self, ea: int, renames: Dict[str, str], timeout: float = 120.0) -> Optional[str]:
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
