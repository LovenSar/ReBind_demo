"""kp_ida.py

IDA(idat_server) 交互层：封装 HTTP 调用、在线探测与常用操作。

目标：让 pipeline/phase 代码只关心“做什么”，不关心 requests/超时/错误处理细节。
"""

from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Dict, Optional, Tuple

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None


logger = logging.getLogger(__name__)


def _enter_pressed_nonblocking() -> bool:
    """Best-effort non-blocking Enter detection to avoid daemon input threads."""

    if not (sys.stdin and getattr(sys.stdin, "isatty", lambda: False)()):
        return False

    try:
        if os.name == "nt":
            import msvcrt  # type: ignore

            # Drain pending keypresses; trigger only when Enter is hit.
            while msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch in ("\r", "\n"):
                    return True
            return False

        import select

        readable, _, _ = select.select([sys.stdin], [], [], 0)
        if not readable:
            return False
        # Any completed line counts as "pressed Enter".
        sys.stdin.readline()
        return True
    except Exception:
        return False


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

            # 等待到：用户触发 / 到达 retry_interval / 达到 max_wait
            per_round_start = time.time()
            while True:
                if interactive and _enter_pressed_nonblocking():
                    break

                now = time.time()
                if now - per_round_start >= float(retry_interval_s):
                    break

                if max_wait_seconds is not None and (now - started) >= float(max_wait_seconds):
                    return False

                time.sleep(0.2)


class IDAService:
    """封装与 idat_server 的 HTTP 通信与错误处理。

    内置看门狗（watchdog）：连续 *max_consecutive_fails* 次连接失败后自动降级为
    离线模式（``degraded=True``），流水线继续运行但跳过所有 IDA 同步。
    降级后每 *recover_interval_s* 秒尝试 ping 一次，若 IDA 恢复则自动重新启用。
    """

    def __init__(
        self,
        url: Optional[str],
        enabled: bool = False,
        *,
        max_consecutive_fails: int = 3,
        connect_timeout_s: float = 60.0,
        recover_interval_s: float = 120.0,
    ):
        self.url = (url or "").strip() or "http://127.0.0.1:12345"
        self.enabled = bool(enabled) and (requests is not None) and bool(self.url)
        self._checked_online = False

        # --- watchdog state ---
        self._consecutive_fails: int = 0
        self._max_consecutive_fails: int = max(1, int(max_consecutive_fails))
        self._degraded: bool = False
        self._degraded_count: int = 0
        self._connect_timeout_s: float = float(connect_timeout_s)
        self._recover_interval_s: float = float(recover_interval_s)
        self._last_recover_attempt: float = 0.0

    # ── watchdog helpers ──────────────────────────────────────

    @property
    def degraded(self) -> bool:
        """True when IDA has been auto-disabled due to consecutive failures."""
        return self._degraded

    def _record_success(self) -> None:
        if self._consecutive_fails > 0 or self._degraded:
            was_degraded = self._degraded
            self._consecutive_fails = 0
            self._degraded = False
            if was_degraded:
                msg = "[IDA-Watchdog] IDA 连接已恢复，重新启用实时同步模式。"
                print(msg)
                logger.info(msg)

    def _record_failure(self) -> None:
        self._consecutive_fails += 1
        if not self._degraded and self._consecutive_fails >= self._max_consecutive_fails:
            self._degraded = True
            self._degraded_count += 1
            self._last_recover_attempt = time.time()
            msg = (
                f"[IDA-Watchdog] 连续 {self._consecutive_fails} 次连接 IDA 失败，"
                f"自动降级为离线模式（仅写入 DB，跳过 IDA 同步）。"
                f" 将每 {self._recover_interval_s:.0f}s 尝试重连。"
            )
            print(msg)
            logger.warning(msg)

    def _should_try_recover(self) -> bool:
        if not self._degraded:
            return False
        return (time.time() - self._last_recover_attempt) >= self._recover_interval_s

    def try_recover(self) -> bool:
        """Attempt to ping IDA and exit degraded mode if successful."""
        if not self.enabled or not self._degraded:
            return not self._degraded
        self._last_recover_attempt = time.time()
        try:
            resp = requests.post(self.url, json={"action": "ping"}, timeout=3.0)  # type: ignore[union-attr]
            if resp.status_code == 200:
                self._record_success()
                self._checked_online = True
                return True
        except Exception:
            pass
        logger.debug("[IDA-Watchdog] 恢复尝试失败，继续离线模式。")
        return False

    # ── public API ────────────────────────────────────────────

    def ensure_online(self) -> None:
        if not self.enabled or self._degraded:
            return
        if self._checked_online:
            return
        try:
            ok = wait_for_ida_server(
                self.url, max_wait_seconds=self._connect_timeout_s,
            )
            self._checked_online = bool(ok)
            if ok:
                self._record_success()
            else:
                self._record_failure()
        except Exception:
            self._checked_online = False
            self._record_failure()

    def request(
        self,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
        timeout: float = 10.0,
        ensure_online: bool = True,
    ) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None

        if self._degraded:
            if self._should_try_recover():
                if not self.try_recover():
                    return None
            else:
                return None

        if ensure_online:
            self.ensure_online()
            if self._degraded:
                return None

        full_payload: Dict[str, Any] = {"action": action}
        if payload:
            full_payload.update(payload)

        try:
            resp = requests.post(self.url, json=full_payload, timeout=float(timeout))  # type: ignore[union-attr]
        except Exception as exc:
            self._checked_online = False
            self._record_failure()
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

        self._record_success()
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

    def save_and_exit(self, timeout: float = 45.0) -> None:
        if not self.enabled:
            return
        if requests is None:
            return
        last_exc: Optional[Exception] = None
        for attempt in range(1, 4):
            try:
                resp = requests.post(
                    self.url,
                    json={"action": "save_and_exit"},
                    timeout=float(timeout),
                )
                if resp.status_code and 200 <= resp.status_code < 300:
                    return
                last_exc = RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
            except Exception as exc:
                last_exc = exc
                msg = str(exc).lower()
                if any(
                    k in msg
                    for k in (
                        "connection reset",
                        "broken pipe",
                        "remote end closed",
                        "connection aborted",
                    )
                ):
                    logger.info(
                        "[IDA] save_and_exit 连接中断（可能 IDA 已在保存后退出）: %s", exc
                    )
                    return
            time.sleep(0.4 * attempt)
        if last_exc is not None:
            logger.warning("[IDA] save_and_exit 失败: %s", last_exc)
