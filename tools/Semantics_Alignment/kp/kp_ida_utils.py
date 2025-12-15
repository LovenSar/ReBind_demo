"""kp_ida_utils.py

Small, dependency-light helpers for talking to idat_server.

These helpers are extracted from knowledge_propagation.py to allow phase modules
to reuse them without importing the monolithic entrypoint.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None


logger = logging.getLogger(__name__)


def force_ida_save_database(ida_url: str, timeout: float = 15.0) -> bool:
    """Request idat_server to save database (without exiting)."""
    if requests is None:
        return False

    try:
        resp = requests.post(ida_url, json={"action": "save_database"}, timeout=timeout)
    except Exception as exc:
        logger.warning("[IDA-Sync] save_database 调用失败: %s", exc)
        return False

    if resp.status_code != 200:
        logger.warning("[IDA-Sync] save_database HTTP %s: %s", resp.status_code, resp.text[:200])
        return False

    try:
        data = resp.json()
    except Exception:
        return False

    return data.get("status") == "ok"


def fetch_ida_pseudocode(entry_va: int, ida_url: str, timeout: float = 10.0) -> Optional[str]:
    """Fetch latest pseudocode for a function from idat_server."""
    if requests is None:
        return None

    payload = {"action": "get_pseudocode", "ea": int(entry_va)}
    try:
        resp = requests.post(ida_url, json=payload, timeout=timeout)
    except Exception as exc:
        logger.warning("[IDA-Sync] get_pseudocode 调用失败 0x%08X: %s", entry_va, exc)
        return None

    if resp.status_code != 200:
        logger.warning("[IDA-Sync] get_pseudocode HTTP %s: %s", resp.status_code, resp.text[:200])
        return None

    try:
        data = resp.json()
    except Exception as exc:
        logger.warning(
            "[IDA-Sync] 解析 get_pseudocode 响应失败 0x%08X: %s; body=%s",
            entry_va,
            exc,
            resp.text[:200],
        )
        return None

    if data.get("status") != "ok":
        logger.warning("[IDA-Sync] get_pseudocode 返回错误 0x%08X: %s", entry_va, data)
        return None

    code = data.get("pseudocode")
    return code if isinstance(code, str) else None


def save_and_refresh_pseudocode(entry_va: int, ida_url: str, wait_seconds: float = 1.0) -> Optional[str]:
    """Force-save IDA database then refetch pseudocode."""
    force_ida_save_database(ida_url)
    if wait_seconds and wait_seconds > 0:
        time.sleep(float(wait_seconds))
    return fetch_ida_pseudocode(entry_va, ida_url)


# Backward-compatible aliases (old names from knowledge_propagation.py)
_force_ida_save_database = force_ida_save_database
_fetch_ida_pseudocode = fetch_ida_pseudocode
_save_and_refresh_pseudocode = save_and_refresh_pseudocode


def fetch_live_ida_subfuncs(ida_url: str, timeout: float = 30.0) -> Dict[int, str]:
    """Get current IDB sub_ functions from idat_server.

    Returns {entry_va(int): name(str)}.
    """
    if requests is None:
        return {}

    payload = {"action": "get_sub_functions"}
    try:
        resp = requests.post(ida_url, json=payload, timeout=timeout)
    except Exception as exc:
        logger.warning("[IDA-Sync] get_sub_functions 调用失败: %s", exc)
        return {}

    if resp.status_code != 200:
        logger.warning("[IDA-Sync] get_sub_functions HTTP %s: %s", resp.status_code, resp.text[:200])
        return {}

    try:
        data = resp.json()
    except Exception as exc:
        logger.warning("[IDA-Sync] 解析 get_sub_functions 响应失败: %s; body=%s", exc, resp.text[:200])
        return {}

    if data.get("status") != "ok":
        logger.warning("[IDA-Sync] get_sub_functions 返回错误: %s", data)
        return {}

    raw = data.get("sub_functions") or {}
    if not isinstance(raw, dict):
        return {}

    result: Dict[int, str] = {}
    for k, v in raw.items():
        name = (v or "").strip()
        if not name:
            continue
        try:
            if isinstance(k, int):
                ea = int(k)
            elif isinstance(k, str):
                s = k.strip()
                if s.lower().startswith("0x"):
                    ea = int(s, 16)
                else:
                    ea = int(s)
            else:
                continue
        except Exception:
            continue
        result[ea] = name

    return result


def fetch_ida_function_info(entry_va: int, ida_url: str, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
    """Fetch function info (name + pseudocode) from idat_server."""
    if requests is None:
        return None

    payload = {"action": "get_function_info", "ea": int(entry_va)}
    try:
        resp = requests.post(ida_url, json=payload, timeout=timeout)
    except Exception as exc:
        logger.warning("[IDA-Sync] get_function_info 调用失败 0x%08X: %s", entry_va, exc)
        return None

    if resp.status_code != 200:
        logger.warning("[IDA-Sync] get_function_info HTTP %s: %s", resp.status_code, resp.text[:200])
        return None

    try:
        data = resp.json()
    except Exception as exc:
        logger.warning(
            "[IDA-Sync] 解析 get_function_info 响应失败 0x%08X: %s; body=%s",
            entry_va,
            exc,
            resp.text[:200],
        )
        return None

    if data.get("status") != "ok":
        logger.warning("[IDA-Sync] get_function_info 返回错误 0x%08X: %s", entry_va, data)
        return None

    return data
