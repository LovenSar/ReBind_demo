"""kp_config.py

Small helpers for reading nested config.yaml values with defaults.

Separated to avoid circular imports when phases are extracted.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


def get_cfg_section(cfg: Optional[Dict[str, Any]], *keys: str) -> Dict[str, Any]:
    cur: Any = cfg or {}
    for k in keys:
        if not isinstance(cur, dict):
            return {}
        cur = cur.get(k)
    return cur if isinstance(cur, dict) else {}


def get_cfg_int(cfg: Optional[Dict[str, Any]], keys: Tuple[str, ...], default: int) -> int:
    cur: Any = cfg or {}
    for k in keys:
        if not isinstance(cur, dict):
            return int(default)
        cur = cur.get(k)
    try:
        return int(cur)
    except Exception:
        return int(default)


def get_cfg_float(cfg: Optional[Dict[str, Any]], keys: Tuple[str, ...], default: float) -> float:
    cur: Any = cfg or {}
    for k in keys:
        if not isinstance(cur, dict):
            return float(default)
        cur = cur.get(k)
    try:
        return float(cur)
    except Exception:
        return float(default)


def get_cfg_bool(cfg: Optional[Dict[str, Any]], keys: Tuple[str, ...], default: bool) -> bool:
    cur: Any = cfg or {}
    for k in keys:
        if not isinstance(cur, dict):
            return bool(default)
        cur = cur.get(k)
    if isinstance(cur, bool):
        return cur
    if isinstance(cur, (int, float)):
        return bool(cur)
    if isinstance(cur, str):
        val = cur.strip().lower()
        if val in ("1", "true", "yes", "y", "on"):
            return True
        if val in ("0", "false", "no", "n", "off", ""):
            return False
    return bool(default)


# 向后兼容别名已移至 kp/_compat.py，此处不再重复定义。
# 请使用正式名称：get_cfg_int / get_cfg_float / get_cfg_bool / get_cfg_section
