"""仓库根目录单一配置文件（config.yaml）的加载与合并工具。

子目录不再维护独立 config.yaml；Ghidra / IDA / Semantics 均在根配置中对应段落，
并可按 platforms.<os> 覆盖。
"""

from __future__ import annotations

import copy
import platform
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

REPO_ROOT = Path(__file__).resolve().parent
ROOT_CONFIG_PATH = REPO_ROOT / "config.yaml"


def load_yaml_file(path: Path, *, allow_missing: bool = False) -> Dict[str, Any]:
    if not path.exists():
        if allow_missing:
            return {}
        raise FileNotFoundError(f"配置文件不存在: {path}")
    with path.open("r", encoding="utf-8") as fp:
        data = yaml.safe_load(fp)
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise RuntimeError(f"配置文件 {path} 必须是一个字典结构。")
    return data


def deep_merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = deep_merge_dicts(merged[key], value)
        else:
            merged[key] = value
    return merged


def detect_platform_key(explicit: Optional[str] = None) -> str:
    if explicit:
        key = explicit.strip().lower()
        if key in {"windows", "macos", "linux"}:
            return key
        raise ValueError(f"不支持的 --platform={explicit!r}，仅支持 windows/macos/linux")
    sys_name = platform.system().strip().lower()
    if sys_name.startswith(("win", "msys", "cygwin", "mingw")):
        return "windows"
    if sys_name.startswith("darwin") or sys_name.startswith("mac"):
        return "macos"
    if sys_name.startswith("linux"):
        return "linux"
    return sys_name or "unknown"


def normalize_module_overrides(section_key: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    if not raw or not isinstance(raw, dict):
        return {}

    if section_key == "ghidra":
        if any(k in raw for k in ("ghidra", "output", "scripts", "filename", "logging")):
            return raw
        ghidra_keys = ("cmd_path", "workspace", "project_name_prefix", "extra_headless_args")
        nested = {k: raw[k] for k in ghidra_keys if k in raw}
        result: Dict[str, Any] = {"ghidra": nested} if nested else {}
        for k in ("output", "scripts", "filename", "logging"):
            if k in raw:
                result[k] = raw[k]
        return result or raw

    if section_key == "ida":
        if any(k in raw for k in ("ida", "output", "scripts", "filename", "logging")):
            return raw
        ida_keys = ("cmd_path", "args")
        nested = {k: raw[k] for k in ida_keys if k in raw}
        result = {"ida": nested} if nested else {}
        for k in ("output", "scripts", "filename", "logging"):
            if k in raw:
                result[k] = raw[k]
        return result or raw

    return raw


def platform_overrides(global_config: Dict[str, Any], platform_key: str, section_key: str) -> Dict[str, Any]:
    platforms = global_config.get("platforms", {})
    if not isinstance(platforms, dict):
        return {}
    by_os = platforms.get(platform_key, {})
    if not isinstance(by_os, dict):
        return {}
    section = by_os.get(section_key, {})
    return section if isinstance(section, dict) else {}


def load_global_config(config_path: Optional[Path] = None, *, allow_missing: bool = False) -> Dict[str, Any]:
    path = Path(config_path).expanduser().resolve() if config_path else ROOT_CONFIG_PATH
    return load_yaml_file(path, allow_missing=allow_missing)


def merge_tool_config(global_config: Dict[str, Any], section_key: str, platform_key: str) -> Dict[str, Any]:
    common = global_config.get(section_key) or {}
    if not isinstance(common, dict):
        common = {}
    plat = platform_overrides(global_config, platform_key, section_key)
    norm_c = normalize_module_overrides(section_key, common)
    norm_p = normalize_module_overrides(section_key, plat)
    merged_overrides = deep_merge_dicts(norm_c, norm_p)
    return merged_overrides


def merge_semantics_config_dict(global_config: Dict[str, Any], platform_key: str) -> Dict[str, Any]:
    semantics_common = global_config.get("semantics") or {}
    if not isinstance(semantics_common, dict):
        semantics_common = {}
    platform_sem = platform_overrides(global_config, platform_key, "semantics")
    if not isinstance(platform_sem, dict):
        platform_sem = {}
    return deep_merge_dicts(semantics_common, platform_sem)


def merge_phase7_config_dict(global_config: Dict[str, Any], platform_key: str) -> Dict[str, Any]:
    """返回平台合并后的 ``semantics.phase7`` 配置。"""
    semantics = merge_semantics_config_dict(global_config, platform_key)
    phase7 = semantics.get("phase7") or {}
    if not isinstance(phase7, dict):
        raise RuntimeError("config.yaml 的 semantics.phase7 必须是一个字典结构。")
    return copy.deepcopy(phase7)
