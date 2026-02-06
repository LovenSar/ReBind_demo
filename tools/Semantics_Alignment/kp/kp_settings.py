"""kp_settings.py

Config + LLM settings helpers (migrated from knowledge_propagation.py).

Goal: allow semantic_align + phases to run without importing knowledge_propagation.py.
"""

from __future__ import annotations

import copy
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


DEFAULT_LLM_MODEL = "gpt-4.1-mini"
DEFAULT_LLM_TEMPERATURE = 0.1
DEFAULT_LLM_MAX_TOKENS = 512
DEFAULT_API_KEY_ENV = "OPENAI_API_KEY"


@dataclass
class LLMSettings:
    model: str
    temperature: float
    max_tokens: int
    api_settings: Dict[str, Any]
    chat_completion_kwargs: Dict[str, Any]


def _deep_merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _deep_merge_dicts(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _detect_platform_key() -> str:
    sys_name = platform.system().strip().lower()
    if sys_name.startswith(("win", "msys", "cygwin", "mingw")):
        return "windows"
    if sys_name.startswith("darwin") or sys_name.startswith("mac"):
        return "macos"
    if sys_name.startswith("linux"):
        return "linux"
    return sys_name or "unknown"


def load_semantics_config(config_path: Optional[str] = None, *, base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Load YAML config.yaml for Semantics Alignment.

    If config_path is None, defaults to <base_dir>/config.yaml, where base_dir
    defaults to this file's parent directory (tools/Semantics_Alignment).
    """

    if config_path:
        path = Path(config_path)
    else:
        root = Path(base_dir) if base_dir is not None else Path(__file__).resolve().parents[1]
        path = root / "config.yaml"

    if not path.exists():
        if config_path:
            raise FileNotFoundError(f"配置文件不存在: {path}")
        return {}

    try:
        with path.open("r", encoding="utf-8") as fp:
            data = yaml.safe_load(fp)
    except yaml.YAMLError as exc:
        raise RuntimeError(f"无法解析配置文件 {path}：{exc}") from exc

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise RuntimeError(f"配置文件 {path} 必须是一个字典结构。")

    # Support being pointed at the repo's global config.yaml (with `semantics:` + `platforms:`).
    # Merge order: module defaults < semantics common overrides < platform overrides.
    if "semantics" in data or "platforms" in data:
        base_root = Path(base_dir) if base_dir is not None else Path(__file__).resolve().parents[1]
        base_config_path = base_root / "config.yaml"
        base_config: Dict[str, Any] = {}
        if base_config_path.exists():
            try:
                with base_config_path.open("r", encoding="utf-8") as fp:
                    loaded_base = yaml.safe_load(fp) or {}
                if isinstance(loaded_base, dict):
                    base_config = loaded_base
            except yaml.YAMLError as exc:
                raise RuntimeError(f"无法解析配置文件 {base_config_path}：{exc}") from exc

        semantics_common = data.get("semantics") if isinstance(data.get("semantics"), dict) else {}
        platforms = data.get("platforms") if isinstance(data.get("platforms"), dict) else {}
        platform_key = _detect_platform_key()
        platform_semantics: Dict[str, Any] = {}
        by_os = platforms.get(platform_key) if isinstance(platforms.get(platform_key), dict) else {}
        if isinstance(by_os, dict):
            platform_semantics = by_os.get("semantics") if isinstance(by_os.get("semantics"), dict) else {}

        merged = _deep_merge_dicts(base_config, semantics_common)
        merged = _deep_merge_dicts(merged, platform_semantics)
        return merged

    return data


def build_llm_settings(
    config: Dict[str, Any],
    *,
    model: Optional[str] = None,
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
) -> LLMSettings:
    """Merge CLI overrides with config.yaml LLM settings."""

    llm_section = config.get("llm") or {}
    if not isinstance(llm_section, dict):
        llm_section = {}

    def _coerce_float(value: Any, default: float) -> float:
        if value is None:
            return default
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def _coerce_int(value: Any, default: int) -> int:
        if value is None:
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    final_model = model or llm_section.get("model") or DEFAULT_LLM_MODEL
    final_temperature = (
        temperature
        if temperature is not None
        else _coerce_float(llm_section.get("temperature"), DEFAULT_LLM_TEMPERATURE)
    )
    final_max_tokens = (
        max_tokens
        if max_tokens is not None
        else _coerce_int(llm_section.get("max_tokens"), DEFAULT_LLM_MAX_TOKENS)
    )

    api_section = llm_section.get("api") or {}
    if not isinstance(api_section, dict):
        api_section = {}

    api_settings: Dict[str, Any] = {k: v for k, v in api_section.items() if v is not None}
    api_settings.setdefault("key_env_var", DEFAULT_API_KEY_ENV)
    # kp_llm.require_openai() 会在启动时进行 key 探针（用于剔除已被 429 限流的 keys）。
    # 部分 OpenAI 兼容网关不支持 /models，因此探针会优先走一个极小的 chat 请求；
    # 这里把最终模型名放进 api_settings，方便探针使用正确的 model。
    api_settings.setdefault("model", str(final_model))

    raw_chat_kwargs = llm_section.get("chat_completion_kwargs") or {}
    chat_kwargs: Dict[str, Any] = dict(raw_chat_kwargs) if isinstance(raw_chat_kwargs, dict) else {}

    return LLMSettings(
        model=str(final_model),
        temperature=float(final_temperature),
        max_tokens=int(final_max_tokens),
        api_settings=api_settings,
        chat_completion_kwargs=chat_kwargs,
    )
