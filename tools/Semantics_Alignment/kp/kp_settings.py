"""kp_settings.py

Config + LLM settings helpers (migrated from knowledge_propagation.py).

Goal: allow semantic_align + phases to run without importing knowledge_propagation.py.
"""

from __future__ import annotations

import copy
import sys
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import project_config  # noqa: E402


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


def load_semantics_config(config_path: Optional[str] = None, *, base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """加载语义流水线配置。

    - 默认读取仓库根目录 ``config.yaml``（唯一配置源）。
    - 若 YAML 含 ``semantics`` / ``platforms``，则合并为扁平的 llm/pipeline/runtime。
    - 否则将整文件视为旧版「仅语义段」YAML。
    ``base_dir`` 已弃用，保留仅为兼容测试/旧调用。
    """

    del base_dir  # 保留签名；配置仅来自根 config 或显式路径

    if config_path:
        path = Path(config_path)
    else:
        path = project_config.ROOT_CONFIG_PATH

    if not path.exists():
        if config_path:
            raise FileNotFoundError(f"配置文件不存在: {path}")
        return {}

    try:
        data = project_config.load_yaml_file(path)
    except yaml.YAMLError as exc:
        raise RuntimeError(f"无法解析配置文件 {path}：{exc}") from exc

    if "semantics" in data or "platforms" in data:
        platform_key = project_config.detect_platform_key()
        return project_config.merge_semantics_config_dict(data, platform_key)

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
