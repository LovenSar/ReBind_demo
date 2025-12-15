"""kp_llm.py

大模型交互层：OpenAI 客户端初始化、请求构造、JSON 解析与 batch 调用封装。

目标：让 Phase 层只关心 prompt/结果应用，不关心 OpenAI SDK 兼容与重试细节。
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import sys
import time
import unicodedata
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, TypeVar

from dynamic_batching import DynamicBatchResult, yield_dynamic_batch


logger = logging.getLogger(__name__)

DEFAULT_API_KEY_ENV = "OPENAI_API_KEY"


def _strip_optional_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and ((value[0] == value[-1] == '"') or (value[0] == value[-1] == "'")):
        return value[1:-1]
    return value


def _load_dotenv_file(dotenv_path: Path) -> int:
    """Load KEY=VALUE pairs from a .env file into os.environ (do not override existing)."""

    try:
        text = dotenv_path.read_text(encoding="utf-8")
    except Exception:
        return 0

    updated = 0
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("export "):
            line = line[len("export ") :].strip()

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue

        value = _strip_optional_quotes(value)
        if key in os.environ:
            continue

        os.environ[key] = value
        updated += 1
    return updated


def _try_load_api_key_from_dotenv(api_settings: Dict[str, Any], api_key_env: str) -> None:
    """Best-effort load .env so OPENAI_API_KEY can be provided without manual export."""

    if os.getenv(api_key_env):
        return

    dotenv_candidate = api_settings.get("dotenv_path") or api_settings.get("dotenv")
    if dotenv_candidate:
        dotenv_path = Path(str(dotenv_candidate)).expanduser()
        if not dotenv_path.is_absolute():
            dotenv_path = (Path(__file__).resolve().parents[1] / dotenv_path).resolve()
        if dotenv_path.exists() and dotenv_path.is_file():
            _load_dotenv_file(dotenv_path)
            return

    default_dotenv = Path(__file__).resolve().parents[1] / ".env"
    if default_dotenv.exists() and default_dotenv.is_file():
        _load_dotenv_file(default_dotenv)


def require_openai(api_settings: Dict[str, Any]) -> Any:
    """延迟导入 openai 并返回一个兼容 openai>=1.0.0 的 client。"""
    api_key_env = str(
        api_settings.get("api_key_env")
        or api_settings.get("key_env_var")
        or DEFAULT_API_KEY_ENV
    )

    # 兼容本项目的 tools/Semantics_Alignment/.env：若没有手动设置环境变量，尝试自动加载。
    _try_load_api_key_from_dotenv(api_settings, api_key_env)

    try:
        import openai  # type: ignore
    except Exception:
        raise RuntimeError("未安装 openai 库，请先执行：pip install openai")

    api_key = os.getenv(api_key_env)
    if not api_key:
        raise RuntimeError(
            f"环境变量 {api_key_env} 未设置，无法调用 OpenAI LLM。"
            "（可选：在 tools/Semantics_Alignment/.env 中设置同名变量）"
        )

    # 新版 openai (>=1.0.0): 使用 OpenAI 客户端
    if hasattr(openai, "OpenAI"):
        client_kwargs: Dict[str, Any] = {
            "api_key": api_key,
        }
        base_url = api_settings.get("base_url") or api_settings.get("api_base")
        if base_url:
            client_kwargs["base_url"] = base_url
        organization = api_settings.get("organization")
        if organization:
            client_kwargs["organization"] = organization
        timeout = api_settings.get("timeout")
        if timeout is not None:
            client_kwargs["timeout"] = timeout
        return openai.OpenAI(**client_kwargs)  # type: ignore[attr-defined]

    # 旧版 openai (<1.0.0): 模块级配置
    openai.api_key = api_key  # type: ignore[attr-defined]

    # 旧版 openai 采用模块级全局配置，尽量兼容老字段命名
    attr_map: Dict[str, str] = {
        "base_url": "api_base",
        "api_base": "api_base",
        "type": "api_type",
        "api_type": "api_type",
        "version": "api_version",
        "api_version": "api_version",
        "organization": "organization",
        "proxy": "proxy",
    }
    for config_key, attr_name in attr_map.items():
        value = api_settings.get(config_key)
        if value:
            setattr(openai, attr_name, value)  # type: ignore[attr-defined]
    return openai


def _is_quota_exhausted_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(
        k in msg
        for k in (
            "insufficient_quota",
            "quota",
            "exceeded your current quota",
            "billing",
            "余额",
            "欠费",
        )
    )


def _repair_json_string(text: str) -> str:
    text = re.sub(r",\s*\]", "]", text)
    text = re.sub(r",\s*\}", "}", text)
    clean_text = text.replace("\n", " ").replace("\r", "")
    return clean_text


def call_llm_analyze_function(
    *,
    conversation: List[Dict[str, str]],
    request_kwargs: Dict[str, Any],
    api_settings: Dict[str, Any],
    max_attempts: int = 3,
    return_raw_on_error: bool = False,
    expect_array: bool = False,
    expected_size: Optional[int] = None,
) -> Any:
    """调用 OpenAI ChatCompletion 做分析。

    默认期望返回单个 JSON 对象；若 expect_array=True，则要求返回 JSON 数组，
    并在 expected_size 给定时校验数组长度。
    """

    client = require_openai(api_settings)

    last_error: Optional[str] = None

    try:
        logger.debug(
            "LLM request payload: %s",
            json.dumps(request_kwargs, ensure_ascii=False, indent=2),
        )
    except Exception:
        logger.debug("LLM request payload (repr): %r", request_kwargs)

    for attempt in range(1, max_attempts + 1):
        text_str = ""
        attempt_start = time.time()
        while True:
            try:
                if hasattr(client, "chat") and hasattr(client.chat, "completions"):
                    resp = client.chat.completions.create(**request_kwargs)  # type: ignore[attr-defined]
                    text = resp.choices[0].message.content or ""  # type: ignore[union-attr]
                elif hasattr(client, "ChatCompletion"):
                    resp = client.ChatCompletion.create(**request_kwargs)  # type: ignore[attr-defined]
                    text = resp["choices"][0]["message"]["content"]  # type: ignore[index]
                else:  # pragma: no cover
                    last_error = "当前 openai 客户端不支持 ChatCompletion 接口"
                    break
            except Exception as exc:
                if _is_quota_exhausted_error(exc):
                    exit_msg = (
                        "检测到 LLM API 余额不足，流程将安全退出；当前任务支持断点续工，"
                        "请充值后重新运行。"
                    )
                    print(exit_msg)
                    logger.error("%s", exit_msg)
                    sys.exit(1)

                last_error = f"LLM 调用失败({attempt}/{max_attempts}): {exc}"
                logger.warning("%s", last_error)
                break

            text_str = (text or "").strip()
            if text_str.startswith("```"):
                lines = text_str.splitlines()
                if lines and lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                text_str = "\n".join(lines).strip()

            candidates = [text_str]
            if "\n" in text_str:
                candidates.append(text_str.replace("\n", " "))

            parse_ok = False
            data: Any = None
            for cand in candidates:
                try:
                    data = json.loads(cand)
                    parse_ok = True
                    break
                except Exception:
                    continue

            if not parse_ok:
                repaired = _repair_json_string(text_str)
                try:
                    data = json.loads(repaired)
                    parse_ok = True
                except Exception:
                    parse_ok = False

            if not parse_ok:
                last_error = f"LLM 返回内容无法解析为 JSON({attempt}/{max_attempts})：{candidates[0]!r}"
                if return_raw_on_error and attempt == max_attempts:
                    logger.warning("%s\n完整的 LLM 回复：%s", last_error, text_str)
                    return {"_raw_error": last_error, "_raw_text": text_str}
                logger.warning("%s\n完整的 LLM 回复：%s", last_error, text_str)
                break

            if expect_array:
                if not isinstance(data, list):
                    last_error = f"LLM 返回的 JSON 不是数组({attempt}/{max_attempts})：{data!r}"
                    logger.warning("%s", last_error)
                    break

                if expected_size is not None and len(data) != expected_size:
                    last_error = (
                        f"LLM 返回数组长度不符({attempt}/{max_attempts})："
                        f"expected={expected_size}, got={len(data)}"
                    )
                    logger.warning("%s", last_error)
                    break

                return data

            if not isinstance(data, dict):
                last_error = f"LLM 返回的 JSON 不是对象({attempt}/{max_attempts})：{data!r}"
                logger.warning("%s", last_error)
                break

            return data

        elapsed = time.time() - attempt_start
        logger.debug("LLM attempt %d/%d finished in %.2fs", attempt, max_attempts, elapsed)

    if last_error:
        logger.error("在 %d 次尝试后仍未获得合法 JSON：%s", max_attempts, last_error)
    return [] if expect_array else {}


def build_chat_request(prompt: str, llm_settings: Any) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """构造要发送给 ChatCompletion 的消息与请求参数。"""

    conversation: List[Dict[str, str]] = [
        {
            "role": "system",
            "content": (
                "You are an expert reverse engineer. "
                "You must respond with a single valid JSON value only."
            ),
        },
        {"role": "user", "content": prompt},
    ]

    request_kwargs: Dict[str, Any] = dict(getattr(llm_settings, "chat_completion_kwargs"))
    request_kwargs.update(
        {
            "model": getattr(llm_settings, "model"),
            "temperature": getattr(llm_settings, "temperature"),
            "max_tokens": getattr(llm_settings, "max_tokens"),
            "messages": conversation,
        }
    )

    return conversation, request_kwargs


def estimate_token_usage(text: str) -> int:
    """按经验比例估算 token 数，便于在批处理前做容量预检。"""

    words = re.findall(r"[A-Za-z]+", text)
    word_tokens = len(words) / 0.75 if words else 0.0

    chinese_chars = re.findall(r"[\u4e00-\u9fff]", text)
    chinese_tokens = len(chinese_chars) / 0.5 if chinese_chars else 0.0

    punctuation_count = sum(1 for ch in text if unicodedata.category(ch).startswith("P"))
    punctuation_tokens = punctuation_count / 3.0 if punctuation_count else 0.0

    english_letter_count = sum(len(w) for w in words)
    residual_count = max(0, len(text) - english_letter_count - len(chinese_chars) - punctuation_count)
    residual_tokens = residual_count * 0.3

    estimated = word_tokens + chinese_tokens + punctuation_tokens + residual_tokens
    return int(math.ceil(estimated))


_BatchItemT = TypeVar("_BatchItemT")


def run_llm_batch_job(
    items: Sequence[_BatchItemT],
    *,
    prompt_builder: Callable[[List[_BatchItemT]], str],
    llm_settings: Any,
    initial_batch_size: int,
    min_batch_size: int = 1,
    max_prompt_tokens: Optional[int] = None,
    token_estimator: Callable[[str], int] = estimate_token_usage,
    disable_dynamic_batching: bool = False,
    prompt_override: Optional[str] = None,
    estimated_tokens_override: Optional[int] = None,
    dry_run: bool = False,
    dry_run_title: str = "",
    expect_array: bool = True,
    max_attempts: int = 3,
    return_raw_on_error: bool = False,
    on_batch_start: Optional[Callable[[DynamicBatchResult], None]] = None,
    on_dry_run_batch: Optional[Callable[[DynamicBatchResult], None]] = None,
    on_batch_failure: Optional[Callable[[DynamicBatchResult, Any], None]] = None,
    on_item: Optional[Callable[[_BatchItemT, Any], None]] = None,
    on_item_failure: Optional[Callable[[_BatchItemT], None]] = None,
) -> None:
    """统一的 LLM batch runner。"""

    if not items:
        return

    max_tokens = int(max_prompt_tokens or getattr(llm_settings, "max_tokens"))
    init_bs = max(1, int(initial_batch_size or 1))
    min_bs = max(1, int(min_batch_size or 1))

    batches: Iterable[DynamicBatchResult]
    if disable_dynamic_batching:
        item_list = list(items)
        prompt = prompt_override if prompt_override is not None else prompt_builder(item_list)
        est_tokens = int(estimated_tokens_override) if estimated_tokens_override is not None else int(token_estimator(prompt))
        batches = [DynamicBatchResult(items=item_list, prompt=prompt, estimated_tokens=est_tokens)]
    else:
        batches = yield_dynamic_batch(
            list(items),
            prompt_builder=prompt_builder,
            max_prompt_tokens=max_tokens,
            token_estimator=token_estimator,
            initial_batch_size=init_bs,
            min_batch_size=min_bs,
        )

    for batch in batches:
        if on_batch_start is not None:
            try:
                on_batch_start(batch)
            except Exception:
                pass

        if dry_run:
            if on_dry_run_batch is not None:
                on_dry_run_batch(batch)
            else:
                title = (dry_run_title or "DRY-RUN").strip() or "DRY-RUN"
                print("=" * 80)
                print(f"[{title}] batch size={len(batch.items)}")
                print((batch.prompt or "")[:2000])
            continue

        conversation, request_kwargs = build_chat_request(batch.prompt, llm_settings)
        result = call_llm_analyze_function(
            conversation=conversation,
            request_kwargs=request_kwargs,
            api_settings=getattr(llm_settings, "api_settings"),
            expect_array=bool(expect_array),
            expected_size=len(batch.items) if expect_array else None,
            max_attempts=max(1, int(max_attempts or 1)),
            return_raw_on_error=bool(return_raw_on_error),
        )

        if expect_array:
            if (not isinstance(result, list)) or (len(result) != len(batch.items)):
                if on_batch_failure is not None:
                    on_batch_failure(batch, result)
                if on_item_failure is not None:
                    for it in batch.items:
                        on_item_failure(it)
                continue

            for it, res in zip(batch.items, result):
                if on_item is not None:
                    on_item(it, res)
            continue

        if not isinstance(result, dict):
            if on_batch_failure is not None:
                on_batch_failure(batch, result)
            if on_item_failure is not None:
                for it in batch.items:
                    on_item_failure(it)
            continue

        if on_item is not None:
            for it in batch.items:
                on_item(it, result)
