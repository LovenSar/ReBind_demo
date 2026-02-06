"""kp_llm.py

大模型交互层：OpenAI 客户端初始化、请求构造、JSON 解析与 batch 调用封装。

目标：让 Phase 层只关心 prompt/结果应用，不关心 OpenAI SDK 兼容与重试细节。

功能特性：
- 支持多个 API Key（逗号分隔）：在 .env 中设置 OPENAI_API_KEY=key1,key2,key3
- 启动探测：自动检查并移除已被限流的 keys（不修改 .env）
- 限流处理（429 错误）：检测到限流时等待 30 秒，然后切换到下一个可用 key
- 自动降级：如果某个 key 被限流，不会再回到该 key，而是永久排除它
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


# 支持在环境变量中以逗号分隔提供多个 API Key，遇到限流或配额错误时可切换到下一个 key。
_API_KEYS: list[str] = []
_API_KEY_INDEX: int = 0
_LAST_PARSED_ENV_KEYS: tuple[str, ...] = ()


def _parse_api_keys_from_env(api_key_env: str) -> list:
    """从环境变量中解析逗号分隔的 API keys 列表，并去掉可选的引号（" 或 '）。"""
    val = os.getenv(api_key_env) or ""
    keys = [_strip_optional_quotes(k.strip()) for k in val.split(",") if k.strip()]
    return keys


def _get_current_api_key() -> Optional[str]:
    global _API_KEYS, _API_KEY_INDEX
    if not _API_KEYS:
        return None
    if _API_KEY_INDEX < 0 or _API_KEY_INDEX >= len(_API_KEYS):
        _API_KEY_INDEX = 0
    return _API_KEYS[_API_KEY_INDEX]


def _rotate_to_next_key() -> bool:
    """尝试切换到下一个 key；返回 True 表示已切换，False 表示没有更多 key。

    注意：该函数仅在不希望删除当前 key 的场景使用。默认场景遇到限流时会删除（discard）当前 key，
    以保证不会再返回到已经被限流的 key 上。
    """
    global _API_KEY_INDEX, _API_KEYS
    if len(_API_KEYS) <= 1:
        return False
    _API_KEY_INDEX += 1
    if _API_KEY_INDEX >= len(_API_KEYS):
        return False
    return True


def _discard_current_key() -> bool:
    """将当前 key 从可用列表中删除并保持索引指向下一个 key（如果有）。

    返回 True 表示删除后仍有下一个 key 可用，False 表示已无可用 key。
    """
    global _API_KEYS, _API_KEY_INDEX
    if not _API_KEYS:
        return False
    # 删除当前 key
    del _API_KEYS[_API_KEY_INDEX]
    # 如果删除后索引越界，表示没有更多 key
    if _API_KEY_INDEX >= len(_API_KEYS):
        return False
    return True


def _mask_key(key: str) -> str:
    if not key:
        return ""
    if len(key) <= 8:
        return key[:4] + "..."
    return key[:6] + "..." + key[-4:]


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


_PRUNED_ON_STARTUP: bool = False


def _prune_rate_limited_keys_on_startup(api_settings: Dict[str, Any], env_keys: list[str]) -> list[str]:
    """在进程启动时逐个检查 env_keys，若某个 key 已经处于限流（429）状态，则从可用列表中移除。

    注意：该函数仅在启动时运行一次（通过 _PRUNED_ON_STARTUP 控制），且不会修改 .env 文件。
    只在检测到明确的限流错误时移除 key；其他错误（例如网络错误或认证失败）不会在启动时移除，
    以免误判。
    """
    try:
        import openai  # type: ignore
    except Exception:
        logger.debug("openai client not installed; skipping startup key probe")
        return env_keys

    kept: list[str] = []
    base_url = api_settings.get("base_url") or api_settings.get("api_base")
    model = api_settings.get("model") or "gpt-3.5-turbo"

    for key in env_keys:
        try:
            # 为了避免污染全局状态，直接构造临时客户端或使用模块级调用
            if hasattr(openai, "OpenAI"):
                client = openai.OpenAI(api_key=key, base_url=base_url)  # type: ignore[attr-defined]
            else:
                # 旧版 openai: 直接设置并使用模块
                openai.api_key = key  # type: ignore[attr-defined]
                client = openai

            probed = False
            # 说明：
            # - 许多 OpenAI 兼容网关并不实现 /models，因此 models.list() 可能返回 404 并产生噪声日志。
            # - 这里改为优先发送一个极小的 chat 请求作为探针（max_tokens=1），以便更通用地探测 429 限流。
            if hasattr(client, "chat") and hasattr(client.chat, "completions"):
                client.chat.completions.create(  # type: ignore[attr-defined]
                    model=model,
                    messages=[{"role": "system", "content": "ping"}],
                    max_tokens=1,
                )
                probed = True
            elif hasattr(client, "ChatCompletion"):
                client.ChatCompletion.create(  # type: ignore[attr-defined]
                    model=model,
                    messages=[{"role": "system", "content": "ping"}],
                    max_tokens=1,
                )
                probed = True

            # 兼容极少数缺少 chat 接口的客户端：退回到 models.list()
            if not probed:
                models_attr = getattr(client, "models", None)
                if models_attr is not None:
                    models_obj = models_attr() if callable(models_attr) else models_attr
                    if hasattr(models_obj, "list"):
                        models_obj.list()  # type: ignore[attr-defined]
                        probed = True

            if not probed:
                # 无法探测的客户端，保守起见保留该 key
                kept.append(key)
                continue

            # 如果探针没有抛出异常，则保留 key
            kept.append(key)
        except Exception as exc:
            if _is_rate_limit_error(exc):
                logger.info("API key %s appears to be rate-limited at startup; skipping it", _mask_key(key))
                # 跳过此 key（不加入 kept）
                continue
            # 对于其他错误，保守保留 key，让运行时再决定
            logger.debug("Probe for API key %s failed (non-rate-limit): %s", _mask_key(key), exc)
            kept.append(key)

    return kept


def require_openai(api_settings: Dict[str, Any]) -> Any:
    """延迟导入 openai 并返回一个兼容 openai>=1.0.0 的 client。

    支持在环境变量中通过逗号分隔提供多个 API_KEY；当某个 key 遭遇限流（rate limit）时，
    会尝试切换到下一个 key 并重新构建客户端。
    """
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

    # 解析环境变量中所有的 key，支持逗号分隔
    env_keys = _parse_api_keys_from_env(api_key_env)
    if not env_keys:
        api_key_single = os.getenv(api_key_env)
        if not api_key_single:
            raise RuntimeError(
                f"环境变量 {api_key_env} 未设置，无法调用 OpenAI LLM。"
                "（可选：在 tools/Semantics_Alignment/.env 中设置同名变量）"
            )
        env_keys = [api_key_single]

    env_keys_snapshot = tuple(env_keys)

    # 在首次调用时探测并移除已被限流的 keys（不修改 .env）
    global _API_KEYS, _API_KEY_INDEX, _PRUNED_ON_STARTUP, _LAST_PARSED_ENV_KEYS
    if not _PRUNED_ON_STARTUP:
        try:
            pruned = _prune_rate_limited_keys_on_startup(api_settings, env_keys)
            # 记录并替换 env_keys 中的内容为探测后的结果
            if pruned != env_keys:
                logger.info("Startup key probe: %d -> %d usable keys", len(env_keys), len(pruned))
            env_keys = pruned
        finally:
            _PRUNED_ON_STARTUP = True

    # 如果首次加载或 env 内容变更，则初始化 keys 列表与索引；否则保留当前索引（便于切换后重试）
    if not _API_KEYS or _LAST_PARSED_ENV_KEYS != env_keys_snapshot:
        _API_KEYS = env_keys
        _API_KEY_INDEX = 0
        _LAST_PARSED_ENV_KEYS = env_keys_snapshot

    current_key = _get_current_api_key()
    if not current_key:
        raise RuntimeError("无法获取有效的 OpenAI API Key")

    logger.debug(
        "Using OpenAI API key: %s (index %d/%d)",
        _mask_key(current_key),
        _API_KEY_INDEX + 1,
        len(_API_KEYS),
    )
    # 新版 openai (>=1.0.0): 使用 OpenAI 客户端
    if hasattr(openai, "OpenAI"):
        client_kwargs: Dict[str, Any] = {
            "api_key": current_key,
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
    openai.api_key = current_key  # type: ignore[attr-defined]

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


def _is_rate_limit_error(exc: Exception) -> bool:
    """检查是否为限流/请求过多的错误（包含英文与中文变体）。"""
    msg = str(exc).lower()
    return any(
        k in msg
        for k in (
            "rate limit",
            "rate_limit",
            "too_many_requests",
            "too many requests",
            "429",
            "达到使用量上限",
            "请求过多",
            "请求频繁",
        )
    )


def _repair_json_string(text: str) -> str:
    text = re.sub(r",\s*\]", "]", text)
    text = re.sub(r",\s*\}", "}", text)
    clean_text = text.replace("\n", " ").replace("\r", "")
    return clean_text


_JSON_DECODER = json.JSONDecoder()


def _try_parse_json_value(text: str) -> Optional[Any]:
    """Best-effort parse a JSON value from an LLM response.

    Supports:
    - clean JSON
    - JSON with trailing text (via raw_decode)
    - JSON embedded in surrounding text (first '{'/'[')
    """

    if not text:
        return None

    raw = text.strip()
    if not raw:
        return None

    candidates: List[str] = [raw]
    if "\n" in raw:
        candidates.append(raw.replace("\n", " "))

    for cand in candidates:
        try:
            return json.loads(cand)
        except Exception:
            pass

        try:
            obj, _idx = _JSON_DECODER.raw_decode(cand.lstrip())
            return obj
        except Exception:
            pass

        m = re.search(r"[\[{]", cand)
        if not m:
            continue

        sub = cand[m.start() :].lstrip()
        try:
            obj, _idx = _JSON_DECODER.raw_decode(sub)
            return obj
        except Exception:
            pass

        last_close = max(sub.rfind("}"), sub.rfind("]"))
        if last_close != -1:
            sub2 = sub[: last_close + 1]
            try:
                return json.loads(sub2)
            except Exception:
                pass

    return None


def call_llm_analyze_function(
    *,
    conversation: List[Dict[str, str]],
    request_kwargs: Dict[str, Any],
    api_settings: Dict[str, Any],
    max_attempts: int = 3,
    return_raw_on_error: bool = False,
    expect_array: bool = False,
    expected_size: Optional[int] = None,
    on_raw_text: Optional[Callable[[str], None]] = None,
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
        # 在每个新 attempt 开始时重新获取 client（特别是在 key 被切换时）
        try:
            client = require_openai(api_settings)
        except Exception as exc:
            # 如果客户端初始化失败（例如没有可用 key），立即失败
            if "无法获取有效的 OpenAI API Key" in str(exc):
                logger.error("所有 API keys 均不可用，无法继续")
                return [] if expect_array else {}
            raise
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

                # 限流错误（Rate limit）：将当前 key 标记为不可用并切换到下一个可用 key（不会再回到已被限流的 key）。
                if _is_rate_limit_error(exc):
                    logger.warning(
                        "检测到限流(429)错误，将等待30秒后尝试切换API key。错误信息: %s",
                        str(exc)[:200]  # 避免日志过长
                    )
                    print("[LLM] 检测到限流，等待30秒...")
                    try:
                        time.sleep(30)
                    except KeyboardInterrupt:
                        logger.warning("用户打断了等待流程")
                        raise

                    has_next = _discard_current_key()
                    if has_next:
                        logger.warning(
                            "已将当前 API key 标记为不可用并切换到下一个 key（key=%s, index=%d/%d）",
                            _mask_key(_get_current_api_key()),
                            _API_KEY_INDEX + 1,
                            len(_API_KEYS),
                        )
                        # 注意：这里 break 而不是 continue，以便进入下一个 attempt
                        # 新的 attempt 会在顶部重新调用 require_openai 构建新客户端
                        break
                    else:
                        last_error = f"所有 API keys 均被限流或已耗尽({exc})"
                        logger.error(last_error)
                        break

                last_error = f"LLM 调用失败({attempt}/{max_attempts}): {exc}"
                logger.warning("%s", last_error)
                break

            if on_raw_text is not None:
                try:
                    on_raw_text(str(text or ""))
                except Exception:
                    logger.debug("on_raw_text 回调执行失败，已忽略。")

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

            data = _try_parse_json_value(text_str)
            if data is None:
                repaired = _repair_json_string(text_str)
                data = _try_parse_json_value(repaired)

            if data is None:
                hint = ""
                s = (text_str or "").strip()
                if s.startswith("{") and not s.endswith("}"):
                    hint = "（疑似被 max_tokens 截断，可尝试减小单次 prompt/分段查询）"
                last_error = (
                    f"LLM 返回内容无法解析为 JSON({attempt}/{max_attempts})：{candidates[0]!r}{hint}"
                )
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
