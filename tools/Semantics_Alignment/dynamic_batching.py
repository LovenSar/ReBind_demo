from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Generator, Iterable, List, Optional, Sequence, Tuple, TypeVar


T = TypeVar("T")


@dataclass(frozen=True)
class DynamicBatchResult:
    items: List[Any]
    prompt: str
    estimated_tokens: int


def yield_dynamic_batch(
    items: Sequence[T],
    prompt_builder: Callable[[Sequence[T]], str],
    max_prompt_tokens: int,
    token_estimator: Callable[[str], int],
    initial_batch_size: int = 10,
    min_batch_size: int = 1,
) -> Generator[DynamicBatchResult, None, None]:
    """通用动态 Batch 生成器。

    - 对输入 items 顺序切片。
    - 每个 batch 调用 prompt_builder(items_slice) 生成 prompt。
    - 用 token_estimator(prompt) 估算 prompt token。
    - 若估算超过 max_prompt_tokens，则指数回退缩小 batch（//2）。

    说明：
    - 当 batch_size==min_batch_size 仍超限时，也会 yield（由上层决定是否强制发送/进一步降级）。
    - prompt_builder 发生异常时会强制缩小 batch 重试。
    """

    if min_batch_size <= 0:
        raise ValueError("min_batch_size must be >= 1")

    total = len(items)
    if total == 0:
        return

    idx = 0
    current_size = max(min_batch_size, int(initial_batch_size) if initial_batch_size else min_batch_size)

    while idx < total:
        current_size = min(current_size, total - idx)
        current_size = max(min_batch_size, current_size)

        while current_size >= min_batch_size:
            batch_items = list(items[idx : idx + current_size])

            try:
                prompt = prompt_builder(batch_items)
                est_tokens = int(token_estimator(prompt))
            except Exception:
                # Prompt 构建异常时，强制缩小 batch
                prompt = ""
                est_tokens = max_prompt_tokens + 1

            if est_tokens <= max_prompt_tokens or current_size == min_batch_size:
                yield DynamicBatchResult(
                    items=batch_items,
                    prompt=prompt,
                    estimated_tokens=est_tokens,
                )
                idx += current_size
                break

            # 超标，指数回退
            current_size = max(min_batch_size, current_size // 2)
