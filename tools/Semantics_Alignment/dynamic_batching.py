from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Generator, List, Optional, Sequence, TypeVar


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
    item_token_estimator: Optional[Callable[[T], int]] = None,
    prompt_overhead_tokens: int = 64,
) -> Generator[DynamicBatchResult, None, None]:
    """通用动态 Batch 生成器。

    - 对输入 items 顺序切片。
    - 每个 batch 调用 prompt_builder(items_slice) 生成 prompt。
    - 用 token_estimator(prompt) 估算 prompt token。
    - 若估算超过 max_prompt_tokens，则指数回退缩小 batch（//2）。
    - 若提供 item_token_estimator，则先按“粗估 token”预选 batch_size，
      以减少重复构造 prompt 的次数。

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
    per_item_estimates: Optional[List[int]] = None
    if item_token_estimator is not None:
        per_item_estimates = []
        for item in items:
            try:
                est = int(item_token_estimator(item))
            except Exception:
                est = 0
            per_item_estimates.append(max(1, est))

    while idx < total:
        remaining = total - idx
        current_size = min(current_size, remaining)
        current_size = max(min_batch_size, current_size)

        # 粗估容量：在不构造 prompt 的情况下，用“每项 token 估算”先约束 batch 大小。
        if per_item_estimates is not None:
            budget = max(1, int(max_prompt_tokens) - max(0, int(prompt_overhead_tokens)))
            coarse_size = 0
            coarse_sum = 0
            for est in per_item_estimates[idx : idx + current_size]:
                if coarse_size >= min_batch_size and coarse_sum + int(est) > budget:
                    break
                if coarse_size == 0 and int(est) > budget:
                    coarse_size = 1
                    break
                coarse_sum += int(est)
                coarse_size += 1
            if coarse_size > 0:
                current_size = max(min_batch_size, min(current_size, int(coarse_size)))

        built_cache: dict[int, tuple[str, int]] = {}
        while current_size >= min_batch_size:
            batch_items = list(items[idx : idx + current_size])

            try:
                cached = built_cache.get(current_size)
                if cached is None:
                    prompt = prompt_builder(batch_items)
                    est_tokens = int(token_estimator(prompt))
                    built_cache[current_size] = (prompt, est_tokens)
                else:
                    prompt, est_tokens = cached
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
