"""kp_scoring.py

Heuristic scoring helpers for scheduling analysis.

Extracted from knowledge_propagation.py so semantic_align + phases can run
without importing the legacy entrypoint.
"""

from __future__ import annotations

import logging
from typing import Dict, Iterable, Optional, Set

from .kp_types import UnifiedGraph


logger = logging.getLogger(__name__)


def compute_unified_scores(
    graph: UnifiedGraph,
    analysis_info: Dict[int, dict],
    *,
    only_entry_vas: Optional[Iterable[int]] = None,
    analyzed_entry_vas: Optional[Set[int]] = None,
) -> Dict[int, int]:
    """Compute heuristic scores for each unified function node (keyed by entry_va)."""

    if analyzed_entry_vas is None:
        analyzed_entry_vas = set()
        fid_to_entry = getattr(graph, "function_id_to_entry_va", None)
        if isinstance(fid_to_entry, dict) and fid_to_entry:
            for fid, info in analysis_info.items():
                if not info:
                    continue
                if info.get("analysis_state") in ("ANALYZED", "LOCKED"):
                    entry_va = fid_to_entry.get(int(fid))
                    if entry_va is not None:
                        analyzed_entry_vas.add(int(entry_va))
        else:
            for entry_va, node in graph.nodes.items():
                for fid in node.function_ids:
                    info = analysis_info.get(int(fid))
                    if info and info.get("analysis_state") in ("ANALYZED", "LOCKED"):
                        analyzed_entry_vas.add(int(entry_va))
                        break

    scores: Dict[int, int] = {}

    entry_vas = list(only_entry_vas) if only_entry_vas is not None else list(graph.nodes.keys())

    for entry_va in entry_vas:
        node = graph.nodes.get(int(entry_va))
        if node is None:
            continue
        n_ext_apis = len(node.external_callee_names)
        n_strings = len(node.string_refs)
        n_internal = len(node.internal_callee_vas)
        n_callers = len(node.caller_vas)
        n_instr = int(node.instr_count or 0)

        score = 0

        apis_contrib = 0
        if n_ext_apis > 0:
            apis_contrib = 200 + 40 * min(n_ext_apis, 5)
            score += apis_contrib

        strings_contrib = 0
        if n_strings > 0:
            strings_contrib = 120 + 15 * min(n_strings, 5)
            score += strings_contrib

        internal_contrib = 0
        if n_internal == 0:
            internal_contrib = 60
            score += internal_contrib
        else:
            internal_contrib = max(0, 40 - n_internal * 4)
            score += internal_contrib

        callers_contrib = min(n_callers * 6, 40)
        score += callers_contrib

        instr_contrib = 0
        if n_instr == 0:
            instr_contrib = -20
        elif n_instr <= 30:
            instr_contrib = 15
        elif n_instr <= 150:
            instr_contrib = 5
        else:
            instr_contrib = -min((n_instr - 150) // 50 * 5, 40)
        score += instr_contrib

        analyzed_callees = len(set(node.internal_callee_vas) & analyzed_entry_vas)
        callees_contrib = analyzed_callees * 25
        score += callees_contrib

        scores[int(entry_va)] = int(score)

        if logger.isEnabledFor(logging.DEBUG):
            name = "/".join(sorted(node.names)) if node.names else f"sub_{int(entry_va):08X}"
            logger.debug(
                "[Phase1-Score] 0x%08X (%s): APIs=%d(+%d), strings=%d(+%d), "
                "internal=%d(+%d), callers=%d(+%d), instr=%d(+%d), "
                "analyzed_callees=%d(+%d) => total=%d",
                int(entry_va),
                name,
                n_ext_apis,
                apis_contrib,
                n_strings,
                strings_contrib,
                n_internal,
                internal_contrib,
                n_callers,
                callers_contrib,
                n_instr,
                instr_contrib,
                analyzed_callees,
                callees_contrib,
                score,
            )

    return scores


def compute_unified_scores_incremental(
    graph: UnifiedGraph,
    analysis_info: Dict[int, dict],
    *,
    changed_entry_vas: Set[int],
    existing_scores: Dict[int, int],
    only_entry_vas: Optional[Iterable[int]] = None,
) -> Dict[int, int]:
    """增量更新评分：只重新计算受影响的函数。
    
    Args:
        graph: 统一函数图
        analysis_info: 分析信息字典
        changed_entry_vas: 新分析的函数 entry_va 集合
        existing_scores: 已有的分数缓存
        only_entry_vas: 如果指定，只计算这些 entry_vas 的分数
    
    Returns:
        更新后的分数字典
    """
    if not changed_entry_vas:
        return existing_scores.copy()

    # 1. 计算受影响的函数集合 = 新分析函数的调用者 + 被调用者（如果依赖）
    impacted = set(changed_entry_vas)
    analyzed_entry_vas = set()
    
    # 构建已分析函数集合
    fid_to_entry = getattr(graph, "function_id_to_entry_va", None)
    if isinstance(fid_to_entry, dict) and fid_to_entry:
        for fid, info in analysis_info.items():
            if not info:
                continue
            if info.get("analysis_state") in ("ANALYZED", "LOCKED"):
                entry_va = fid_to_entry.get(int(fid))
                if entry_va is not None:
                    analyzed_entry_vas.add(int(entry_va))
    else:
        for entry_va, node in graph.nodes.items():
            for fid in node.function_ids:
                info = analysis_info.get(int(fid))
                if info and info.get("analysis_state") in ("ANALYZED", "LOCKED"):
                    analyzed_entry_vas.add(int(entry_va))
                    break

    # 2. 扩展受影响集合：调用者（因为子函数已分析，调用者分数应提升）
    for entry_va in changed_entry_vas:
        node = graph.nodes.get(entry_va)
        if node:
            # 调用者需要重算（因为它们的 callees_contrib 会变化）
            impacted.update(node.caller_vas)
            # 被调用者：如果被调用者依赖当前函数，也需要重算
            # 这里简化处理：如果被调用者还未分析，暂时不重算（等它被分析时再算）
            # 但如果被调用者已经分析，且当前函数是它的依赖，则需要重算
            # 为了简化，这里只重算调用者

    # 3. 只重算 impacted 集合中的函数
    new_scores = existing_scores.copy()
    entry_vas_to_compute = list(impacted)
    if only_entry_vas is not None:
        entry_vas_to_compute = [va for va in entry_vas_to_compute if va in only_entry_vas]

    for entry_va in entry_vas_to_compute:
        node = graph.nodes.get(int(entry_va))
        if node is None:
            continue
        
        n_ext_apis = len(node.external_callee_names)
        n_strings = len(node.string_refs)
        n_internal = len(node.internal_callee_vas)
        n_callers = len(node.caller_vas)
        n_instr = int(node.instr_count or 0)

        score = 0

        apis_contrib = 0
        if n_ext_apis > 0:
            apis_contrib = 200 + 40 * min(n_ext_apis, 5)
            score += apis_contrib

        strings_contrib = 0
        if n_strings > 0:
            strings_contrib = 120 + 15 * min(n_strings, 5)
            score += strings_contrib

        internal_contrib = 0
        if n_internal == 0:
            internal_contrib = 60
            score += internal_contrib
        else:
            internal_contrib = max(0, 40 - n_internal * 4)
            score += internal_contrib

        callers_contrib = min(n_callers * 6, 40)
        score += callers_contrib

        instr_contrib = 0
        if n_instr == 0:
            instr_contrib = -20
        elif n_instr <= 30:
            instr_contrib = 15
        elif n_instr <= 150:
            instr_contrib = 5
        else:
            instr_contrib = -min((n_instr - 150) // 50 * 5, 40)
        score += instr_contrib

        analyzed_callees = len(set(node.internal_callee_vas) & analyzed_entry_vas)
        callees_contrib = analyzed_callees * 25
        score += callees_contrib

        new_scores[int(entry_va)] = int(score)

    return new_scores
