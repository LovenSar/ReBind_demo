"""kp_scoring.py

Heuristic scoring helpers for scheduling analysis.

Extracted from knowledge_propagation.py so semantic_align + phases can run
without importing the legacy entrypoint.
"""

from __future__ import annotations

import logging
from typing import Dict, Set

from .kp_types import UnifiedGraph


logger = logging.getLogger(__name__)


def compute_unified_scores(
    graph: UnifiedGraph,
    analysis_info: Dict[int, dict],
) -> Dict[int, int]:
    """Compute heuristic scores for each unified function node (keyed by entry_va)."""

    analyzed_entry_vas: Set[int] = set()
    for entry_va, node in graph.nodes.items():
        for fid in node.function_ids:
            info = analysis_info.get(int(fid))
            if info and info.get("analysis_state") in ("ANALYZED", "LOCKED"):
                analyzed_entry_vas.add(int(entry_va))
                break

    scores: Dict[int, int] = {}

    for entry_va, node in graph.nodes.items():
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
