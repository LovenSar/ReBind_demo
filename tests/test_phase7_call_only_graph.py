#!/usr/bin/env python3
"""Tests for Phase7's explicit lightweight call-only graph mode."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SA_ROOT = _PROJECT_ROOT / "tools" / "Semantics_Alignment"
if str(_SA_ROOT) not in sys.path:
    sys.path.insert(0, str(_SA_ROOT))

from depth.graph_augment import _build_call_only_graph  # noqa: E402
from depth.practical_accuracy import (  # noqa: E402
    PracticalSettings,
    configure_practical_context,
    rank_nodes_by_call_evidence,
)
from depth.profile_ops import _rank_nodes_for_compare  # noqa: E402
from depth.practical_engine import _parse_practical_args  # noqa: E402
from kp.kp_types import UnifiedFunctionNode, UnifiedGraph  # noqa: E402


class TestPhase7CallOnlyGraph(unittest.TestCase):
    def test_includes_only_internal_call_edges(self) -> None:
        graph = UnifiedGraph(
            binary_id=1,
            nodes={
                0x1000: UnifiedFunctionNode(
                    entry_va=0x1000,
                    binary_id=1,
                    function_ids={1},
                    internal_callee_vas={0x2000, 0x9999},
                ),
                0x2000: UnifiedFunctionNode(
                    entry_va=0x2000,
                    binary_id=1,
                    function_ids={2},
                ),
            },
            tool_map={},
            func_tool={},
        )

        adjacency, func_to_globals, stats = _build_call_only_graph(graph)

        self.assertEqual(adjacency[0x1000][0x2000], {"call"})
        self.assertEqual(adjacency[0x2000][0x1000], {"call"})
        self.assertNotIn(0x9999, adjacency[0x1000])
        self.assertEqual(func_to_globals, {})
        self.assertEqual(stats["graph_mode"], "call-only")
        self.assertEqual(stats["direct_data_edge_sources"], 0)

    def test_compare_rank_prioritizes_explicit_goal(self) -> None:
        graph = UnifiedGraph(
            binary_id=1,
            nodes={
                0x1000: UnifiedFunctionNode(entry_va=0x1000, binary_id=1, function_ids={1}),
                0x2000: UnifiedFunctionNode(entry_va=0x2000, binary_id=1, function_ids={2}),
            },
            tool_map={},
            func_tool={},
        )
        adjacency = {0x1000: {0x2000: {"call"}}, 0x2000: {0x1000: {"call"}}}

        ranked = _rank_nodes_for_compare(
            graph,
            adjacency,
            {0x1000, 0x2000},
            goal_structs=[],
            limit=1,
            priority_nodes={0x1000},
        )

        self.assertEqual(ranked, [0x1000])

    def test_practical_rank_prefers_compact_equal_evidence_candidate(self) -> None:
        graph = UnifiedGraph(
            binary_id=1,
            nodes={
                0x1000: UnifiedFunctionNode(
                    entry_va=0x1000,
                    binary_id=1,
                    function_ids={1},
                    instr_count=200,
                    external_callee_names={"ApiA"},
                ),
                0x2000: UnifiedFunctionNode(
                    entry_va=0x2000,
                    binary_id=1,
                    function_ids={2},
                    instr_count=12,
                    external_callee_names={"ApiB"},
                ),
            },
            tool_map={},
            func_tool={},
        )
        configure_practical_context(graph=graph, settings=PracticalSettings())

        ranked = rank_nodes_by_call_evidence(
            graph,
            {},
            {0x1000, 0x2000},
            goal_structs=[],
            limit=1,
        )

        self.assertEqual(ranked, [0x2000])

    def test_practical_profile_budget_defaults(self) -> None:
        practical, remaining = _parse_practical_args([])

        self.assertEqual(remaining, [])
        self.assertEqual(practical.practical_profile_max_tokens, 1600)
        self.assertEqual(practical.practical_profile_max_disasm_lines, 80)
        self.assertEqual(practical.practical_profile_max_pseudo_chars, 1400)
        self.assertEqual(practical.practical_profile_max_strings, 8)
        self.assertEqual(practical.practical_max_compare_nodes, 2)
        self.assertFalse(practical.practical_fast)

    def test_practical_fast_mode_is_recognized(self) -> None:
        practical, remaining = _parse_practical_args(["--practical-fast"])

        self.assertEqual(remaining, [])
        self.assertTrue(practical.practical_fast)


if __name__ == "__main__":
    unittest.main()
