#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SA_ROOT = _PROJECT_ROOT / "tools" / "Semantics_Alignment"
if str(_SA_ROOT) not in sys.path:
    sys.path.insert(0, str(_SA_ROOT))

from depth import practical_accuracy as base
from depth.practical_evidence import install_evidence_extensions


def _node(va: int, name: str, *, strings=(), apis=(), callers=(), callees=()):
    return SimpleNamespace(
        entry_va=va,
        names={name},
        function_ids=set(),
        string_refs=set(strings),
        external_callee_names=set(apis),
        caller_vas=set(callers),
        internal_callee_vas=set(callees),
        instr_count=10,
    )


def setup_function():
    graph = SimpleNamespace(
        nodes={
            0x1000: _node(0x1000, "network_dispatch", strings={"AUTH failed"}, callees={0x1100}),
            0x1100: _node(0x1100, "parse_auth_packet", callers={0x1000}),
            0x2000: _node(0x2000, "license_table_reader"),
        }
    )
    base.configure_practical_context(
        graph=graph,
        mixed_adjacency={
            0x1000: {0x1100: {"call"}, 0x2000: {"data", "indirect"}},
            0x1100: {0x1000: {"call"}},
            0x2000: {0x1000: {"data", "indirect"}},
        },
        settings=base.PracticalSettings(
            node_budget=4,
            evidence_threshold=0.25,
            min_evidence_signals=1,
        ),
    )
    install_evidence_extensions()


def test_non_call_relations_are_rendered_as_evidence():
    block = base.build_static_evidence_block(0x1000, 0x1100)
    assert "caller_evidence_relations" in block
    assert "license_table_reader@0x00002000(data,indirect)" in block


def test_relation_overlap_is_counted_but_not_strong_enough_alone():
    result = base.score_profile_static_evidence(
        {
            "entry_va": "0x1000",
            "name": "read_license_table",
            "summary_signature": "int read_license_table(void)",
            "semantic_summary": "Reads entries from a license table.",
            "confidence_score": 95,
        }
    )
    assert "license" in result["overlaps"]["relation"]
    assert result["score"] == 0.2
    assert result["score"] < base._CONTEXT.settings.evidence_threshold


def test_exact_existing_symbol_name_is_independent_static_evidence():
    result = base.score_profile_static_evidence(
        {
            "entry_va": "0x1000",
            "name": "network_dispatch",
            "summary_signature": "int network_dispatch(int fd)",
            "semantic_summary": "Dispatches network packets.",
            "confidence_score": 95,
        }
    )
    assert "network" in result["overlaps"]["symbol_name"]
    assert result["independent_signal_count"] >= 1
    assert result["score"] >= base._CONTEXT.settings.evidence_threshold


def load_tests(_loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for func in (
        test_non_call_relations_are_rendered_as_evidence,
        test_relation_overlap_is_counted_but_not_strong_enough_alone,
        test_exact_existing_symbol_name_is_independent_static_evidence,
    ):
        def run_test(test_func=func):
            setup_function()
            test_func()

        suite.addTest(unittest.FunctionTestCase(run_test, description=func.__name__))
    return suite
