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

from depth import practical_accuracy as pa


def _node(
    va: int,
    *,
    names=(),
    callers=(),
    callees=(),
    apis=(),
    strings=(),
    instr_count: int = 10,
):
    return SimpleNamespace(
        entry_va=int(va),
        names=set(names),
        function_ids=set(),
        caller_vas=set(callers),
        internal_callee_vas=set(callees),
        external_callee_names=set(apis),
        string_refs=set(strings),
        instr_count=int(instr_count),
    )


def _graph():
    nodes = {
        0x1000: _node(
            0x1000,
            names={"network_dispatch"},
            callees={0x1100},
            apis={"recv", "memcpy"},
            strings={"AUTH failed", "packet too large"},
        ),
        0x1100: _node(
            0x1100,
            names={"parse_auth_packet"},
            callers={0x1000},
            callees={0x1200},
        ),
        0x1200: _node(
            0x1200,
            names={"apply_session_state"},
            callers={0x1100},
        ),
        0x2000: _node(
            0x2000,
            names={"unrelated_logger"},
            strings={"AUTH failed"},
        ),
    }
    return SimpleNamespace(nodes=nodes)


def setup_function():
    pa.configure_practical_context(
        graph=_graph(),
        func_to_globals={0x1000: [(0x5000, 3)]},
        settings=pa.PracticalSettings(
            node_budget=3,
            evidence_threshold=0.25,
            min_evidence_signals=1,
        ),
    )


def test_call_budget_neighborhood_excludes_string_only_edges():
    adjacency = {
        0x1000: {
            0x1100: {"call"},
            0x2000: {"string"},
        },
        0x1100: {0x1000: {"call"}, 0x1200: {"call"}},
        0x1200: {0x1100: {"call"}},
        0x2000: {0x1000: {"string"}},
    }
    trace = {}
    nodes, distances = pa.call_budget_neighborhood(
        adjacency,
        0x1000,
        radius=99.0,
        weights={"call": 0.45, "string": 0.15},
        max_nodes=180,
        trace_out=trace,
    )

    assert nodes == {0x1000, 0x1100, 0x1200}
    assert 0x2000 not in nodes
    assert distances[0x1200] == 2.0
    assert trace["algorithm"] == "directed_call_node_budget"
    assert trace["node_budget"] == 3


def test_static_evidence_block_contains_api_string_global_and_neighbors():
    block = pa.build_static_evidence_block(0x1000, 0x1100)

    assert "recv" in block
    assert "AUTH failed" in block
    assert "0x00005000(refs=3)" in block
    assert "parse_auth_packet" in block


def test_prompt_patch_injects_evidence_constraints():
    pa._CONTEXT.original_prompt = lambda **_kwargs: "BASE\n[输出要求]\nJSON"
    prompt = pa.practical_deep_path_step_prompt(
        from_va="0x1000",
        to_va="0x1100",
    )

    assert "[独立静态证据]" in prompt
    assert "[证据约束]" in prompt
    assert "AUTH failed" in prompt
    assert prompt.index("[独立静态证据]") < prompt.index("[输出要求]")


def test_profile_gate_rejects_unsupported_llm_candidate():
    old_profile = {
        "entry_va": "0x00001000",
        "name": "network_dispatch",
        "summary_signature": "int network_dispatch(int fd)",
        "semantic_summary": "Receives network data and dispatches packet parsing.",
    }
    new_profile = {
        "entry_va": "0x00001000",
        "status": "ok",
        "name": "decrypt_license_blob",
        "summary_signature": "int decrypt_license_blob(void *ctx)",
        "semantic_summary": "Decrypts a proprietary license payload with a secret key.",
        "structured_analysis": "{}",
        "confidence_score": 95,
    }
    result = pa.select_profile_with_static_gate(
        old_profile,
        new_profile,
        {"choose": "new", "old_score": 0.2, "new_score": 0.9},
        min_delta=0.1,
    )

    assert result["selected"] == "old"
    assert result["evidence_gate"]["passed"] is False
    assert "static_evidence_gate_failed" in result["evidence_gate"]["rejection_reasons"]


def test_profile_gate_accepts_candidate_supported_by_strings():
    old_profile = {
        "entry_va": "0x00001000",
        "name": "sub_1000",
        "summary_signature": "",
        "semantic_summary": "",
    }
    new_profile = {
        "entry_va": "0x00001000",
        "status": "ok",
        "name": "parse_auth_packet",
        "summary_signature": "int parse_auth_packet(int fd)",
        "semantic_summary": "Parses an AUTH packet received from the network connection.",
        "structured_analysis": '{"tags":["network","auth"]}',
        "confidence_score": 90,
    }
    result = pa.select_profile_with_static_gate(
        old_profile,
        new_profile,
        {"choose": "new", "old_score": 0.1, "new_score": 0.8},
        min_delta=0.1,
    )

    assert result["selected"] == "new"
    assert result["evidence_gate"]["passed"] is True
    assert "auth" in result["evidence_gate"]["overlaps"]["string"]


def load_tests(_loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for func in (
        test_call_budget_neighborhood_excludes_string_only_edges,
        test_static_evidence_block_contains_api_string_global_and_neighbors,
        test_prompt_patch_injects_evidence_constraints,
        test_profile_gate_rejects_unsupported_llm_candidate,
        test_profile_gate_accepts_candidate_supported_by_strings,
    ):
        def run_test(test_func=func):
            setup_function()
            test_func()

        suite.addTest(unittest.FunctionTestCase(run_test, description=func.__name__))
    return suite
