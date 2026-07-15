#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path


_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "phase7_stress.py"
_SPEC = importlib.util.spec_from_file_location("phase7_stress_runner", _SCRIPT)
assert _SPEC and _SPEC.loader
stress = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = stress
_SPEC.loader.exec_module(stress)


def test_build_matrix_balanced_profile(tmp_path: Path):
    db = tmp_path / "sample.db"
    sqlite3.connect(db).close()
    manifest_path = tmp_path / "manifest.json"
    manifest = {"samples": [{"name": "one", "db": str(db)}]}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    matrix = stress.build_run_matrix(
        manifest_path,
        manifest,
        profile="balanced",
        repeat_override=None,
        budgets_override=None,
        engines_override=None,
    )

    assert len(matrix) == 8
    assert [spec.variant for spec in matrix[:4]] == [
        "legacy",
        "practical-b12",
        "practical-b24",
        "practical-b40",
    ]


def test_clone_sqlite_copies_content(tmp_path: Path):
    source = tmp_path / "source.db"
    destination = tmp_path / "copy.db"
    conn = sqlite3.connect(source)
    conn.execute("CREATE TABLE sample(value TEXT)")
    conn.execute("INSERT INTO sample VALUES ('ok')")
    conn.commit()
    conn.close()

    stress.clone_sqlite(source, destination)

    copied = sqlite3.connect(destination)
    try:
        assert copied.execute("SELECT value FROM sample").fetchone()[0] == "ok"
    finally:
        copied.close()


def test_build_command_forces_safe_writeback_off(tmp_path: Path):
    spec = stress.RunSpec(
        sample_name="sample",
        engine="practical",
        repeat_index=1,
        practical_budget=24,
        input_path=None,
        db_path=tmp_path / "source.db",
        task_config=None,
        ida_dir=None,
        binary_id=None,
        goal_keywords=(),
        goal_vas=(),
        goal_structs=(),
        common_args=("--apply-db",),
        extra_args=(),
        expectations={},
    )
    command = stress.build_command(
        spec,
        work_db=tmp_path / "work.db",
        run_dir=tmp_path / "run",
        llm_mode="off",
        engine_dry_run=True,
    )

    assert "--practical-node-budget" in command
    assert command[-3:] == ["--no-resume", "--no-force-resume", "--no-console-progress"]
    assert command.index("--no-apply-db") > command.index("--apply-db")


def test_extract_metrics_with_expectations(tmp_path: Path):
    report = {
        "selected_goals": [{"entry_va": "0x1000"}],
        "generations": [
            {
                "actual_generations": 1,
                "generations": [
                    {
                        "lambda_nodes": ["0x1000", "0x1100"],
                        "result": {
                            "paths": [{"path_vas": ["0x1000", "0x1100"], "depth": 1}],
                            "llm": {
                                "token_usage": {
                                    "prompt_tokens": 10,
                                    "completion_tokens": 5,
                                    "total_tokens": 15,
                                    "api_calls": 1,
                                },
                                "steps": [{"status": "ok", "confidence": 0.8}],
                            },
                        },
                    }
                ],
            }
        ],
        "function_compare": [
            {
                "selection": {
                    "selected": "new",
                    "evidence_gate": {"passed": True},
                }
            }
        ],
        "selected_profiles": [
            {
                "entry_va": "0x1100",
                "name": "parse_auth_packet",
                "semantic_summary": "Parses an auth packet",
            }
        ],
        "db_apply": {"planned_count": 0, "applied_count": 0},
    }
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    metrics = stress.extract_report_metrics(
        report_path,
        {
            "goal_vas": ["0x1000"],
            "path_subsequences": [["0x1000", "0x1100"]],
            "profile_tokens": {"0x1100": ["auth", "packet"]},
        },
    )

    assert metrics["coverage_node_count"] == 2
    assert metrics["total_tokens"] == 15
    assert metrics["goal_recall"] == 1.0
    assert metrics["path_recall"] == 1.0
    assert metrics["profile_token_recall"] == 1.0


def test_comparison_reports_speed_and_token_reduction():
    summary = [
        {
            "sample": "s",
            "variant": "legacy",
            "wall_time_sec_mean": 20.0,
            "total_tokens_mean": 1000.0,
            "coverage_node_count_mean": 30.0,
            "deepest_path_depth_mean": 5.0,
            "goal_recall_mean": 0.5,
            "path_recall_mean": 0.5,
            "profile_token_recall_mean": 0.5,
        },
        {
            "sample": "s",
            "variant": "practical-b24",
            "wall_time_sec_mean": 10.0,
            "total_tokens_mean": 700.0,
            "coverage_node_count_mean": 24.0,
            "deepest_path_depth_mean": 6.0,
            "goal_recall_mean": 1.0,
            "path_recall_mean": 0.75,
            "profile_token_recall_mean": 0.75,
        },
    ]

    comparison = stress.build_comparisons(summary)[0]

    assert comparison["wall_speedup"] == 2.0
    assert comparison["token_reduction_pct"] == 30.0
    assert comparison["goal_recall_delta"] == 0.5
