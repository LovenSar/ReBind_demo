#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


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


def test_matrix_rejects_normalized_name_collision(tmp_path: Path):
    db = tmp_path / "sample.db"
    sqlite3.connect(db).close()
    manifest = {
        "samples": [
            {"name": "a b", "db": str(db)},
            {"name": "a-b", "db": str(db)},
        ]
    }

    try:
        stress.build_run_matrix(
            tmp_path / "manifest.json",
            manifest,
            profile="smoke",
            repeat_override=None,
            budgets_override=None,
            engines_override=None,
        )
    except ValueError as exc:
        assert "collide after normalization" in str(exc)
    else:
        raise AssertionError("normalized sample-name collision was accepted")


def test_manifest_rejects_malformed_expectations(tmp_path: Path):
    db = tmp_path / "sample.db"
    sqlite3.connect(db).close()
    manifest = {
        "samples": [
            {
                "name": "sample",
                "db": str(db),
                "expectations": {"goal_vas": "0x1000"},
            }
        ]
    }

    try:
        stress.build_run_matrix(
            tmp_path / "manifest.json",
            manifest,
            profile="smoke",
            repeat_override=None,
            budgets_override=None,
            engines_override=None,
        )
    except ValueError as exc:
        assert "goal_vas must be a JSON array" in str(exc)
    else:
        raise AssertionError("malformed expectations were accepted")


def test_aggregate_excludes_failed_runs_from_performance_metrics():
    summary = stress.aggregate_results(
        [
            {
                "sample": "s",
                "variant": "legacy",
                "status": "ok",
                "report_status": "ok",
                "wall_time_sec": 10.0,
                "total_tokens": 100,
            },
            {
                "sample": "s",
                "variant": "legacy",
                "status": "runner_error",
                "report_status": "missing",
                "wall_time_sec": 0.0,
            },
        ]
    )[0]

    assert summary["success_rate"] == 0.5
    assert summary["failure_rate"] == 0.5
    assert summary["runner_errors"] == 1
    assert summary["wall_time_sec_mean"] == 10.0


def test_run_process_terminates_tree_on_keyboard_interrupt(tmp_path: Path):
    class FakeProcess:
        pid = 12345

        def __init__(self):
            self.alive = True

        def poll(self):
            return None if self.alive else 130

    process = FakeProcess()

    def terminate(proc):
        proc.alive = False

    with patch.object(stress.subprocess, "Popen", return_value=process), patch.object(
        stress, "_process_tree_rss_mb", return_value=None
    ), patch.object(stress, "_terminate_process_tree", side_effect=terminate) as terminate_mock, patch.object(
        stress.time, "sleep", side_effect=KeyboardInterrupt
    ):
        result = stress.run_process(["phase7"], tmp_path / "run", timeout_seconds=60)

    assert result.interrupted is True
    assert result.return_code == 130
    assert terminate_mock.call_count == 1
    assert process.alive is False


def test_execute_run_rejects_partial_llm_success(tmp_path: Path):
    source_db = tmp_path / "source.db"
    sqlite3.connect(source_db).close()
    spec = stress.RunSpec(
        sample_name="sample",
        engine="legacy",
        repeat_index=1,
        practical_budget=None,
        input_path=None,
        db_path=source_db,
        task_config=None,
        ida_dir=None,
        binary_id=None,
        goal_keywords=(),
        goal_vas=(),
        goal_structs=(),
        common_args=(),
        extra_args=(),
        expectations={},
    )
    metrics = {
        "report_status": "ok",
        "db_apply_applied": 0,
        "llm_interactions": 2,
        "successful_llm_interactions": 1,
    }
    process_result = stress.ProcessResult(
        return_code=0,
        timed_out=False,
        interrupted=False,
        wall_time_sec=1.0,
        peak_rss_mb=1.0,
    )

    with patch.object(stress, "clone_sqlite"), patch.object(
        stress, "run_process", return_value=process_result
    ), patch.object(stress, "extract_report_metrics", return_value=metrics):
        result = stress.execute_run(
            spec,
            output_root=tmp_path / "out",
            timeout_seconds=60,
            llm_mode="on",
            engine_dry_run=False,
            keep_work_db=False,
        )

    assert result["status"] == "failed"
    assert "successful=1 attempted=2" in result["runner_error"]


def test_tokenization_splits_compound_function_names():
    assert stress._tokens("attack_main sendHTTP") == {"attack", "main", "send", "http"}


_TMP_PATH_TESTS = (
    test_build_matrix_balanced_profile,
    test_clone_sqlite_copies_content,
    test_build_command_forces_safe_writeback_off,
    test_extract_metrics_with_expectations,
    test_matrix_rejects_normalized_name_collision,
    test_manifest_rejects_malformed_expectations,
    test_run_process_terminates_tree_on_keyboard_interrupt,
    test_execute_run_rejects_partial_llm_success,
)


def load_tests(_loader, _tests, _pattern):
    suite = unittest.TestSuite()
    for func in _TMP_PATH_TESTS:
        def run_tmp_test(test_func=func):
            with tempfile.TemporaryDirectory() as temp_dir:
                test_func(Path(temp_dir))

        suite.addTest(unittest.FunctionTestCase(run_tmp_test, description=func.__name__))
    for func in (
        test_comparison_reports_speed_and_token_reduction,
        test_aggregate_excludes_failed_runs_from_performance_metrics,
        test_tokenization_splits_compound_function_names,
    ):
        suite.addTest(unittest.FunctionTestCase(func, description=func.__name__))
    return suite
