#!/usr/bin/env python3
"""深路径 LLM 逐步 checkpoint、恢复与摘要日志。"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SA_ROOT = _PROJECT_ROOT / "tools" / "Semantics_Alignment"
if str(_SA_ROOT) not in sys.path:
    sys.path.insert(0, str(_SA_ROOT))

from depth.deep_path_step import LLMStepCheckpointError, run_llm_poll_on_deepest_path  # noqa: E402
from kp.kp_llm import _extract_usage_from_chat_response  # noqa: E402
from kp.kp_types import UnifiedFunctionNode, UnifiedGraph  # noqa: E402


def _result(from_name: str, to_name: str) -> dict[str, object]:
    return {
        "from": from_name,
        "to": to_name,
        "likely_initial_input": "argv",
        "required_state_now": "ready",
        "gate_condition": "x != 0",
        "condition_relation_with_previous": "AND",
        "reasoning": "evidence",
        "evidence": ["cmp x, 0"],
        "confidence": 0.8,
    }


class TestDeepPathStepResume(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute(
            "CREATE TABLE pseudo_functions(id INTEGER PRIMARY KEY, function_id INTEGER, prototype TEXT, body TEXT);"
        )
        nodes = {}
        func_tool = {}
        for idx, va in enumerate((0x1000, 0x2000, 0x3000), 1):
            nodes[va] = UnifiedFunctionNode(
                entry_va=va,
                binary_id=1,
                names={f"f{idx}"},
                function_ids={idx},
            )
            func_tool[idx] = "ida"
            self.conn.execute(
                "INSERT INTO pseudo_functions(function_id, prototype, body) VALUES(?, ?, ?);",
                (idx, f"int f{idx}()", f"return {idx};"),
            )
        self.graph = UnifiedGraph(binary_id=1, nodes=nodes, tool_map={}, func_tool=func_tool)
        self.paths = [
            {
                "entry_va": "0x00001000",
                "entry_name": "f1",
                "depth": 2,
                "path_vas": ["0x00001000", "0x00002000", "0x00003000"],
                "path_names": ["f1", "f2", "f3"],
                "edge_conditions": [{"status": "ok"}, {"status": "ok"}],
            }
        ]
        self.settings = SimpleNamespace(
            model="fake",
            temperature=0.0,
            max_tokens=128,
            chat_completion_kwargs={"extra_headers": {"Authorization": "Bearer test-secret"}},
            api_settings={},
        )

    def tearDown(self) -> None:
        self.conn.close()

    def test_usage_extraction_supports_object_and_dict_responses(self) -> None:
        obj = SimpleNamespace(
            usage=SimpleNamespace(prompt_tokens=10, completion_tokens=4, total_tokens=14)
        )
        self.assertEqual(_extract_usage_from_chat_response(obj)["total_tokens"], 14)
        self.assertEqual(
            _extract_usage_from_chat_response(
                {"usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}}
            )["total_tokens"],
            5,
        )

    def test_resume_skips_checkpointed_api_step_and_logs_summary_only(self) -> None:
        saved: dict[str, object] = {}

        def fail_after_save(payload: dict[str, object]) -> None:
            saved.update(payload)
            raise OSError("simulated checkpoint interruption")

        with tempfile.TemporaryDirectory() as td:
            log_path = Path(td) / "llm.jsonl"
            with patch(
                "depth.deep_path_step.call_llm_analyze_function",
                side_effect=[_result("f1", "f2")],
            ) as first_call:
                with self.assertRaises(LLMStepCheckpointError):
                    run_llm_poll_on_deepest_path(
                        conn=self.conn,
                        graph=self.graph,
                        paths=self.paths,
                        llm_settings=self.settings,
                        max_attempts=1,
                        code_chars=400,
                        max_steps=0,
                        dry_run=False,
                        progress=False,
                        log_file=str(log_path),
                        on_step_checkpoint=fail_after_save,
                    )
                self.assertEqual(first_call.call_count, 1)

            checkpoints: list[dict[str, object]] = []
            with patch(
                "depth.deep_path_step.call_llm_analyze_function",
                side_effect=[_result("f2", "f3")],
            ) as resumed_call:
                result = run_llm_poll_on_deepest_path(
                    conn=self.conn,
                    graph=self.graph,
                    paths=self.paths,
                    llm_settings=self.settings,
                    max_attempts=1,
                    code_chars=400,
                    max_steps=0,
                    dry_run=False,
                    progress=False,
                    log_file=str(log_path),
                    resume_state=saved,
                    on_step_checkpoint=lambda payload: checkpoints.append(payload),
                )
                self.assertEqual(resumed_call.call_count, 1)

            self.assertEqual(len(result["steps"]), 2)
            self.assertEqual(len(checkpoints), 1)
            events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
            prompt_events = [x for x in events if x.get("type") == "step_prompt"]
            request_events = [x for x in events if x.get("type") == "step_request"]
            self.assertTrue(prompt_events)
            self.assertTrue(all("prompt" not in x for x in prompt_events))
            self.assertTrue(all("prompt_summary" not in x for x in prompt_events))
            self.assertTrue(all(len(str(x.get("prompt_sha256") or "")) == 64 for x in prompt_events))
            self.assertTrue(all("request_kwargs" not in x for x in request_events))
            self.assertTrue(
                all(
                    x["request_summary"]["extra_headers"]["Authorization"] == "<redacted>"
                    for x in request_events
                )
            )
            self.assertTrue(any(x.get("type") == "step_resumed" for x in events))

    def test_raw_request_logging_redacts_authorization_header(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            log_path = Path(td) / "llm.jsonl"
            with (
                patch(
                    "depth.deep_path_step.call_llm_analyze_function",
                    return_value=_result("f1", "f2"),
                ),
                redirect_stdout(StringIO()),
            ):
                run_llm_poll_on_deepest_path(
                    conn=self.conn,
                    graph=self.graph,
                    paths=[{**self.paths[0], "path_vas": self.paths[0]["path_vas"][:2], "path_names": self.paths[0]["path_names"][:2], "edge_conditions": self.paths[0]["edge_conditions"][:1]}],
                    llm_settings=self.settings,
                    max_attempts=1,
                    code_chars=400,
                    max_steps=0,
                    dry_run=False,
                    verbose=True,
                    progress=False,
                    log_file=str(log_path),
                )
            events = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
            request = next(x for x in events if x.get("type") == "step_request")
            self.assertEqual(
                request["request_kwargs"]["extra_headers"]["Authorization"],
                "<redacted>",
            )


if __name__ == "__main__":
    unittest.main()
