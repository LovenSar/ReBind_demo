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
from kp import kp_llm  # noqa: E402
from kp.kp_llm import (  # noqa: E402
    _extract_chat_message_text,
    _request_kwargs_for_attempt,
    _extract_usage_from_chat_response,
    _try_parse_json_value,
    call_llm_analyze_function,
)
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

    def test_message_text_supports_block_content(self) -> None:
        response = {
            "choices": [{"message": {"content": [{"type": "text", "text": '{"ok":true}'}]}}]
        }
        self.assertEqual(_extract_chat_message_text(response), '{"ok":true}')

    def test_retry_request_demands_compact_json(self) -> None:
        original = {
            "messages": [{"role": "user", "content": "analyze"}],
            "temperature": 0.7,
            "max_tokens": 1600,
        }

        first = _request_kwargs_for_attempt(original, 1)
        retry = _request_kwargs_for_attempt(
            original,
            2,
            retry_token_multiplier=2.0,
            retry_max_tokens=6000,
        )
        final_retry = _request_kwargs_for_attempt(
            original,
            3,
            retry_token_multiplier=2.0,
            retry_max_tokens=6000,
        )

        self.assertEqual(len(first["messages"]), 1)
        self.assertEqual(len(retry["messages"]), 2)
        self.assertIn("compact JSON", retry["messages"][-1]["content"])
        self.assertEqual(retry["temperature"], 0.1)
        self.assertEqual(retry["max_tokens"], 3200)
        self.assertEqual(final_retry["max_tokens"], 6000)
        self.assertEqual(original["max_tokens"], 1600)

    def test_truncated_json_retry_expands_budget_and_recovers(self) -> None:
        responses = iter(
            [
                SimpleNamespace(
                    choices=[SimpleNamespace(message=SimpleNamespace(content='{"summary":'))],
                    usage=None,
                ),
                SimpleNamespace(
                    choices=[SimpleNamespace(message=SimpleNamespace(content='{"summary":"ok"}'))],
                    usage=None,
                ),
            ]
        )

        class CapturingCompletions:
            def __init__(self) -> None:
                self.requests: list[dict[str, object]] = []

            def create(self, **kwargs):
                self.requests.append(kwargs)
                return next(responses)

        completions = CapturingCompletions()
        client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
        with patch("kp.kp_llm.require_openai", return_value=client):
            result = call_llm_analyze_function(
                conversation=[],
                request_kwargs={
                    "messages": [{"role": "user", "content": "analyze"}],
                    "temperature": 0.1,
                    "max_tokens": 1600,
                },
                api_settings={
                    "json_retry_token_multiplier": 2.0,
                    "json_retry_max_tokens": 6000,
                },
                max_attempts=2,
            )

        self.assertEqual(result, {"summary": "ok"})
        self.assertEqual([row["max_tokens"] for row in completions.requests], [1600, 3200])

    def test_empty_response_retry_expands_budget_and_records_summary(self) -> None:
        responses = iter(
            [
                SimpleNamespace(
                    choices=[SimpleNamespace(message=SimpleNamespace(content=""))],
                    usage=None,
                ),
                SimpleNamespace(
                    choices=[SimpleNamespace(message=SimpleNamespace(content='{"status":"ok"}'))],
                    usage=None,
                ),
            ]
        )

        class EmptyOnce:
            def create(self, **_kwargs):
                return next(responses)

        usage: list[dict[str, object]] = []
        client = SimpleNamespace(chat=SimpleNamespace(completions=EmptyOnce()))
        with patch("kp.kp_llm.require_openai", return_value=client):
            result = call_llm_analyze_function(
                conversation=[],
                request_kwargs={"messages": [], "max_tokens": 1600},
                api_settings={
                    "json_retry_token_multiplier": 2.0,
                    "json_retry_max_tokens": 6000,
                },
                max_attempts=2,
                usage_collect=usage,
            )

        self.assertEqual(result, {"status": "ok"})
        self.assertEqual(
            [(row["request_max_tokens"], row["response_chars"]) for row in usage],
            [(1600, 0), (3200, 15)],
        )

    def test_single_key_rate_limit_uses_bounded_retry(self) -> None:
        response = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))],
            usage=None,
        )

        class RateLimitedOnce:
            calls = 0

            def create(self, **_kwargs):
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("429 too many requests")
                return response

        client = SimpleNamespace(chat=SimpleNamespace(completions=RateLimitedOnce()))
        old_keys = list(kp_llm._API_KEYS)
        old_index = kp_llm._API_KEY_INDEX
        old_blocked = dict(kp_llm._BLOCKED_KEYS)
        kp_llm._API_KEYS[:] = ["only_key"]
        kp_llm._API_KEY_INDEX = 0
        kp_llm._BLOCKED_KEYS.clear()
        try:
            with patch("kp.kp_llm.require_openai", return_value=client), patch(
                "kp.kp_llm.time.sleep"
            ) as sleep:
                result = call_llm_analyze_function(
                    conversation=[],
                    request_kwargs={},
                    api_settings={"wait_on_rate_limit": False},
                    max_attempts=2,
                )
            self.assertEqual(result, {"ok": True})
            sleep.assert_called_once_with(1.5)
            self.assertFalse(kp_llm._BLOCKED_KEYS)
        finally:
            kp_llm._API_KEYS[:] = old_keys
            kp_llm._API_KEY_INDEX = old_index
            kp_llm._BLOCKED_KEYS.clear()
            kp_llm._BLOCKED_KEYS.update(old_blocked)

    def test_single_key_final_rate_limit_does_not_enter_long_wait(self) -> None:
        class AlwaysRateLimited:
            def create(self, **_kwargs):
                raise RuntimeError("429 too many requests")

        client = SimpleNamespace(chat=SimpleNamespace(completions=AlwaysRateLimited()))
        old_keys = list(kp_llm._API_KEYS)
        old_index = kp_llm._API_KEY_INDEX
        old_blocked = dict(kp_llm._BLOCKED_KEYS)
        kp_llm._API_KEYS[:] = ["only_key"]
        kp_llm._API_KEY_INDEX = 0
        kp_llm._BLOCKED_KEYS.clear()
        try:
            with patch("kp.kp_llm.require_openai", return_value=client), patch(
                "kp.kp_llm.time.sleep"
            ) as sleep, patch("kp.kp_llm._wait_for_key_recovery") as wait:
                result = call_llm_analyze_function(
                    conversation=[],
                    request_kwargs={},
                    api_settings={"wait_on_rate_limit": False},
                    max_attempts=2,
                )
            self.assertEqual(result, {})
            sleep.assert_called_once_with(1.5)
            wait.assert_not_called()
        finally:
            kp_llm._API_KEYS[:] = old_keys
            kp_llm._API_KEY_INDEX = old_index
            kp_llm._BLOCKED_KEYS.clear()
            kp_llm._BLOCKED_KEYS.update(old_blocked)

    def test_failed_api_attempts_are_counted(self) -> None:
        class FailingCompletions:
            def create(self, **_kwargs):
                raise RuntimeError("simulated provider rejection")

        client = SimpleNamespace(
            chat=SimpleNamespace(completions=FailingCompletions())
        )
        usage_records: list[dict[str, object]] = []
        with patch("kp.kp_llm.require_openai", return_value=client):
            result = call_llm_analyze_function(
                conversation=[],
                request_kwargs={},
                api_settings={},
                max_attempts=2,
                usage_collect=usage_records,
            )

        self.assertEqual(result, {})
        self.assertEqual(len(usage_records), 2)
        self.assertTrue(all(row["status"] == "error" for row in usage_records))

    def test_transient_connection_error_uses_backoff_before_retry(self) -> None:
        response = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))],
            usage=None,
        )

        class FlakyCompletions:
            calls = 0

            def create(self, **_kwargs):
                self.calls += 1
                if self.calls == 1:
                    raise RuntimeError("Connection error")
                return response

        client = SimpleNamespace(
            chat=SimpleNamespace(completions=FlakyCompletions())
        )
        usage_records: list[dict[str, object]] = []
        with patch("kp.kp_llm.require_openai", return_value=client), patch(
            "kp.kp_llm.time.sleep"
        ) as sleep:
            result = call_llm_analyze_function(
                conversation=[],
                request_kwargs={},
                api_settings={},
                max_attempts=2,
                usage_collect=usage_records,
            )

        self.assertEqual(result, {"ok": True})
        sleep.assert_called_once_with(1.5)
        self.assertEqual([row["status"] for row in usage_records], ["error", "ok"])

    def test_successful_response_without_usage_still_counts_api_call(self) -> None:
        response = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok": true}'))],
            usage=None,
        )
        client = SimpleNamespace(
            chat=SimpleNamespace(
                completions=SimpleNamespace(create=lambda **_kwargs: response)
            )
        )
        usage_records: list[dict[str, object]] = []
        with patch("kp.kp_llm.require_openai", return_value=client):
            result = call_llm_analyze_function(
                conversation=[],
                request_kwargs={},
                api_settings={},
                max_attempts=1,
                usage_collect=usage_records,
            )

        self.assertEqual(result, {"ok": True})
        self.assertEqual(len(usage_records), 1)
        self.assertEqual(usage_records[0]["status"], "ok")

    def test_json_parser_prefers_expected_object_after_reasoning_array(self) -> None:
        response = (
            "Parameter [0] carries the socket handle.\n"
            "```json\n"
            '{"from":"caller","to":"callee","confidence":0.9}'
            "\n```"
        )

        self.assertEqual(
            _try_parse_json_value(response, preferred_type=dict),
            {"from": "caller", "to": "callee", "confidence": 0.9},
        )

    def test_json_parser_prefers_expected_array_after_reasoning_object(self) -> None:
        response = 'Schema example {"name":"placeholder"}; final: ["network", "socket"]'

        self.assertEqual(
            _try_parse_json_value(response, preferred_type=list),
            ["network", "socket"],
        )

    def test_json_parser_discards_completed_reasoning_block(self) -> None:
        response = '<think>work through the answer first</think>\n{"name":"NtCreateFile"}'

        self.assertEqual(
            _try_parse_json_value(response, preferred_type=dict),
            {"name": "NtCreateFile"},
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
