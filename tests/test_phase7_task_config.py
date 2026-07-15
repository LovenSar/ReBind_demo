#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase7 根配置、单次任务 JSON 与 CLI 的合并。"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SA_ROOT = _PROJECT_ROOT / "tools" / "Semantics_Alignment"
if str(_SA_ROOT) not in sys.path:
    sys.path.insert(0, str(_SA_ROOT))
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import project_config  # noqa: E402
from depth.engine import _build_arg_parser  # noqa: E402
from depth.phase7_task_config import (  # noqa: E402
    apply_task_defaults_to_parser,
    apply_cli_append_overrides,
    phase7_task_defaults,
    peek_explicit_platform_key,
    peek_explicit_task_config_path,
    resolve_phase7_task_file,
    _strip_meta_keys,
)


class TestPhase7TaskConfig(unittest.TestCase):
    def test_defaults_come_only_from_root_config(self) -> None:
        self.assertFalse((_PROJECT_ROOT / "phase7_task.defaults.json").exists())
        payload = phase7_task_defaults()
        self.assertEqual(payload.get("goal_limit"), 3)
        self.assertEqual(payload.get("gen1_subtree_mode"), "entry")
        self.assertEqual(payload.get("gen1_entry_top_k"), 3)

    def test_peek_explicit_path(self) -> None:
        self.assertEqual(
            peek_explicit_task_config_path(["--task-config", "/tmp/x.json", "--goal-limit", "1"]),
            "/tmp/x.json",
        )
        self.assertEqual(
            peek_explicit_task_config_path(["--task-config=/a/b.json"]),
            "/a/b.json",
        )
        self.assertEqual(peek_explicit_platform_key(["--platform", "windows"]), "windows")
        self.assertEqual(peek_explicit_platform_key(["--platform=linux"]), "linux")

    def test_cli_overrides_merged_defaults(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump({"goal_limit": 7, "max_paths": 50}, f)
            f.flush()
            tmp = Path(f.name)
        try:
            ap = _build_arg_parser()
            _p, data, _fp = resolve_phase7_task_file(argv=["--task-config", str(tmp)])
            apply_task_defaults_to_parser(ap, data)
            args = ap.parse_args(["--goal-limit", "2"])
            self.assertEqual(args.goal_limit, 2)
            self.assertEqual(args.max_paths, 50)
        finally:
            tmp.unlink(missing_ok=True)

    def test_boolean_cli_can_override_task_true(self) -> None:
        ap = _build_arg_parser()
        apply_task_defaults_to_parser(ap, {"incremental_indirect": True})
        args = ap.parse_args(["--no-incremental-indirect"])
        self.assertFalse(args.incremental_indirect)

    def test_cli_append_values_replace_task_list(self) -> None:
        ap = _build_arg_parser()
        apply_task_defaults_to_parser(
            ap,
            {"goal_va": ["0x1000"], "goal_keyword": ["from_task"]},
        )
        argv = ["--goal-va", "0x2000", "--goal-va=0x3000", "--goal-keyword", "from_cli"]
        args = ap.parse_args(argv)
        apply_cli_append_overrides(args, ap, argv)
        self.assertEqual(args.goal_va, ["0x2000", "0x3000"])
        self.assertEqual(args.goal_keyword, ["from_cli"])

    def test_invalid_choice_and_unknown_key_are_rejected(self) -> None:
        ap = _build_arg_parser()
        with self.assertRaises(SystemExit):
            apply_task_defaults_to_parser(ap, {"llm_mode": "sometimes"})
        with self.assertRaises(SystemExit):
            apply_task_defaults_to_parser(ap, {"max_pathz": 10})
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            ap.parse_args(["--llm-config", "/tmp/not-the-root-config.yaml"])

    def test_platform_phase7_override_deep_merges(self) -> None:
        config = {
            "semantics": {"phase7": {"task_defaults": {"goal_limit": 3, "max_paths": 200}}},
            "platforms": {
                "linux": {"semantics": {"phase7": {"task_defaults": {"max_paths": 80}}}}
            },
        }
        phase7 = project_config.merge_phase7_config_dict(config, "linux")
        self.assertEqual(phase7["task_defaults"], {"goal_limit": 3, "max_paths": 80})

    def test_legacy_entry_limit_key_is_normalized(self) -> None:
        self.assertEqual(
            _strip_meta_keys({"gen1_entry_auto_limit": 2}),
            {"gen1_entry_top_k": 2},
        )


if __name__ == "__main__":
    unittest.main()
