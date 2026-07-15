#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run_management 断点续跑签名：--llm-config 应对临时路径稳定。"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SA_ROOT = _PROJECT_ROOT / "tools" / "Semantics_Alignment"
if str(_SA_ROOT) not in sys.path:
    sys.path.insert(0, str(_SA_ROOT))

from depth.run_management import (  # noqa: E402
    _build_resume_signature,
    _build_resume_signature_payload,
    _build_run_layout,
    _build_resume_signature_llm_path_only,
    _llm_config_semantic_sha256,
    resume_signature_compatible_with_manifest,
    resume_signature_compatible_with_manifest_semantics,
)


def _minimal_args(**kwargs: object) -> argparse.Namespace:
    base = {
        "input_path": "/tmp/sample.exe",
        "db": None,
        "binary_id": None,
        "goal_va": [],
        "goal_keyword": [],
        "goal_struct": [],
        "goal_limit": 3,
        "auto_goal_limit": 20,
        "gen1_subtree_mode": "entry",
        "gen1_entry_top_k": 3,
        "gen1_root_va": None,
        "lambda_radius": 2.5,
        "w_call": 0.45,
        "w_data": 0.30,
        "w_string": 0.15,
        "w_global": 0.10,
        "max_depth": 0,
        "max_paths": 200,
        "max_branch": 6,
        "max_call_sites": 3,
        "cond_window": 10,
        "max_guards_per_site": 3,
        "max_generations": 0,
        "gen_stop_new_ratio": 0.05,
        "gen_token_budget": 0,
        "gen2_ancestor_depth": 5,
        "gen2_min_wlca": 0.28,
        "gen2_frontier_k": 3,
        "gen2_alpha": 0.65,
        "gen2_beta": 0.08,
        "gen2_gamma": 0.40,
        "indirect_edge_mode": "auto",
        "indirect_edge_budget": 25000,
        "incremental_indirect": False,
        "incremental_indirect_topn": 3000,
        "llm_mode": "auto",
        "llm_model": None,
        "llm_temperature": None,
        "llm_max_tokens": None,
        "llm_max_attempts": 3,
        "llm_code_chars": 1200,
        "llm_max_steps": 0,
        "max_compare_nodes": 12,
        "compare_min_delta": 0.1,
        "apply_db": False,
        "apply_max_rows": 0,
        "apply_min_confidence": 70,
        "phase7_5_ida_dir": None,
        "phase7_5_keep_rebuilt_db": False,
        "runs_root": None,
        "run_id": None,
        "resume": False,
        "force_resume": False,
        "log_raw_llm": False,
        "dry_run": False,
        "no_console_progress": False,
        "output": None,
        "task_config": None,
        "phase7_task_loaded_from": None,
        "phase7_task_fingerprint": "fp_test",
    }
    base.update(kwargs)
    return argparse.Namespace(**base)


class TestResumeSignature(unittest.TestCase):
    def test_llm_config_same_content_different_paths_same_signature(self) -> None:
        content = b"semantics:\n  x: 1\n"
        db_path = Path("/tmp/fake.db")
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as a:
            a.write(content)
            pa = Path(a.name)
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as b:
            b.write(content)
            pb = Path(b.name)
        try:
            args_a = _minimal_args(llm_config=str(pa))
            args_b = _minimal_args(llm_config=str(pb))
            self.assertEqual(
                _build_resume_signature(args_a, db_path),
                _build_resume_signature(args_b, db_path),
            )
        finally:
            pa.unlink(missing_ok=True)
            pb.unlink(missing_ok=True)

    def test_legacy_path_only_differs_from_content_based(self) -> None:
        content = b"k: v\n"
        db_path = Path("/tmp/fake.db")
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as a:
            a.write(content)
            pa = Path(a.name)
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as b:
            b.write(content)
            pb = Path(b.name)
        try:
            args_a = _minimal_args(llm_config=str(pa))
            args_b = _minimal_args(llm_config=str(pb))
            self.assertNotEqual(
                _build_resume_signature_llm_path_only(args_a, db_path),
                _build_resume_signature_llm_path_only(args_b, db_path),
            )
        finally:
            pa.unlink(missing_ok=True)
            pb.unlink(missing_ok=True)

    def test_manifest_migration_when_legacy_matches(self) -> None:
        content = b"cfg: true\n"
        db_path = Path("/tmp/sample.db")
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as cur:
            cur.write(content)
            cur_path = Path(cur.name)
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False) as old:
            old.write(content)
            old_path = Path(old.name)
        try:
            args = _minimal_args(llm_config=str(cur_path))
            merged = argparse.Namespace(**{**vars(args), "llm_config": str(old_path)})
            prev_sig = _build_resume_signature_llm_path_only(merged, db_path)
            current_sig = _build_resume_signature(args, db_path)
            self.assertNotEqual(prev_sig, current_sig)

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, encoding="utf-8"
            ) as mf:
                json.dump({"args": {"llm_config": str(old_path)}}, mf)
                man_path = Path(mf.name)

            self.assertTrue(
                resume_signature_compatible_with_manifest(
                    prev_sig, current_sig, args, db_path, man_path
                )
            )
            man_path.unlink(missing_ok=True)
        finally:
            cur_path.unlink(missing_ok=True)
            old_path.unlink(missing_ok=True)

    def test_llm_config_semantic_sha256(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yaml") as f:
            f.write("a: 1\nb: 2\n")
            p = Path(f.name)
        try:
            self.assertEqual(len(_llm_config_semantic_sha256(str(p)) or ""), 64)
        finally:
            p.unlink(missing_ok=True)

    def test_yaml_key_order_same_semantic_hash(self) -> None:
        db_path = Path("/tmp/fake.db")
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yaml") as a:
            a.write("z: 1\na: 2\n")
            pa = Path(a.name)
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yaml") as b:
            b.write("a: 2\nz: 1\n")
            pb = Path(b.name)
        try:
            args_a = _minimal_args(llm_config=str(pa))
            args_b = _minimal_args(llm_config=str(pb))
            self.assertEqual(
                _build_resume_signature(args_a, db_path),
                _build_resume_signature(args_b, db_path),
            )
        finally:
            pa.unlink(missing_ok=True)
            pb.unlink(missing_ok=True)

    def test_manifest_semantics_accepts_same_llm_content(self) -> None:
        db_path = Path("/tmp/sample.db")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as old:
            old.write("a: 1\n")
            old_path = Path(old.name)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as new:
            new.write("a: 1\n")
            new_path = Path(new.name)
        args_old = _minimal_args(llm_config=str(old_path))
        args_new = _minimal_args(llm_config=str(new_path))
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as mf:
            json.dump({"resume_signature_payload": _build_resume_signature_payload(args_old, db_path)}, mf)
            man_path = Path(mf.name)
        try:
            self.assertTrue(
                resume_signature_compatible_with_manifest_semantics(
                    man_path, args_new, db_path
                )
            )
        finally:
            man_path.unlink(missing_ok=True)
            old_path.unlink(missing_ok=True)
            new_path.unlink(missing_ok=True)

    def test_manifest_semantics_rejects_changed_llm_content(self) -> None:
        db_path = Path("/tmp/sample.db")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as old:
            old.write("a: 1\n")
            old_path = Path(old.name)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as new:
            new.write("a: 2\n")
            new_path = Path(new.name)
        args_old = _minimal_args(llm_config=str(old_path))
        args_new = _minimal_args(llm_config=str(new_path))
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as mf:
            json.dump({"resume_signature_payload": _build_resume_signature_payload(args_old, db_path)}, mf)
            man_path = Path(mf.name)
        try:
            self.assertFalse(resume_signature_compatible_with_manifest_semantics(man_path, args_new, db_path))
        finally:
            man_path.unlink(missing_ok=True)
            old_path.unlink(missing_ok=True)
            new_path.unlink(missing_ok=True)

    def test_manifest_semantics_accepts_new_optional_none_argument(self) -> None:
        db_path = Path("/tmp/sample.db")
        old_args = _minimal_args()
        new_args = _minimal_args(platform=None)
        payload = _build_resume_signature_payload(old_args, db_path)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as mf:
            json.dump({"resume_signature_payload": payload}, mf)
            man_path = Path(mf.name)
        try:
            self.assertTrue(
                resume_signature_compatible_with_manifest_semantics(man_path, new_args, db_path)
            )
        finally:
            man_path.unlink(missing_ok=True)

    def test_run_layout_uses_timestamp_and_resume_picks_latest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            first = _build_run_layout(
                db_path=root / "x.db",
                input_path=str(root / "sample.exe"),
                explicit_output=None,
                runs_root=str(root / "runs"),
                run_id=None,
                resume=False,
            )
            self.assertNotEqual(first.run_id, "unknown")
            first.run_dir.mkdir(parents=True)
            resumed = _build_run_layout(
                db_path=root / "x.db",
                input_path=str(root / "sample.exe"),
                explicit_output=None,
                runs_root=str(root / "runs"),
                run_id=None,
                resume=True,
            )
            self.assertEqual(resumed.run_dir, first.run_dir)


if __name__ == "__main__":
    unittest.main()
