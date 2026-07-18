#!/usr/bin/env python3
"""Phase7 严格对齐 checkpoint 与临时产物清理的安全回归。"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
import sqlite3

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SA_ROOT = _PROJECT_ROOT / "tools" / "Semantics_Alignment"
if str(_SA_ROOT) not in sys.path:
    sys.path.insert(0, str(_SA_ROOT))

from depth.engine import (  # noqa: E402
    _load_prevalidated_phase7_5_report,
    _phase7_5_checkpoint_reusable,
)
from depth.profile_ops import _redact_request_data  # noqa: E402
from depth.strict_align import _collect_ida_profile, _remove_sidecars  # noqa: E402


class TestPhase7Safety(unittest.TestCase):
    def test_only_successful_phase75_reports_are_reusable(self) -> None:
        self.assertTrue(_phase7_5_checkpoint_reusable({"status": "aligned"}))
        self.assertTrue(_phase7_5_checkpoint_reusable({"status": "replaced"}))
        self.assertFalse(_phase7_5_checkpoint_reusable({"status": "failed"}))
        self.assertFalse(_phase7_5_checkpoint_reusable({"status": "running"}))
        self.assertFalse(_phase7_5_checkpoint_reusable({}))

    def test_prevalidated_phase75_report_requires_matching_input_and_ida_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sample = root / "sample.bin"
            ida_dir = root / "sample_idademo"
            sample.write_bytes(b"test")
            ida_dir.mkdir()
            report_path = root / "phase7_5_report.json"
            report_path.write_text(
                json.dumps(
                    {"status": "aligned", "input_path": str(sample), "ida_dir": str(ida_dir)}
                ),
                encoding="utf-8",
            )

            report = _load_prevalidated_phase7_5_report(
                report_path,
                input_path=str(sample),
                ida_dir=str(ida_dir),
            )
            self.assertEqual(report["mode"], "prevalidated")
            self.assertEqual(report["status"], "aligned")
            with self.assertRaises(ValueError):
                _load_prevalidated_phase7_5_report(
                    report_path,
                    input_path=str(root / "other.bin"),
                    ida_dir=str(ida_dir),
                )

    def test_rebuilt_db_sidecars_can_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "rebuilt.db"
            for suffix in ("-wal", "-shm"):
                db.with_name(db.name + suffix).write_bytes(b"x")
            _remove_sidecars(db)
            self.assertFalse(db.with_name(db.name + "-wal").exists())
            self.assertFalse(db.with_name(db.name + "-shm").exists())

    def test_profile_trace_redacts_nested_credentials(self) -> None:
        safe = _redact_request_data(
            {"extra_headers": {"Authorization": "Bearer secret"}, "model": "x"}
        )
        self.assertEqual(safe["extra_headers"]["Authorization"], "<redacted>")
        self.assertEqual(safe["model"], "x")

    def test_profile_can_read_wal_database_without_existing_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db = Path(td) / "wal_profile.db"
            conn = sqlite3.connect(str(db))
            try:
                conn.executescript(
                    """
                    PRAGMA journal_mode=WAL;
                    CREATE TABLE tools(id INTEGER PRIMARY KEY, name TEXT);
                    CREATE TABLE binary_views(id INTEGER PRIMARY KEY, binary_id INTEGER, tool_id INTEGER);
                    CREATE TABLE symbols(id INTEGER PRIMARY KEY, view_id INTEGER, address_va INTEGER, raw_address TEXT, name TEXT, kind TEXT, raw_type TEXT, source TEXT, is_global INTEGER, is_primary INTEGER, is_external INTEGER, namespace TEXT);
                    CREATE TABLE strings(id INTEGER PRIMARY KEY, view_id INTEGER, address_va INTEGER, value TEXT, length INTEGER);
                    CREATE TABLE functions(id INTEGER PRIMARY KEY, view_id INTEGER, entry_va INTEGER, name TEXT, size_bytes INTEGER, raw_file TEXT);
                    CREATE TABLE instructions(id INTEGER PRIMARY KEY, view_id INTEGER, function_id INTEGER, index_in_function INTEGER, address_va INTEGER, bytes TEXT, mnemonic TEXT, op_str TEXT, raw_line TEXT);
                    CREATE TABLE xrefs(id INTEGER PRIMARY KEY, view_id INTEGER, src_va INTEGER, dst_va INTEGER, dst_name TEXT, ref_type_raw TEXT, containing_function TEXT, is_primary INTEGER);
                    CREATE TABLE pseudo_functions(id INTEGER PRIMARY KEY, view_id INTEGER, function_id INTEGER, entry_va INTEGER, name TEXT, prototype TEXT, body TEXT, raw_file TEXT);
                    INSERT INTO tools VALUES(1, 'ida');
                    INSERT INTO binary_views VALUES(1, 1, 1);
                    """
                )
                conn.commit()
            finally:
                conn.close()
            _remove_sidecars(db)
            profile = _collect_ida_profile(db, ["CALL"])
            self.assertEqual(profile["functions"]["count"], 0)


if __name__ == "__main__":
    unittest.main()
