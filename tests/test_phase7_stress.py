#!/usr/bin/env python3
"""Phase7 热路径的有界压力回归。"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SA_ROOT = _PROJECT_ROOT / "tools" / "Semantics_Alignment"
if str(_SA_ROOT) not in sys.path:
    sys.path.insert(0, str(_SA_ROOT))

from depth.gen_observability import append_generations_index  # noqa: E402
from depth.strict_align import _collect_ida_profile, _metric_digest  # noqa: E402


class TestPhase7Stress(unittest.TestCase):
    def test_phase75_indexed_joins_scale_on_20k_instructions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "profile.db"
            conn = sqlite3.connect(str(db_path))
            try:
                conn.executescript(
                    """
                    CREATE TABLE tools(id INTEGER PRIMARY KEY, name TEXT);
                    CREATE TABLE binary_views(id INTEGER PRIMARY KEY, binary_id INTEGER, tool_id INTEGER);
                    CREATE TABLE symbols(id INTEGER PRIMARY KEY, view_id INTEGER, address_va INTEGER,
                        raw_address TEXT, name TEXT, kind TEXT, raw_type TEXT, source TEXT,
                        is_global INTEGER, is_primary INTEGER, is_external INTEGER, namespace TEXT);
                    CREATE TABLE strings(id INTEGER PRIMARY KEY, view_id INTEGER, address_va INTEGER,
                        value TEXT, length INTEGER);
                    CREATE TABLE functions(id INTEGER PRIMARY KEY, view_id INTEGER, entry_va INTEGER,
                        name TEXT, size_bytes INTEGER, raw_file TEXT);
                    CREATE TABLE instructions(id INTEGER PRIMARY KEY, view_id INTEGER, function_id INTEGER,
                        index_in_function INTEGER, address_va INTEGER, bytes TEXT, mnemonic TEXT,
                        op_str TEXT, raw_line TEXT);
                    CREATE INDEX idx_instructions_view_addr ON instructions(view_id, address_va);
                    CREATE TABLE xrefs(id INTEGER PRIMARY KEY, view_id INTEGER, src_va INTEGER,
                        dst_va INTEGER, dst_name TEXT, ref_type_raw TEXT,
                        containing_function TEXT, is_primary INTEGER);
                    CREATE INDEX idx_xrefs_view_src ON xrefs(view_id, src_va);
                    CREATE INDEX idx_xrefs_view_dst ON xrefs(view_id, dst_va);
                    CREATE INDEX idx_xrefs_view_ref ON xrefs(view_id, ref_type_raw);
                    CREATE TABLE pseudo_functions(id INTEGER PRIMARY KEY, view_id INTEGER,
                        function_id INTEGER, entry_va INTEGER, name TEXT, prototype TEXT,
                        body TEXT, raw_file TEXT);
                    INSERT INTO tools VALUES(1, 'ida');
                    INSERT INTO binary_views VALUES(1, 1, 1);
                    """
                )
                functions = [
                    (fid, 1, 0x100000 + fid * 0x100, f"f{fid}", 100, "")
                    for fid in range(1, 201)
                ]
                conn.executemany("INSERT INTO functions VALUES(?, ?, ?, ?, ?, ?);", functions)
                instructions = []
                for fid, _view, entry, _name, _size, _raw in functions:
                    for index in range(100):
                        instructions.append(
                            (None, 1, fid, index, entry + index, "90", "nop", "", "nop")
                        )
                conn.executemany(
                    "INSERT INTO instructions VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?);",
                    instructions,
                )
                xrefs = []
                for xid in range(1, 8001):
                    src_fid = (xid % 200) + 1
                    dst_fid = ((xid * 7) % 200) + 1
                    src = 0x100000 + src_fid * 0x100 + (xid % 100)
                    dst = 0x100000 + dst_fid * 0x100
                    xrefs.append((xid, 1, src, dst, "", "CALL", "", 0))
                conn.executemany("INSERT INTO xrefs VALUES(?, ?, ?, ?, ?, ?, ?, ?);", xrefs)
                conn.commit()
            finally:
                conn.close()

            started = time.monotonic()
            profile = _collect_ida_profile(db_path, ["CALL"])
            elapsed = time.monotonic() - started
            self.assertEqual(profile["instructions"]["count"], 20_000)
            self.assertEqual(profile["fcg_call_edges"]["count"], 8_000)
            self.assertLess(elapsed, 8.0)

    def test_metric_digest_streams_100k_rows_deterministically(self) -> None:
        conn = sqlite3.connect(":memory:")
        try:
            conn.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, value TEXT);")
            conn.executemany(
                "INSERT INTO t(id, value) VALUES(?, ?);",
                ((i, f"value-{i % 997}") for i in range(100_000)),
            )
            progress: list[int] = []
            started = time.monotonic()
            count1, digest1 = _metric_digest(
                conn,
                "SELECT id, value FROM t ORDER BY id;",
                on_row_progress=progress.append,
                progress_row_interval=10_000,
                progress_min_interval_sec=0,
            )
            count2, digest2 = _metric_digest(conn, "SELECT id, value FROM t ORDER BY id;")
            elapsed = time.monotonic() - started
            self.assertEqual(count1, 100_000)
            self.assertEqual((count1, digest1), (count2, digest2))
            self.assertGreaterEqual(len(progress), 10)
            self.assertLess(elapsed, 15.0)
        finally:
            conn.close()

    def test_generation_index_survives_repeated_resume_upserts(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            artifacts = Path(td) / "artifacts"
            for attempt in range(100):
                for goal_index in range(1, 11):
                    for generation in range(1, 7):
                        append_generations_index(
                            artifacts,
                            {
                                "goal_index": goal_index,
                                "generation": generation,
                                "attempt": attempt,
                            },
                        )
            index_path = artifacts / "generations" / "INDEX.json"
            rows = json.loads(index_path.read_text(encoding="utf-8"))
            self.assertEqual(len(rows), 60)
            self.assertTrue(all(row["attempt"] == 99 for row in rows))
            self.assertFalse(index_path.with_suffix(".json.tmp").exists())


if __name__ == "__main__":
    unittest.main()
