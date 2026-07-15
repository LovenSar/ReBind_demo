#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phase7_preprocess 单测。"""

from __future__ import annotations

import sys
import sqlite3
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SA_ROOT = _PROJECT_ROOT / "tools" / "Semantics_Alignment"
if str(_SA_ROOT) not in sys.path:
    sys.path.insert(0, str(_SA_ROOT))
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from depth.phase7_preprocess import (  # noqa: E402
    Phase7DbStats,
    collect_db_stats,
    infer_tier,
)
from depth.phase7_task_config import load_phase7_config  # noqa: E402


class TestPhase7Preprocess(unittest.TestCase):
    def test_infer_tier(self) -> None:
        self.assertEqual(infer_tier(Phase7DbStats(1, 1, 100, 0, 0)), "exploratory")
        self.assertEqual(infer_tier(Phase7DbStats(1, 1, 5000, 0, 0)), "balanced")
        self.assertEqual(infer_tier(Phase7DbStats(1, 1, 9000, 0, 0)), "conservative")

    def test_presets_exist_in_root_config(self) -> None:
        presets = load_phase7_config().get("presets") or {}
        self.assertEqual(set(presets), {"exploratory", "balanced", "conservative"})

    def test_stats_are_scoped_to_binary_id(self) -> None:
        conn = sqlite3.connect(":memory:")
        try:
            conn.executescript(
                """
                CREATE TABLE tools(id INTEGER PRIMARY KEY, name TEXT);
                CREATE TABLE binary_views(id INTEGER PRIMARY KEY, binary_id INTEGER, tool_id INTEGER);
                CREATE TABLE functions(id INTEGER PRIMARY KEY, view_id INTEGER);
                CREATE TABLE xrefs(id INTEGER PRIMARY KEY, view_id INTEGER);
                CREATE TABLE pseudo_functions(id INTEGER PRIMARY KEY, view_id INTEGER);
                INSERT INTO tools(id, name) VALUES(1, 'ida');
                INSERT INTO binary_views(id, binary_id, tool_id) VALUES(10, 1, 1), (20, 2, 1);
                INSERT INTO functions(view_id) VALUES(10), (20), (20);
                INSERT INTO xrefs(view_id) VALUES(10), (20), (20), (20);
                INSERT INTO pseudo_functions(view_id) VALUES(10), (20);
                """
            )
            stats, warnings = collect_db_stats(conn, binary_id=2)
            self.assertEqual(warnings, [])
            self.assertEqual(stats.ida_view_id, 20)
            self.assertEqual(stats.function_count, 2)
            self.assertEqual(stats.xref_count, 3)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
