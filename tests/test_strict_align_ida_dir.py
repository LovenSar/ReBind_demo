#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""strict_align IDA 目录解析单测。"""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SA_ROOT = _PROJECT_ROOT / "tools" / "Semantics_Alignment"
if str(_SA_ROOT) not in sys.path:
    sys.path.insert(0, str(_SA_ROOT))
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from depth.strict_align import (  # noqa: E402
    Phase75StrictAlignError,
    _pick_ida_export_dir,
    _run_alignment_loader_ida_only,
)


def _minimal_sqlite_with_ida_view(db_path: Path, output_dir: str) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE tools (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
            CREATE TABLE binary_views (
                id INTEGER PRIMARY KEY,
                binary_id INTEGER NOT NULL,
                tool_id INTEGER NOT NULL,
                output_dir TEXT NOT NULL
            );
            INSERT INTO tools(id, name) VALUES (1, 'ida');
            """
        )
        conn.execute(
            "INSERT INTO binary_views(id, binary_id, tool_id, output_dir) VALUES (1, 1, 1, ?);",
            (output_dir,),
        )
        conn.commit()
    finally:
        conn.close()


class TestStrictAlignIdaDir(unittest.TestCase):
    def test_nested_rebind_demo_layout(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_path = root / "sample.exe.db"
            db_path.write_bytes(b"")
            nested = root / "sample_exe_rebind_demo" / "sample_exe_idademo"
            nested.mkdir(parents=True)
            (nested / ".marker").write_text("ok", encoding="utf-8")

            got = _pick_ida_export_dir(
                db_path=db_path,
                input_path=str(root / "sample.exe"),
                ida_dir_override=None,
            )
            self.assertEqual(got.resolve(), nested.resolve())

    def test_binary_views_output_dir_wins(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_path = root / "sample.exe.db"
            nested = root / "a_rebind_demo" / "real_idademo"
            nested.mkdir(parents=True)
            _minimal_sqlite_with_ida_view(db_path, str(nested))

            got = _pick_ida_export_dir(
                db_path=db_path,
                input_path=str(root / "sample.exe"),
                ida_dir_override=None,
            )
            self.assertEqual(got.resolve(), nested.resolve())

    def test_ambiguous_multiple_idademo(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_path = root / "sample.exe.db"
            db_path.write_bytes(b"")
            (root / "x_rebind_demo" / "a_idademo").mkdir(parents=True)
            (root / "y_rebind_demo" / "b_idademo").mkdir(parents=True)

            with self.assertRaises(Phase75StrictAlignError) as ctx:
                _pick_ida_export_dir(
                    db_path=db_path,
                    input_path=str(root / "sample.exe"),
                    ida_dir_override=None,
                )
            self.assertIn("多个", str(ctx.exception))

    def test_tty_loader_does_not_deadlock_on_large_child_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fake_loader = root / "fake_loader.py"
            fake_loader.write_text(
                """
import pathlib
import sys
db = pathlib.Path(sys.argv[sys.argv.index('--db') + 1])
sys.stdout.write('o' * 1200000)
sys.stderr.write('e' * 1200000)
db.write_bytes(b'ok')
""".strip(),
                encoding="utf-8",
            )
            rebuilt = root / "artifacts" / "rebuilt.db"
            ida_dir = root / "sample_idademo"
            ida_dir.mkdir()
            with (
                patch("depth.strict_align.ALIGNMENT_LOADER_SCRIPT", fake_loader),
                patch("depth.strict_align._phase75_line2_tty_ok", return_value=True),
                patch("depth.strict_align._phase75_line2_render"),
            ):
                _run_alignment_loader_ida_only(
                    rebuilt_db=rebuilt,
                    ida_dir=ida_dir,
                    console_progress=True,
                )
            self.assertEqual(rebuilt.read_bytes(), b"ok")
            self.assertGreater((rebuilt.parent / "alignment_loader.log").stat().st_size, 2_000_000)


if __name__ == "__main__":
    unittest.main()
