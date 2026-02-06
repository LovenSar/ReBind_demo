import importlib.util
import sqlite3
import tempfile
import unittest
from pathlib import Path
import sys

from openpyxl import load_workbook


def _load_alignment_loader():
    repo_root = Path(__file__).resolve().parents[1]
    path = repo_root / "tools" / "Semantics_Alignment" / "alignment_loader.py"
    spec = importlib.util.spec_from_file_location("alignment_loader", path)
    if not spec or not spec.loader:
        raise RuntimeError(f"Failed to load module spec: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestAlignmentLoaderExcelExport(unittest.TestCase):
    def test_export_sqlite_to_workbook_sanitizes_illegal_chars(self):
        mod = _load_alignment_loader()

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            db_path = td_path / "t.db"
            xlsx_path = td_path / "out.xlsx"

            conn = sqlite3.connect(str(db_path))
            try:
                conn.execute("CREATE TABLE strings(value TEXT);")
                conn.execute("INSERT INTO strings(value) VALUES (?);", ("A\x07B",))
                conn.execute("CREATE TABLE blobs(data BLOB);")
                conn.execute(
                    "INSERT INTO blobs(data) VALUES (?);",
                    (sqlite3.Binary(b"\x00\xff"),),
                )
                conn.commit()
            finally:
                conn.close()

            mod.export_sqlite_to_workbook(
                db_path=db_path,
                workbook_path=xlsx_path,
                tables=["strings", "blobs"],
            )
            wb = load_workbook(xlsx_path)
            try:
                ws_strings = wb["strings"]
                self.assertEqual(ws_strings["A2"].value, "AB")

                ws_blobs = wb["blobs"]
                cell = ws_blobs["A2"].value
                self.assertIsInstance(cell, str)
                self.assertTrue(cell.startswith("base64:"))
            finally:
                wb.close()


if __name__ == "__main__":
    unittest.main()
