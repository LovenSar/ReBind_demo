import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import sys


def _load_phase7_5_module():
    repo_root = Path(__file__).resolve().parents[1]
    path = repo_root / "tools" / "Semantics_Alignment" / "phases" / "phase7_5_strict_align.py"
    spec = importlib.util.spec_from_file_location("phase7_5_strict_align", path)
    if not spec or not spec.loader:
        raise RuntimeError(f"Failed to load module spec: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestPhase75StrictAlign(unittest.TestCase):
    def test_mode_off_skips_without_db(self):
        mod = _load_phase7_5_module()
        report = mod.run_phase7_5_strict_align(
            db_path=Path("/tmp/does_not_exist.db"),
            input_path=None,
            artifacts_dir=Path("/tmp/unused"),
            call_ref_types=("CALL",),
            mode="off",
        )
        self.assertEqual(report.get("status"), "skipped")
        self.assertFalse(bool(report.get("enabled")))

    def test_aligned_path_does_not_replace(self):
        mod = _load_phase7_5_module()
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            db_path = td_path / "sample.db"
            db_path.write_bytes(b"db")
            ida_dir = td_path / "sample_idademo"
            ida_dir.mkdir(parents=True, exist_ok=True)
            artifacts_dir = td_path / "artifacts"

            with (
                mock.patch.object(mod, "_pick_ida_export_dir", return_value=ida_dir),
                mock.patch.object(mod, "_run_alignment_loader_ida_only", return_value=None),
                mock.patch.object(
                    mod,
                    "_collect_ida_profile",
                    side_effect=[
                        {"functions": {"count": 1, "sha256": "aaa"}},
                        {"functions": {"count": 1, "sha256": "aaa"}},
                    ],
                ),
                mock.patch.object(mod, "_replace_db_atomically") as mocked_replace,
            ):
                report = mod.run_phase7_5_strict_align(
                    db_path=db_path,
                    input_path=str(db_path),
                    artifacts_dir=artifacts_dir,
                    call_ref_types=("CALL",),
                    mode="strict",
                    keep_rebuilt_db=False,
                )

            self.assertEqual(report.get("status"), "aligned")
            self.assertEqual(int(report.get("profile_diff_count", -1)), 0)
            mocked_replace.assert_not_called()

    def test_drift_replaces_and_passes_recheck(self):
        mod = _load_phase7_5_module()
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            db_path = td_path / "sample.db"
            db_path.write_bytes(b"db")
            ida_dir = td_path / "sample_idademo"
            ida_dir.mkdir(parents=True, exist_ok=True)
            artifacts_dir = td_path / "artifacts"

            with (
                mock.patch.object(mod, "_pick_ida_export_dir", return_value=ida_dir),
                mock.patch.object(mod, "_run_alignment_loader_ida_only", return_value=None),
                mock.patch.object(
                    mod,
                    "_collect_ida_profile",
                    side_effect=[
                        {"functions": {"count": 1, "sha256": "old"}},
                        {"functions": {"count": 1, "sha256": "new"}},
                        {"functions": {"count": 1, "sha256": "new"}},
                    ],
                ),
                mock.patch.object(mod, "_replace_db_atomically") as mocked_replace,
            ):
                report = mod.run_phase7_5_strict_align(
                    db_path=db_path,
                    input_path=str(db_path),
                    artifacts_dir=artifacts_dir,
                    call_ref_types=("CALL",),
                    mode="strict",
                    keep_rebuilt_db=True,
                )

            self.assertEqual(report.get("status"), "replaced")
            self.assertEqual(int(report.get("profile_diff_count", -1)), 1)
            self.assertEqual(int(report.get("post_replace_diff_count", -1)), 0)
            mocked_replace.assert_called_once()

    def test_drift_replace_but_post_check_still_diff_raises(self):
        mod = _load_phase7_5_module()
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            db_path = td_path / "sample.db"
            db_path.write_bytes(b"db")
            ida_dir = td_path / "sample_idademo"
            ida_dir.mkdir(parents=True, exist_ok=True)
            artifacts_dir = td_path / "artifacts"

            with (
                mock.patch.object(mod, "_pick_ida_export_dir", return_value=ida_dir),
                mock.patch.object(mod, "_run_alignment_loader_ida_only", return_value=None),
                mock.patch.object(
                    mod,
                    "_collect_ida_profile",
                    side_effect=[
                        {"functions": {"count": 1, "sha256": "old"}},
                        {"functions": {"count": 1, "sha256": "new"}},
                        {"functions": {"count": 1, "sha256": "old"}},
                    ],
                ),
                mock.patch.object(mod, "_replace_db_atomically"),
            ):
                with self.assertRaises(mod.Phase75StrictAlignError):
                    mod.run_phase7_5_strict_align(
                        db_path=db_path,
                        input_path=str(db_path),
                        artifacts_dir=artifacts_dir,
                        call_ref_types=("CALL",),
                        mode="strict",
                        keep_rebuilt_db=True,
                    )


if __name__ == "__main__":
    unittest.main()
