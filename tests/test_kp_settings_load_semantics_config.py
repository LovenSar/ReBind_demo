import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import sys


def _load_kp_settings():
    repo_root = Path(__file__).resolve().parents[1]
    path = repo_root / "tools" / "Semantics_Alignment" / "kp" / "kp_settings.py"
    spec = importlib.util.spec_from_file_location("kp_settings", path)
    if not spec or not spec.loader:
        raise RuntimeError(f"Failed to load module spec: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestLoadSemanticsConfig(unittest.TestCase):
    def test_global_config_merges_platform_overrides(self):
        mod = _load_kp_settings()

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            global_config = td_path / "config.yaml"
            global_config.write_text(
                "\n".join(
                    [
                        "platforms:",
                        "  windows:",
                        "    semantics:",
                        "      runtime:",
                        "        idat_exe: 'C:\\\\IDA\\\\idat64.exe'",
                        "semantics:",
                        "  runtime:",
                        "    ida_url: 'http://127.0.0.1:9999'",
                        "  llm:",
                        "    model: override-model",
                        "  pipeline:",
                        "    ida_sync:",
                        "      connect_max_wait_seconds: 10",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            with mock.patch.object(mod.platform, "system", return_value="Windows"):
                merged = mod.load_semantics_config(str(global_config))

            self.assertEqual(merged.get("llm", {}).get("model"), "override-model")
            self.assertEqual(merged.get("runtime", {}).get("ida_url"), "http://127.0.0.1:9999")
            self.assertEqual(merged.get("runtime", {}).get("idat_exe"), r"C:\\IDA\\idat64.exe")
            self.assertEqual(merged.get("pipeline", {}).get("ida_sync", {}).get("connect_max_wait_seconds"), 10)

    def test_platform_detection_treats_msys_as_windows(self):
        mod = _load_kp_settings()

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            global_config = td_path / "config.yaml"
            global_config.write_text(
                "\n".join(
                    [
                        "platforms:",
                        "  windows:",
                        "    semantics:",
                        "      runtime:",
                        "        idat_exe: 'C:\\\\IDA\\\\idat64.exe'",
                        "semantics:",
                        "  llm:",
                        "    model: base",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            with mock.patch.object(mod.platform, "system", return_value="MSYS_NT-10.0"):
                merged = mod.load_semantics_config(str(global_config))

            self.assertEqual(merged.get("runtime", {}).get("idat_exe"), r"C:\\IDA\\idat64.exe")


if __name__ == "__main__":
    unittest.main()
