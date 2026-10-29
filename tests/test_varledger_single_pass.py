import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IDA_TOOLS = ROOT / "tools" / "IDA_Headless_Demo"
sys.path.insert(0, str(IDA_TOOLS))

from varledger_single_pass import (
    bounded_symbol_filename,
    export_functions_once,
    function_pseudocode_filename,
)


class FakeCfunc:
    def __init__(self, ea):
        self.ea = ea


def test_pseudocode_and_mapping_share_one_decompilation_result():
    functions = [(0x1000, "first"), (0x2000, "second")]
    calls = []
    mapped = []
    outputs = []
    cfuncs = {}

    def decompile(ea):
        calls.append(ea)
        cfuncs[ea] = FakeCfunc(ea)
        return cfuncs[ea]

    result = export_functions_once(
        functions,
        decompile,
        render=lambda cfunc: "pseudo-%x" % cfunc.ea,
        emit=lambda ea, name, code: outputs.append((ea, name, code)),
        map_function=lambda ea, cfunc, code: mapped.append((ea, cfunc, code)),
    )

    assert calls == [0x1000, 0x2000]
    assert [item[0] for item in outputs] == [0x1000, 0x2000]
    assert all(mapped[i][1] is cfuncs[mapped[i][0]] for i in range(2))
    assert [item[2] for item in mapped] == [item[2] for item in outputs]


def test_one_function_failure_does_not_skip_following_functions():
    calls = []
    mapped = []
    errors = []

    def decompile(ea):
        calls.append(ea)
        if ea == 0x1000:
            return None
        return FakeCfunc(ea)

    result = export_functions_once(
        [(0x1000, "bad"), (0x2000, "good")],
        decompile,
        render=lambda cfunc: "ok",
        emit=lambda *args: None,
        map_function=lambda ea, cfunc, code: mapped.append(ea),
        on_error=lambda ea, name, error: errors.append((ea, name, str(error))),
    )

    assert calls == [0x1000, 0x2000]
    assert mapped == [0x2000]
    assert result[0][1] == "failed"
    assert result[1][1] == "completed"
    assert errors and errors[0][0] == 0x1000


def test_cached_function_skips_decompilation_and_emits_restored_pseudocode():
    calls = []
    outputs = []
    restored = []
    completed = []
    payload = {"pseudo_text": "cached body"}

    result = export_functions_once(
        [(0x1000, "cached"), (0x2000, "fresh")],
        decompile=lambda ea: calls.append(ea) or FakeCfunc(ea),
        render=lambda cfunc: "fresh body",
        emit=lambda ea, name, code: outputs.append((ea, name, code)),
        map_function=lambda ea, cfunc, code: None,
        cache_lookup=lambda ea, name: payload if ea == 0x1000 else None,
        cache_restore=lambda ea, name, value: restored.append((ea, value)) or True,
        on_cache_complete=lambda ea, name, value: completed.append(ea),
    )

    assert calls == [0x2000]
    assert outputs == [(0x1000, "cached", "cached body"), (0x2000, "fresh", "fresh body")]
    assert restored == [(0x1000, payload)]
    assert completed == [0x1000]
    assert [row[1] for row in result] == ["completed", "completed"]


def test_invalid_cached_function_falls_back_to_single_decompilation():
    calls = []
    mapped = []
    result = export_functions_once(
        [(0x1000, "cached")],
        decompile=lambda ea: calls.append(ea) or FakeCfunc(ea),
        render=lambda cfunc: "fresh body",
        emit=lambda *args: None,
        map_function=lambda ea, cfunc, code: mapped.append((ea, cfunc, code)),
        cache_lookup=lambda *args: {"pseudo_text": "stale"},
        cache_restore=lambda *args: False,
    )
    assert calls == [0x1000]
    assert mapped[0][2] == "fresh body"
    assert result[0][1] == "completed"


def test_integrated_pseudocode_filename_respects_long_windows_output_paths():
    pseudo_dir = "C:/" + "nested/" * 24
    filename = function_pseudocode_filename(
        pseudo_dir,
        0x18007D330,
        "?very_long_cpp_symbol@" + "template@" * 30,
        lambda name, max_len: name[:max_len],
    )

    assert len(str(Path(pseudo_dir) / filename)) <= 240
    assert filename.startswith("0x18007D330_")


def test_integrated_xref_filename_respects_long_windows_output_paths():
    xref_dir = "C:/" + "nested/" * 24
    filename = bounded_symbol_filename(
        xref_dir,
        "input_0x18006F000_",
        "?very_long_cpp_symbol@" + "template@" * 30,
        "_refs.csv",
        lambda name, max_len: "".join(char if char.isalnum() else "_" for char in name)[:max_len],
        max_name_length=60,
    )

    assert len(str(Path(xref_dir) / filename)) <= 240
    assert filename.startswith("input_0x18006F000_")
    assert filename.endswith("_refs.csv")


def test_integrated_extractor_routes_the_shared_cfunc_through_the_single_pass_driver():
    source = (IDA_TOOLS / "ExtractAll_IDA.py").read_text(encoding="utf-8")
    branch = source.split('mapping_exporter = os.environ.get("VARLEDGER_MAP_EXPORTER")', 1)[1]
    integrated, standalone = branch.split("export_whole_program_pseudocode(pseudo_dir, safe_base)", 1)
    assert "function_driver=export_functions_once" in integrated
    assert "render_function=lambda cfunc: render_cfunc(cfunc, preserve_all_lines=True)" in integrated
    assert "mapping_module[\"export_mapping\"]" in integrated
    assert "ida_hexrays.decompile_many(" in source
    assert "return True, None" in integrated
    assert "bounded_symbol_filename" in source
    assert "total_funcs = 0" in standalone
