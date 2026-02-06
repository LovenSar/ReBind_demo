"""Phase 6: Refresh IDA headless demo outputs from a finalized IDA database.

This phase replays the IDA_Headless_Demo export scripts against a finalized
IDA database (.i64/.idb) and writes updated outputs into the target *_idademo
directory. It is intended to be the last step after all naming/annotation work
has been saved into the IDA database.
"""

from __future__ import annotations

import shutil
import subprocess
import re
from pathlib import Path
from typing import Iterable, List, Optional


# Phase 6 is DB-first export; do not recreate DB (-c) and disable auto analysis (-a).
DEFAULT_IDAT_ARGS: List[str] = ["-A", "-a"]
DEFAULT_IDA_SCRIPTS: List[str] = [
    "ExtractBinaryInfo_IDA.py",
    "ExtractDisassembly_IDA.py",
    "ExtractPseudocode_IDA.py",
]
PSEUDOCODE_SCRIPT = "ExtractPseudocode_IDA.py"


def _normalize_cmd_path(value: str) -> str:
    text = str(value or "").strip()
    text = text.replace(r"\\\"", '"').replace(r"\\'", "'")
    text = text.replace(r"\"", '"').replace(r"\'", "'")
    if len(text) >= 2 and ((text[0] == text[-1] == '"') or (text[0] == text[-1] == "'")):
        text = text[1:-1].strip()
    return text


def _sanitize_filename(name: str, max_len: int = 100) -> str:
    if not name:
        name = "None"
    for ch in (".", ":", "<", ">", "*", "?", " ", "\"", "|", "\\", "/"):
        name = name.replace(ch, "_")
    safe = "".join(
        c if (u"0" <= c <= u"9") or (u"a" <= c <= u"z") or (u"A" <= c <= u"Z") or c in ("_", "-") else "_"
        for c in name
    )
    safe = safe.strip("_-")
    while "__" in safe:
        safe = safe.replace("__", "_")
    if len(safe) > max_len:
        safe = safe[:max_len]
    return safe or "sanitized_empty_name"


def _derive_safe_base(source_path: Path) -> str:
    base_with_ext = source_path.name.replace(".", "_")
    return _sanitize_filename(base_with_ext)


def _prefer_idat64_for_i64(idat_path: Path, ida_db_path: Path) -> Path:
    """When opening .i64, prefer idat64 if available next to configured idat."""
    if ida_db_path.suffix.lower() != ".i64":
        return idat_path

    name = idat_path.name.lower()
    if "idat64" in name:
        return idat_path

    # Typical Windows install: idat.exe + idat64.exe in same folder.
    sibling = idat_path.with_name("idat64.exe")
    if sibling.exists():
        return sibling
    sibling = idat_path.with_name("idat64")
    if sibling.exists():
        return sibling
    return idat_path


def _resolve_ida_db_path(
    sample_path: Optional[Path],
    explicit: Optional[Path],
    ida_dir: Optional[Path],
) -> Path:
    if explicit:
        explicit = Path(explicit).expanduser().resolve()
        if not explicit.exists():
            raise FileNotFoundError(f"[Phase 6] 指定的 IDA 数据库不存在: {explicit}")
        return explicit

    if sample_path is None:
        candidates: List[Path] = []
        if ida_dir:
            candidates.extend(sorted(ida_dir.glob("*.i64")))
            candidates.extend(sorted(ida_dir.glob("*.idb")))
        if len(candidates) == 1:
            return candidates[0].resolve()
        hint = "\n".join(f"  - {c}" for c in candidates) if candidates else "  - (无候选)"
        raise FileNotFoundError(
            "[Phase 6] 未提供 --sample 且无法自动定位唯一的 IDA 数据库。"
            "请使用 --phase6-ida-db 显式指定 .i64/.idb。\n"
            f"候选路径:\n{hint}"
        )

    # If user passed a .i64/.idb as sample, accept it directly.
    if sample_path.suffix.lower() in (".i64", ".idb") and sample_path.exists():
        return sample_path.resolve()

    name = sample_path.name
    candidates: List[Path] = [
        sample_path.parent / f"{name}.i64",
        sample_path.parent / f"{name}.idb",
    ]
    if ida_dir:
        candidates.extend(
            [
                ida_dir / f"{name}.i64",
                ida_dir / f"{name}.idb",
            ]
        )

    for cand in candidates:
        if cand.exists():
            return cand.resolve()

    hint = "\n".join(f"  - {c}" for c in candidates)
    raise FileNotFoundError(
        "[Phase 6] 未找到可用的 IDA 数据库(.i64/.idb)。请确认数据库已保存，或使用 --phase6-ida-db 指定路径。\n"
        f"候选路径:\n{hint}"
    )


def _select_launch_target(sample_path: Optional[Path], ida_db_path: Path) -> Path:
    """Select launch target.

    - If sample_path is provided, prefer sample path (legacy/stable behavior).
    - If sample_path is absent, use DB path first (DB-first behavior).
    """
    if sample_path is None:
        return ida_db_path

    if sample_path is not None:
        sample_path = Path(sample_path).expanduser().resolve()
        if sample_path.exists() and sample_path.is_file():
            return sample_path

    # Fallback: if db is like xxx.sys.i64, try launching with xxx.sys.
    if ida_db_path.suffix.lower() in (".i64", ".idb"):
        candidate = ida_db_path.with_suffix("")
        if candidate.exists() and candidate.is_file():
            return candidate

    return ida_db_path


def _paired_input_from_db(ida_db_path: Path) -> Optional[Path]:
    """Return paired raw input path for xxx.i64/xxx.idb if it exists."""
    if ida_db_path.suffix.lower() not in (".i64", ".idb"):
        return None

    candidates: List[Path] = [ida_db_path.with_suffix("")]
    stem = ida_db_path.stem
    m = re.match(r"^(.+?\.(?:exe|dll|sys|bin))(?:[-_].*)?$", stem, flags=re.IGNORECASE)
    if m:
        candidates.append(ida_db_path.with_name(m.group(1)))

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return candidate
    return None


def _clean_output_dirs(ida_dir: Path, safe_base: str) -> None:
    suffixes = ("binaryinfo", "disassembly", "pesudocode", "pseudocode")
    for suffix in suffixes:
        target = ida_dir / f"{safe_base}_{suffix}"
        if not target.exists():
            continue
        if target.is_dir():
            shutil.rmtree(target, ignore_errors=True)
        else:
            try:
                target.unlink()
            except Exception:
                pass


def run_refresh_ida_demo_phase(
    *,
    sample_path: Optional[Path],
    ida_dir: Path,
    idat_exe: str,
    ida_scripts_dir: Path,
    ida_db_path: Optional[Path] = None,
    idat_args: Optional[Iterable[str]] = None,
    clean_output: bool = True,
    skip_pseudocode: bool = False,
) -> None:
    """Run Phase 6 to regenerate *_idademo outputs from the IDA database."""

    ida_dir = Path(ida_dir).expanduser().resolve()
    ida_dir.mkdir(parents=True, exist_ok=True)

    idat_exe = _normalize_cmd_path(idat_exe)
    if not idat_exe:
        raise SystemExit("[Phase 6] 未提供 idat_exe，无法执行 IDA 导出。")

    idat_path = Path(idat_exe)
    if not idat_path.exists():
        resolved = shutil.which(idat_exe)
        if resolved:
            idat_path = Path(resolved)
        else:
            raise SystemExit(f"[Phase 6] 未找到 idat 可执行文件: {idat_exe}")

    sample_path = (
        Path(sample_path).expanduser().resolve() if sample_path is not None else None
    )
    ida_db_path = _resolve_ida_db_path(sample_path, ida_db_path, ida_dir)
    idat_path = _prefer_idat64_for_i64(idat_path, ida_db_path)
    launch_target = _select_launch_target(sample_path, ida_db_path)

    scripts_dir = Path(ida_scripts_dir).expanduser().resolve()
    script_names = list(DEFAULT_IDA_SCRIPTS)
    if skip_pseudocode:
        script_names = [x for x in script_names if x != PSEUDOCODE_SCRIPT]
    scripts: List[Path] = [scripts_dir / name for name in script_names]
    for script in scripts:
        if not script.exists():
            raise FileNotFoundError(f"[Phase 6] 未找到脚本: {script}")

    if clean_output:
        clean_base_source = launch_target
        if clean_base_source.suffix.lower() in (".i64", ".idb"):
            clean_base_source = _paired_input_from_db(ida_db_path) or ida_db_path.with_suffix("")
        safe_base = _derive_safe_base(clean_base_source)
        print(f"[Phase 6] 清理旧输出目录 (base={safe_base}) ...")
        _clean_output_dirs(ida_dir, safe_base)

    args = list(idat_args) if idat_args is not None else list(DEFAULT_IDAT_ARGS)
    print(f"[Phase 6] 使用 IDA 数据库: {ida_db_path}")
    print(f"[Phase 6] 启动目标: {launch_target}")
    print(f"[Phase 6] 输出目录: {ida_dir}")

    for idx, script in enumerate(scripts, 1):
        cmd = [str(idat_path), *args, f"-S{script}", str(launch_target)]
        print(f"[Phase 6] [{idx}/{len(scripts)}] 执行: {' '.join(cmd)}")
        result = subprocess.run(cmd, cwd=str(ida_dir))
        if result.returncode == 0:
            continue

        fallback_target = None
        if sample_path is None and launch_target == ida_db_path:
            fallback_target = _paired_input_from_db(ida_db_path)

        if fallback_target is not None:
            fallback_cmd = [str(idat_path), *args, f"-S{script}", str(fallback_target)]
            print(
                "[Phase 6] 直接打开 DB 失败，回退到同名样本重试: "
                f"{' '.join(fallback_cmd)}"
            )
            result = subprocess.run(fallback_cmd, cwd=str(ida_dir))
            if result.returncode == 0:
                continue

        raise SystemExit(
            f"[Phase 6] 脚本执行失败: {script.name} (exit={result.returncode})"
        )

    print("[Phase 6] IDA 输出刷新完成。")
