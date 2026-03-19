#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phase7_5_strict_align.py

Phase7.5: 严格对齐组件（IDA 导出 -> DB）。

目标：
1) 在 Phase7 主干搜索前，先把 DB 与当前 IDA 导出结果严格对齐；
2) 对关键语义表做哈希级校验（函数/指令/xrefs/字符串/符号/伪代码 + FCG/CFG 边）；
3) 若发现漂移，使用重建库原子替换工作 DB，并保留备份与对账报告。
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


ALIGNMENT_LOADER_SCRIPT = Path(__file__).resolve().parents[1] / "breadth" / "alignment_loader.py"
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ASSIGN_LHS_RE = re.compile(r"(?<![=!<>])\b([A-Za-z_][A-Za-z0-9_]*)\s*=")
PROTO_ARG_BLOCK_RE = re.compile(r"\((.*)\)", re.DOTALL)
C_KEYWORDS: set[str] = {
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "int",
    "long",
    "register",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
    "bool",
    "true",
    "false",
    "__int8",
    "__int16",
    "__int32",
    "__int64",
}


class Phase75StrictAlignError(RuntimeError):
    """Raised when strict alignment cannot be completed safely."""


def _filter_variable_token(token: str) -> bool:
    t = str(token or "").strip()
    if not t:
        return False
    tl = t.lower()
    if tl in C_KEYWORDS:
        return False
    if tl.startswith("sub_") or tl.startswith("loc_"):
        return False
    if t.startswith("__"):
        return False
    return True


def _extract_proto_arg_names(proto: str) -> List[str]:
    raw = str(proto or "")
    m = PROTO_ARG_BLOCK_RE.search(raw)
    if not m:
        return []
    arg_text = m.group(1).strip()
    if not arg_text or arg_text.lower() == "void":
        return []
    out: List[str] = []
    for part in arg_text.split(","):
        tokens = IDENT_RE.findall(part)
        if not tokens:
            continue
        cand = tokens[-1]
        if _filter_variable_token(cand):
            out.append(cand)
    return out


def _extract_variable_names_from_pseudo(prototype: str, body: str) -> List[str]:
    names: set[str] = set()
    for name in _extract_proto_arg_names(prototype):
        names.add(name)
    for m in ASSIGN_LHS_RE.finditer(str(body or "")):
        cand = str(m.group(1) or "")
        if _filter_variable_token(cand):
            names.add(cand)
    return sorted(names)


def _collect_pseudo_variable_metric(conn: sqlite3.Connection) -> Dict[str, Any]:
    sql = """
    SELECT p.entry_va, COALESCE(p.name, ''), COALESCE(p.prototype, ''), COALESCE(p.body, '')
    FROM pseudo_functions AS p
    JOIN binary_views AS bv ON p.view_id = bv.id
    JOIN tools AS t ON bv.tool_id = t.id
    WHERE LOWER(t.name) = 'ida'
    ORDER BY p.entry_va, COALESCE(p.name, ''), p.id;
    """
    cur = conn.execute(sql)
    h = hashlib.sha256()
    fn_count = 0
    token_total = 0
    for row in cur:
        entry_va = int(row[0] or 0)
        name = str(row[1] or "")
        prototype = str(row[2] or "")
        body = str(row[3] or "")
        var_names = _extract_variable_names_from_pseudo(prototype, body)
        payload = [entry_va, name, var_names]
        blob = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)
        h.update(blob.encode("utf-8"))
        h.update(b"\n")
        fn_count += 1
        token_total += len(var_names)
    return {"count": int(fn_count), "sha256": h.hexdigest(), "token_total": int(token_total)}


def _focus_metric_entry(
    metric_key: str,
    current_profile: Dict[str, Dict[str, Any]],
    rebuilt_profile: Dict[str, Dict[str, Any]],
    active_profile: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    cur = current_profile.get(metric_key) or {}
    reb = rebuilt_profile.get(metric_key) or {}
    act = active_profile.get(metric_key) or {}
    return {
        "metric": metric_key,
        "current": {
            "count": int(cur.get("count", 0) or 0),
            "sha256": str(cur.get("sha256", "")),
        },
        "rebuilt": {
            "count": int(reb.get("count", 0) or 0),
            "sha256": str(reb.get("sha256", "")),
        },
        "active": {
            "count": int(act.get("count", 0) or 0),
            "sha256": str(act.get("sha256", "")),
        },
        "aligned_after_phase7_5": str(act.get("sha256", "")) == str(reb.get("sha256", "")),
    }


def _build_focus_metrics_summary(
    *,
    current_profile: Dict[str, Dict[str, Any]],
    rebuilt_profile: Dict[str, Dict[str, Any]],
    active_profile: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "imports": _focus_metric_entry("import_symbols", current_profile, rebuilt_profile, active_profile),
        "exports": _focus_metric_entry("export_symbols", current_profile, rebuilt_profile, active_profile),
        "variable_names": _focus_metric_entry("pseudo_variable_names", current_profile, rebuilt_profile, active_profile),
    }


def _safe_name(text: str) -> str:
    raw = str(text or "").strip()
    if not raw:
        return "sample"
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in raw).strip("._-") or "sample"


def _default_ida_dir_name_from_input(input_path: Optional[str], db_path: Path) -> str:
    if input_path:
        name = Path(input_path).name
        if name:
            return f"{name.replace('.', '_')}_idademo"
    stem = db_path.stem or "sample"
    return f"{stem.replace('.', '_')}_idademo"


def _pick_ida_export_dir(
    *,
    db_path: Path,
    input_path: Optional[str],
    ida_dir_override: Optional[str],
) -> Path:
    if ida_dir_override:
        p = Path(ida_dir_override).expanduser().resolve()
        if not p.exists() or not p.is_dir():
            raise Phase75StrictAlignError(f"指定的 --phase7-5-ida-dir 不存在或不是目录: {p}")
        return p

    candidates: List[Path] = []
    seen: set[str] = set()

    def _add(p: Path) -> None:
        rp = str(p.resolve())
        if rp not in seen:
            seen.add(rp)
            candidates.append(p.resolve())

    db_parent = db_path.parent.resolve()
    _add(db_parent / _default_ida_dir_name_from_input(input_path, db_path))
    _add(db_parent / f"{db_path.stem.replace('.', '_')}_idademo")

    if input_path:
        inp = Path(input_path).expanduser().resolve()
        _add(inp.parent / f"{inp.name.replace('.', '_')}_idademo")
        if inp.stem:
            _add(inp.parent / f"{inp.stem.replace('.', '_')}_idademo")

    for p in sorted(db_parent.glob("*_idademo")):
        if p.is_dir():
            _add(p)

    existing = [p for p in candidates if p.exists() and p.is_dir()]
    if not existing:
        hint = "\n".join(f"  - {p}" for p in candidates[:8])
        raise Phase75StrictAlignError(
            "未找到可用的 IDA 导出目录(*_idademo)。\n"
            f"db={db_path}\n"
            "尝试过：\n"
            f"{hint if hint else '  (no candidates)'}"
        )

    preferred = db_parent / f"{db_path.stem.replace('.', '_')}_idademo"
    if preferred.exists() and preferred.is_dir():
        return preferred.resolve()

    if len(existing) == 1:
        return existing[0]

    hint = "\n".join(f"  - {p}" for p in existing)
    raise Phase75StrictAlignError(
        "检测到多个 *_idademo 目录，无法自动唯一确定。\n"
        f"请使用 --phase7-5-ida-dir 指定：\n{hint}"
    )


def _metric_digest(
    conn: sqlite3.Connection,
    sql: str,
    params: Sequence[Any] = (),
) -> Tuple[int, str]:
    cur = conn.execute(sql, tuple(params))
    h = hashlib.sha256()
    cnt = 0
    for row in cur:
        normalized: List[Any] = []
        for cell in row:
            if isinstance(cell, bytes):
                normalized.append({"__bytes_hex__": cell.hex()})
            else:
                normalized.append(cell)
        blob = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), default=str)
        h.update(blob.encode("utf-8"))
        h.update(b"\n")
        cnt += 1
    return cnt, h.hexdigest()


def _collect_ida_profile(db_path: Path, call_ref_types: Sequence[str]) -> Dict[str, Dict[str, Any]]:
    if not db_path.exists():
        raise Phase75StrictAlignError(f"数据库不存在: {db_path}")

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        metrics: Dict[str, Dict[str, Any]] = {}
        call_types = [str(x) for x in call_ref_types if str(x or "").strip()]
        if not call_types:
            call_types = ["CALL"]
        call_ph = ",".join("?" for _ in call_types)

        queries: List[Tuple[str, str, Sequence[Any]]] = [
            (
                "symbols_all",
                """
                SELECT COALESCE(s.address_va, -1), COALESCE(s.raw_address, ''), COALESCE(s.name, ''),
                       COALESCE(s.kind, ''), COALESCE(s.raw_type, ''), COALESCE(s.source, ''),
                       COALESCE(s.is_global, -1), COALESCE(s.is_primary, -1),
                       COALESCE(s.is_external, -1), COALESCE(s.namespace, '')
                FROM symbols AS s
                JOIN binary_views AS bv ON s.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                ORDER BY COALESCE(s.address_va, -1), COALESCE(s.name, ''), s.id;
                """,
                (),
            ),
            (
                "import_symbols",
                """
                SELECT COALESCE(s.address_va, -1), COALESCE(s.name, ''), COALESCE(s.raw_type, ''),
                       COALESCE(s.source, ''), COALESCE(s.raw_address, ''), COALESCE(s.is_external, -1)
                FROM symbols AS s
                JOIN binary_views AS bv ON s.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                  AND (
                    LOWER(COALESCE(s.kind, '')) = 'import'
                    OR COALESCE(s.is_external, 0) = 1
                    OR UPPER(COALESCE(s.source, '')) LIKE '%IMPORT%'
                    OR UPPER(COALESCE(s.raw_type, '')) LIKE '%IMPORT%'
                  )
                ORDER BY COALESCE(s.address_va, -1), COALESCE(s.name, ''), s.id;
                """,
                (),
            ),
            (
                "export_symbols",
                """
                SELECT COALESCE(s.address_va, -1), COALESCE(s.name, ''), COALESCE(s.raw_type, ''),
                       COALESCE(s.source, ''), COALESCE(s.raw_address, ''), COALESCE(s.is_external, -1)
                FROM symbols AS s
                JOIN binary_views AS bv ON s.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                  AND (
                    LOWER(COALESCE(s.kind, '')) = 'export'
                    OR UPPER(COALESCE(s.source, '')) LIKE '%EXPORT%'
                    OR UPPER(COALESCE(s.raw_type, '')) LIKE '%EXPORT%'
                  )
                ORDER BY COALESCE(s.address_va, -1), COALESCE(s.name, ''), s.id;
                """,
                (),
            ),
            (
                "strings",
                """
                SELECT s.address_va, COALESCE(s.value, ''), COALESCE(s.length, -1)
                FROM strings AS s
                JOIN binary_views AS bv ON s.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                ORDER BY s.address_va, COALESCE(s.value, ''), s.id;
                """,
                (),
            ),
            (
                "functions",
                """
                SELECT f.entry_va, COALESCE(f.name, ''), COALESCE(f.size_bytes, -1), COALESCE(f.raw_file, '')
                FROM functions AS f
                JOIN binary_views AS bv ON f.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                ORDER BY f.entry_va, COALESCE(f.name, ''), f.id;
                """,
                (),
            ),
            (
                "instructions",
                """
                SELECT f.entry_va, i.index_in_function, i.address_va, COALESCE(i.bytes, ''),
                       COALESCE(i.mnemonic, ''), COALESCE(i.op_str, ''), COALESCE(i.raw_line, '')
                FROM instructions AS i
                JOIN functions AS f ON i.function_id = f.id
                JOIN binary_views AS bv ON i.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                ORDER BY f.entry_va, i.index_in_function, i.address_va, i.id;
                """,
                (),
            ),
            (
                "xrefs",
                """
                SELECT x.src_va, COALESCE(x.dst_va, -1), COALESCE(x.dst_name, ''),
                       COALESCE(x.ref_type_raw, ''), COALESCE(x.containing_function, ''),
                       COALESCE(x.is_primary, -1)
                FROM xrefs AS x
                JOIN binary_views AS bv ON x.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                ORDER BY x.src_va, COALESCE(x.dst_va, -1), COALESCE(x.ref_type_raw, ''), x.id;
                """,
                (),
            ),
            (
                "pseudo_functions",
                """
                SELECT p.entry_va, COALESCE(p.name, ''), COALESCE(p.prototype, ''),
                       COALESCE(p.body, ''), COALESCE(p.raw_file, '')
                FROM pseudo_functions AS p
                JOIN binary_views AS bv ON p.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                ORDER BY p.entry_va, COALESCE(p.name, ''), p.id;
                """,
                (),
            ),
            (
                "fcg_call_edges",
                f"""
                SELECT sf.entry_va, df.entry_va, COALESCE(x.ref_type_raw, '')
                FROM xrefs AS x
                JOIN instructions AS si ON si.view_id = x.view_id AND si.address_va = x.src_va
                JOIN instructions AS di ON di.view_id = x.view_id AND di.address_va = x.dst_va
                JOIN functions AS sf ON sf.id = si.function_id
                JOIN functions AS df ON df.id = di.function_id
                JOIN binary_views AS bv ON x.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                  AND COALESCE(x.ref_type_raw, '') IN ({call_ph})
                ORDER BY sf.entry_va, df.entry_va, COALESCE(x.ref_type_raw, ''), x.id;
                """,
                call_types,
            ),
            (
                "cfg_intra_edges",
                f"""
                SELECT sf.entry_va, x.src_va, x.dst_va, COALESCE(x.ref_type_raw, '')
                FROM xrefs AS x
                JOIN instructions AS si ON si.view_id = x.view_id AND si.address_va = x.src_va
                JOIN instructions AS di ON di.view_id = x.view_id AND di.address_va = x.dst_va
                JOIN functions AS sf ON sf.id = si.function_id
                JOIN binary_views AS bv ON x.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                  AND si.function_id = di.function_id
                  AND COALESCE(x.ref_type_raw, '') NOT IN ({call_ph})
                ORDER BY sf.entry_va, x.src_va, x.dst_va, COALESCE(x.ref_type_raw, ''), x.id;
                """,
                call_types,
            ),
        ]

        for name, sql, params in queries:
            cnt, digest = _metric_digest(conn, sql, params)
            metrics[name] = {"count": int(cnt), "sha256": str(digest)}
        metrics["pseudo_variable_names"] = _collect_pseudo_variable_metric(conn)
        return metrics
    finally:
        conn.close()


def _diff_profiles(
    current: Dict[str, Dict[str, Any]],
    rebuilt: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    keys = sorted(set(current.keys()) | set(rebuilt.keys()))
    diffs: List[Dict[str, Any]] = []
    for k in keys:
        a = current.get(k) or {"count": -1, "sha256": ""}
        b = rebuilt.get(k) or {"count": -1, "sha256": ""}
        if int(a.get("count", -1)) != int(b.get("count", -1)) or str(a.get("sha256", "")) != str(b.get("sha256", "")):
            diffs.append(
                {
                    "metric": k,
                    "current_count": int(a.get("count", -1)),
                    "rebuilt_count": int(b.get("count", -1)),
                    "current_sha256": str(a.get("sha256", "")),
                    "rebuilt_sha256": str(b.get("sha256", "")),
                }
            )
    return diffs


def _copy_sidecar_if_exists(src_db: Path, dst_db: Path) -> None:
    for suffix in ("-wal", "-shm"):
        src = src_db.with_name(src_db.name + suffix)
        if src.exists():
            dst = dst_db.with_name(dst_db.name + suffix)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def _remove_sidecars(db_path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        p = db_path.with_name(db_path.name + suffix)
        if p.exists():
            p.unlink()


def _replace_db_atomically(
    *,
    target_db: Path,
    rebuilt_db: Path,
    backup_db: Path,
) -> None:
    backup_db.parent.mkdir(parents=True, exist_ok=True)
    if target_db.exists():
        shutil.copy2(target_db, backup_db)
        _copy_sidecar_if_exists(target_db, backup_db)

    _remove_sidecars(target_db)
    staged = target_db.with_suffix(target_db.suffix + ".phase7_5_tmp")
    if staged.exists():
        staged.unlink()
    shutil.copy2(rebuilt_db, staged)
    staged.replace(target_db)
    _remove_sidecars(target_db)


def _run_alignment_loader_ida_only(
    *,
    rebuilt_db: Path,
    ida_dir: Path,
) -> None:
    rebuilt_db.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(ALIGNMENT_LOADER_SCRIPT),
        "--db",
        str(rebuilt_db),
        "--ida-dir",
        str(ida_dir),
        "--delete-db",
    ]
    result = subprocess.run(cmd, cwd=str(ALIGNMENT_LOADER_SCRIPT.parent))
    if result.returncode != 0:
        raise Phase75StrictAlignError(
            f"alignment_loader.py(IDA-only) 失败，退出码={result.returncode}"
        )
    if not rebuilt_db.exists():
        raise Phase75StrictAlignError(f"重建 DB 未生成: {rebuilt_db}")


def run_phase7_5_strict_align(
    *,
    db_path: Path,
    input_path: Optional[str],
    artifacts_dir: Path,
    call_ref_types: Sequence[str],
    mode: str = "strict",
    ida_dir: Optional[str] = None,
    keep_rebuilt_db: bool = False,
) -> Dict[str, Any]:
    """Run strict alignment and return a structured report."""

    mode_norm = str(mode or "strict").strip().lower()
    if mode_norm not in {"strict", "off"}:
        raise Phase75StrictAlignError(f"无效的 phase7.5 模式: {mode}")

    report: Dict[str, Any] = {
        "enabled": mode_norm != "off",
        "mode": mode_norm,
        "status": "skipped" if mode_norm == "off" else "running",
        "db_path": str(db_path),
        "input_path": str(input_path or ""),
        "ida_dir": "",
        "rebuilt_db": "",
        "backup_db": "",
        "profile_diff_count": 0,
        "profile_diffs": [],
        "current_profile": {},
        "rebuilt_profile": {},
        "post_replace_profile": {},
        "focus_metrics_summary": {},
        "notes": [],
    }
    if mode_norm == "off":
        report["notes"] = ["phase7.5 disabled by --phase7-5-mode off"]
        return report

    if not db_path.exists():
        raise Phase75StrictAlignError(f"目标 DB 不存在: {db_path}")

    ida_export_dir = _pick_ida_export_dir(
        db_path=db_path,
        input_path=input_path,
        ida_dir_override=ida_dir,
    )

    phase75_dir = artifacts_dir / "phase7_5"
    phase75_dir.mkdir(parents=True, exist_ok=True)
    rebuilt_db = phase75_dir / f"{_safe_name(db_path.stem)}.rebuilt_from_ida.db"
    backup_db = phase75_dir / f"{_safe_name(db_path.name)}.before_replace.db"

    report["ida_dir"] = str(ida_export_dir)
    report["rebuilt_db"] = str(rebuilt_db)
    report["backup_db"] = str(backup_db)

    _run_alignment_loader_ida_only(rebuilt_db=rebuilt_db, ida_dir=ida_export_dir)

    current_profile = _collect_ida_profile(db_path, call_ref_types)
    rebuilt_profile = _collect_ida_profile(rebuilt_db, call_ref_types)
    profile_diffs = _diff_profiles(current_profile, rebuilt_profile)

    report["current_profile"] = current_profile
    report["rebuilt_profile"] = rebuilt_profile
    report["profile_diffs"] = profile_diffs
    report["profile_diff_count"] = len(profile_diffs)

    if profile_diffs:
        _replace_db_atomically(
            target_db=db_path,
            rebuilt_db=rebuilt_db,
            backup_db=backup_db,
        )
        post_profile = _collect_ida_profile(db_path, call_ref_types)
        post_diff = _diff_profiles(post_profile, rebuilt_profile)
        report["post_replace_profile"] = post_profile
        report["post_replace_diff_count"] = len(post_diff)
        report["post_replace_diffs"] = post_diff
        report["focus_metrics_summary"] = _build_focus_metrics_summary(
            current_profile=current_profile,
            rebuilt_profile=rebuilt_profile,
            active_profile=post_profile,
        )
        if post_diff:
            report["status"] = "failed"
            raise Phase75StrictAlignError(
                "Phase7.5 替换 DB 后仍与重建结果不一致，已中止。"
            )
        report["status"] = "replaced"
        report["notes"] = ["drift detected; active DB replaced by rebuilt IDA-only DB"]
    else:
        report["status"] = "aligned"
        report["notes"] = ["active DB already matches rebuilt IDA-only profile"]
        report["focus_metrics_summary"] = _build_focus_metrics_summary(
            current_profile=current_profile,
            rebuilt_profile=rebuilt_profile,
            active_profile=current_profile,
        )

    if not keep_rebuilt_db and rebuilt_db.exists():
        rebuilt_db.unlink()
        report["rebuilt_db_removed"] = True
    else:
        report["rebuilt_db_removed"] = False

    return report
