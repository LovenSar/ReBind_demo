"""Phase7 任务预处理：根据对齐 DB 规模选择根 ``config.yaml`` 中的预设。"""

from __future__ import annotations

import copy
import json
import sqlite3
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from project_config import deep_merge_dicts  # noqa: E402

from depth.phase7_task_config import load_phase7_config  # noqa: E402
from depth.strict_align import Phase75StrictAlignError, _pick_ida_export_dir  # noqa: E402
from kp.kp_deep_path import pick_binary_id  # noqa: E402


@dataclass
class Phase7DbStats:
    binary_id: int
    ida_view_id: Optional[int]
    function_count: int
    xref_count: Optional[int]
    pseudo_fn_count: Optional[int]


@dataclass
class Phase7PreprocessReport:
    db_path: str
    input_path: Optional[str]
    binary_id: int
    stats: Phase7DbStats
    tier: str
    matched_preset_file: Optional[str]
    ida_dir_suggested: Optional[str]
    ida_dir_note: str
    heuristic_overrides: Dict[str, Any]
    warnings: List[str] = field(default_factory=list)


def _strip_task_meta(d: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in d.items() if not str(k).startswith("_")}


def _resolve_ida_view_id(conn: sqlite3.Connection, binary_id: int) -> Optional[int]:
    cur = conn.execute(
        """
        SELECT bv.id
        FROM binary_views AS bv
        JOIN tools AS t ON bv.tool_id = t.id
        WHERE bv.binary_id = ? AND LOWER(COALESCE(t.name, '')) = 'ida'
        ORDER BY bv.id
        LIMIT 1;
        """,
        (int(binary_id),),
    )
    row = cur.fetchone()
    return int(row[0]) if row else None


def _count_safe(conn: sqlite3.Connection, sql: str, params: Tuple[Any, ...]) -> Optional[int]:
    try:
        row = conn.execute(sql, params).fetchone()
        return int(row[0]) if row and row[0] is not None else 0
    except Exception:
        return None


def collect_db_stats(
    conn: sqlite3.Connection,
    *,
    binary_id: int,
) -> Tuple[Phase7DbStats, List[str]]:
    warnings: List[str] = []
    vid = _resolve_ida_view_id(conn, binary_id)
    if vid is None:
        warnings.append("未找到 IDA 视图的 binary_views（LOWER(tool.name)='ida'）；规模统计可能为 0。")
        fn_count = 0
        xr = None
        pseudo_n = None
    else:
        fn_count = _count_safe(conn, "SELECT COUNT(*) FROM functions WHERE view_id = ?;", (vid,)) or 0
        xr = _count_safe(conn, "SELECT COUNT(*) FROM xrefs WHERE view_id = ?;", (vid,))
        pseudo_n = _count_safe(
            conn,
            "SELECT COUNT(*) FROM pseudo_functions WHERE view_id = ?;",
            (vid,),
        )
    stats = Phase7DbStats(
        binary_id=int(binary_id),
        ida_view_id=vid,
        function_count=int(fn_count),
        xref_count=xr,
        pseudo_fn_count=pseudo_n,
    )
    return stats, warnings


def infer_tier(stats: Phase7DbStats, preprocess_config: Optional[Dict[str, Any]] = None) -> str:
    """返回档位：exploratory | balanced | conservative。"""
    cfg = preprocess_config or {}
    exploratory_limit = int(cfg.get("exploratory_function_limit", 800) or 800)
    balanced_limit = int(cfg.get("balanced_function_limit", 8000) or 8000)
    n = int(stats.function_count)
    if n < exploratory_limit:
        return "exploratory"
    if n < balanced_limit:
        return "balanced"
    return "conservative"


def _heuristic_clamps(
    stats: Phase7DbStats,
    preprocess_config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """在预设之上按 xref/函数规模做数值夹紧。"""
    cfg = preprocess_config or {}
    n = max(1, int(stats.function_count))
    xr = int(stats.xref_count or 0)
    very_large_n = int(cfg.get("very_large_function_limit", 15000) or 15000)
    very_large_xr = int(cfg.get("very_large_xref_limit", 800000) or 800000)
    large_n = int(cfg.get("large_function_limit", 8000) or 8000)
    large_xr = int(cfg.get("large_xref_limit", 300000) or 300000)
    if n > very_large_n or xr > very_large_xr:
        raw = cfg.get("very_large_overrides") or {}
        return copy.deepcopy(raw) if isinstance(raw, dict) else {}
    if n > large_n or xr > large_xr:
        raw = cfg.get("large_overrides") or {}
        return copy.deepcopy(raw) if isinstance(raw, dict) else {}
    return {}


def _scan_rebind_nested_ida(db_path: Path) -> List[Path]:
    """在 db 同级目录下扫描 ``*_rebind_demo/*_idademo``（嵌套导出常见布局）。"""
    root = db_path.parent
    found: List[Path] = []
    for pattern in ("*_rebind_demo/*_idademo", "*_rebind_demo/*/*_idademo"):
        for p in root.glob(pattern):
            if p.is_dir():
                found.append(p.resolve())
    return sorted(set(found))


def suggest_ida_dir_str(*, db_path: Path, input_path: Optional[str]) -> Tuple[Optional[str], str]:
    try:
        p = _pick_ida_export_dir(db_path=db_path, input_path=input_path, ida_dir_override=None)
        return str(p.resolve()), ""
    except Phase75StrictAlignError as exc:
        note = str(exc).strip()
        nested = _scan_rebind_nested_ida(db_path)
        if len(nested) == 1:
            return str(nested[0]), note + "\n(补充扫描 *_rebind_demo/*_idademo 得到唯一目录)"
        if len(nested) > 1:
            joined = "\n".join(f"  - {p}" for p in nested[:16])
            return None, note + "\n补充扫描仍有多处 *_idademo，请手动指定 phase7_5_ida_dir：\n" + joined
        return None, note


def build_suggested_task_config(
    *,
    repo_root: Path,
    db_path: Path,
    input_path: Optional[str],
    binary_id: Optional[int],
) -> Tuple[Dict[str, Any], Phase7PreprocessReport]:
    config_path = repo_root / "config.yaml"
    phase7_config = load_phase7_config(config_path)
    raw_base = phase7_config.get("task_defaults") or {}
    if not isinstance(raw_base, dict):
        raise ValueError("config.yaml 的 semantics.phase7.task_defaults 必须是字典")
    base = _strip_task_meta(raw_base)
    raw_presets = phase7_config.get("presets") or {}
    presets = raw_presets if isinstance(raw_presets, dict) else {}
    raw_preprocess = phase7_config.get("preprocess") or {}
    preprocess_config = raw_preprocess if isinstance(raw_preprocess, dict) else {}

    conn = sqlite3.connect(str(db_path))
    try:
        bid = pick_binary_id(conn, binary_id)
        stats, warns = collect_db_stats(conn, binary_id=bid)
    finally:
        conn.close()

    tier = infer_tier(stats, preprocess_config)
    merged = copy.deepcopy(base)
    matched_preset: Optional[str] = None
    preset_data = presets.get(tier) or {}
    if isinstance(preset_data, dict):
        preset_data = _strip_task_meta(preset_data)
        merged = deep_merge_dicts(merged, preset_data)
        matched_preset = f"{config_path}#semantics.phase7.presets.{tier}"

    clamps = _heuristic_clamps(stats, preprocess_config)
    merged = deep_merge_dicts(merged, clamps)
    merged["binary_id"] = int(bid)

    ida_s, ida_note = suggest_ida_dir_str(db_path=db_path, input_path=input_path)
    if ida_s:
        merged["phase7_5_ida_dir"] = ida_s

    merged["_phase7_preprocess"] = {
        "tier": tier,
        "matched_preset_file": matched_preset,
        "binary_id": bid,
        "stats": {
            "ida_view_id": stats.ida_view_id,
            "function_count": stats.function_count,
            "xref_count": stats.xref_count,
        },
        "heuristic_overrides": clamps,
        "note": "以 _ 开头的键仅供阅读；Phase7 加载任务 JSON 时不会当作运行参数。",
    }

    report = Phase7PreprocessReport(
        db_path=str(db_path.resolve()),
        input_path=input_path,
        binary_id=bid,
        stats=stats,
        tier=tier,
        matched_preset_file=matched_preset,
        ida_dir_suggested=ida_s,
        ida_dir_note=ida_note,
        heuristic_overrides=clamps,
        warnings=warns,
    )
    return merged, report


def report_to_jsonable(r: Phase7PreprocessReport) -> Dict[str, Any]:
    return {
        "db_path": r.db_path,
        "input_path": r.input_path,
        "binary_id": r.binary_id,
        "tier": r.tier,
        "matched_preset_file": r.matched_preset_file,
        "ida_dir_suggested": r.ida_dir_suggested,
        "ida_dir_note": r.ida_dir_note,
        "stats": {
            "ida_view_id": r.stats.ida_view_id,
            "function_count": r.stats.function_count,
            "xref_count": r.stats.xref_count,
            "pseudo_function_count": r.stats.pseudo_fn_count,
        },
        "heuristic_overrides": r.heuristic_overrides,
        "warnings": r.warnings,
    }


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)
        fp.write("\n")
    tmp.replace(path)
