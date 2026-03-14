#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""goal_deep_engine.py

独立的“目标驱动 + 深度主干 + 代际子树”分析入口。

设计目标：
1) 不并入 semantic_align 主流程，避免大样本下资源浪费；
2) 复用现有 kp_* / deep_path 能力，减少重复实现；
3) 默认先落临时 JSON，可按需回填 DB。
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import math
import re
import sqlite3
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from kp.kp_deep_path import (
    estimate_global_deepest_depth,
    parse_va,
    pick_binary_id,
    resolve_db_path,
    run_deep_path_analysis,
)
from kp.kp_graph import build_unified_graph
from kp.kp_llm import build_chat_request, call_llm_analyze_function
from kp.kp_schema import load_analysis_info
from kp.kp_settings import build_llm_settings, load_semantics_config
from kp.kp_types import CALL_REF_TYPES, UnifiedGraph, UnifiedFunctionNode
from kp.kp_unified_prompt import build_unified_prompt
from phases.phase2_deep_path import run_llm_poll_on_deepest_path
from phases.phase7_5_strict_align import Phase75StrictAlignError, run_phase7_5_strict_align


STRUCT_HINT_RE = re.compile(r"\b(?:struct|field_|_ctx|_cfg|_info|_node|_state)\b|->", re.IGNORECASE)
TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")
DEFAULT_DB_COMPARE_THRESHOLD = 0.1


@dataclass
class GoalItem:
    entry_va: int
    source: str
    xref_count: int
    richness: int
    manual_score: int = 0


@dataclass
class IndirectEdgeStatus:
    enabled: bool
    degraded: bool
    reason: str
    total_candidates: int
    selected_candidates: int
    incremental_applied: bool


@dataclass
class RunLayout:
    sample_tag: str
    run_id: str
    run_dir: Path
    artifacts_dir: Path
    logs_dir: Path
    checkpoints_dir: Path
    reports_dir: Path
    out_file: Path
    backup_file: Path
    gen1_deepest_file: Path
    manifest_file: Path
    checkpoint_file: Path
    journal_file: Path
    llm_poll_log_file: Path
    llm_trace_file: Path


def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="独立目标驱动深度语义分析引擎")
    ap.add_argument("input_path", nargs="?", default=None, help="输入路径（exe/idb/i64/db）")
    ap.add_argument("--db", default=None, help="显式指定 DB（优先级最高）")
    ap.add_argument("--binary-id", type=int, default=None, help="可选 binary_id")

    ap.add_argument("--goal-va", action="append", default=[], help="人工目标函数地址，可重复")
    ap.add_argument("--goal-keyword", action="append", default=[], help="人工目标关键词，可重复")
    ap.add_argument("--goal-struct", action="append", default=[], help="人工结构体名/线索，可重复")
    ap.add_argument("--goal-limit", type=int, default=3, help="最终分析目标数量（默认 3）")
    ap.add_argument("--auto-goal-limit", type=int, default=20, help="自动候选池上限（默认 20）")

    ap.add_argument("--lambda-radius", type=float, default=2.5, help="混合距离半径 λ（默认 2.5）")
    ap.add_argument("--w-call", type=float, default=0.45, help="混合距离中 call 权重（默认 0.45）")
    ap.add_argument("--w-data", type=float, default=0.30, help="混合距离中 data 权重（默认 0.30）")
    ap.add_argument("--w-string", type=float, default=0.15, help="混合距离中 string 权重（默认 0.15）")
    ap.add_argument("--w-global", type=float, default=0.10, help="混合距离中 global 权重（默认 0.10）")

    ap.add_argument("--max-depth", type=int, default=0, help="DFS 最大深度，0=自动")
    ap.add_argument("--max-paths", type=int, default=200, help="每轮最多路径数")
    ap.add_argument("--max-branch", type=int, default=6, help="每层最大分支")
    ap.add_argument("--max-call-sites", type=int, default=3, help="每条边最多调用点")
    ap.add_argument("--cond-window", type=int, default=10, help="守卫窗口")
    ap.add_argument("--max-guards-per-site", type=int, default=3, help="每调用点最多守卫")

    ap.add_argument("--gen2-ancestor-depth", type=int, default=5, help="二代向上追溯深度")
    ap.add_argument("--gen2-min-wlca", type=float, default=0.28, help="W-LCA 最低阈值")
    ap.add_argument("--gen2-frontier-k", type=int, default=3, help="W-LCA 失败时多根前沿数量")
    ap.add_argument("--gen2-alpha", type=float, default=0.65, help="W-LCA 距离衰减 alpha")
    ap.add_argument("--gen2-beta", type=float, default=0.08, help="W-LCA 入度惩罚 beta")
    ap.add_argument("--gen2-gamma", type=float, default=0.40, help="W-LCA 语义重叠 gamma")

    ap.add_argument(
        "--indirect-edge-mode",
        choices=("auto", "on", "off"),
        default="auto",
        help="间接调用补边模式（默认 auto）",
    )
    ap.add_argument("--indirect-edge-budget", type=int, default=25000, help="auto 模式下间接边预算")
    ap.add_argument(
        "--incremental-indirect",
        action="store_true",
        default=False,
        help="auto 降级后，是否做间接边增量分析",
    )
    ap.add_argument("--incremental-indirect-topn", type=int, default=3000, help="增量间接边 topN")

    ap.add_argument("--llm-mode", choices=("auto", "on", "off"), default="auto", help="LLM 执行模式")
    ap.add_argument("--llm-config", default=None, help="LLM 配置路径")
    ap.add_argument("--llm-model", default=None)
    ap.add_argument("--llm-temperature", type=float, default=None)
    ap.add_argument("--llm-max-tokens", type=int, default=None)
    ap.add_argument("--llm-max-attempts", type=int, default=3)
    ap.add_argument("--llm-code-chars", type=int, default=1200)
    ap.add_argument("--llm-max-steps", type=int, default=0)

    ap.add_argument("--max-compare-nodes", type=int, default=12, help="备份比较最多函数数")
    ap.add_argument(
        "--compare-min-delta",
        type=float,
        default=DEFAULT_DB_COMPARE_THRESHOLD,
        help="LLM 选优最小分差阈值（默认 0.1）",
    )
    ap.add_argument(
        "--apply-db",
        action="store_true",
        default=False,
        help="将 selected=new 的结果回填到 analysis_status（默认关闭）",
    )
    ap.add_argument(
        "--apply-max-rows",
        type=int,
        default=0,
        help="回填最多行数，0 表示不限制（默认 0）",
    )
    ap.add_argument(
        "--apply-min-confidence",
        type=int,
        default=70,
        help="回填最小置信度（0-100，默认 70）",
    )
    ap.add_argument(
        "--phase7-5-mode",
        choices=("strict", "off"),
        default="strict",
        help="Phase7.5 严格对齐模式：strict/off（默认 strict）",
    )
    ap.add_argument(
        "--phase7-5-ida-dir",
        default=None,
        help="Phase7.5 指定 IDA 导出目录(*_idademo)。不传则自动推断。",
    )
    ap.add_argument(
        "--phase7-5-keep-rebuilt-db",
        action="store_true",
        default=False,
        help="Phase7.5 保留重建 DB（默认完成后删除）。",
    )
    ap.add_argument("--runs-root", default=None, help="运行目录根路径（默认: <db_dir>/runs）")
    ap.add_argument("--run-id", default=None, help="运行 ID（默认按时间戳生成）")
    ap.add_argument("--resume", action="store_true", default=False, help="从 run_id 对应的 checkpoint 断点续跑")
    ap.add_argument(
        "--force-resume",
        action="store_true",
        default=False,
        help="允许参数变化后强制恢复（默认禁止）",
    )
    ap.add_argument(
        "--log-raw-llm",
        action="store_true",
        default=False,
        help="落盘 LLM 原始请求/响应文本（默认仅摘要）",
    )
    ap.add_argument("--dry-run", action="store_true", default=False, help="仅输出结构，不调用 LLM")
    ap.add_argument("--output", default=None, help="可选：显式输出 JSON 文件")
    return ap.parse_args()


def _safe_stem(text: str) -> str:
    s = str(text or "").strip()
    if not s:
        return "unknown"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


def _build_output_paths(db_path: Path, input_path: Optional[str], explicit_output: Optional[str]) -> Tuple[Path, Path, Path]:
    if explicit_output:
        out_file = Path(explicit_output).expanduser().resolve()
        out_dir = out_file.parent
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = out_dir / f"backup_{ts}.json"
        return out_dir, out_file, backup_file

    if input_path:
        input_name = Path(input_path).name
    else:
        input_name = db_path.stem

    run_dir = db_path.parent / f"goal_engine_runs_{_safe_stem(input_name)}"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = run_dir / f"goal_run_{ts}.json"
    backup_file = run_dir / f"goal_backup_{ts}.json"
    return run_dir, out_file, backup_file


def _build_gen1_deepest_output_path(out_file: Path) -> Path:
    return out_file.with_name(f"{out_file.stem}.gen1_deepest.json")


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _write_json_file(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)
    tmp.replace(path)


def _append_jsonl(path: Path, event: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(event, ensure_ascii=False) + "\n")


def _goal_to_dict(goal: GoalItem) -> Dict[str, Any]:
    return {
        "entry_va": int(goal.entry_va),
        "source": str(goal.source),
        "xref_count": int(goal.xref_count),
        "richness": int(goal.richness),
        "manual_score": int(goal.manual_score),
    }


def _goal_from_dict(item: Dict[str, Any]) -> GoalItem:
    return GoalItem(
        entry_va=int(item.get("entry_va", 0) or 0),
        source=str(item.get("source") or ""),
        xref_count=int(item.get("xref_count", 0) or 0),
        richness=int(item.get("richness", 0) or 0),
        manual_score=int(item.get("manual_score", 0) or 0),
    )


def _build_resume_signature(args: argparse.Namespace, db_path: Path) -> str:
    raw = vars(args)
    excluded = {
        "resume",
        "force_resume",
        "run_id",
        "runs_root",
        "output",
        "log_raw_llm",
    }
    payload: Dict[str, Any] = {
        k: raw[k]
        for k in sorted(raw.keys())
        if k not in excluded
    }
    payload["db_path"] = str(db_path)
    enc = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(enc.encode("utf-8")).hexdigest()


def _pick_latest_run_id(sample_root: Path) -> Optional[str]:
    if not sample_root.exists() or not sample_root.is_dir():
        return None
    candidates = [p for p in sample_root.iterdir() if p.is_dir()]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0].name


def _build_run_layout(
    *,
    db_path: Path,
    input_path: Optional[str],
    explicit_output: Optional[str],
    runs_root: Optional[str],
    run_id: Optional[str],
    resume: bool,
) -> RunLayout:
    if input_path:
        sample_name = Path(input_path).name
    else:
        sample_name = db_path.stem
    sample_tag = _safe_stem(sample_name)

    root = Path(runs_root).expanduser().resolve() if runs_root else (db_path.parent / "runs")
    sample_root = root / sample_tag

    rid = _safe_stem(str(run_id or "").strip())
    if not rid:
        if resume:
            latest = _pick_latest_run_id(sample_root)
            if not latest:
                raise SystemExit(f"未找到可恢复 run: {sample_root}")
            rid = latest
        else:
            rid = datetime.now().strftime("%Y%m%d_%H%M%S")

    run_dir = sample_root / rid
    artifacts_dir = run_dir / "artifacts"
    logs_dir = run_dir / "logs"
    checkpoints_dir = run_dir / "checkpoints"
    reports_dir = run_dir / "reports"

    if explicit_output:
        out_file = Path(explicit_output).expanduser().resolve()
        backup_file = out_file.with_name("goal_backup.json")
        gen1_file = out_file.with_name("goal_gen1_deepest.json")
    else:
        out_file = reports_dir / "goal_run.json"
        backup_file = reports_dir / "goal_backup.json"
        gen1_file = reports_dir / "goal_gen1_deepest.json"

    return RunLayout(
        sample_tag=sample_tag,
        run_id=rid,
        run_dir=run_dir,
        artifacts_dir=artifacts_dir,
        logs_dir=logs_dir,
        checkpoints_dir=checkpoints_dir,
        reports_dir=reports_dir,
        out_file=out_file,
        backup_file=backup_file,
        gen1_deepest_file=gen1_file,
        manifest_file=run_dir / "manifest.json",
        checkpoint_file=checkpoints_dir / "state.json",
        journal_file=logs_dir / "journal.jsonl",
        llm_poll_log_file=logs_dir / "llm_poll.jsonl",
        llm_trace_file=logs_dir / "llm_trace.jsonl",
    )


def _load_checkpoint(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fp:
            data = json.load(fp)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_checkpoint(path: Path, state: Dict[str, Any]) -> None:
    payload = dict(state)
    payload["ts"] = _now_iso()
    _write_json_file(path, payload)


def _write_manifest(layout: RunLayout, payload: Dict[str, Any]) -> None:
    _write_json_file(layout.manifest_file, payload)


def _log_event(layout: RunLayout, event_type: str, **data: Any) -> None:
    event = {"ts": _now_iso(), "event": str(event_type)}
    event.update(data)
    _append_jsonl(layout.journal_file, event)


def _checkpoint_stage(layout: RunLayout, state: Dict[str, Any], stage: str) -> None:
    payload = dict(state)
    payload["stage"] = str(stage)
    _save_checkpoint(layout.checkpoint_file, payload)


def _load_analysis_info_safe(conn: sqlite3.Connection) -> Dict[int, dict]:
    try:
        return load_analysis_info(conn)
    except Exception:
        return {}


def _node_text_blob(node: UnifiedFunctionNode) -> str:
    parts: List[str] = []
    if node.names:
        parts.append(" ".join(sorted(node.names)))
    for code in node.pseudocodes.values():
        if code:
            parts.append(code)
    for s in node.string_refs:
        parts.append(s)
    for api in node.external_callee_names:
        parts.append(api)
    return "\n".join(parts)


def _semantic_richness(node: UnifiedFunctionNode, struct_tokens: Sequence[str]) -> int:
    text = _node_text_blob(node).lower()
    struct_hits = len(STRUCT_HINT_RE.findall(text))
    manual_struct_hits = 0
    for t in struct_tokens:
        tok = str(t or "").strip().lower()
        if tok and tok in text:
            manual_struct_hits += 1

    ext_api = len(node.external_callee_names)
    strings = len(node.string_refs)
    internal = len(node.internal_callee_vas)
    callers = len(node.caller_vas)
    instr_bucket = 2 if int(node.instr_count or 0) >= 120 else (1 if int(node.instr_count or 0) >= 30 else 0)

    score = 4 * min(ext_api, 15)
    score += 3 * min(strings, 20)
    score += 2 * min(internal, 20)
    score += 2 * min(callers, 20)
    score += 5 * min(struct_hits, 10)
    score += 8 * min(manual_struct_hits, 6)
    score += instr_bucket
    return int(score)


def _collect_direct_data_edges(conn: sqlite3.Connection, graph: UnifiedGraph) -> Dict[int, Set[int]]:
    adjacency: Dict[int, Set[int]] = defaultdict(set)
    view_ids = sorted(set(graph.function_id_to_view_id.values()))
    if not view_ids:
        return adjacency

    call_types = sorted(CALL_REF_TYPES)
    view_ph = ",".join("?" for _ in view_ids)
    call_ph = ",".join("?" for _ in call_types)

    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT src.function_id, dst.function_id
        FROM xrefs AS x
        JOIN instructions AS src
             ON src.view_id = x.view_id AND src.address_va = x.src_va
        JOIN instructions AS dst
             ON dst.view_id = x.view_id AND dst.address_va = x.dst_va
        WHERE x.view_id IN ({view_ph})
          AND x.ref_type_raw NOT IN ({call_ph})
        GROUP BY src.function_id, dst.function_id;
        """,
        [*view_ids, *call_types],
    )

    for src_fid, dst_fid in cur.fetchall():
        s_entry = graph.function_id_to_entry_va.get(int(src_fid))
        d_entry = graph.function_id_to_entry_va.get(int(dst_fid))
        if s_entry is None or d_entry is None or int(s_entry) == int(d_entry):
            continue
        adjacency[int(s_entry)].add(int(d_entry))
        adjacency[int(d_entry)].add(int(s_entry))

    return adjacency


def _collect_global_ref_map(conn: sqlite3.Connection, graph: UnifiedGraph) -> Tuple[Dict[int, Set[int]], Dict[int, List[Tuple[int, int]]]]:
    """Return:
    - global_to_funcs: global_va -> set(entry_va)
    - func_to_globals: entry_va -> [(global_va, ref_count), ...]
    """
    global_to_funcs: Dict[int, Set[int]] = defaultdict(set)
    func_to_globals_counter: Dict[int, Dict[int, int]] = defaultdict(lambda: defaultdict(int))

    view_ids = sorted(set(graph.function_id_to_view_id.values()))
    if not view_ids:
        return global_to_funcs, {}

    cur = conn.cursor()
    view_ph = ",".join("?" for _ in view_ids)
    cur.execute(
        f"""
        SELECT src.function_id, x.dst_va, COUNT(*)
        FROM xrefs AS x
        JOIN instructions AS src
             ON src.view_id = x.view_id AND src.address_va = x.src_va
        LEFT JOIN instructions AS dst
               ON dst.view_id = x.view_id AND dst.address_va = x.dst_va
        LEFT JOIN strings AS s
               ON s.view_id = x.view_id AND s.address_va = x.dst_va
        WHERE x.view_id IN ({view_ph})
          AND x.dst_va IS NOT NULL
          AND dst.function_id IS NULL
          AND s.address_va IS NULL
        GROUP BY src.function_id, x.dst_va;
        """,
        view_ids,
    )

    for src_fid, dst_va, cnt in cur.fetchall():
        entry = graph.function_id_to_entry_va.get(int(src_fid))
        if entry is None:
            continue
        gva = int(dst_va)
        c = int(cnt or 0)
        if c <= 0:
            continue
        global_to_funcs[gva].add(int(entry))
        func_to_globals_counter[int(entry)][gva] += c

    func_to_globals: Dict[int, List[Tuple[int, int]]] = {}
    for entry_va, counter in func_to_globals_counter.items():
        pairs = sorted(counter.items(), key=lambda x: x[1], reverse=True)
        func_to_globals[int(entry_va)] = pairs[:128]

    return global_to_funcs, func_to_globals


def _build_name_index(graph: UnifiedGraph) -> Dict[str, Set[int]]:
    idx: Dict[str, Set[int]] = defaultdict(set)
    for entry_va, node in graph.nodes.items():
        for n in node.names:
            key = str(n or "").strip().lower()
            if key:
                idx[key].add(int(entry_va))
    return idx


def _collect_indirect_edges(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    *,
    mode: str,
    budget: int,
    incremental: bool,
    incremental_topn: int,
) -> Tuple[Dict[int, Set[int]], IndirectEdgeStatus]:
    if mode == "off":
        return {}, IndirectEdgeStatus(False, False, "mode_off", 0, 0, False)

    view_ids = sorted(set(graph.function_id_to_view_id.values()))
    if not view_ids:
        return {}, IndirectEdgeStatus(False, False, "no_views", 0, 0, False)

    cur = conn.cursor()
    view_ph = ",".join("?" for _ in view_ids)

    # 仅看 COMPUTED_CALL / IDA 19 这类潜在间接调用。
    cur.execute(
        f"""
        SELECT COUNT(*)
        FROM xrefs AS x
        WHERE x.view_id IN ({view_ph})
          AND x.ref_type_raw IN ('COMPUTED_CALL', '19');
        """,
        view_ids,
    )
    total_candidates = int(cur.fetchone()[0] or 0)

    degraded = False
    incremental_applied = False
    selected_limit: Optional[int] = None
    reason = "enabled"

    if mode == "auto" and total_candidates > int(max(1, budget)):
        degraded = True
        reason = f"auto_degraded_over_budget(total={total_candidates}, budget={budget})"
        if incremental:
            selected_limit = max(1, int(incremental_topn or 1))
            incremental_applied = True
            reason += f"_incremental_topn={selected_limit}"
        else:
            return {}, IndirectEdgeStatus(False, True, reason, total_candidates, 0, False)

    name_index = _build_name_index(graph)

    query = f"""
        SELECT src.function_id, COALESCE(x.dst_name, ''), COUNT(*) AS cnt
        FROM xrefs AS x
        JOIN instructions AS src
             ON src.view_id = x.view_id AND src.address_va = x.src_va
        LEFT JOIN instructions AS dst
               ON dst.view_id = x.view_id AND dst.address_va = x.dst_va
        WHERE x.view_id IN ({view_ph})
          AND x.ref_type_raw IN ('COMPUTED_CALL', '19')
          AND dst.function_id IS NULL
          AND COALESCE(x.dst_name, '') <> ''
        GROUP BY src.function_id, x.dst_name
    """
    params: List[Any] = [*view_ids]
    if selected_limit is not None:
        query += " ORDER BY cnt DESC LIMIT ?"
        params.append(int(selected_limit))
    query += ";"

    cur.execute(query, params)

    edges: Dict[int, Set[int]] = defaultdict(set)
    selected_candidates = 0
    for src_fid, dst_name, _cnt in cur.fetchall():
        src_entry = graph.function_id_to_entry_va.get(int(src_fid))
        if src_entry is None:
            continue
        dname = str(dst_name or "").strip().lower()
        if not dname:
            continue
        matched = name_index.get(dname, set())
        if not matched:
            continue
        for dst_entry in matched:
            if int(dst_entry) == int(src_entry):
                continue
            edges[int(src_entry)].add(int(dst_entry))
            edges[int(dst_entry)].add(int(src_entry))
            selected_candidates += 1

    status = IndirectEdgeStatus(
        enabled=True,
        degraded=degraded,
        reason=reason,
        total_candidates=total_candidates,
        selected_candidates=int(selected_candidates),
        incremental_applied=incremental_applied,
    )
    return edges, status


def _add_undirected_edge(adj: Dict[int, Dict[int, Set[str]]], a: int, b: int, kind: str) -> None:
    if int(a) == int(b):
        return
    adj[int(a)].setdefault(int(b), set()).add(str(kind))
    adj[int(b)].setdefault(int(a), set()).add(str(kind))


def _build_mixed_graph(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    *,
    include_indirect_edges: Dict[int, Set[int]],
) -> Tuple[Dict[int, Dict[int, Set[str]]], Dict[int, List[Tuple[int, int]]], Dict[str, Any]]:
    """Build mixed adjacency with edge kinds: call/data/string/global/indirect."""
    adj: Dict[int, Dict[int, Set[str]]] = defaultdict(dict)

    for entry_va, node in graph.nodes.items():
        for callee in node.internal_callee_vas:
            if int(callee) in graph.nodes:
                _add_undirected_edge(adj, int(entry_va), int(callee), "call")

    direct_data = _collect_direct_data_edges(conn, graph)
    for a, nbs in direct_data.items():
        for b in nbs:
            _add_undirected_edge(adj, int(a), int(b), "data")

    global_to_funcs, func_to_globals = _collect_global_ref_map(conn, graph)
    for _gva, funcs in global_to_funcs.items():
        nodes = sorted(funcs)
        if len(nodes) <= 1:
            continue
        if len(nodes) > 24:
            nodes = nodes[:24]
        for i in range(len(nodes)):
            for j in range(i + 1, len(nodes)):
                _add_undirected_edge(adj, nodes[i], nodes[j], "global")

    string_map: Dict[str, List[int]] = defaultdict(list)
    for entry_va, node in graph.nodes.items():
        for s in node.string_refs:
            key = str(s or "").strip().lower()
            if key:
                string_map[key].append(int(entry_va))

    for _s, funcs in string_map.items():
        uniq = sorted(set(funcs))
        if len(uniq) <= 1:
            continue
        if len(uniq) > 20:
            uniq = uniq[:20]
        for i in range(len(uniq)):
            for j in range(i + 1, len(uniq)):
                _add_undirected_edge(adj, uniq[i], uniq[j], "string")

    for a, nbs in include_indirect_edges.items():
        for b in nbs:
            _add_undirected_edge(adj, int(a), int(b), "indirect")

    stats = {
        "call_nodes": len(graph.nodes),
        "direct_data_edge_sources": len(direct_data),
        "global_clusters": len(global_to_funcs),
        "string_clusters": len(string_map),
    }
    return adj, func_to_globals, stats


def _edge_cost(kinds: Set[str], weights: Dict[str, float]) -> float:
    vals: List[float] = []
    for k in kinds:
        vals.append(float(weights.get(k, 1.0)))
    if not vals:
        return 1.0
    return float(min(vals))


def _mixed_neighborhood(
    adj: Dict[int, Dict[int, Set[str]]],
    start_va: int,
    *,
    radius: float,
    weights: Dict[str, float],
) -> Tuple[Set[int], Dict[int, float]]:
    start = int(start_va)
    dist: Dict[int, float] = {start: 0.0}
    pq: List[Tuple[float, int]] = [(0.0, start)]

    while pq:
        cur_d, va = heapq.heappop(pq)
        if cur_d > dist.get(va, float("inf")):
            continue
        if cur_d > float(radius):
            continue
        for nb, kinds in adj.get(va, {}).items():
            step = _edge_cost(kinds, weights)
            nd = cur_d + step
            if nd > float(radius):
                continue
            if nd + 1e-9 < dist.get(nb, float("inf")):
                dist[int(nb)] = float(nd)
                heapq.heappush(pq, (float(nd), int(nb)))

    return set(dist.keys()), dist


def _extract_tokens(text: str) -> Set[str]:
    toks = {m.group(0).lower() for m in TOKEN_RE.finditer(str(text or ""))}
    return {t for t in toks if len(t) >= 3}


def _node_name_tokens(node: UnifiedFunctionNode) -> Set[str]:
    tokens: Set[str] = set()
    for n in node.names:
        tokens.update(_extract_tokens(n))
    return tokens


def _pick_manual_goals(
    graph: UnifiedGraph,
    adjacency: Dict[int, Dict[int, Set[str]]],
    *,
    goal_vas: Sequence[str],
    goal_keywords: Sequence[str],
    goal_structs: Sequence[str],
    goal_limit: int,
) -> List[GoalItem]:
    selected: Dict[int, GoalItem] = {}

    # 地址直指
    for raw in goal_vas:
        token = str(raw or "").strip()
        if not token:
            continue
        try:
            va = int(parse_va(token))
        except Exception:
            continue
        if va not in graph.nodes:
            continue
        node = graph.nodes[va]
        item = GoalItem(
            entry_va=int(va),
            source="manual_va",
            xref_count=len(adjacency.get(int(va), {})),
            richness=_semantic_richness(node, goal_structs),
            manual_score=100,
        )
        selected[int(va)] = item

    # 关键词 / 结构体文本匹配
    tokens = [str(x or "").strip().lower() for x in [*goal_keywords, *goal_structs] if str(x or "").strip()]
    if tokens:
        for va, node in graph.nodes.items():
            blob = _node_text_blob(node).lower()
            score = 0
            hit = False
            for t in tokens:
                if t and t in blob:
                    hit = True
                    score += 10 if t in [s.lower() for s in goal_structs] else 6
            if not hit:
                continue
            old = selected.get(int(va))
            xref_count = len(adjacency.get(int(va), {}))
            richness = _semantic_richness(node, goal_structs)
            item = GoalItem(
                entry_va=int(va),
                source="manual_text",
                xref_count=int(xref_count),
                richness=int(richness),
                manual_score=int(score),
            )
            if old is None:
                selected[int(va)] = item
            else:
                if (item.manual_score, item.xref_count, item.richness) > (old.manual_score, old.xref_count, old.richness):
                    selected[int(va)] = item

    out = sorted(
        selected.values(),
        key=lambda x: (int(x.manual_score), int(x.xref_count), int(x.richness), -int(x.entry_va)),
        reverse=True,
    )
    return out[: max(1, int(goal_limit))]


def _pick_auto_goals(
    graph: UnifiedGraph,
    adjacency: Dict[int, Dict[int, Set[str]]],
    *,
    goal_structs: Sequence[str],
    auto_limit: int,
    goal_limit: int,
) -> List[GoalItem]:
    items: List[GoalItem] = []
    for va, node in graph.nodes.items():
        xref_count = len(adjacency.get(int(va), {}))
        richness = _semantic_richness(node, goal_structs)
        items.append(
            GoalItem(
                entry_va=int(va),
                source="auto",
                xref_count=int(xref_count),
                richness=int(richness),
                manual_score=0,
            )
        )

    candidates = sorted(items, key=lambda x: (int(x.xref_count), int(x.richness), -int(x.entry_va)), reverse=True)
    candidates = candidates[: max(1, int(auto_limit))]
    return candidates[: max(1, int(goal_limit))]


def _best_paths_within(paths: Sequence[Dict[str, Any]], allowed_nodes: Set[int]) -> List[Dict[str, Any]]:
    if not allowed_nodes:
        return list(paths)
    kept: List[Dict[str, Any]] = []
    for p in paths:
        vas = p.get("path_vas", []) or []
        ok = True
        for s in vas:
            try:
                va = int(parse_va(str(s)))
            except Exception:
                ok = False
                break
            if va not in allowed_nodes:
                ok = False
                break
        if ok:
            kept.append(dict(p))
    if kept:
        return kept
    return list(paths)


def _pick_deepest_path(paths: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    best: Optional[Dict[str, Any]] = None
    best_key: Optional[Tuple[int, int, int]] = None
    for p in paths:
        depth = int(p.get("depth", 0) or 0)
        path_len = len(p.get("path_vas", []) or [])
        gate = int(p.get("path_gating_strength", 0) or 0)
        key = (depth, path_len, gate)
        if best is None or key > (best_key or (-1, -1, -1)):
            best = dict(p)
            best_key = key
    return best


def _run_deep_generation(
    *,
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entries: List[int],
    args: argparse.Namespace,
    llm_settings: Any,
    llm_mode: str,
    allowed_nodes: Optional[Set[int]] = None,
    label: str,
    llm_poll_log_file: Optional[str] = None,
    log_raw_llm: bool = False,
) -> Dict[str, Any]:
    if not entries:
        return {"status": "skipped", "reason": "no_entries", "label": label}

    req_depth = int(args.max_depth or 0)
    if req_depth <= 0:
        depth = max(1, int(estimate_global_deepest_depth(graph, only_entry_vas=entries)))
    else:
        depth = req_depth

    result = run_deep_path_analysis(
        conn=conn,
        graph=graph,
        entries=list(entries),
        max_depth=int(depth),
        max_paths=max(1, int(args.max_paths or 1)),
        max_branch=max(1, int(args.max_branch or 1)),
        max_call_sites=max(1, int(args.max_call_sites or 1)),
        cond_window=max(1, int(args.cond_window or 1)),
        max_guards_per_site=max(1, int(args.max_guards_per_site or 1)),
    )

    paths = list(result.get("paths", []) or [])
    if allowed_nodes is not None:
        paths = _best_paths_within(paths, allowed_nodes)

    llm_poll: Optional[Dict[str, Any]] = None
    if llm_mode == "off":
        llm_poll = {"status": "skipped", "reason": "llm_mode_off"}
    elif args.dry_run:
        llm_poll = run_llm_poll_on_deepest_path(
            conn=conn,
            graph=graph,
            paths=paths,
            llm_settings=llm_settings,
            max_attempts=max(1, int(args.llm_max_attempts or 1)),
            code_chars=max(200, int(args.llm_code_chars or 1200)),
            max_steps=max(0, int(args.llm_max_steps or 0)),
            dry_run=True,
            verbose=bool(log_raw_llm),
            log_file=llm_poll_log_file,
        )
    else:
        try:
            llm_poll = run_llm_poll_on_deepest_path(
                conn=conn,
                graph=graph,
                paths=paths,
                llm_settings=llm_settings,
                max_attempts=max(1, int(args.llm_max_attempts or 1)),
                code_chars=max(200, int(args.llm_code_chars or 1200)),
                max_steps=max(0, int(args.llm_max_steps or 0)),
                dry_run=False,
                verbose=bool(log_raw_llm),
                log_file=llm_poll_log_file,
            )
        except Exception as exc:
            if llm_mode == "on":
                raise
            llm_poll = {"status": "skipped", "reason": "llm_failed_auto", "error": str(exc)}

    return {
        "label": label,
        "entries": [f"0x{int(x):08X}" for x in entries],
        "max_depth": int(depth),
        "stats": result.get("stats", {}),
        "paths": paths,
        "llm": llm_poll,
    }


def _pick_anchor_nodes(
    graph: UnifiedGraph,
    *,
    primary_goal: int,
    gen1_paths: Sequence[Dict[str, Any]],
    neighborhood_nodes: Set[int],
    goal_structs: Sequence[str],
) -> List[int]:
    scores: Dict[int, int] = defaultdict(int)

    for p in gen1_paths[:12]:
        for s in p.get("path_vas", []) or []:
            try:
                va = int(parse_va(str(s)))
            except Exception:
                continue
            scores[int(va)] += 5

    for va in neighborhood_nodes:
        node = graph.nodes.get(int(va))
        if not node:
            continue
        scores[int(va)] += _semantic_richness(node, goal_structs)

    scores[int(primary_goal)] += 50
    anchors = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    return [int(va) for va, _ in anchors[:6]]


def _compute_wlca_roots(
    graph: UnifiedGraph,
    anchors: Sequence[int],
    *,
    max_depth: int,
    min_wlca: float,
    frontier_k: int,
    alpha: float,
    beta: float,
    gamma: float,
) -> Dict[str, Any]:
    roots: Set[int] = set()
    details: List[Dict[str, Any]] = []

    for anchor_va in anchors:
        anchor = int(anchor_va)
        anchor_node = graph.nodes.get(anchor)
        if not anchor_node:
            continue

        anchor_tokens = _node_name_tokens(anchor_node)
        q = deque([(anchor, 0)])
        seen: Set[int] = {anchor}
        cand: Dict[int, Dict[str, Any]] = {}

        while q:
            cur, d = q.popleft()
            if d >= int(max_depth):
                continue
            node = graph.nodes.get(int(cur))
            if not node:
                continue
            for parent in node.caller_vas:
                p = int(parent)
                if p in seen:
                    continue
                seen.add(p)
                q.append((p, d + 1))

                pnode = graph.nodes.get(p)
                if not pnode:
                    continue

                overlap = 0.0
                p_tokens = _node_name_tokens(pnode)
                if anchor_tokens and p_tokens:
                    overlap = len(anchor_tokens & p_tokens) / float(len(anchor_tokens | p_tokens))

                indeg = len(pnode.caller_vas)
                weight = math.exp(-float(alpha) * float(d + 1))
                weight *= 1.0 / (1.0 + float(beta) * float(indeg))
                weight *= 1.0 + float(gamma) * float(overlap)

                old = cand.get(p)
                if old is None or float(weight) > float(old.get("weight", -1.0)):
                    cand[p] = {
                        "ancestor": f"0x{p:08X}",
                        "distance": int(d + 1),
                        "indegree": int(indeg),
                        "token_overlap": round(float(overlap), 4),
                        "weight": round(float(weight), 6),
                    }

        if not cand:
            details.append(
                {
                    "anchor": f"0x{anchor:08X}",
                    "mode": "fallback_anchor",
                    "roots": [f"0x{anchor:08X}"],
                    "reason": "no_ancestor_candidates",
                }
            )
            roots.add(anchor)
            continue

        ordered = sorted(cand.values(), key=lambda x: float(x.get("weight", 0.0)), reverse=True)
        best = ordered[0]
        best_w = float(best.get("weight", 0.0))

        if best_w >= float(min_wlca):
            va = int(best["ancestor"], 16)
            roots.add(va)
            details.append(
                {
                    "anchor": f"0x{anchor:08X}",
                    "mode": "wlca",
                    "roots": [best["ancestor"]],
                    "best_weight": round(best_w, 6),
                    "top_candidates": ordered[:5],
                }
            )
        else:
            picks = ordered[: max(1, int(frontier_k))]
            root_list = [str(x["ancestor"]) for x in picks]
            for x in picks:
                roots.add(int(str(x["ancestor"]), 16))
            details.append(
                {
                    "anchor": f"0x{anchor:08X}",
                    "mode": "frontier_multi_root",
                    "roots": root_list,
                    "best_weight": round(best_w, 6),
                    "threshold": float(min_wlca),
                    "top_candidates": ordered[:8],
                }
            )

    return {
        "roots": sorted(int(x) for x in roots if int(x) in graph.nodes),
        "details": details,
    }


def _extract_name_from_signature(signature: str) -> str:
    sig = str(signature or "").strip()
    if not sig:
        return ""
    before = sig.split("(", 1)[0].strip()
    if not before:
        return ""
    toks = before.split()
    if not toks:
        return ""
    return toks[-1].strip("*&")


def _load_backup_profile(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    analysis_info: Dict[int, dict],
    entry_va: int,
) -> Dict[str, Any]:
    va = int(entry_va)
    node = graph.nodes.get(va)
    if not node:
        return {"entry_va": f"0x{va:08X}", "exists": False}

    ida_names = sorted(node.names_by_tool.get("ida", set())) if node.names_by_tool else []
    default_name = ida_names[0] if ida_names else (sorted(node.names)[0] if node.names else f"sub_{va:08X}")

    chosen_info: Optional[dict] = None
    chosen_fid: Optional[int] = None
    ida_fids = [fid for fid in node.function_ids if str(graph.func_tool.get(int(fid), "")).lower() == "ida"]
    if ida_fids:
        for fid in ida_fids:
            info = analysis_info.get(int(fid))
            if info:
                chosen_info = info
                chosen_fid = int(fid)
                break
    if chosen_info is None:
        for fid in sorted(node.function_ids):
            info = analysis_info.get(int(fid))
            if info:
                chosen_info = info
                chosen_fid = int(fid)
                break

    profile = {
        "entry_va": f"0x{va:08X}",
        "name": default_name,
        "function_id": int(chosen_fid) if chosen_fid is not None else None,
        "analysis_state": str((chosen_info or {}).get("analysis_state") or "PENDING"),
        "summary_signature": str((chosen_info or {}).get("summary_signature") or ""),
        "semantic_summary": str((chosen_info or {}).get("semantic_summary") or ""),
        "structured_analysis": str((chosen_info or {}).get("structured_analysis") or ""),
        "confidence_score": int((chosen_info or {}).get("confidence_score") or 0),
        "annotation_status": int((chosen_info or {}).get("annotation_status") or 0),
    }

    # 备份完整行，方便后续真实回填时做回滚。
    if chosen_fid is not None:
        cur = conn.cursor()
        try:
            cur.execute(
                """
                SELECT function_id, analysis_state, confidence_score, summary_signature,
                       semantic_summary, phase1_pending, phase2_pending,
                       lvar_optimized, annotation_status, structured_analysis
                FROM analysis_status
                WHERE function_id = ?;
                """,
                (int(chosen_fid),),
            )
            row = cur.fetchone()
            if row:
                profile["analysis_status_row"] = {
                    "function_id": int(row[0]),
                    "analysis_state": row[1],
                    "confidence_score": int(row[2] or 0),
                    "summary_signature": row[3] or "",
                    "semantic_summary": row[4] or "",
                    "phase1_pending": int(row[5] or 0),
                    "phase2_pending": int(row[6] or 0),
                    "lvar_optimized": int(row[7] or 0),
                    "annotation_status": int(row[8] or 0),
                    "structured_analysis": row[9] or "",
                }
        except Exception:
            pass

    return profile


def _call_llm_with_trace(
    *,
    prompt: str,
    llm_settings: Any,
    max_attempts: int,
    llm_trace_file: Optional[Path],
    trace_label: str,
    trace_meta: Optional[Dict[str, Any]] = None,
    log_raw_llm: bool = False,
) -> Any:
    conversation, request_kwargs = build_chat_request(prompt, llm_settings)
    prompt_text = str(prompt or "")
    prompt_sha = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
    meta = dict(trace_meta or {})

    if llm_trace_file is not None:
        event: Dict[str, Any] = {
            "ts": _now_iso(),
            "stage": str(trace_label),
            "event": "request",
            "meta": meta,
            "model": str(getattr(llm_settings, "model", "")),
            "temperature": getattr(llm_settings, "temperature", None),
            "max_tokens": getattr(llm_settings, "max_tokens", None),
            "max_attempts": int(max(1, int(max_attempts or 1))),
            "prompt_chars": len(prompt_text),
            "prompt_sha256": prompt_sha,
        }
        if log_raw_llm:
            event["prompt"] = prompt_text
            event["conversation"] = conversation
            event["request_kwargs"] = request_kwargs
        else:
            event["request_keys"] = sorted(request_kwargs.keys())
        _append_jsonl(llm_trace_file, event)

    raw_holder: Dict[str, str] = {"raw": ""}

    def _on_raw_text(raw: str) -> None:
        raw_holder["raw"] = str(raw or "")

    result = call_llm_analyze_function(
        conversation=conversation,
        request_kwargs=request_kwargs,
        api_settings=llm_settings.api_settings,
        max_attempts=max(1, int(max_attempts or 1)),
        on_raw_text=_on_raw_text if log_raw_llm else None,
    )

    if llm_trace_file is not None:
        response_event: Dict[str, Any] = {
            "ts": _now_iso(),
            "stage": str(trace_label),
            "event": "response",
            "meta": meta,
            "ok": isinstance(result, dict) and bool(result),
            "result_type": type(result).__name__,
        }
        if log_raw_llm:
            response_event["raw_text"] = raw_holder.get("raw", "")
            response_event["result"] = result
        else:
            if isinstance(result, dict):
                response_event["result_keys"] = sorted(result.keys())
            else:
                response_event["result_preview"] = str(result)[:240]
        _append_jsonl(llm_trace_file, response_event)

    return result


def _analyze_node_semantics_with_llm(
    *,
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    analysis_info: Dict[int, dict],
    entry_va: int,
    llm_settings: Any,
    max_attempts: int,
    dry_run: bool,
    llm_trace_file: Optional[Path] = None,
    log_raw_llm: bool = False,
) -> Dict[str, Any]:
    va = int(entry_va)
    node = graph.nodes.get(va)
    if not node:
        return {"entry_va": f"0x{va:08X}", "status": "missing_node"}

    if dry_run:
        return {"entry_va": f"0x{va:08X}", "status": "dry_run"}

    prompt = build_unified_prompt(
        conn=conn,
        graph=graph,
        node=node,
        analysis_info=analysis_info,
        max_disasm_lines=180,
        max_pseudo_chars_per_tool=3200,
        max_strings=20,
    )
    result = _call_llm_with_trace(
        prompt=prompt,
        llm_settings=llm_settings,
        max_attempts=max_attempts,
        llm_trace_file=llm_trace_file,
        trace_label="analyze_node",
        trace_meta={"entry_va": f"0x{va:08X}"},
        log_raw_llm=bool(log_raw_llm),
    )
    if not isinstance(result, dict) or not result:
        return {"entry_va": f"0x{va:08X}", "status": "llm_failed", "raw": result}

    signature = str(result.get("signature") or "").strip()
    summary = str(result.get("summary") or "").strip()
    confidence = 0.0
    try:
        confidence = float(result.get("confidence", 0.0) or 0.0)
    except Exception:
        confidence = 0.0

    return {
        "entry_va": f"0x{va:08X}",
        "status": "ok",
        "name": _extract_name_from_signature(signature),
        "summary_signature": signature,
        "semantic_summary": summary,
        "structured_analysis": json.dumps(
            {
                "tags": result.get("tags") or [],
                "notes": result.get("notes") or "",
                "libfunction": result.get("libfunction", 0),
            },
            ensure_ascii=False,
        ),
        "confidence_score": int(max(0.0, min(1.0, confidence)) * 100.0),
        "raw": result,
    }


def _llm_compare_profiles(
    *,
    old_profile: Dict[str, Any],
    new_profile: Dict[str, Any],
    llm_settings: Any,
    max_attempts: int,
    dry_run: bool,
    llm_trace_file: Optional[Path] = None,
    log_raw_llm: bool = False,
) -> Dict[str, Any]:
    if dry_run:
        return {
            "status": "dry_run",
            "choose": "old",
            "old_score": 0.0,
            "new_score": 0.0,
            "reason": "dry_run",
        }

    prompt = (
        "你是二进制语义恢复裁决器。请比较同一函数的旧语义与新语义，选择更适合逆向分析的一方。\n"
        "比较时必须综合全部字段：name, summary_signature, semantic_summary, structured_analysis, confidence_score。\n"
        "只返回 JSON："
        "{\"choose\":\"old|new\",\"old_score\":0.0,\"new_score\":0.0,\"reason\":\"...\"}\n\n"
        f"[OLD]\n{json.dumps(old_profile, ensure_ascii=False, indent=2)}\n\n"
        f"[NEW]\n{json.dumps(new_profile, ensure_ascii=False, indent=2)}"
    )
    result = _call_llm_with_trace(
        prompt=prompt,
        llm_settings=llm_settings,
        max_attempts=max_attempts,
        llm_trace_file=llm_trace_file,
        trace_label="compare_profiles",
        trace_meta={"entry_va": str(old_profile.get("entry_va") or "")},
        log_raw_llm=bool(log_raw_llm),
    )
    if not isinstance(result, dict) or not result:
        return {
            "status": "llm_failed",
            "choose": "old",
            "old_score": 0.0,
            "new_score": 0.0,
            "reason": "llm_failed",
            "raw": result,
        }

    choose = str(result.get("choose") or "old").strip().lower()
    if choose not in {"old", "new"}:
        choose = "old"

    def _f(v: Any) -> float:
        try:
            return float(v)
        except Exception:
            return 0.0

    return {
        "status": "ok",
        "choose": choose,
        "old_score": _f(result.get("old_score", 0.0)),
        "new_score": _f(result.get("new_score", 0.0)),
        "reason": str(result.get("reason") or ""),
        "raw": result,
    }


def _select_profile(
    old_profile: Dict[str, Any],
    new_profile: Dict[str, Any],
    compare_result: Dict[str, Any],
    *,
    min_delta: float,
) -> Dict[str, Any]:
    choose = str(compare_result.get("choose") or "old").strip().lower()
    old_score = float(compare_result.get("old_score", 0.0) or 0.0)
    new_score = float(compare_result.get("new_score", 0.0) or 0.0)

    selected = "old"
    if choose == "new" and (new_score - old_score) >= float(min_delta):
        selected = "new"

    selected_profile = dict(new_profile if selected == "new" else old_profile)
    return {
        "selected": selected,
        "selected_profile": selected_profile,
        "old_score": old_score,
        "new_score": new_score,
        "delta": round(new_score - old_score, 6),
        "threshold": float(min_delta),
    }


def _rank_nodes_for_compare(
    graph: UnifiedGraph,
    adjacency: Dict[int, Dict[int, Set[str]]],
    nodes: Iterable[int],
    goal_structs: Sequence[str],
    limit: int,
) -> List[int]:
    scored: List[Tuple[int, int, int]] = []
    for va in set(int(x) for x in nodes if int(x) in graph.nodes):
        node = graph.nodes[int(va)]
        xref = len(adjacency.get(int(va), {}))
        rich = _semantic_richness(node, goal_structs)
        scored.append((int(xref), int(rich), int(va)))
    scored.sort(reverse=True)
    return [int(x[2]) for x in scored[: max(1, int(limit or 1))]]


def _collect_path_nodes(paths: Sequence[Dict[str, Any]]) -> Set[int]:
    out: Set[int] = set()
    for p in paths:
        for s in p.get("path_vas", []) or []:
            try:
                out.add(int(parse_va(str(s))))
            except Exception:
                continue
    return out


def _profile_to_analysis_state(profile: Dict[str, Any]) -> str:
    structured = profile.get("structured_analysis")
    parsed_struct: Dict[str, Any] = {}
    if isinstance(structured, dict):
        parsed_struct = structured
    else:
        raw = str(structured or "").strip()
        if raw:
            try:
                obj = json.loads(raw)
                if isinstance(obj, dict):
                    parsed_struct = obj
            except Exception:
                parsed_struct = {}

    raw_lib = parsed_struct.get("libfunction", 0)
    try:
        is_lib = int(raw_lib) != 0
    except Exception:
        is_lib = bool(raw_lib)

    if is_lib:
        return "LOCKED"

    name = str(profile.get("name") or "").strip()
    signature = str(profile.get("summary_signature") or "").strip()
    if name and signature:
        return "ANALYZED"
    return "PENDING"


def _update_analysis_status_with_fallback(conn: sqlite3.Connection, function_id: int, profile: Dict[str, Any]) -> str:
    fid = int(function_id)
    state = _profile_to_analysis_state(profile)
    try:
        confidence = int(profile.get("confidence_score", 0) or 0)
    except Exception:
        confidence = 0
    confidence = max(0, min(100, int(confidence)))
    signature = str(profile.get("summary_signature") or "")
    summary = str(profile.get("semantic_summary") or "")
    structured = str(profile.get("structured_analysis") or "")

    attempts: List[Tuple[str, str, Tuple[Any, ...]]] = [
        (
            "full",
            """
            UPDATE analysis_status
            SET analysis_state = ?,
                confidence_score = ?,
                summary_signature = ?,
                semantic_summary = ?,
                structured_analysis = ?,
                phase1_pending = 0,
                phase2_pending = 1,
                lvar_optimized = 0,
                annotation_status = 0
            WHERE function_id = ?;
            """,
            (state, confidence, signature, summary, structured, fid),
        ),
        (
            "no_phase_flags",
            """
            UPDATE analysis_status
            SET analysis_state = ?,
                confidence_score = ?,
                summary_signature = ?,
                semantic_summary = ?,
                structured_analysis = ?,
                annotation_status = 0
            WHERE function_id = ?;
            """,
            (state, confidence, signature, summary, structured, fid),
        ),
        (
            "basic",
            """
            UPDATE analysis_status
            SET analysis_state = ?,
                confidence_score = ?,
                summary_signature = ?,
                semantic_summary = ?
            WHERE function_id = ?;
            """,
            (state, confidence, signature, summary, fid),
        ),
    ]

    last_error: Optional[Exception] = None
    for schema_mode, sql, params in attempts:
        try:
            conn.execute(sql, params)
            return schema_mode
        except sqlite3.OperationalError as exc:
            last_error = exc
            continue

    if last_error:
        raise last_error
    raise RuntimeError(f"update analysis_status failed for function_id={fid}")


def _apply_selected_profiles_to_db(
    conn: sqlite3.Connection,
    compare_items: Sequence[Dict[str, Any]],
    *,
    max_rows: int,
    min_confidence: int,
) -> Dict[str, Any]:
    planned: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for item in compare_items:
        entry_va = str(item.get("entry_va") or "")
        old_profile = item.get("old_profile") if isinstance(item.get("old_profile"), dict) else {}
        new_profile = item.get("new_profile") if isinstance(item.get("new_profile"), dict) else {}
        selection = item.get("selection") if isinstance(item.get("selection"), dict) else {}

        selected = str(selection.get("selected") or "old").strip().lower()
        if selected != "new":
            skipped.append({"entry_va": entry_va, "reason": "selected_old"})
            continue

        if str(new_profile.get("status") or "").strip().lower() != "ok":
            skipped.append({"entry_va": entry_va, "reason": "new_profile_not_ok"})
            continue

        selected_profile = selection.get("selected_profile")
        if not isinstance(selected_profile, dict):
            selected_profile = dict(new_profile)

        fid_raw = selected_profile.get("function_id")
        if fid_raw is None:
            fid_raw = old_profile.get("function_id")
        try:
            fid = int(fid_raw)
        except Exception:
            skipped.append({"entry_va": entry_va, "reason": "missing_function_id"})
            continue

        selected_profile = dict(selected_profile)
        selected_profile["function_id"] = int(fid)
        try:
            confidence_score = int(selected_profile.get("confidence_score", 0) or 0)
        except Exception:
            confidence_score = 0
        confidence_score = max(0, min(100, int(confidence_score)))
        if confidence_score < int(min_confidence):
            skipped.append(
                {
                    "entry_va": entry_va,
                    "reason": f"confidence_below_threshold({confidence_score}<{int(min_confidence)})",
                }
            )
            continue

        planned.append(
            {
                "entry_va": entry_va,
                "function_id": int(fid),
                "profile": selected_profile,
            }
        )

    max_rows = max(0, int(max_rows or 0))
    if max_rows > 0 and len(planned) > max_rows:
        for item in planned[max_rows:]:
            skipped.append(
                {
                    "entry_va": str(item.get("entry_va") or ""),
                    "reason": f"apply_max_rows_limit({max_rows})",
                }
            )
        planned = planned[:max_rows]

    if not planned:
        return {
            "enabled": True,
            "status": "skipped",
            "reason": "no_applicable_rows",
            "planned_count": 0,
            "applied_count": 0,
            "skipped_count": len(skipped),
            "applied_items": [],
            "skipped_items": skipped,
        }

    applied: List[Dict[str, Any]] = []
    try:
        conn.execute("BEGIN")
        for item in planned:
            entry_va = str(item.get("entry_va") or "")
            fid = int(item["function_id"])
            profile = item["profile"]
            schema_mode = _update_analysis_status_with_fallback(conn, fid, profile)
            applied.append(
                {
                    "entry_va": entry_va,
                    "function_id": int(fid),
                    "schema_mode": schema_mode,
                    "analysis_state": _profile_to_analysis_state(profile),
                    "confidence_score": int(max(0, min(100, int(profile.get("confidence_score", 0) or 0)))),
                }
            )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        return {
            "enabled": True,
            "status": "failed",
            "reason": "db_write_failed",
            "error": str(exc),
            "planned_count": len(planned),
            "applied_count": 0,
            "skipped_count": len(skipped),
            "applied_items": [],
            "skipped_items": skipped,
        }

    return {
        "enabled": True,
        "status": "applied",
        "reason": "ok",
        "planned_count": len(planned),
        "applied_count": len(applied),
        "skipped_count": len(skipped),
        "applied_items": applied,
        "skipped_items": skipped,
    }


def main() -> int:
    args = _parse_args()

    db_path = resolve_db_path(args.input_path, args.db)
    layout = _build_run_layout(
        db_path=db_path,
        input_path=args.input_path,
        explicit_output=args.output,
        runs_root=args.runs_root,
        run_id=args.run_id,
        resume=bool(args.resume),
    )

    if not bool(args.resume) and layout.run_dir.exists():
        if bool(args.force_resume):
            args.resume = True
        else:
            raise SystemExit(
                f"run 目录已存在: {layout.run_dir}\n"
                "可使用 --resume 继续执行，或改用新的 --run-id。"
            )

    if bool(args.resume) and not layout.run_dir.exists():
        raise SystemExit(f"未找到可恢复 run 目录: {layout.run_dir}")

    layout.run_dir.mkdir(parents=True, exist_ok=True)
    layout.artifacts_dir.mkdir(parents=True, exist_ok=True)
    layout.logs_dir.mkdir(parents=True, exist_ok=True)
    layout.checkpoints_dir.mkdir(parents=True, exist_ok=True)
    layout.reports_dir.mkdir(parents=True, exist_ok=True)

    resume_signature = _build_resume_signature(args, db_path)
    state = _load_checkpoint(layout.checkpoint_file) if (bool(args.resume) or layout.checkpoint_file.exists()) else {}
    if bool(args.resume) and not state:
        raise SystemExit(f"未找到 checkpoint: {layout.checkpoint_file}")

    if state:
        prev_sig = str(state.get("resume_signature") or "")
        if prev_sig and prev_sig != resume_signature and not bool(args.force_resume):
            raise SystemExit("检测到参数变化，拒绝恢复。若确需继续，请加 --force-resume。")
        prev_db = str(state.get("db_path") or "")
        if prev_db and prev_db != str(db_path) and not bool(args.force_resume):
            raise SystemExit("checkpoint 对应的 db_path 与当前不一致，拒绝恢复。")
    else:
        state = {}

    state.setdefault("created_ts", _now_iso())
    state["resume_signature"] = resume_signature
    state["db_path"] = str(db_path)
    state["run_id"] = str(layout.run_id)
    state["sample_tag"] = str(layout.sample_tag)
    state["resume"] = bool(args.resume)
    if bool(args.resume):
        state["resumed_ts"] = _now_iso()

    _write_manifest(
        layout,
        {
            "created_ts": state.get("created_ts"),
            "updated_ts": _now_iso(),
            "run_id": layout.run_id,
            "sample_tag": layout.sample_tag,
            "run_dir": str(layout.run_dir),
            "db_path": str(db_path),
            "resume": bool(args.resume),
            "force_resume": bool(args.force_resume),
            "llm_raw_logging": bool(args.log_raw_llm),
            "checkpoint": str(layout.checkpoint_file),
            "report": str(layout.out_file),
            "args": vars(args),
        },
    )
    _log_event(
        layout,
        "run_start",
        run_id=layout.run_id,
        run_dir=str(layout.run_dir),
        resume=bool(args.resume),
        force_resume=bool(args.force_resume),
        db_path=str(db_path),
    )

    phase7_5_report_file = layout.artifacts_dir / "phase7_5_report.json"
    cached_phase7_5 = state.get("phase7_5")
    phase7_5_report: Dict[str, Any]
    if bool(args.resume) and isinstance(cached_phase7_5, dict) and cached_phase7_5:
        phase7_5_report = dict(cached_phase7_5)
        _log_event(
            layout,
            "phase7_5_loaded_from_checkpoint",
            status=str(phase7_5_report.get("status") or ""),
            report_file=str(phase7_5_report_file),
        )
    else:
        try:
            phase7_5_report = run_phase7_5_strict_align(
                db_path=db_path,
                input_path=args.input_path,
                artifacts_dir=layout.artifacts_dir,
                call_ref_types=sorted(CALL_REF_TYPES),
                mode=str(args.phase7_5_mode),
                ida_dir=args.phase7_5_ida_dir,
                keep_rebuilt_db=bool(args.phase7_5_keep_rebuilt_db),
            )
        except Phase75StrictAlignError as exc:
            phase7_5_report = {
                "enabled": str(args.phase7_5_mode).strip().lower() != "off",
                "mode": str(args.phase7_5_mode),
                "status": "failed",
                "reason": str(exc),
                "db_path": str(db_path),
                "input_path": str(args.input_path or ""),
            }
            _write_json_file(phase7_5_report_file, phase7_5_report)
            state["phase7_5"] = phase7_5_report
            state["phase7_5_report_file"] = str(phase7_5_report_file)
            _checkpoint_stage(layout, state, "phase7_5_failed")
            _log_event(layout, "phase7_5_failed", reason=str(exc))
            raise SystemExit(f"Phase7.5 严格对齐失败: {exc}")

        _write_json_file(phase7_5_report_file, phase7_5_report)
        state["phase7_5"] = phase7_5_report
        state["phase7_5_report_file"] = str(phase7_5_report_file)
        _checkpoint_stage(layout, state, "phase7_5_completed")
        _log_event(
            layout,
            "phase7_5_completed",
            status=str(phase7_5_report.get("status") or ""),
            diff_count=int(phase7_5_report.get("profile_diff_count", 0) or 0),
            report_file=str(phase7_5_report_file),
        )

    weights = {
        "call": float(args.w_call),
        "data": float(args.w_data),
        "string": float(args.w_string),
        "global": float(args.w_global),
        "indirect": float(args.w_data),
    }

    llm_cfg = load_semantics_config(args.llm_config)
    llm_settings = build_llm_settings(
        llm_cfg,
        model=args.llm_model,
        temperature=args.llm_temperature,
        max_tokens=args.llm_max_tokens,
    )

    conn = sqlite3.connect(str(db_path))
    try:
        binary_id = pick_binary_id(conn, args.binary_id)
        prev_binary_id = state.get("binary_id")
        if prev_binary_id is not None and int(prev_binary_id) != int(binary_id) and not bool(args.force_resume):
            raise SystemExit(
                f"checkpoint binary_id={prev_binary_id} 与当前 binary_id={binary_id} 不一致，拒绝恢复。"
            )
        state["binary_id"] = int(binary_id)

        graph = build_unified_graph(
            conn=conn,
            binary_id=int(binary_id),
            include_call_xrefs=True,
            include_string_xrefs=True,
        )
        analysis_info = _load_analysis_info_safe(conn)

        indirect_edges, indirect_status = _collect_indirect_edges(
            conn,
            graph,
            mode=str(args.indirect_edge_mode),
            budget=max(1, int(args.indirect_edge_budget or 1)),
            incremental=bool(args.incremental_indirect),
            incremental_topn=max(1, int(args.incremental_indirect_topn or 1)),
        )

        mixed_adj, _func_to_globals, mixed_stats = _build_mixed_graph(
            conn,
            graph,
            include_indirect_edges=indirect_edges,
        )

        cached_goals = list(state.get("selected_goals", []) or [])
        if cached_goals:
            selected_goals = [_goal_from_dict(x) for x in cached_goals if isinstance(x, dict)]
            goal_mode = str(state.get("goal_mode") or "resume")
            _log_event(layout, "goals_loaded_from_checkpoint", count=len(selected_goals), goal_mode=goal_mode)
        else:
            manual_goals = _pick_manual_goals(
                graph,
                mixed_adj,
                goal_vas=list(args.goal_va or []),
                goal_keywords=list(args.goal_keyword or []),
                goal_structs=list(args.goal_struct or []),
                goal_limit=max(1, int(args.goal_limit or 1)),
            )

            if manual_goals:
                selected_goals = manual_goals
                goal_mode = "manual_priority"
            else:
                selected_goals = _pick_auto_goals(
                    graph,
                    mixed_adj,
                    goal_structs=list(args.goal_struct or []),
                    auto_limit=max(1, int(args.auto_goal_limit or 1)),
                    goal_limit=max(1, int(args.goal_limit or 1)),
                )
                goal_mode = "auto"

            state["goal_mode"] = str(goal_mode)
            state["selected_goals"] = [_goal_to_dict(g) for g in selected_goals]
            _checkpoint_stage(layout, state, "goals_selected")
            _log_event(layout, "goals_selected", count=len(selected_goals), goal_mode=goal_mode)

        if not selected_goals:
            raise SystemExit("未选出任何可分析目标。")

        generation_results: List[Dict[str, Any]] = [
            dict(x) for x in (state.get("generation_results", []) or []) if isinstance(x, dict)
        ]
        gen1_deepest_items: List[Dict[str, Any]] = [
            dict(x) for x in (state.get("gen1_deepest_items", []) or []) if isinstance(x, dict)
        ]
        comparison_candidate_nodes: Set[int] = set(
            int(x) for x in (state.get("comparison_candidate_nodes", []) or []) if x is not None
        )
        completed_goal_indices: Set[int] = set()
        for item in gen1_deepest_items:
            try:
                completed_goal_indices.add(int(item.get("goal_index", 0) or 0))
            except Exception:
                continue

        for idx, goal in enumerate(selected_goals, 1):
            if int(idx) in completed_goal_indices:
                _log_event(layout, "goal_resume_skip", goal_index=int(idx), entry_va=f"0x{int(goal.entry_va):08X}")
                continue

            goal_va = int(goal.entry_va)
            goal_node = graph.nodes.get(goal_va)
            if not goal_node:
                continue

            gen1_nodes, gen1_dist = _mixed_neighborhood(
                mixed_adj,
                start_va=goal_va,
                radius=float(args.lambda_radius),
                weights=weights,
            )

            gen1 = _run_deep_generation(
                conn=conn,
                graph=graph,
                entries=[goal_va],
                args=args,
                llm_settings=llm_settings,
                llm_mode=str(args.llm_mode),
                allowed_nodes=gen1_nodes,
                label=f"goal#{idx}_gen1",
                llm_poll_log_file=str(layout.llm_poll_log_file),
                log_raw_llm=bool(args.log_raw_llm),
            )
            gen1_paths = list(gen1.get("paths", []) or [])
            gen1_deepest = _pick_deepest_path(gen1_paths)
            deepest_item = {
                "goal_index": int(idx),
                "goal_entry_va": f"0x{goal_va:08X}",
                "goal_names": sorted(goal_node.names),
                "has_path": bool(gen1_deepest),
                "deepest_path": gen1_deepest or {},
            }
            gen1_deepest_items.append(deepest_item)

            anchors = _pick_anchor_nodes(
                graph,
                primary_goal=goal_va,
                gen1_paths=gen1_paths,
                neighborhood_nodes=gen1_nodes,
                goal_structs=list(args.goal_struct or []),
            )

            wlca = _compute_wlca_roots(
                graph,
                anchors,
                max_depth=max(1, int(args.gen2_ancestor_depth or 1)),
                min_wlca=float(args.gen2_min_wlca),
                frontier_k=max(1, int(args.gen2_frontier_k or 1)),
                alpha=float(args.gen2_alpha),
                beta=float(args.gen2_beta),
                gamma=float(args.gen2_gamma),
            )
            gen2_roots = list(wlca.get("roots", []) or [])

            gen2_nodes_union: Set[int] = set()
            for r in gen2_roots:
                sub_nodes, _sub_dist = _mixed_neighborhood(
                    mixed_adj,
                    start_va=int(r),
                    radius=float(args.lambda_radius),
                    weights=weights,
                )
                gen2_nodes_union.update(sub_nodes)

            gen2 = _run_deep_generation(
                conn=conn,
                graph=graph,
                entries=[int(x) for x in gen2_roots],
                args=args,
                llm_settings=llm_settings,
                llm_mode=str(args.llm_mode),
                allowed_nodes=gen2_nodes_union if gen2_nodes_union else None,
                label=f"goal#{idx}_gen2",
                llm_poll_log_file=str(layout.llm_poll_log_file),
                log_raw_llm=bool(args.log_raw_llm),
            )

            gen1_path_nodes = _collect_path_nodes(gen1_paths)
            gen2_path_nodes = _collect_path_nodes(list(gen2.get("paths", []) or []))
            comparison_candidate_nodes.update(gen1_path_nodes)
            comparison_candidate_nodes.update(gen2_path_nodes)

            generation_item = {
                "goal_index": int(idx),
                "goal": {
                    "entry_va": f"0x{goal_va:08X}",
                    "names": sorted(goal_node.names),
                    "source": goal.source,
                    "xref_count": int(goal.xref_count),
                    "richness": int(goal.richness),
                    "manual_score": int(goal.manual_score),
                },
                "gen1": {
                    "lambda_nodes": [f"0x{int(x):08X}" for x in sorted(gen1_nodes)],
                    "lambda_dist": {f"0x{int(k):08X}": round(float(v), 4) for k, v in sorted(gen1_dist.items())},
                    "result": gen1,
                },
                "gen2": {
                    "anchors": [f"0x{int(x):08X}" for x in anchors],
                    "wlca": wlca,
                    "lambda_nodes_union": [f"0x{int(x):08X}" for x in sorted(gen2_nodes_union)],
                    "result": gen2,
                },
            }
            generation_results.append(generation_item)
            _write_json_file(layout.artifacts_dir / f"goal_{int(idx):02d}.json", generation_item)
            _write_json_file(layout.artifacts_dir / f"goal_{int(idx):02d}.deepest.json", deepest_item)

            state["generation_results"] = generation_results
            state["gen1_deepest_items"] = gen1_deepest_items
            state["comparison_candidate_nodes"] = sorted(comparison_candidate_nodes)
            _checkpoint_stage(layout, state, f"goal_{int(idx)}_completed")
            _log_event(
                layout,
                "goal_completed",
                goal_index=int(idx),
                entry_va=f"0x{goal_va:08X}",
                gen1_paths=len(gen1_paths),
                gen2_paths=len(list(gen2.get("paths", []) or [])),
            )

        if not comparison_candidate_nodes:
            for g in generation_results:
                g1_paths = (((g.get("gen1") or {}).get("result") or {}).get("paths", []) or [])
                g2_paths = (((g.get("gen2") or {}).get("result") or {}).get("paths", []) or [])
                comparison_candidate_nodes.update(_collect_path_nodes(g1_paths))
                comparison_candidate_nodes.update(_collect_path_nodes(g2_paths))
            state["comparison_candidate_nodes"] = sorted(comparison_candidate_nodes)

        cached_compare_nodes = list(state.get("compare_nodes", []) or [])
        if cached_compare_nodes:
            compare_nodes = [int(x) for x in cached_compare_nodes]
            _log_event(layout, "compare_nodes_loaded_from_checkpoint", count=len(compare_nodes))
        else:
            compare_nodes = _rank_nodes_for_compare(
                graph,
                mixed_adj,
                comparison_candidate_nodes,
                goal_structs=list(args.goal_struct or []),
                limit=max(1, int(args.max_compare_nodes or 1)),
            )
            state["compare_nodes"] = [int(x) for x in compare_nodes]
            _checkpoint_stage(layout, state, "compare_nodes_selected")
            _log_event(layout, "compare_nodes_selected", count=len(compare_nodes))

        backup_profiles: List[Dict[str, Any]] = [
            dict(x) for x in (state.get("backup_profiles", []) or []) if isinstance(x, dict)
        ]
        compare_items: List[Dict[str, Any]] = [
            dict(x) for x in (state.get("compare_items", []) or []) if isinstance(x, dict)
        ]
        selected_profiles: List[Dict[str, Any]] = [
            dict(x) for x in (state.get("selected_profiles", []) or []) if isinstance(x, dict)
        ]

        completed_compare_vas: Set[int] = set()
        for item in compare_items:
            try:
                completed_compare_vas.add(int(parse_va(str(item.get("entry_va") or ""))))
            except Exception:
                continue

        backup_by_va: Dict[int, Dict[str, Any]] = {}
        for item in backup_profiles:
            try:
                va = int(parse_va(str(item.get("entry_va") or "")))
            except Exception:
                continue
            backup_by_va[va] = item

        for va in compare_nodes:
            entry_hex = f"0x{int(va):08X}"
            if int(va) in completed_compare_vas:
                _log_event(layout, "compare_resume_skip", entry_va=entry_hex)
                continue

            old_profile = backup_by_va.get(int(va))
            if old_profile is None:
                old_profile = _load_backup_profile(conn, graph, analysis_info, va)
                backup_profiles.append(old_profile)
                backup_by_va[int(va)] = old_profile

            if str(args.llm_mode) == "off":
                new_profile = {
                    "entry_va": entry_hex,
                    "status": "skipped",
                    "reason": "llm_mode_off",
                }
                compare_result = {
                    "status": "skipped",
                    "choose": "old",
                    "old_score": 0.0,
                    "new_score": 0.0,
                    "reason": "llm_mode_off",
                }
                select_result = _select_profile(
                    old_profile,
                    new_profile,
                    compare_result,
                    min_delta=float(args.compare_min_delta),
                )
            else:
                try:
                    new_profile = _analyze_node_semantics_with_llm(
                        conn=conn,
                        graph=graph,
                        analysis_info=analysis_info,
                        entry_va=int(va),
                        llm_settings=llm_settings,
                        max_attempts=max(1, int(args.llm_max_attempts or 1)),
                        dry_run=bool(args.dry_run),
                        llm_trace_file=layout.llm_trace_file,
                        log_raw_llm=bool(args.log_raw_llm),
                    )
                    state["last_llm_entry_va"] = entry_hex
                    state["last_llm_action"] = "analyze_node"
                    _checkpoint_stage(layout, state, f"llm_analyze_{int(va):08X}")

                    compare_result = _llm_compare_profiles(
                        old_profile=old_profile,
                        new_profile=new_profile,
                        llm_settings=llm_settings,
                        max_attempts=max(1, int(args.llm_max_attempts or 1)),
                        dry_run=bool(args.dry_run),
                        llm_trace_file=layout.llm_trace_file,
                        log_raw_llm=bool(args.log_raw_llm),
                    )
                    state["last_llm_entry_va"] = entry_hex
                    state["last_llm_action"] = "compare_profiles"
                    _checkpoint_stage(layout, state, f"llm_compare_{int(va):08X}")

                    select_result = _select_profile(
                        old_profile,
                        new_profile,
                        compare_result,
                        min_delta=float(args.compare_min_delta),
                    )
                except Exception as exc:
                    if str(args.llm_mode) == "on":
                        raise
                    new_profile = {
                        "entry_va": entry_hex,
                        "status": "llm_failed",
                        "error": str(exc),
                    }
                    compare_result = {
                        "status": "llm_failed",
                        "choose": "old",
                        "old_score": 0.0,
                        "new_score": 0.0,
                        "reason": str(exc),
                    }
                    select_result = _select_profile(
                        old_profile,
                        new_profile,
                        compare_result,
                        min_delta=float(args.compare_min_delta),
                    )

            compare_item = {
                "entry_va": entry_hex,
                "old_profile": old_profile,
                "new_profile": new_profile,
                "llm_compare": compare_result,
                "selection": select_result,
            }
            compare_items.append(compare_item)
            selected_profiles.append(select_result.get("selected_profile", old_profile))
            _write_json_file(layout.artifacts_dir / f"compare_0x{int(va):08X}.json", compare_item)

            state["backup_profiles"] = backup_profiles
            state["compare_items"] = compare_items
            state["selected_profiles"] = selected_profiles
            _checkpoint_stage(layout, state, f"compare_node_{int(va):08X}_completed")
            _log_event(
                layout,
                "compare_node_completed",
                entry_va=entry_hex,
                selected=str(select_result.get("selected") or "old"),
                delta=float(select_result.get("delta", 0.0) or 0.0),
            )

        cached_db_apply = state.get("db_apply")
        if isinstance(cached_db_apply, dict) and bool(state.get("db_apply_done")):
            db_apply = dict(cached_db_apply)
            _log_event(layout, "db_apply_loaded_from_checkpoint", status=str(db_apply.get("status") or ""))
        else:
            if bool(args.apply_db):
                if bool(args.dry_run):
                    db_apply = {
                        "enabled": True,
                        "status": "skipped",
                        "reason": "dry_run",
                        "planned_count": 0,
                        "applied_count": 0,
                        "skipped_count": 0,
                        "applied_items": [],
                        "skipped_items": [],
                    }
                else:
                    db_apply = _apply_selected_profiles_to_db(
                        conn,
                        compare_items,
                        max_rows=max(0, int(args.apply_max_rows or 0)),
                        min_confidence=max(0, min(100, int(args.apply_min_confidence or 0))),
                    )
            else:
                db_apply = {
                    "enabled": False,
                    "status": "skipped",
                    "reason": "apply_db_off",
                    "planned_count": 0,
                    "applied_count": 0,
                    "skipped_count": 0,
                    "applied_items": [],
                    "skipped_items": [],
                }
            state["db_apply"] = db_apply
            state["db_apply_done"] = True
            _checkpoint_stage(layout, state, "db_apply_completed")
            _log_event(
                layout,
                "db_apply_completed",
                status=str(db_apply.get("status") or ""),
                applied=int(db_apply.get("applied_count", 0) or 0),
            )

        selected_goals_for_report: List[Dict[str, Any]] = []
        for g in selected_goals:
            selected_goals_for_report.append(
                {
                    "entry_va": f"0x{int(g.entry_va):08X}",
                    "source": g.source,
                    "xref_count": int(g.xref_count),
                    "richness": int(g.richness),
                    "manual_score": int(g.manual_score),
                }
            )

        report = {
            "run_meta": {
                "ts": _now_iso(),
                "run_id": str(layout.run_id),
                "run_dir": str(layout.run_dir),
                "input_path": str(Path(args.input_path).expanduser().resolve()) if args.input_path else "",
                "db_path": str(db_path),
                "binary_id": int(binary_id),
                "goal_mode": goal_mode,
                "resume": bool(args.resume),
                "checkpoint_file": str(layout.checkpoint_file),
                "journal_file": str(layout.journal_file),
                "llm_poll_log_file": str(layout.llm_poll_log_file),
                "llm_trace_file": str(layout.llm_trace_file),
                "phase7_5_report_file": str(phase7_5_report_file),
            },
            "config": {
                "goal_limit": int(args.goal_limit),
                "auto_goal_limit": int(args.auto_goal_limit),
                "manual_goal_va": list(args.goal_va or []),
                "manual_goal_keyword": list(args.goal_keyword or []),
                "manual_goal_struct": list(args.goal_struct or []),
                "lambda_radius": float(args.lambda_radius),
                "weights": weights,
                "gen2": {
                    "ancestor_depth": int(args.gen2_ancestor_depth),
                    "min_wlca": float(args.gen2_min_wlca),
                    "frontier_k": int(args.gen2_frontier_k),
                    "alpha": float(args.gen2_alpha),
                    "beta": float(args.gen2_beta),
                    "gamma": float(args.gen2_gamma),
                },
                "indirect_edge_mode": str(args.indirect_edge_mode),
                "indirect_edge_budget": int(args.indirect_edge_budget),
                "incremental_indirect": bool(args.incremental_indirect),
                "incremental_indirect_topn": int(args.incremental_indirect_topn),
                "llm_mode": str(args.llm_mode),
                "llm_max_attempts": int(args.llm_max_attempts),
                "log_raw_llm": bool(args.log_raw_llm),
                "dry_run": bool(args.dry_run),
                "compare_min_delta": float(args.compare_min_delta),
                "apply_db": bool(args.apply_db),
                "apply_max_rows": int(args.apply_max_rows),
                "apply_min_confidence": int(args.apply_min_confidence),
                "phase7_5_mode": str(args.phase7_5_mode),
                "phase7_5_ida_dir": str(args.phase7_5_ida_dir or ""),
                "phase7_5_keep_rebuilt_db": bool(args.phase7_5_keep_rebuilt_db),
            },
            "phase7_5": phase7_5_report,
            "mixed_graph_stats": mixed_stats,
            "indirect_edge_status": {
                "enabled": bool(indirect_status.enabled),
                "degraded": bool(indirect_status.degraded),
                "reason": str(indirect_status.reason),
                "total_candidates": int(indirect_status.total_candidates),
                "selected_candidates": int(indirect_status.selected_candidates),
                "incremental_applied": bool(indirect_status.incremental_applied),
            },
            "selected_goals": selected_goals_for_report,
            "generations": generation_results,
            "gen1_deepest_output": str(layout.gen1_deepest_file),
            "function_compare": compare_items,
            "selected_profiles": selected_profiles,
            "db_apply": db_apply,
            "next_option": {
                "question": "是否要进行间接调用边的增量分析？",
                "suggested_command": (
                    f"python {Path(__file__).name} "
                    f"{str(db_path)!r} --db {str(db_path)!r} "
                    "--indirect-edge-mode auto --incremental-indirect"
                ),
            },
        }

        _write_json_file(
            layout.backup_file,
            {
                "ts": _now_iso(),
                "db_path": str(db_path),
                "binary_id": int(binary_id),
                "backup_profiles": backup_profiles,
            },
        )
        _write_json_file(layout.out_file, report)
        _write_json_file(
            layout.gen1_deepest_file,
            {
                "ts": _now_iso(),
                "db_path": str(db_path),
                "binary_id": int(binary_id),
                "source_output": str(layout.out_file),
                "items": gen1_deepest_items,
            },
        )

        state["report_file"] = str(layout.out_file)
        state["backup_file"] = str(layout.backup_file)
        state["gen1_deepest_file"] = str(layout.gen1_deepest_file)
        _checkpoint_stage(layout, state, "completed")
        _log_event(layout, "run_completed", report=str(layout.out_file))

        print(f"[GoalDeep] run_id={layout.run_id}")
        print(f"[GoalDeep] run_dir={layout.run_dir}")
        print(f"[GoalDeep] db={db_path}")
        print(f"[GoalDeep] binary_id={binary_id}")
        print(f"[GoalDeep] goals={len(selected_goals)} compare_nodes={len(compare_nodes)}")
        print(
            f"[GoalDeep] db_apply={db_apply.get('status')} "
            f"applied={int(db_apply.get('applied_count', 0) or 0)} "
            f"planned={int(db_apply.get('planned_count', 0) or 0)}"
        )
        print(f"[GoalDeep] checkpoint={layout.checkpoint_file}")
        print(f"[GoalDeep] journal={layout.journal_file}")
        print(f"[GoalDeep] llm_poll_log={layout.llm_poll_log_file}")
        print(f"[GoalDeep] llm_trace={layout.llm_trace_file}")
        print(f"[GoalDeep] backup={layout.backup_file}")
        print(f"[GoalDeep] output={layout.out_file}")
        print(f"[GoalDeep] gen1_deepest={layout.gen1_deepest_file}")
        print(
            f"[GoalDeep] phase7.5={phase7_5_report.get('status')} "
            f"diffs={int(phase7_5_report.get('profile_diff_count', 0) or 0)} "
            f"report={phase7_5_report_file}"
        )

        if indirect_status.degraded and not indirect_status.incremental_applied:
            print("[GoalDeep] 间接调用边已自动降级。可加 --incremental-indirect 做增量分析。")

    finally:
        conn.close()

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
