#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""engine.py — 深度优先分析入口（原 goal_deep_engine）。

目标驱动 + 深度主干 + 代际子树；与广度 6 步流水线（breadth/）并列。
"""

from __future__ import annotations

import sys
from pathlib import Path

_DEPTH_DIR = Path(__file__).resolve().parent
_SA_ROOT = _DEPTH_DIR.parent
if str(_SA_ROOT) not in sys.path:
    sys.path.insert(0, str(_SA_ROOT))

import argparse
import json
import math
import sqlite3
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from kp.kp_deep_path import (
    estimate_global_deepest_depth,
    parse_va,
    pick_binary_id,
    resolve_db_path,
    run_deep_path_analysis,
)
from kp.kp_graph import build_unified_graph
from kp.kp_schema import load_analysis_info
from kp.kp_settings import build_llm_settings, load_semantics_config
from kp.kp_types import CALL_REF_TYPES, UnifiedGraph, UnifiedFunctionNode
from depth.deep_path_step import run_llm_poll_on_deepest_path
from depth.strict_align import Phase75StrictAlignError, run_phase7_5_strict_align
from depth.run_management import (
    RunLayout,
    _safe_stem,
    _build_output_paths,
    _build_gen1_deepest_output_path,
    _now_iso,
    _write_json_file,
    _append_jsonl,
    _build_resume_signature,
    _pick_latest_run_id,
    _build_run_layout,
    _load_checkpoint,
    _save_checkpoint,
    _write_manifest,
    _log_event,
    _checkpoint_stage,
)
from depth.goal_collector import (
    GoalItem,
    _goal_to_dict,
    _goal_from_dict,
    _load_analysis_info_safe,
    _node_text_blob,
    _semantic_richness,
    _extract_tokens,
    _node_name_tokens,
    _pick_manual_goals,
    _pick_auto_goals,
)
from depth.graph_augment import (
    IndirectEdgeStatus,
    _collect_direct_data_edges,
    _collect_global_ref_map,
    _build_name_index,
    _collect_indirect_edges,
    _add_undirected_edge,
    _build_mixed_graph,
    _edge_cost,
    _mixed_neighborhood,
)
from depth.profile_ops import (
    _load_backup_profile,
    _call_llm_with_trace,
    _analyze_node_semantics_with_llm,
    _llm_compare_profiles,
    _select_profile,
    _rank_nodes_for_compare,
    _collect_path_nodes,
    _profile_to_analysis_state,
    _update_analysis_status_with_fallback,
    _apply_selected_profiles_to_db,
)
from depth.blackboard import (
    SemanticBlackboard,
    populate_from_profile,
    populate_from_step_result,
)


DEFAULT_DB_COMPARE_THRESHOLD = 0.1


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
    ap.add_argument(
        "--llm-config",
        default=None,
        help="LLM/流水线 YAML（默认：仓库根目录 config.yaml 的 semantics 段）",
    )
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

    blackboard_file = layout.artifacts_dir / "blackboard.json"
    board = SemanticBlackboard()
    if blackboard_file.exists():
        board.load(blackboard_file)

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
                parse_va_fn=parse_va,
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
                max_nodes=180,
                adaptive_shrink=True,
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
                    max_nodes=180,
                    adaptive_shrink=True,
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

            gen1_path_nodes = _collect_path_nodes(gen1_paths, parse_va)
            gen2_path_nodes = _collect_path_nodes(list(gen2.get("paths", []) or []), parse_va)
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

            gen1_llm = gen1.get("llm") or {}
            if isinstance(gen1_llm, dict):
                for step in gen1_llm.get("steps", []) or []:
                    if isinstance(step, dict) and step.get("status") == "ok":
                        populate_from_step_result(
                            board, step,
                            source="gen1", generation=1, goal_index=int(idx),
                        )
            gen2_llm = gen2.get("llm") or {}
            if isinstance(gen2_llm, dict):
                for step in gen2_llm.get("steps", []) or []:
                    if isinstance(step, dict) and step.get("status") == "ok":
                        populate_from_step_result(
                            board, step,
                            source="gen2", generation=2, goal_index=int(idx),
                        )
            board.save(blackboard_file)

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
                blackboard_entries=board.total_entries,
            )

        if not comparison_candidate_nodes:
            for g in generation_results:
                g1_paths = (((g.get("gen1") or {}).get("result") or {}).get("paths", []) or [])
                g2_paths = (((g.get("gen2") or {}).get("result") or {}).get("paths", []) or [])
                comparison_candidate_nodes.update(_collect_path_nodes(g1_paths, parse_va))
                comparison_candidate_nodes.update(_collect_path_nodes(g2_paths, parse_va))
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
            selected_profile = select_result.get("selected_profile", old_profile)
            selected_profiles.append(selected_profile)
            populate_from_profile(
                board, int(va), selected_profile,
                source=str(select_result.get("selected") or "gen1"),
                generation=1, goal_index=0,
            )
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
            "blackboard": board.summary_stats(),
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

        board.save(blackboard_file)

        state["report_file"] = str(layout.out_file)
        state["backup_file"] = str(layout.backup_file)
        state["gen1_deepest_file"] = str(layout.gen1_deepest_file)
        state["blackboard_file"] = str(blackboard_file)
        _checkpoint_stage(layout, state, "completed")
        _log_event(
            layout, "run_completed",
            report=str(layout.out_file),
            blackboard_entries=board.total_entries,
            blackboard_conflicts=board.conflict_count,
        )

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

        bb_stats = board.summary_stats()
        print(
            f"[GoalDeep] blackboard entries={bb_stats['total_entries']} "
            f"addresses={bb_stats['total_addresses']} "
            f"conflicts={bb_stats['conflict_count']}"
        )
        print(f"[GoalDeep] blackboard_file={blackboard_file}")

        if indirect_status.degraded and not indirect_status.incremental_applied:
            print("[GoalDeep] 间接调用边已自动降级。可加 --incremental-indirect 做增量分析。")

    finally:
        conn.close()

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
