#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pipeline.py — 广度优先 6 步流水线入口。

对齐加载 + Phase1~5 语义传播 + Phase6 IDA 刷新；与深度优先（depth/）工作流分离。
"""

from __future__ import annotations

import sys
from pathlib import Path

# sys.path 设置：SA_ROOT（含 kp 包）和 BREADTH_DIR（含 phases/alignment_loader）
_BREADTH_DIR = Path(__file__).resolve().parent
_SA_ROOT = _BREADTH_DIR.parent
for _p in (_SA_ROOT, _BREADTH_DIR):
    _p_str = str(_p)
    if _p_str not in sys.path:
        sys.path.insert(0, _p_str)

import argparse
import heapq
import json
import logging
import re
import signal
import sqlite3
import subprocess
import time
from typing import Callable, Dict, Iterable, List, Optional, Set

from dynamic_batching import yield_dynamic_batch
from kp.kp_config import get_cfg_bool, get_cfg_int
from kp.kp_ida import IDAService
from kp.kp_llm import estimate_token_usage
from kp.kp_logging import install_stdout_tee, setup_logging
from kp.kp_settings import build_llm_settings, load_semantics_config
from kp.kp_utils import install_print_with_location
from kp.kp_graph import build_unified_graph, hydrate_unified_xrefs_for_nodes
from kp.kp_scoring import compute_unified_scores
from kp.kp_schema import (
    ensure_analysis_rows_for_binary,
    ensure_analysis_schema,
    load_analysis_info,
    load_analysis_info_for_fids,
)
from kp.kp_types import DEFAULT_FUNC_NAME_PATTERN, UnifiedFunctionNode, UnifiedGraph
from kp.kp_unified_prompt import build_unified_batch_prompt, build_unified_prompt
from tqdm import tqdm

from ida_launcher import (
    DEFAULT_IDA_URL,
    default_idat_exe_for_platform,
    coerce_float,
    exit_if_library_init_failed,
    install_ctrl_c_handler,
    launch_idat_server,
    log_indicates_library_failure,
    run_alignment_loader,
    send_ida_save_and_exit,
    wait_for_ida_process_exit,
)
from layout_helpers import derive_tmp_layout, derive_tmp_layout_from_ida_db
from phases.phase1_kp import analyze_one_unified_function as phase1_analyze_one_unified_function
from phases.phase1_kp import analyze_unified_batch as phase1_analyze_unified_batch
from phases.phase2_validation import run_validation_phase as phase2_run_validation_phase
from phases.phase3_globals import run_global_var_phase as phase3_run_global_var_phase
from phases.phase4_lvar import run_local_var_phase as phase4_run_local_var_phase
from phases.phase5_annotation import run_annotation_phase as phase5_run_annotation_phase
from phases.phase6_refresh_ida_demo import run_refresh_ida_demo_phase
from alignment_loader import inspect_sqlite_database


SCRIPT_PATH = Path(__file__).resolve()
TOOLS_DIR = _SA_ROOT          # Semantics_Alignment/ 目录，含 idat_server.py / sync_ida_to_db.py
REPO_ROOT = SCRIPT_PATH.parents[3]


install_print_with_location()

def _pick_single_binary_id(conn: sqlite3.Connection) -> int:
    cur = conn.cursor()
    cur.execute("SELECT id FROM binaries ORDER BY id LIMIT 1;")
    row = cur.fetchone()
    if not row:
        raise RuntimeError("数据库中不存在 binaries 记录，无法确定 binary_id。")
    return int(row[0])


def _configure_sqlite_runtime(conn: sqlite3.Connection, semantics_config: Optional[Dict[str, object]], logger: logging.Logger) -> None:
    """Apply runtime SQLite tuning for long-running local pipelines."""
    enable = get_cfg_bool(semantics_config, ("pipeline", "sqlite_tuning", "enabled"), True)
    if not enable:
        return

    busy_timeout_ms = max(0, get_cfg_int(semantics_config, ("pipeline", "sqlite_tuning", "busy_timeout_ms"), 5000))
    cache_size_kib = max(0, get_cfg_int(semantics_config, ("pipeline", "sqlite_tuning", "cache_size_kib"), 131072))
    use_wal = get_cfg_bool(semantics_config, ("pipeline", "sqlite_tuning", "wal"), True)
    use_temp_store_memory = get_cfg_bool(semantics_config, ("pipeline", "sqlite_tuning", "temp_store_memory"), True)
    use_sync_normal = get_cfg_bool(semantics_config, ("pipeline", "sqlite_tuning", "synchronous_normal"), True)

    try:
        conn.execute(f"PRAGMA busy_timeout = {int(busy_timeout_ms)};")
    except Exception:
        pass
    if use_wal:
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
        except Exception:
            pass
    if use_sync_normal:
        try:
            conn.execute("PRAGMA synchronous = NORMAL;")
        except Exception:
            pass
    if use_temp_store_memory:
        try:
            conn.execute("PRAGMA temp_store = MEMORY;")
        except Exception:
            pass
    if cache_size_kib > 0:
        try:
            # Negative value means KiB for SQLite cache_size.
            conn.execute(f"PRAGMA cache_size = {-int(cache_size_kib)};")
        except Exception:
            pass

    logger.info(
        "[SQLite] tuning applied: wal=%s sync_normal=%s temp_store_memory=%s cache_kib=%d busy_timeout_ms=%d",
        use_wal,
        use_sync_normal,
        use_temp_store_memory,
        cache_size_kib,
        busy_timeout_ms,
    )


def _phase1_pending_nodes(
    graph: UnifiedGraph, analysis_info: Dict[int, dict]
) -> List[UnifiedFunctionNode]:
    """Return Phase1 candidates that still look like default IDA sub_/fun_/loc_ and are not analyzed yet."""
    targets = []
    for entry_va, node in graph.nodes.items():
        if not _node_has_ida_subfunc_candidate(node, graph):
            continue

        # Skip already analyzed/locked unified nodes (fast-path for large DB reruns).
        already_done = False
        for fid in node.function_ids:
            info = analysis_info.get(int(fid)) or {}
            if (info.get("analysis_state") or "PENDING").upper() in ("ANALYZED", "LOCKED"):
                already_done = True
                break
        if already_done:
            continue

        targets.append(node)
    return targets


def _phase1_node_pending(node: UnifiedFunctionNode, analysis_info: Dict[int, dict]) -> bool:
    for fid in node.function_ids:
        info = analysis_info.get(int(fid)) or {}
        if (info.get("analysis_state") or "PENDING").upper() in ("ANALYZED", "LOCKED"):
            return False
    return True


def _phase1_node_has_history(node: UnifiedFunctionNode, analysis_info: Dict[int, dict]) -> bool:
    """Return True if node has prior Phase1 trace in analysis_status.

    用于恢复运行时的总体进度展示（已完成 / 总量）：
    - analysis_state in (ANALYZED, LOCKED) 视为已处理；
    - phase1_pending=1 视为至少进入过 Phase1 队列。
    """
    for fid in node.function_ids:
        info = analysis_info.get(int(fid)) or {}
        state = (info.get("analysis_state") or "PENDING").upper()
        if state in ("ANALYZED", "LOCKED"):
            return True
        try:
            if int(info.get("phase1_pending") or 0) != 0:
                return True
        except Exception:
            pass
    return False


def _node_has_ida_subfunc_candidate(node: UnifiedFunctionNode, graph: UnifiedGraph) -> bool:
    """Only keep nodes backed by IDA's default sub_/fun_/loc_ entries."""
    ida_present = any(graph.func_tool.get(fid, "").lower() == "ida" for fid in node.function_ids)
    if not ida_present:
        return False
    ida_names = node.names_by_tool.get("ida")
    if not ida_names:
        return False
    return any(DEFAULT_FUNC_NAME_PATTERN.fullmatch(name or "") for name in ida_names)


def run_semantic_pipeline(
    *,
    db_path: Path,
    ida_url: str,
    ida_sync: bool,
    semantics_config_path: Optional[str] = None,
    phases: Optional[Iterable[int]] = None,
    phase5_force_all: bool = False,
    dump_txt: Optional[Path] = None,
    dump_xlsx: Optional[Path] = None,
    graph_mode: str = "auto",
    ida_restart_fn: Optional[Callable[[], bool]] = None,
) -> None:
    """Run selected phases in-process (no subprocess) and optionally dump DB snapshots."""

    logger = logging.getLogger(__name__)

    phases_to_run = {1, 2, 3, 4, 5}
    if phases is not None:
        phases_to_run = {int(x) for x in phases if int(x) in (1, 2, 3, 4, 5)}
        if not phases_to_run:
            raise ValueError("phases 为空或无效，允许值为 1..5。")

    # 统一日志输出，便于回溯（沿用 knowledge_propagation 的日志格式）
    setup_logging(TOOLS_DIR / "log.log", input_db=db_path)
    install_stdout_tee(logger)
    logger.info("知识传播管线启动，数据库: %s", db_path)

    semantics_config = load_semantics_config(semantics_config_path)
    llm_settings = build_llm_settings(
        semantics_config,
        model=None,
        temperature=None,
        max_tokens=None,
    )

    ida = IDAService(ida_url, enabled=ida_sync)

    def _ida_health_check_between_phases(phase_just_finished: int) -> None:
        """Phase 间看门狗：检测 IDA 是否存活，尝试重启并恢复同步。"""
        nonlocal ida_sync
        if not ida_sync and not ida.degraded:
            return
        if ida.degraded and ida_restart_fn is not None:
            print(f"[IDA-Watchdog] Phase {phase_just_finished} 结束，IDA 处于离线状态，尝试重启...")
            try:
                restarted = ida_restart_fn()
            except Exception as exc:
                logger.error("[IDA-Watchdog] 重启 IDA 失败: %s", exc)
                restarted = False

            if restarted:
                from kp.kp_ida import wait_for_ida_server
                ok = wait_for_ida_server(ida_url, max_wait_seconds=30.0)
                if ok:
                    ida._record_success()
                    ida_sync = True
                    print("[IDA-Watchdog] IDA 重启成功，后续阶段恢复实时同步。")
                else:
                    print("[IDA-Watchdog] IDA 重启后仍无法连接，继续离线运行。")
            else:
                print("[IDA-Watchdog] IDA 重启未成功，继续离线运行。")
        elif ida.degraded:
            ida.try_recover()
            if not ida.degraded:
                ida_sync = True
                print("[IDA-Watchdog] IDA 自行恢复，后续阶段恢复实时同步。")

    conn = sqlite3.connect(str(db_path))
    try:
        _configure_sqlite_runtime(conn, semantics_config, logger)
        binary_id = _pick_single_binary_id(conn)

        # 若对齐库未正确加载视图，后续建图会失败；这里提前给出更明确的引导。
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM binary_views WHERE binary_id = ?;", (int(binary_id),))
        view_cnt = int(cur.fetchone()[0] or 0)
        if view_cnt <= 0:
            raise RuntimeError(
                "对齐数据库中缺少 binary_views 记录，无法建图。\n"
                f"  binary_id={binary_id}, binary_views.count={view_cnt}\n"
                "通常原因：alignment_loader 未成功加载 Ghidra/IDA 输出目录（例如缺少 *_binaryinfo），或复用了旧 DB。\n"
                "建议：重新运行 alignment_loader（在本脚本中不要使用 --no-align），并确认输出目录包含 *_binaryinfo / *_disassembly / *_pseudocode(或 *_pesudocode)。"
            )

        t0 = time.perf_counter()
        ensure_analysis_schema(conn)
        ensure_analysis_rows_for_binary(conn, binary_id)
        t1 = time.perf_counter()
        logger.info("[Startup] analysis_status init done in %.2fs", t1 - t0)

        mode = (graph_mode or "auto").strip().lower()
        if mode not in {"auto", "full", "calls_only", "structure_only"}:
            raise ValueError(f"graph_mode 无效: {graph_mode}（允许: auto/full/calls_only/structure_only）")

        include_calls = False
        include_strings = False
        if mode == "full":
            include_calls, include_strings = True, True
        elif mode == "calls_only":
            include_calls, include_strings = True, False
        elif mode == "structure_only":
            include_calls, include_strings = False, False
        else:
            # auto: choose minimal upfront work; Phase1 strings/edges can be lazy-hydrated per batch.
            if 2 in phases_to_run:
                include_calls, include_strings = True, False
            else:
                include_calls, include_strings = False, False

        t2 = time.perf_counter()
        unified_graph = build_unified_graph(
            conn,
            binary_id,
            include_call_xrefs=include_calls,
            include_string_xrefs=include_strings,
        )
        t3 = time.perf_counter()
        logger.info(
            "[Startup] graph build done in %.2fs (mode=%s, calls=%s, strings=%s)",
            t3 - t2,
            mode,
            include_calls,
            include_strings,
        )

        # ---------------------
        # Phase 1: Knowledge Propagation (unified analysis)
        # ---------------------
        if 1 in phases_to_run:
            print("[SemanticAlign] Phase 1: Knowledge Propagation")
            processed = 0
            phase1_attempted: Set[int] = set()

            analysis_info = load_analysis_info(conn)
            phase1_targets = [
                node
                for node in _phase1_pending_nodes(unified_graph, analysis_info)
                if int(node.entry_va) not in phase1_attempted
            ]
            phase1_total_targets = len(phase1_targets)
            phase1_done_count = sum(
                1
                for node in unified_graph.nodes.values()
                if (not _phase1_node_pending(node, analysis_info)) and _phase1_node_has_history(node, analysis_info)
            )
            phase1_overall_total = phase1_done_count + phase1_total_targets
            phase1_progress: Optional[tqdm] = None
            if phase1_total_targets:
                preview_cap = max(0, get_cfg_int(semantics_config, ("pipeline", "phase1", "target_preview_max"), 20))
                sorted_targets = sorted(phase1_targets, key=lambda n: n.entry_va)
                if phase1_overall_total > 0:
                    percent = (phase1_done_count / phase1_overall_total) * 100.0
                    print(
                        f"[SemanticAlign] Phase 1 进度恢复："
                        f"{phase1_done_count}/{phase1_overall_total} ({percent:.1f}%)，"
                        f"本轮待处理 {phase1_total_targets} 个函数。"
                    )
                else:
                    print(f"[SemanticAlign] Phase 1 即将重命名 {phase1_total_targets} 个函数。")
                if preview_cap > 0:
                    preview = sorted_targets[:preview_cap]
                    for node in preview:
                        if node.names:
                            name_repr = ", ".join(sorted(node.names))
                        else:
                            name_repr = "(当前无语义命名)"
                        print(f"  - entry_va=0x{int(node.entry_va):08X}, 原始名称={name_repr}")
                    remain = len(sorted_targets) - len(preview)
                    if remain > 0:
                        print(f"  ... 其余 {remain} 个函数已省略（详见 debug 日志）。")
                    logger.debug(
                        "[Phase1] All targets: %s",
                        ", ".join(f"0x{int(n.entry_va):08X}" for n in sorted_targets),
                    )
                phase1_progress = tqdm(
                    total=phase1_overall_total if phase1_overall_total > 0 else phase1_total_targets,
                    initial=phase1_done_count if phase1_overall_total > 0 else 0,
                    desc="[SemanticAlign] Phase 1",
                    unit="func",
                    leave=True,
                )
            else:
                if phase1_overall_total > 0:
                    print(
                        f"[SemanticAlign] Phase 1 当前无需要重命名的函数，"
                        f"累计进度 {phase1_done_count}/{phase1_overall_total} (100.0%)。"
                    )
                else:
                    print("[SemanticAlign] Phase 1 当前无需要重命名的函数。")

            phase1_nodes_by_va: Dict[int, UnifiedFunctionNode] = {int(n.entry_va): n for n in phase1_targets}
            phase1_score_heap: List[tuple[int, int, int]] = []
            phase1_heap_seq = 0
            phase1_latest_seq: Dict[int, int] = {}
            phase1_scores: Dict[int, int] = {}

            class LazyHeap:
                """延迟删除的堆（优化：避免堆中积累过期条目）。"""
                def __init__(self):
                    self.heap: List[tuple[int, int, int]] = []
                    self.entry_va_to_best: Dict[int, tuple[int, int]] = {}  # entry_va -> (score, seq)
                
                def push(self, entry_va: int, score: int, seq: int) -> None:
                    """只保留每个 entry_va 的最新分数。"""
                    if entry_va in self.entry_va_to_best:
                        old_score, old_seq = self.entry_va_to_best[entry_va]
                        if seq <= old_seq:  # 旧序列号，忽略
                            return
                    self.entry_va_to_best[entry_va] = (score, seq)
                    heapq.heappush(self.heap, (-score, seq, entry_va))
                
                def pop(self) -> Optional[tuple[int, int, int]]:
                    """弹出时跳过过期条目。"""
                    while self.heap:
                        neg_score, seq, entry_va = heapq.heappop(self.heap)
                        best_score, best_seq = self.entry_va_to_best.get(entry_va, (0, 0))
                        if seq == best_seq:  # 是最新条目
                            del self.entry_va_to_best[entry_va]
                            return (-neg_score, seq, entry_va)
                    return None
                
                def __bool__(self) -> bool:
                    """检查堆是否为空（跳过过期条目）。"""
                    while self.heap:
                        neg_score, seq, entry_va = self.heap[0]
                        best_score, best_seq = self.entry_va_to_best.get(entry_va, (0, 0))
                        if seq == best_seq:
                            return True
                        heapq.heappop(self.heap)  # 移除过期条目
                    return False

            phase1_lazy_heap = LazyHeap()

            def _push_phase1_score(entry_va: int, score: int) -> None:
                nonlocal phase1_heap_seq
                phase1_heap_seq += 1
                phase1_latest_seq[int(entry_va)] = phase1_heap_seq
                phase1_scores[int(entry_va)] = int(score)
                phase1_lazy_heap.push(int(entry_va), int(score), phase1_heap_seq)

            if phase1_nodes_by_va:
                init_scores: Dict[int, int] = {}
                try:
                    init_scores = compute_unified_scores(
                        unified_graph,
                        analysis_info,
                        only_entry_vas=list(phase1_nodes_by_va.keys()),
                    )
                except Exception:
                    init_scores = {}
                for entry_va in phase1_nodes_by_va.keys():
                    _push_phase1_score(int(entry_va), int(init_scores.get(int(entry_va), 0)))

            phase1_recompute_every_batches = max(
                1,
                get_cfg_int(semantics_config, ("pipeline", "phase1", "score_recompute_every_batches"), 8),
            )
            phase1_batch_count = 0
            phase1_scheduler_top_k = max(1, get_cfg_int(semantics_config, ("pipeline", "phase1", "scheduler_top_k"), 50))

            while phase1_lazy_heap:
                requested_nodes: List[UnifiedFunctionNode] = []
                requested_entry_vas: List[int] = []
                while phase1_lazy_heap and len(requested_nodes) < phase1_scheduler_top_k:
                    result = phase1_lazy_heap.pop()
                    if result is None:
                        break
                    score, seq, entry_va = result
                    node = phase1_nodes_by_va.get(int(entry_va))
                    if node is None:
                        continue
                    if int(entry_va) in phase1_attempted:
                        continue
                    if not _phase1_node_pending(node, analysis_info):
                        continue
                    requested_nodes.append(node)
                    requested_entry_vas.append(int(entry_va))

                if not requested_nodes:
                    break

                def _phase1_builder(nodes):
                    # Large-DB fast-path: hydrate xref-derived context only for the current batch.
                    try:
                        hydrate_unified_xrefs_for_nodes(
                            conn,
                            unified_graph,
                            list(nodes),
                            include_strings=True,
                            include_calls=True,
                            max_strings_per_node=20,
                        )
                    except Exception:
                        pass
                    if len(nodes) == 1:
                        return build_unified_prompt(conn, unified_graph, nodes[0], analysis_info)
                    return build_unified_batch_prompt(conn, unified_graph, nodes, analysis_info)

                try:
                    batch = next(
                        yield_dynamic_batch(
                            requested_nodes,
                            prompt_builder=_phase1_builder,
                            max_prompt_tokens=llm_settings.max_tokens,
                            token_estimator=estimate_token_usage,
                            initial_batch_size=len(requested_nodes),
                            min_batch_size=1,
                            item_token_estimator=lambda n: (
                                180
                                + min(int(getattr(n, "instr_count", 0) or 0), 400)
                                + min(len(getattr(n, "internal_callee_vas", set())), 60) * 12
                                + min(len(getattr(n, "external_callee_names", set())), 40) * 8
                                + min(len(getattr(n, "string_refs", set())), 40) * 6
                            ),
                            prompt_overhead_tokens=320,
                        )
                    )
                except StopIteration:
                    break

                selected_nodes = batch.items
                if not selected_nodes:
                    break
                selected_entry_vas = {int(n.entry_va) for n in selected_nodes}
                for entry_va in requested_entry_vas:
                    if entry_va not in selected_entry_vas and entry_va not in phase1_attempted:
                        node = phase1_nodes_by_va.get(int(entry_va))
                        if node and _phase1_node_pending(node, analysis_info):
                            _push_phase1_score(int(entry_va), int(phase1_scores.get(int(entry_va), 0)))

                if len(selected_nodes) > 1:
                    phase1_analyze_unified_batch(
                        conn=conn,
                        graph=unified_graph,
                        nodes=selected_nodes,
                        analysis_info=analysis_info,
                        llm_settings=llm_settings,
                        prompt=batch.prompt,
                        estimated_tokens=batch.estimated_tokens,
                        dry_run=False,
                        ida_sync=ida_sync,
                        ida_url=ida_url,
                    )
                    phase1_attempted.update(int(node.entry_va) for node in selected_nodes)
                    processed += len(selected_nodes)
                    if phase1_progress:
                        phase1_progress.update(len(selected_nodes))

                    updated_fids: Set[int] = set()
                    for n in selected_nodes:
                        updated_fids.update(int(fid) for fid in n.function_ids)
                    analysis_info.update(load_analysis_info_for_fids(conn, updated_fids))
                else:
                    node = selected_nodes[0]
                    phase1_analyze_one_unified_function(
                        conn=conn,
                        graph=unified_graph,
                        entry_va=node.entry_va,
                        analysis_info=analysis_info,
                        llm_settings=llm_settings,
                        dry_run=False,
                        ida_sync=ida_sync,
                        ida_url=ida_url,
                    )
                    phase1_attempted.add(int(node.entry_va))
                    processed += 1
                    if phase1_progress:
                        phase1_progress.update(1)

                    analysis_info.update(load_analysis_info_for_fids(conn, {int(fid) for fid in node.function_ids}))

                # 增量更新：优先刷新“受影响调用者”的分数；每 K 批做一次全量重算兜底。
                impacted_entry_vas: Set[int] = set()
                for node in selected_nodes:
                    impacted_entry_vas.add(int(node.entry_va))
                    for caller_va in getattr(node, "caller_vas", set()):
                        impacted_entry_vas.add(int(caller_va))

                impacted_candidates = [
                    int(va)
                    for va in impacted_entry_vas
                    if int(va) in phase1_nodes_by_va
                    and int(va) not in phase1_attempted
                    and _phase1_node_pending(phase1_nodes_by_va[int(va)], analysis_info)
                ]
                if impacted_candidates:
                    try:
                        # 使用增量评分优化
                        from kp.kp_scoring import compute_unified_scores_incremental
                        changed_vas = {int(node.entry_va) for node in selected_nodes}
                        impacted_scores = compute_unified_scores_incremental(
                            unified_graph,
                            analysis_info,
                            changed_entry_vas=changed_vas,
                            existing_scores=phase1_scores,
                            only_entry_vas=impacted_candidates,
                        )
                    except Exception:
                        # 回退到全量计算
                        impacted_scores = compute_unified_scores(
                            unified_graph,
                            analysis_info,
                            only_entry_vas=impacted_candidates,
                        )
                    for entry_va in impacted_candidates:
                        new_score = int(impacted_scores.get(int(entry_va), phase1_scores.get(int(entry_va), 0)))
                        phase1_scores[int(entry_va)] = new_score
                        _push_phase1_score(int(entry_va), new_score)

                phase1_batch_count += 1
                if phase1_batch_count % phase1_recompute_every_batches == 0:
                    remaining = [
                        int(va)
                        for va, node in phase1_nodes_by_va.items()
                        if int(va) not in phase1_attempted and _phase1_node_pending(node, analysis_info)
                    ]
                    if remaining:
                        try:
                            refreshed_scores = compute_unified_scores(
                                unified_graph,
                                analysis_info,
                                only_entry_vas=remaining,
                            )
                        except Exception:
                            refreshed_scores = {}
                        for entry_va in remaining:
                            _push_phase1_score(int(entry_va), int(refreshed_scores.get(int(entry_va), 0)))

            if phase1_progress:
                phase1_progress.close()
            print(f"[SemanticAlign] Phase 1 完成，处理物理函数数量：{processed}")
        else:
            print("[SemanticAlign] 跳过 Phase 1（未选中）。")

        if 1 in phases_to_run:
            _ida_health_check_between_phases(1)

        # ---------------------
        # Phase 2: Top-down validation
        # ---------------------
        if 2 in phases_to_run:
            print("[SemanticAlign] Phase 2: Validation")
            phase2_run_validation_phase(
                conn=conn,
                graph=unified_graph,
                llm_settings=llm_settings,
                ida_sync=ida_sync,
                ida_url=ida_url,
                dry_run=False,
                batch_size=10,
            )
        else:
            print("[SemanticAlign] 跳过 Phase 2（未选中）。")

        if 2 in phases_to_run:
            _ida_health_check_between_phases(2)

        # ---------------------
        # Phase 3: Globals
        # ---------------------
        if 3 in phases_to_run:
            print("[SemanticAlign] Phase 3: Globals")
            phase3_run_global_var_phase(
                conn=conn,
                graph=unified_graph,
                llm_settings=llm_settings,
                max_globals=None,
                ida_sync=ida_sync,
                ida_url=ida_url,
                dry_run=False,
                batch_size=10,
            )
        else:
            print("[SemanticAlign] 跳过 Phase 3（未选中）。")

        if 3 in phases_to_run:
            _ida_health_check_between_phases(3)

        # ---------------------
        # Phase 4: Local vars
        # ---------------------
        if 4 in phases_to_run:
            print("[SemanticAlign] Phase 4: Local Vars")
            phase4_min_lines = get_cfg_int(
                semantics_config, ("pipeline", "phase4_lvar", "min_pseudo_lines_default"), 6
            )
            phase4_run_local_var_phase(
                conn=conn,
                graph=unified_graph,
                llm_settings=llm_settings,
                ida_sync=ida_sync,
                ida_url=ida_url,
                semantics_config=semantics_config,
                dry_run=False,
                batch_size=3,
                only_sub=False,
                ida_only=ida_sync,
                min_pseudo_lines=int(phase4_min_lines),
                exclude_import_export=True,
            )
        else:
            print("[SemanticAlign] 跳过 Phase 4（未选中）。")

        if 4 in phases_to_run:
            _ida_health_check_between_phases(4)

        phase5_ran = False

        # ---------------------
        # Phase 5: Annotation
        # ---------------------
        if 5 in phases_to_run:
            print("[SemanticAlign] Phase 5: Annotation")
            phase5_min_lines = get_cfg_int(
                semantics_config, ("pipeline", "phase5_annotation", "min_pseudo_lines"), 6
            )
            phase5_run_annotation_phase(
                conn=conn,
                graph=unified_graph,
                llm_settings=llm_settings,
                ida_sync=ida_sync,
                ida_url=ida_url,
                semantics_config=semantics_config,
                dry_run=False,
                batch_size=5,
                min_pseudo_lines=int(phase5_min_lines),
                force_all=bool(phase5_force_all),
            )
            phase5_ran = True
        else:
            print("[SemanticAlign] 跳过 Phase 5（未选中）。")

        if phase5_ran and (dump_txt or dump_xlsx):
            export_txt_path = dump_txt or (
                db_path.with_suffix(".txt") if db_path.suffix else db_path.with_name(db_path.name + ".txt")
            )
            workbook_path = dump_xlsx or (
                db_path.with_suffix(".xlsx") if db_path.suffix else db_path.with_name(db_path.name + ".xlsx")
            )
            print(
                f"[SemanticAlign] Phase 5 完成，正在导出数据库快照 -> txt: {export_txt_path}, xlsx: {workbook_path}"
            )
            inspect_sqlite_database(
                db_path=db_path,
                export_path=export_txt_path,
                workbook_path=workbook_path,
            )

    finally:
        conn.close()

    # 请求 IDA 保存并退出（可选）
    if ida_sync:
        try:
            print(f"[SemanticAlign] 请求 IDA 保存并退出: {ida_url}")
            # 大库保存可能较慢；与 ida_launcher.send_ida_save_and_exit 默认超时对齐
            ida.save_and_exit(timeout=45.0)
        except Exception:
            # 连接中断通常是 IDA 正在关闭，属于预期
            pass


def main(argv: Optional[Iterable[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="一键执行 alignment_loader + IDA(idat_server) + Phase(默认 1-5，可选仅跑 Phase5) 的语义对齐流水线。",
    )
    parser.add_argument(
        "--db",
        default=None,
        help="SQLite 对齐数据库路径（默认: 在样本目录下生成 {sample_name}.db，例如 tmp/Malware_sample.exe.db）",
    )
    parser.add_argument(
        "--ghidra-dir",
        default=None,
        help="Ghidra 输出目录（默认: 基于 --sample 自动生成 tmp/<sample>_ghidemo）",
    )
    parser.add_argument(
        "--ida-dir",
        default=None,
        help="IDA 输出目录（默认: 基于 --sample 自动生成 tmp/<sample>_idademo）",
    )
    parser.add_argument(
        "--sample",
        required=False,
        help="待分析二进制样本路径（Phase1-5 必填；Phase6-only 可省略并改用 --phase6-ida-db）。",
    )
    parser.add_argument(
        "--config",
        default=None,
        help=(
            "配置文件路径（默认: 仓库根目录 config.yaml，读取其中 semantics + platforms）"
        ),
    )
    parser.add_argument(
        "--idat-exe",
        default=None,
        help="IDA 命令行可执行文件名或完整路径（优先级：命令行 > config.yaml(runtime.idat_exe) > 平台默认值）。",
    )
    parser.add_argument(
        "--ida-script",
        default=None,
        help="在 IDA 中运行的 idat_server.py 脚本路径（优先级：命令行 > config.yaml(runtime.ida_script) > 默认值）。",
    )
    parser.add_argument(
        "--ida-url",
        default=None,
        help=f"连接的 IDA HTTP 服务地址（优先级：命令行 > config.yaml(runtime.ida_url) > 默认值：{DEFAULT_IDA_URL}）。",
    )
    parser.add_argument(
        "--no-align",
        action="store_true",
        default=None,
        help="跳过 alignment_loader 阶段，仅执行 IDA + 语义阶段（默认 Phase1-5；可配合 --phase5-only）。",
    )
    parser.add_argument(
        "--no-ida",
        action="store_true",
        default=None,
        help="不启动 IDA / idat_server，仅离线运行语义阶段（默认 Phase1-5；可配合 --phase5-only；不会做 IDA 同步）。",
    )
    parser.add_argument(
        "--phase5-only",
        action="store_true",
        help="仅运行 Phase 5（逐行注释注入），跳过 Phase 1-4。",
    )
    # Backward-compatible phase selector flags (alias to --phases).
    parser.add_argument(
        "--phase-1",
        "--phase1",
        dest="phase_1",
        action="store_true",
        help="兼容参数：仅选择 Phase 1（等价于 --phases 1；可与其它 --phase-* 组合）。",
    )
    parser.add_argument(
        "--phase-2",
        "--phase2",
        dest="phase_2",
        action="store_true",
        help="兼容参数：仅选择 Phase 2（等价于 --phases 2；可与其它 --phase-* 组合）。",
    )
    parser.add_argument(
        "--phase-3",
        "--phase3",
        dest="phase_3",
        action="store_true",
        help="兼容参数：仅选择 Phase 3（等价于 --phases 3；可与其它 --phase-* 组合）。",
    )
    parser.add_argument(
        "--phase-4",
        "--phase4",
        dest="phase_4",
        action="store_true",
        help="兼容参数：仅选择 Phase 4（等价于 --phases 4；可与其它 --phase-* 组合）。",
    )
    parser.add_argument(
        "--phase-5",
        "--phase5",
        dest="phase_5",
        action="store_true",
        help="兼容参数：仅选择 Phase 5（等价于 --phases 5；可与其它 --phase-* 组合）。",
    )
    parser.add_argument(
        "--phase-6",
        "--phase6",
        dest="phase_6",
        action="store_true",
        help="兼容参数：仅选择 Phase 6（等价于 --phases 6；可与其它 --phase-* 组合）。",
    )
    parser.add_argument(
        "--phases",
        nargs="+",
        type=int,
        default=None,
        help="仅运行指定 Phase（允许 1..6，例如 --phases 1 2 6）。优先级高于 --phase5-only。",
    )
    parser.add_argument(
        "--graph-mode",
        choices=["auto", "full", "calls_only", "structure_only"],
        default=None,
        help=(
            "建图模式：auto 根据所选 Phase 做最小化建图；full 全量（含 strings+call xrefs）；"
            "calls_only 仅构建调用边；structure_only 仅合并函数/伪代码/指令计数（更快，Phase1 将按批次惰性补全上下文）。"
        ),
    )
    parser.add_argument(
        "--phase5-only-force-all",
        action="store_true",
        help="Phase5-only 进阶：忽略“是否已注释”状态，强制对所有可用伪代码的物理函数跑一次 Phase 5（不改变 min_pseudo_lines 过滤）。",
    )
    parser.add_argument(
        "--phase6-ida-db",
        default=None,
        help="Phase 6: 指定 IDA 数据库(.i64/.idb)路径；不传 --sample 时此参数必填。",
    )
    parser.add_argument(
        "--phase6-no-clean",
        action="store_true",
        help="Phase 6: 不清理现有 *_binaryinfo/_disassembly/_pesudocode 目录。",
    )
    parser.add_argument(
        "--phase6-skip-pseudocode",
        action="store_true",
        help="Phase 6: 跳过 ExtractPseudocode_IDA.py，仅刷新 binaryinfo/disassembly。",
    )
    parser.add_argument(
        "--dump-db-only",
        action="store_true",
        help="仅根据现有数据库导出 TXT/XLSX 快照（跳过 alignment_loader、IDA、Phase 流程）。",
    )
    parser.add_argument(
        "--sync-ida-before-dump",
        action="store_true",
        help="导出前先从 IDA 同步函数名到 DB（需配合 --dump-db-only 使用，会启动 IDA）。",
    )
    parser.add_argument(
        "--unlock-locked-on-sync",
        action="store_true",
        help="同步 IDA 时解锁所有 LOCKED 状态（配合 --sync-ida-before-dump 使用）。",
    )
    parser.add_argument(
        "--ida-start-delay",
        type=float,
        default=None,
        help="启动 idat 后在本地等待的秒数，再启动语义阶段（默认 3 秒）。",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    selected_phases: Optional[List[int]] = None
    if args.phases:
        selected_phases = [int(x) for x in args.phases]
        invalid = [p for p in selected_phases if p not in (1, 2, 3, 4, 5, 6)]
        if invalid:
            raise SystemExit(
                f"[SemanticAlign] --phases 包含无效值: {invalid}（允许 1..6）。"
            )
    elif any(getattr(args, f"phase_{i}", False) for i in (1, 2, 3, 4, 5, 6)):
        selected_phases = [i for i in (1, 2, 3, 4, 5, 6) if getattr(args, f"phase_{i}", False)]
    elif args.phase5_only or args.phase5_only_force_all:
        selected_phases = [5]

    if args.phase5_only_force_all and (not selected_phases or 5 not in selected_phases):
        raise SystemExit("[SemanticAlign] --phase5-only-force-all 仅在包含 Phase 5 时有效（例如 --phase5-only 或 --phases 5）。")

    if args.phase5_only_force_all and selected_phases and 5 in selected_phases and selected_phases != [5]:
        print("[SemanticAlign] 注意：--phase5-only-force-all 与 --phases 同时使用时，仅对 Phase 5 生效。")
    if selected_phases == [5] and args.phase5_only_force_all:
        print("[SemanticAlign] 仅运行 Phase 5（--phase5-only-force-all），并强制覆盖候选集。")
    elif selected_phases == [5] and args.phase5_only:
        print("[SemanticAlign] 仅运行 Phase 5（--phase5-only），跳过 Phase 1-4。")
    elif selected_phases == [6]:
        print("[SemanticAlign] 仅运行 Phase 6（刷新 IDA 输出目录），跳过 Phase 1-5。")

    phase6_selected = bool(selected_phases and 6 in selected_phases)
    phases_for_pipeline: Optional[List[int]]
    if selected_phases is None:
        phases_for_pipeline = None
    else:
        phases_for_pipeline = [p for p in selected_phases if p in (1, 2, 3, 4, 5)]
    needs_pipeline = (phases_for_pipeline is None) or bool(phases_for_pipeline)
    phase6_db_arg = Path(args.phase6_ida_db).expanduser().resolve() if args.phase6_ida_db else None

    sample_path: Optional[Path] = None
    if args.sample:
        sample_path = Path(args.sample).expanduser().resolve()
    elif needs_pipeline or args.dump_db_only:
        raise SystemExit("[SemanticAlign] 当前运行模式需要 --sample。")
    elif phase6_selected and phase6_db_arg is None:
        raise SystemExit("[SemanticAlign] Phase6-only 未提供 --sample 时，必须提供 --phase6-ida-db。")

    if sample_path is not None:
        tmp_defaults = derive_tmp_layout(sample_path)
    elif phase6_db_arg is not None:
        tmp_defaults = derive_tmp_layout_from_ida_db(phase6_db_arg)
    else:
        raise SystemExit("[SemanticAlign] 无法推导输出布局，请提供 --sample 或 --phase6-ida-db。")

    semantics_config = load_semantics_config(args.config)
    runtime = semantics_config.get("runtime", {}) if isinstance(semantics_config, dict) else {}
    if not isinstance(runtime, dict):
        runtime = {}

    graph_mode = str(args.graph_mode or runtime.get("graph_mode") or "auto").strip().lower()

    if args.db:
        db_path = Path(args.db).expanduser().resolve()
    else:
        db_path = tmp_defaults["db_path"]

    if args.ghidra_dir:
        ghidra_dir = Path(args.ghidra_dir).expanduser().resolve()
    else:
        ghidra_dir = tmp_defaults["ghidra_dir"]

    if args.ida_dir:
        ida_dir = Path(args.ida_dir).expanduser().resolve()
    else:
        ida_dir = tmp_defaults["ida_dir"]

    dump_txt = tmp_defaults["dump_txt"]
    dump_xlsx = tmp_defaults["dump_xlsx"]

    idat_exe = (
        args.idat_exe
        or runtime.get("idat_exe")
        or default_idat_exe_for_platform()
    )
    ida_url = args.ida_url or runtime.get("ida_url") or DEFAULT_IDA_URL
    ida_start_delay = (
        float(args.ida_start_delay)
        if args.ida_start_delay is not None
        else coerce_float(runtime.get("ida_start_delay"), 3.0)
    )

    ida_script_value = (
        args.ida_script
        or runtime.get("ida_script")
        or str(TOOLS_DIR / "idat_server.py")
    )
    ida_script = Path(str(ida_script_value)).expanduser().resolve()

    no_align = args.no_align if args.no_align is not None else bool(runtime.get("no_align", False))
    no_ida = args.no_ida if args.no_ida is not None else bool(runtime.get("no_ida", False))

    if args.dump_db_only and phase6_selected:
        raise SystemExit("[SemanticAlign] --dump-db-only 不支持 Phase 6，请单独运行 Phase 6。")

    if args.dump_db_only:
        if not db_path.exists():
            raise SystemExit(
                f"[SemanticAlign] --dump-db-only 指定的数据库不存在: {db_path}"
            )
        
        # 可选：从 IDA 同步函数名
        if args.sync_ida_before_dump:
            print("[SemanticAlign] 启动 IDA 以同步函数名到 DB...")
            
            # 启动 IDA
            ida_log = tmp_defaults["ida_log"]
            ida_proc = launch_idat_server(
                idat_exe=idat_exe,
                ida_script=ida_script,
                sample_path=sample_path,
                log_path=ida_log,
            )
            
            if ida_start_delay > 0:
                print(f"[SemanticAlign] 等待 {ida_start_delay:.1f} 秒以便 IDA 启动...")
                time.sleep(float(ida_start_delay))
            
            exit_if_library_init_failed(ida_log, ida_proc)
            
            # 调用同步脚本
            sync_cmd = [
                sys.executable,
                str(TOOLS_DIR / "sync_ida_to_db.py"),
                str(db_path),
                "--ida-url", str(ida_url),
                "--wait",
            ]
            if args.unlock_locked_on_sync:
                sync_cmd.append("--unlock-locked")
            
            print("[SemanticAlign] 同步 IDA 函数名到 DB...")
            result = subprocess.run(sync_cmd, cwd=str(REPO_ROOT))
            if result.returncode != 0:
                print("[SemanticAlign] 同步失败，但继续导出...", file=sys.stderr)
            
            # 请求 IDA 退出
            send_ida_save_and_exit()
            wait_for_ida_process_exit(ida_proc, timeout=30.0)
        
        print(
            f"[SemanticAlign] 导出数据库快照 -> txt: {dump_txt}, xlsx: {dump_xlsx}"
        )
        inspect_sqlite_database(
            db_path=db_path,
            export_path=dump_txt,
            workbook_path=dump_xlsx,
        )
        return

    if not no_align and needs_pipeline:
        run_alignment_loader(
            db_path=db_path,
            ghidra_dir=ghidra_dir,
            ida_dir=ida_dir,
            dump_txt=dump_txt,
            dump_xlsx=dump_xlsx,
            delete_db=True,
        )
    elif not needs_pipeline:
        print("[SemanticAlign] 跳过 alignment_loader 阶段（Phase6-only）。")
    else:
        print("[SemanticAlign] 跳过 alignment_loader 阶段（--no-align）。")

    # 如果不需要 IDA，同步逻辑会关闭，仅离线跑 knowledge_propagation
    if no_ida:
        if phase6_selected:
            raise SystemExit("[SemanticAlign] Phase 6 需要 IDA headless，不能与 --no-ida 同时使用。")
        if needs_pipeline:
            print("[SemanticAlign] 不启动 IDA / idat_server，仅离线运行 Phase1-5（不做 IDA 同步）。")
            run_semantic_pipeline(
                db_path=db_path,
                ida_url=str(ida_url),
                ida_sync=False,
                semantics_config_path=args.config,
                phases=phases_for_pipeline,
                phase5_force_all=bool(args.phase5_only_force_all),
                dump_txt=dump_txt,
                dump_xlsx=dump_xlsx,
                graph_mode=graph_mode,
            )
        else:
            print("[SemanticAlign] 未选择 Phase1-5，且 --no-ida 已启用；无可执行阶段。")
        return

    if needs_pipeline:
        install_ctrl_c_handler(str(ida_url))

        # 启动 IDA(idat) + idat_server
        ida_log = tmp_defaults["ida_log"]
        ida_proc = launch_idat_server(
            idat_exe=idat_exe,
            ida_script=ida_script,
            sample_path=sample_path,
            log_path=ida_log,
        )

        # 给 IDA 一点时间启动（真正的连接检测由各 Phase 内的 wait_for_ida_server 负责）
        if ida_start_delay > 0:
            print(f"[SemanticAlign] 等待 {ida_start_delay:.1f} 秒以便 IDA 启动...")
            time.sleep(float(ida_start_delay))

        exit_if_library_init_failed(ida_log, ida_proc)

        # IDA 重启闭包：看门狗检测到 IDA 崩溃时自动调用
        _ida_proc_ref = [ida_proc]

        def _restart_ida() -> bool:
            """Kill stale IDA (if any) and launch a fresh one. Returns True on success."""
            old = _ida_proc_ref[0]
            if old is not None and old.poll() is None:
                try:
                    old.terminate()
                    old.wait(timeout=5)
                except Exception:
                    try:
                        old.kill()
                    except Exception:
                        pass
            print("[IDA-Watchdog] 正在重新启动 IDA(idat)...")
            try:
                new_proc = launch_idat_server(
                    idat_exe=idat_exe,
                    ida_script=ida_script,
                    sample_path=sample_path,
                    log_path=ida_log,
                )
            except SystemExit as exc:
                print(f"[IDA-Watchdog] IDA 启动失败: {exc}")
                return False
            _ida_proc_ref[0] = new_proc
            if ida_start_delay > 0:
                print(f"[IDA-Watchdog] 等待 {ida_start_delay:.1f}s 以便 IDA 启动...")
                time.sleep(float(ida_start_delay))
            if log_indicates_library_failure(ida_log):
                print("[IDA-Watchdog] IDA 库初始化失败，放弃重启。")
                return False
            return True

        # 运行语义传播 Phase1-5（会在内部与 idat_server 建立连接）
        try:
            run_semantic_pipeline(
                db_path=db_path,
                ida_url=str(ida_url),
                ida_sync=True,
                semantics_config_path=args.config,
                phases=phases_for_pipeline,
                phase5_force_all=bool(args.phase5_only_force_all),
                dump_txt=dump_txt,
                dump_xlsx=dump_xlsx,
                graph_mode=graph_mode,
                ida_restart_fn=_restart_ida,
            )
        except Exception:
            print("[SemanticAlign] 语义流水线异常终止，正在请求 IDA(save_and_exit)...")
            send_ida_save_and_exit()
            wait_for_ida_process_exit(_ida_proc_ref[0], timeout=30.0)
            raise

        # 运行成功后等待 IDA 进程退出
        print("[SemanticAlign] 等待 IDA(idat) 进程退出...")
        wait_for_ida_process_exit(_ida_proc_ref[0])

    # Phase 6: refresh IDA headless outputs from finalized IDA database
    if phase6_selected:
        run_refresh_ida_demo_phase(
            sample_path=sample_path,
            ida_dir=ida_dir,
            idat_exe=str(idat_exe),
            ida_scripts_dir=REPO_ROOT / "tools" / "IDA_Headless_Demo",
            ida_db_path=phase6_db_arg,
            clean_output=not bool(args.phase6_no_clean),
            skip_pseudocode=bool(args.phase6_skip_pseudocode),
        )


    # 若 run_semantic_pipeline 中无异常，则整体成功


if __name__ == "__main__":
    main()
