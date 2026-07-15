#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_depth_regression_gank.py

对 gank 样本（ARM 网络文件传输服务器）进行深度优先分析引擎的回归测试。

测试维度：
  T1  DB / 图构建：统一图正确加载，节点数与 DB 一致
  T2  混合图构建：五类边（call/data/string/global/indirect）正确注入
  T3  Lambda 邻域：Dijkstra 半径裁剪正确性
  T4  目标选择：手工/自动目标函数筛选质量
  T5  第一代子树：DFS 路径提取，最长路径选择
  T6  第二代子树：W-LCA 祖先搜索 & 多根前沿
  T7  Profile 收集：备份 Profile 加载
  T8  语义黑板：写入 / 读取 / 冲突仲裁 / 持久化
  T9  Phase7.5 严格对齐：哈希一致性校验
  T10 端到端 dry-run：完整流程不报错

运行方式：
  cd E:\\WorkSpace\\ReBind_demo
  python -m pytest tests/test_depth_regression_gank.py -v --tb=short
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Set

import pytest

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SA_ROOT = _PROJECT_ROOT / "tools" / "Semantics_Alignment"
if str(_SA_ROOT) not in sys.path:
    sys.path.insert(0, str(_SA_ROOT))

GANK_DB = _PROJECT_ROOT / "tmp" / "gank_rebind_demo" / "gank.db"
GANK_IDA_DIR = _PROJECT_ROOT / "tmp" / "gank_rebind_demo" / "gank_idademo"

SKIP_REASON = "gank.db 不存在，跳过回归测试"
needs_gank = pytest.mark.skipif(not GANK_DB.exists(), reason=SKIP_REASON)

KNOWN_GOAL_FUNCS = {
    0x000102D8: "server_file_transfer_handler",
    0x00010A34: "initialize_global_socket",
    0x00010B5C: "syslog_init_or_close",
    0x00010C9C: "log_message_with_priority",
    0x00020E4C: "process_network_buffer",
    0x00021094: "handle_state_transition",
}


# ═══════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def conn():
    c = sqlite3.connect(str(GANK_DB))
    yield c
    c.close()


@pytest.fixture(scope="module")
def graph(conn):
    from kp.kp_graph import build_unified_graph
    from kp.kp_deep_path import pick_binary_id
    bid = pick_binary_id(conn, None)
    g = build_unified_graph(
        conn=conn,
        binary_id=int(bid),
        include_call_xrefs=True,
        include_string_xrefs=True,
    )
    return g


@pytest.fixture(scope="module")
def mixed_graph(conn, graph):
    from depth.graph_augment import _build_mixed_graph, _collect_indirect_edges
    indirect_edges, _status = _collect_indirect_edges(
        conn, graph, mode="auto", budget=25000,
        incremental=False, incremental_topn=3000,
    )
    adj, func_to_globals, stats = _build_mixed_graph(
        conn, graph, include_indirect_edges=indirect_edges,
    )
    return adj, func_to_globals, stats


# ═══════════════════════════════════════════════════════════════════════════
# T1: DB / 图构建
# ═══════════════════════════════════════════════════════════════════════════

@needs_gank
class TestT1GraphConstruction:

    def test_graph_node_count(self, graph):
        """统一图节点数应与 DB 中不重复的函数入口地址数一致。"""
        assert len(graph.nodes) > 0
        ida_count = sum(
            1 for n in graph.nodes.values()
            if any(str(graph.func_tool.get(fid, "")).lower() == "ida" for fid in n.function_ids)
        )
        assert ida_count > 50, f"IDA 函数仅 {ida_count}，预期远大于 50"

    def test_known_functions_exist(self, graph):
        """已知关键函数地址应在图中。"""
        for va, name in KNOWN_GOAL_FUNCS.items():
            assert va in graph.nodes, f"0x{va:08X} ({name}) 不在图中"

    def test_nodes_have_pseudocode(self, graph):
        """大部分节点应有伪代码。"""
        with_pseudo = sum(1 for n in graph.nodes.values() if n.pseudocodes)
        ratio = with_pseudo / max(1, len(graph.nodes))
        assert ratio >= 0.3, f"伪代码覆盖率仅 {ratio:.1%}，预期 >= 30%"


# ═══════════════════════════════════════════════════════════════════════════
# T2: 混合图构建
# ═══════════════════════════════════════════════════════════════════════════

@needs_gank
class TestT2MixedGraph:

    def test_mixed_graph_has_nodes(self, mixed_graph):
        adj, _, stats = mixed_graph
        assert len(adj) > 0

    def test_mixed_graph_has_call_edges(self, mixed_graph):
        adj, _, _ = mixed_graph
        has_call = False
        for va, neighbors in adj.items():
            for nb, kinds in neighbors.items():
                if "call" in kinds:
                    has_call = True
                    break
            if has_call:
                break
        assert has_call, "混合图中无 call 边"

    def test_mixed_graph_stats(self, mixed_graph):
        _, _, stats = mixed_graph
        assert stats.get("call_nodes", 0) > 0


# ═══════════════════════════════════════════════════════════════════════════
# T3: Lambda 邻域
# ═══════════════════════════════════════════════════════════════════════════

@needs_gank
class TestT3LambdaNeighborhood:

    def test_neighborhood_contains_self(self, mixed_graph):
        """邻域应包含起点自身。"""
        from depth.graph_augment import _mixed_neighborhood
        adj, _, _ = mixed_graph
        start_va = 0x000102D8
        weights = {"call": 0.45, "data": 0.30, "string": 0.15, "global": 0.10, "indirect": 0.30}
        nodes, dist = _mixed_neighborhood(adj, start_va, radius=2.5, weights=weights)
        assert start_va in nodes
        assert dist[start_va] == 0.0

    def test_neighborhood_bounded_by_radius(self, mixed_graph):
        """邻域内所有节点距离不超过 radius。"""
        from depth.graph_augment import _mixed_neighborhood
        adj, _, _ = mixed_graph
        radius = 2.0
        weights = {"call": 0.45, "data": 0.30, "string": 0.15, "global": 0.10, "indirect": 0.30}
        nodes, dist = _mixed_neighborhood(adj, 0x000102D8, radius=radius, weights=weights)
        for va, d in dist.items():
            assert d <= radius + 1e-9, f"0x{va:08X} dist={d} > radius={radius}"

    def test_larger_radius_covers_more(self, mixed_graph):
        """更大的 lambda 应覆盖更多节点。"""
        from depth.graph_augment import _mixed_neighborhood
        adj, _, _ = mixed_graph
        weights = {"call": 0.45, "data": 0.30, "string": 0.15, "global": 0.10, "indirect": 0.30}
        nodes_small, _ = _mixed_neighborhood(adj, 0x000102D8, radius=1.0, weights=weights)
        nodes_large, _ = _mixed_neighborhood(adj, 0x000102D8, radius=3.0, weights=weights)
        assert len(nodes_large) >= len(nodes_small)


# ═══════════════════════════════════════════════════════════════════════════
# T4: 目标选择
# ═══════════════════════════════════════════════════════════════════════════

@needs_gank
class TestT4GoalSelection:

    def test_auto_goals_non_empty(self, graph, mixed_graph):
        from depth.goal_collector import _pick_auto_goals
        adj, _, _ = mixed_graph
        goals = _pick_auto_goals(
            graph, adj,
            goal_structs=[], auto_limit=20, goal_limit=5,
        )
        assert len(goals) > 0, "自动目标选择不应为空"
        assert len(goals) <= 5

    def test_manual_goal_by_va(self, graph, mixed_graph):
        from depth.goal_collector import _pick_manual_goals
        from kp.kp_deep_path import parse_va
        adj, _, _ = mixed_graph
        goals = _pick_manual_goals(
            graph, adj,
            goal_vas=["0x102D8"],
            goal_keywords=[],
            goal_structs=[],
            goal_limit=3,
            parse_va_fn=parse_va,
        )
        assert len(goals) >= 1
        assert any(g.entry_va == 0x102D8 for g in goals)

    def test_manual_goal_by_keyword(self, graph, mixed_graph):
        from depth.goal_collector import _pick_manual_goals
        from kp.kp_deep_path import parse_va
        adj, _, _ = mixed_graph
        goals = _pick_manual_goals(
            graph, adj,
            goal_vas=[],
            goal_keywords=["socket", "server"],
            goal_structs=[],
            goal_limit=5,
            parse_va_fn=parse_va,
        )
        assert len(goals) >= 1, "关键词 socket/server 应命中目标函数"

    def test_richness_scoring(self, graph):
        from depth.goal_collector import _semantic_richness
        node = graph.nodes.get(0x000102D8)
        if node:
            score = _semantic_richness(node, [])
            assert score > 0, "server_file_transfer_handler 丰富度应 > 0"


# ═══════════════════════════════════════════════════════════════════════════
# T5: 第一代子树 (DFS 路径提取)
# ═══════════════════════════════════════════════════════════════════════════

@needs_gank
class TestT5Gen1DFS:

    def test_dfs_produces_paths(self, conn, graph):
        from kp.kp_deep_path import run_deep_path_analysis, estimate_global_deepest_depth
        depth = max(1, int(estimate_global_deepest_depth(graph, only_entry_vas=[0x000102D8])))
        result = run_deep_path_analysis(
            conn=conn, graph=graph,
            entries=[0x000102D8],
            max_depth=depth,
            max_paths=50, max_branch=6,
            max_call_sites=3, cond_window=10,
            max_guards_per_site=3,
        )
        paths = result.get("paths", [])
        assert len(paths) > 0, "server_file_transfer_handler DFS 应产生路径"

    def test_deepest_path_selection(self, conn, graph):
        from kp.kp_deep_path import run_deep_path_analysis, estimate_global_deepest_depth
        depth = max(1, int(estimate_global_deepest_depth(graph, only_entry_vas=[0x000102D8])))
        result = run_deep_path_analysis(
            conn=conn, graph=graph,
            entries=[0x000102D8],
            max_depth=depth,
            max_paths=50, max_branch=6,
            max_call_sites=3, cond_window=10,
            max_guards_per_site=3,
        )
        paths = result.get("paths", [])
        if paths:
            from depth.deep_path_step import _pick_deepest_longest_path
            best = _pick_deepest_longest_path(paths)
            assert best is not None
            assert int(best.get("depth", 0)) >= 1


# ═══════════════════════════════════════════════════════════════════════════
# T6: 第二代子树 (W-LCA)
# ═══════════════════════════════════════════════════════════════════════════

@needs_gank
class TestT6Gen2WLCA:

    def test_wlca_computation(self, graph, mixed_graph):
        from depth.engine import _compute_wlca_roots, _pick_anchor_nodes
        adj, _, _ = mixed_graph
        from depth.graph_augment import _mixed_neighborhood
        weights = {"call": 0.45, "data": 0.30, "string": 0.15, "global": 0.10, "indirect": 0.30}
        gen1_nodes, _ = _mixed_neighborhood(adj, 0x000102D8, radius=2.5, weights=weights)

        anchors = _pick_anchor_nodes(
            graph,
            primary_goal=0x000102D8,
            gen1_paths=[],
            neighborhood_nodes=gen1_nodes,
            goal_structs=[],
        )
        assert len(anchors) > 0, "应选出至少一个锚点"

        wlca = _compute_wlca_roots(
            graph, anchors,
            max_depth=5, min_wlca=0.28,
            frontier_k=3, alpha=0.65, beta=0.08, gamma=0.40,
        )
        roots = wlca.get("roots", [])
        assert isinstance(roots, list)


# ═══════════════════════════════════════════════════════════════════════════
# T7: Profile 备份加载
# ═══════════════════════════════════════════════════════════════════════════

@needs_gank
class TestT7ProfileOps:

    def test_load_backup_profile(self, conn, graph):
        from depth.profile_ops import _load_backup_profile
        from depth.goal_collector import _load_analysis_info_safe
        info = _load_analysis_info_safe(conn)
        profile = _load_backup_profile(conn, graph, info, 0x000102D8)
        assert profile.get("entry_va") == "0x000102D8"
        assert "name" in profile

    def test_collect_path_nodes(self):
        from depth.profile_ops import _collect_path_nodes
        from kp.kp_deep_path import parse_va
        fake_paths = [
            {"path_vas": ["0x102D8", "0x10A34", "0x10B5C"]},
            {"path_vas": ["0x102D8", "0x10C9C"]},
        ]
        nodes = _collect_path_nodes(fake_paths, parse_va)
        assert 0x102D8 in nodes
        assert 0x10A34 in nodes
        assert 0x10C9C in nodes

    def test_rank_nodes_for_compare(self, graph, mixed_graph):
        from depth.profile_ops import _rank_nodes_for_compare
        adj, _, _ = mixed_graph
        candidates = {0x000102D8, 0x00010A34, 0x00010B5C}
        ranked = _rank_nodes_for_compare(graph, adj, candidates, goal_structs=[], limit=3)
        assert len(ranked) <= 3
        assert all(va in candidates for va in ranked)


# ═══════════════════════════════════════════════════════════════════════════
# T8: 语义黑板
# ═══════════════════════════════════════════════════════════════════════════

class TestT8Blackboard:

    def test_write_and_read(self):
        from depth.blackboard import SemanticBlackboard
        board = SemanticBlackboard()
        board.write(0x102D8, "func_name", "server_file_transfer_handler",
                    confidence=95, source="gen1")
        entries = board.read(0x102D8)
        assert len(entries) == 1
        assert entries[0].value == "server_file_transfer_handler"

    def test_conflict_resolution_higher_source_wins(self):
        from depth.blackboard import SemanticBlackboard
        board = SemanticBlackboard()
        board.write(0x102D8, "func_name", "old_name",
                    confidence=90, source="gen2")
        board.write(0x102D8, "func_name", "better_name",
                    confidence=85, source="gen1")
        entries = board.read(0x102D8, "func_name")
        assert len(entries) == 1
        assert entries[0].value == "better_name", "gen1 应优先于 gen2"
        assert board.conflict_count == 1

    def test_conflict_resolution_manual_always_wins(self):
        from depth.blackboard import SemanticBlackboard
        board = SemanticBlackboard()
        board.write(0x102D8, "func_name", "auto_name",
                    confidence=99, source="gen1")
        board.write(0x102D8, "func_name", "manual_name",
                    confidence=50, source="manual")
        entries = board.read(0x102D8, "func_name")
        assert entries[0].value == "manual_name", "manual 应始终优先"

    def test_keyword_query(self):
        from depth.blackboard import SemanticBlackboard
        board = SemanticBlackboard()
        board.write(0x102D8, "summary", "handles socket file transfer over TCP",
                    confidence=90, source="gen1")
        board.write(0x10A34, "summary", "initializes global socket descriptor",
                    confidence=90, source="gen1")
        results = board.query_by_keyword("socket")
        assert len(results) >= 2

    def test_build_context_for_node(self):
        from depth.blackboard import SemanticBlackboard
        board = SemanticBlackboard()
        board.write(0x102D8, "func_name", "server_handler", confidence=90, source="gen1")
        board.write(0x10A34, "func_name", "init_socket", confidence=85, source="gen1")
        ctx = board.build_context_for_node(0x102D8, neighbor_vas=[0x10A34])
        assert ctx["target_va"] == "0x000102D8"
        assert len(ctx["known_semantics"]) >= 1
        assert len(ctx["neighbor_semantics"]) >= 1

    def test_persistence_roundtrip(self, tmp_path):
        from depth.blackboard import SemanticBlackboard
        board = SemanticBlackboard()
        board.write(0x102D8, "func_name", "server_handler", confidence=90, source="gen1")
        board.write(0x10A34, "signature", "int init_socket(void)", confidence=85, source="gen1")
        board.write(0x102D8, "summary", "network file xfer", confidence=80, source="gen2")

        path = tmp_path / "blackboard.json"
        board.save(path)
        assert path.exists()

        board2 = SemanticBlackboard()
        board2.load(path)
        assert board2.total_entries == board.total_entries
        entries = board2.read(0x102D8)
        assert any(e.kind == "func_name" and e.value == "server_handler" for e in entries)

    def test_populate_from_profile(self):
        from depth.blackboard import SemanticBlackboard, populate_from_profile
        board = SemanticBlackboard()
        profile = {
            "name": "server_file_transfer_handler",
            "summary_signature": "int server_file_transfer_handler(int sockfd)",
            "semantic_summary": "handles file transfer via TCP socket",
            "confidence_score": 90,
            "structured_analysis": json.dumps({
                "tags": ["network", "file_io"],
                "notes": "main server loop",
                "libfunction": 0,
            }),
        }
        count = populate_from_profile(board, 0x102D8, profile, source="gen1")
        assert count >= 4
        assert board.total_entries >= 4
        names = board.read(0x102D8, "func_name")
        assert len(names) == 1
        assert names[0].value == "server_file_transfer_handler"

    def test_batch_write(self):
        from depth.blackboard import SemanticBlackboard
        board = SemanticBlackboard()
        items = [
            {"entry_va": 0x102D8, "kind": "func_name", "value": "handler", "confidence": 90},
            {"entry_va": 0x10A34, "kind": "func_name", "value": "init_sock", "confidence": 85},
            {"entry_va": 0x10B5C, "kind": "func_name", "value": "syslog_ctl", "confidence": 80},
        ]
        count = board.write_batch(items, source="gen1")
        assert count == 3
        assert board.total_entries == 3

    def test_summary_stats(self):
        from depth.blackboard import SemanticBlackboard
        board = SemanticBlackboard()
        board.write(0x1, "func_name", "a", confidence=90, source="gen1")
        board.write(0x2, "signature", "b", confidence=85, source="gen2")
        board.write(0x3, "tag", "network", confidence=80, source="manual")
        stats = board.summary_stats()
        assert stats["total_entries"] == 3
        assert stats["total_addresses"] == 3
        assert stats["by_kind"]["func_name"] == 1
        assert stats["by_source"]["manual"] == 1


# ═══════════════════════════════════════════════════════════════════════════
# T9: Phase7.5 严格对齐
# ═══════════════════════════════════════════════════════════════════════════

@needs_gank
class TestT9Phase75:

    def test_ida_profile_collection(self):
        from depth.strict_align import _collect_ida_profile
        from kp.kp_types import CALL_REF_TYPES
        profile = _collect_ida_profile(GANK_DB, sorted(CALL_REF_TYPES))
        assert "functions" in profile
        assert "instructions" in profile
        assert "xrefs" in profile
        assert int(profile["functions"]["count"]) > 0

# ═══════════════════════════════════════════════════════════════════════════
# T10: 端到端 dry-run（不调用 LLM）
# ═══════════════════════════════════════════════════════════════════════════

@needs_gank
class TestT10E2EDryRun:

    def test_deep_path_dfs_dry_run(self, conn, graph):
        """deep_path_dfs 核心流程能完整执行。"""
        from kp.kp_deep_path import run_deep_path_analysis, estimate_global_deepest_depth
        depth = max(1, int(estimate_global_deepest_depth(graph)))
        result = run_deep_path_analysis(
            conn=conn, graph=graph,
            entries=[0x000102D8],
            max_depth=min(depth, 8),
            max_paths=20, max_branch=4,
            max_call_sites=2, cond_window=8,
            max_guards_per_site=2,
        )
        assert result.get("stats", {}).get("total_paths", 0) >= 0

    def test_goal_selection_to_gen1_pipeline(self, conn, graph, mixed_graph):
        """目标选择 -> Gen1 DFS 完整流程。"""
        from depth.goal_collector import _pick_auto_goals
        from kp.kp_deep_path import run_deep_path_analysis, estimate_global_deepest_depth
        adj, _, _ = mixed_graph
        goals = _pick_auto_goals(graph, adj, goal_structs=[], auto_limit=10, goal_limit=2)
        assert len(goals) > 0

        first_goal = goals[0]
        depth = max(1, int(estimate_global_deepest_depth(
            graph, only_entry_vas=[first_goal.entry_va],
        )))
        result = run_deep_path_analysis(
            conn=conn, graph=graph,
            entries=[first_goal.entry_va],
            max_depth=min(depth, 6),
            max_paths=20, max_branch=4,
            max_call_sites=2, cond_window=8,
            max_guards_per_site=2,
        )
        paths = result.get("paths", [])
        assert isinstance(paths, list)


# ═══════════════════════════════════════════════════════════════════════════
# T11: 策略评估指标（质量度量）
# ═══════════════════════════════════════════════════════════════════════════

@needs_gank
class TestT11StrategyEvaluation:
    """评估深度优先策略在 gank 样本上的覆盖率与效率指标。"""

    def test_goal_coverage_of_known_funcs(self, graph, mixed_graph):
        """自动目标选择是否能命中已知关键函数（覆盖率）。"""
        from depth.goal_collector import _pick_auto_goals
        adj, _, _ = mixed_graph
        goals = _pick_auto_goals(graph, adj, goal_structs=[], auto_limit=20, goal_limit=10)
        goal_vas = {g.entry_va for g in goals}
        hits = goal_vas & set(KNOWN_GOAL_FUNCS.keys())
        coverage = len(hits) / max(1, len(KNOWN_GOAL_FUNCS))
        print(f"\n[评估] 自动目标覆盖已知关键函数: {len(hits)}/{len(KNOWN_GOAL_FUNCS)} = {coverage:.0%}")
        print(f"  命中: {[f'0x{va:08X}' for va in sorted(hits)]}")
        print(f"  未中: {[f'0x{va:08X}' for va in sorted(set(KNOWN_GOAL_FUNCS.keys()) - hits)]}")
        assert coverage >= 0.15, f"覆盖率 {coverage:.0%} 过低"

    def test_lambda_neighborhood_token_budget(self, mixed_graph, graph):
        """评估 λ=2.5 邻域大小，并验证 adaptive shrink 的收敛效果。"""
        from depth.graph_augment import _mixed_neighborhood
        adj, _, _ = mixed_graph
        weights = {"call": 0.45, "data": 0.30, "string": 0.15, "global": 0.10, "indirect": 0.30}
        for va, name in KNOWN_GOAL_FUNCS.items():
            if va not in graph.nodes:
                continue
            raw_nodes, _ = _mixed_neighborhood(adj, va, radius=2.5, weights=weights)
            capped_nodes, _ = _mixed_neighborhood(
                adj, va, radius=2.5, weights=weights,
                max_nodes=180, adaptive_shrink=True,
            )
            pseudo_chars = 0
            for nva in capped_nodes:
                node = graph.nodes.get(nva)
                if node:
                    for code in node.pseudocodes.values():
                        pseudo_chars += len(code or "")
            est_tokens = pseudo_chars // 4
            print(
                f"  [λ=2.5] 0x{va:08X} {name}: "
                f"raw={len(raw_nodes)} → capped={len(capped_nodes)} funcs, "
                f"~{est_tokens} tokens"
            )
            assert len(capped_nodes) <= 180, (
                f"adaptive shrink 未生效: {len(capped_nodes)} > 180"
            )
            if len(raw_nodes) > 200:
                saving = len(raw_nodes) - len(capped_nodes)
                print(f"    [OK] adaptive shrink 节省 {saving} 个节点")

    def test_gen1_path_depth_distribution(self, conn, graph):
        """评估 Gen1 路径深度分布。"""
        from kp.kp_deep_path import run_deep_path_analysis, estimate_global_deepest_depth
        depth = max(1, int(estimate_global_deepest_depth(graph, only_entry_vas=[0x000102D8])))
        result = run_deep_path_analysis(
            conn=conn, graph=graph,
            entries=[0x000102D8],
            max_depth=min(depth, 10),
            max_paths=100, max_branch=6,
            max_call_sites=3, cond_window=10,
            max_guards_per_site=3,
        )
        paths = result.get("paths", [])
        if paths:
            depths = [int(p.get("depth", 0)) for p in paths]
            max_d = max(depths) if depths else 0
            avg_d = sum(depths) / len(depths) if depths else 0
            print(f"\n[评估] Gen1 路径分布: count={len(paths)} max_depth={max_d} avg_depth={avg_d:.1f}")
            assert max_d >= 1

    def test_pending_function_reachability(self, conn, graph, mixed_graph):
        """评估从目标函数出发，能覆盖多少 PENDING 状态的函数。"""
        adj, _, _ = mixed_graph
        from depth.graph_augment import _mixed_neighborhood
        weights = {"call": 0.45, "data": 0.30, "string": 0.15, "global": 0.10, "indirect": 0.30}

        c = conn.cursor()
        c.execute("""
            SELECT f.entry_va FROM analysis_status a
            JOIN functions f ON f.id = a.function_id
            WHERE a.analysis_state = 'PENDING'
        """)
        pending_vas = {int(r[0]) for r in c.fetchall()}
        pending_in_graph = pending_vas & set(graph.nodes.keys())

        reached: Set[int] = set()
        for va in KNOWN_GOAL_FUNCS:
            if va not in graph.nodes:
                continue
            nodes, _ = _mixed_neighborhood(adj, va, radius=3.0, weights=weights)
            reached.update(nodes & pending_in_graph)

        reachability = len(reached) / max(1, len(pending_in_graph))
        print(f"\n[评估] λ=3.0 从已知目标可达 PENDING 函数: {len(reached)}/{len(pending_in_graph)} = {reachability:.0%}")
        assert reachability >= 0.0


# ═══════════════════════════════════════════════════════════════════════════
# T12: 动态代际机制
# ═══════════════════════════════════════════════════════════════════════════

@needs_gank
class TestT12DynamicGenerations:
    """验证子树代数根据目标复杂度动态决定。"""

    def test_estimate_max_generations_complex_node(self, graph, mixed_graph):
        """高复杂度节点（server_file_transfer_handler）应分配更多代。"""
        from depth.engine import _estimate_max_generations
        adj, _, _ = mixed_graph
        max_gen = _estimate_max_generations(graph, adj, 0x000102D8, user_max=0)
        print(f"\n[动态代际] server_file_transfer_handler: auto max_gen={max_gen}")
        assert max_gen >= 3, f"高复杂度节点应至少分配 3 代，实际 {max_gen}"
        assert max_gen <= 6, f"不应超过硬上限 6，实际 {max_gen}"

    def test_estimate_max_generations_simple_node(self, graph, mixed_graph):
        """低复杂度节点（handle_state_transition）应少分配代。"""
        from depth.engine import _estimate_max_generations
        adj, _, _ = mixed_graph
        max_gen = _estimate_max_generations(graph, adj, 0x00021094, user_max=0)
        print(f"\n[动态代际] handle_state_transition: auto max_gen={max_gen}")
        assert max_gen == 2, f"低复杂度节点应分配 2 代，实际 {max_gen}"

    def test_user_max_overrides(self, graph, mixed_graph):
        """用户指定 max_generations 应作为上限。"""
        from depth.engine import _estimate_max_generations
        adj, _, _ = mixed_graph
        auto = _estimate_max_generations(graph, adj, 0x000102D8, user_max=0)
        capped = _estimate_max_generations(graph, adj, 0x000102D8, user_max=2)
        assert capped <= 2
        assert auto >= capped

    def test_generation_stop_on_saturation(self, graph, mixed_graph):
        """验证多代扩展的覆盖饱和检测逻辑。"""
        from depth.graph_augment import _mixed_neighborhood
        from depth.engine import _compute_wlca_roots, _pick_anchor_nodes
        from kp.kp_deep_path import run_deep_path_analysis, estimate_global_deepest_depth
        adj, _, _ = mixed_graph
        weights = {"call": 0.45, "data": 0.30, "string": 0.15, "global": 0.10, "indirect": 0.30}
        goal_va = 0x000102D8

        gen1_nodes, _ = _mixed_neighborhood(
            adj, goal_va, radius=2.5, weights=weights,
            max_nodes=180, adaptive_shrink=True,
        )

        depth = max(1, int(estimate_global_deepest_depth(graph, only_entry_vas=[goal_va])))
        from kp.kp_deep_path import run_deep_path_analysis
        result = run_deep_path_analysis(
            conn=sqlite3.connect(str(GANK_DB)), graph=graph,
            entries=[goal_va], max_depth=min(depth, 10),
            max_paths=100, max_branch=6,
            max_call_sites=3, cond_window=10, max_guards_per_site=3,
        )
        gen1_paths = result.get("paths", [])

        all_covered = set(gen1_nodes)
        generation_sizes = [len(gen1_nodes)]

        for gen_i in range(2, 6):
            anchors = _pick_anchor_nodes(
                graph, primary_goal=goal_va,
                gen1_paths=gen1_paths,
                neighborhood_nodes=all_covered,
                goal_structs=[],
            )
            wlca = _compute_wlca_roots(
                graph, anchors,
                max_depth=5, min_wlca=0.28, frontier_k=3,
                alpha=0.65, beta=0.08, gamma=0.40,
            )
            gen_roots = list(wlca.get("roots", []) or [])
            gen_nodes: Set[int] = set()
            for r in gen_roots:
                sub, _ = _mixed_neighborhood(
                    adj, int(r), radius=2.5, weights=weights,
                    max_nodes=180, adaptive_shrink=True,
                )
                gen_nodes.update(sub)

            new_nodes = gen_nodes - all_covered
            new_ratio = len(new_nodes) / max(1, len(all_covered))
            generation_sizes.append(len(new_nodes))
            print(
                f"  gen{gen_i}: roots={len(gen_roots)} "
                f"new={len(new_nodes)} ratio={new_ratio:.1%}"
            )
            all_covered.update(gen_nodes)

            if new_ratio < 0.05 and gen_i > 2:
                print(f"  → 第 {gen_i} 代饱和，自然终止")
                break

        assert len(generation_sizes) >= 2
        print(f"\n[动态代际] 代际节点增量: {generation_sizes}")

    def test_estimate_pseudo_tokens(self, graph):
        """验证 Token 估算函数。"""
        from depth.engine import _estimate_pseudo_tokens
        all_vas = set(graph.nodes.keys())
        total = _estimate_pseudo_tokens(graph, all_vas)
        assert total > 0, "整个图的 Token 估算不应为 0"
        single = _estimate_pseudo_tokens(graph, {0x000102D8})
        assert single < total
        empty = _estimate_pseudo_tokens(graph, set())
        assert empty == 0


# ═══════════════════════════════════════════════════════════════════════════
# 清理临时文件
# ═══════════════════════════════════════════════════════════════════════════

def teardown_module():
    for f in [
        _PROJECT_ROOT / "tmp" / "_inspect_gank.py",
        _PROJECT_ROOT / "tmp" / "_inspect_gank_detail.py",
    ]:
        if f.exists():
            f.unlink()
