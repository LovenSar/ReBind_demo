"""depth/graph_augment.py

混合调用图构建：从 DB 中收集直接数据边、全局变量引用、间接调用候选，
并将所有边类型合并到带权无向邻接表（混合图）。

从 engine.py 拆分而来，不依赖 LLM 或目标选择逻辑。
"""

from __future__ import annotations

import heapq
import sqlite3
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from kp.kp_types import CALL_REF_TYPES, UnifiedGraph


# ──────────────────────────────────────────────────────────────────────────────
# 数据结构
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class IndirectEdgeStatus:
    """间接边收集结果描述。"""
    enabled: bool
    degraded: bool
    reason: str
    total_candidates: int
    selected_candidates: int
    incremental_applied: bool


# ──────────────────────────────────────────────────────────────────────────────
# 图边收集
# ──────────────────────────────────────────────────────────────────────────────

def _collect_direct_data_edges(conn: sqlite3.Connection, graph: UnifiedGraph) -> Dict[int, Set[int]]:
    """从 xrefs 表中收集非调用类型的直接数据引用边（双向）。"""
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


def _collect_global_ref_map(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
) -> Tuple[Dict[int, Set[int]], Dict[int, List[Tuple[int, int]]]]:
    """收集全局变量引用关系。

    Returns:
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
    """从统一图构建名称 -> entry_va 的小写索引，用于间接调用匹配。"""
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
    """收集 COMPUTED_CALL / IDA_19 类型的间接调用边。"""
    if mode == "off":
        return {}, IndirectEdgeStatus(False, False, "mode_off", 0, 0, False)

    view_ids = sorted(set(graph.function_id_to_view_id.values()))
    if not view_ids:
        return {}, IndirectEdgeStatus(False, False, "no_views", 0, 0, False)

    cur = conn.cursor()
    view_ph = ",".join("?" for _ in view_ids)

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


# ──────────────────────────────────────────────────────────────────────────────
# 混合邻接图构建
# ──────────────────────────────────────────────────────────────────────────────

def _add_undirected_edge(adj: Dict[int, Dict[int, Set[str]]], a: int, b: int, kind: str) -> None:
    """向带权无向邻接表中添加一条边。"""
    if int(a) == int(b):
        return
    adj[int(a)].setdefault(int(b), set()).add(str(kind))
    adj[int(b)].setdefault(int(a), set()).add(str(kind))


def _build_call_only_graph(
    graph: UnifiedGraph,
) -> Tuple[Dict[int, Dict[int, Set[str]]], Dict[int, List[Tuple[int, int]]], Dict[str, Any]]:
    """Build a lightweight graph containing only direct internal call edges.

    This mode is intended for explicitly scoped, call-path-only analysis of
    very large binaries.  It deliberately avoids scanning the full xref and
    instruction tables for data/global/string relationships.
    """
    adj: Dict[int, Dict[int, Set[str]]] = defaultdict(dict)
    for entry_va, node in graph.nodes.items():
        for callee in node.internal_callee_vas:
            if int(callee) in graph.nodes:
                _add_undirected_edge(adj, int(entry_va), int(callee), "call")

    return adj, {}, {
        "call_nodes": len(graph.nodes),
        "direct_data_edge_sources": 0,
        "global_clusters": 0,
        "string_clusters": 0,
        "graph_mode": "call-only",
    }


def _build_mixed_graph(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    *,
    include_indirect_edges: Dict[int, Set[int]],
) -> Tuple[Dict[int, Dict[int, Set[str]]], Dict[int, List[Tuple[int, int]]], Dict[str, Any]]:
    """构建包含 call / data / string / global / indirect 五类边的混合无向图。"""
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
        "graph_mode": "full",
    }
    return adj, func_to_globals, stats


def _edge_cost(kinds: Set[str], weights: Dict[str, float]) -> float:
    """计算一条多类型边的综合代价（取最小权重）。"""
    vals: List[float] = [float(weights.get(k, 1.0)) for k in kinds]
    return float(min(vals)) if vals else 1.0


def _mixed_neighborhood(
    adj: Dict[int, Dict[int, Set[str]]],
    start_va: int,
    *,
    radius: float,
    weights: Dict[str, float],
    max_nodes: int = 0,
    adaptive_shrink: bool = True,
    trace_out: Optional[Dict[str, Any]] = None,
) -> Tuple[Set[int], Dict[int, float]]:
    """用 Dijkstra 在混合图中计算 start_va 的 radius 内邻域。

    Args:
        max_nodes: 邻域节点数硬上限，0 表示不限制。
        adaptive_shrink: 当邻域超过 soft_limit（max_nodes * 0.8）时，
                         自动将剩余扩展的有效半径缩小 40%，避免 Token 爆炸。
    """
    start = int(start_va)
    dist: Dict[int, float] = {start: 0.0}
    pq: List[Tuple[float, int]] = [(0.0, start)]
    effective_radius = float(radius)
    hard_limit = max(0, int(max_nodes))
    soft_limit = int(hard_limit * 0.8) if hard_limit > 0 else 0
    shrunk = False

    while pq:
        if hard_limit > 0 and len(dist) >= hard_limit:
            break

        cur_d, va = heapq.heappop(pq)
        if cur_d > dist.get(va, float("inf")):
            continue
        if cur_d > effective_radius:
            continue

        if adaptive_shrink and soft_limit > 0 and len(dist) >= soft_limit and not shrunk:
            effective_radius = cur_d + (effective_radius - cur_d) * 0.6
            shrunk = True

        for nb, kinds in adj.get(va, {}).items():
            if hard_limit > 0 and len(dist) >= hard_limit:
                break
            step = _edge_cost(kinds, weights)
            nd = cur_d + step
            if nd > effective_radius:
                continue
            if nd + 1e-9 < dist.get(nb, float("inf")):
                dist[int(nb)] = float(nd)
                heapq.heappush(pq, (float(nd), int(nb)))

    if trace_out is not None:
        vals = [float(x) for x in dist.values()]
        trace_out.clear()
        trace_out.update(
            {
                "algorithm": "dijkstra_on_mixed_undirected_graph",
                "description": (
                    "混合图由 call/data/string/global/indirect 五类无向边构成；"
                    "每条边代价为与该边类型集合对应权重中的最小值；"
                    "从起点做最短路扩展，累计距离不超过 radius（及自适应收缩后的有效半径）；"
                    "节点数达到硬上限 max_nodes 时停止。"
                ),
                "start_va_hex": f"0x{int(start):08X}",
                "radius_requested": float(radius),
                "effective_radius_terminal": float(effective_radius),
                "weights_used": {str(k): float(v) for k, v in sorted(weights.items())},
                "max_nodes_hard_cap": int(hard_limit),
                "soft_limit_for_adaptive_shrink": int(soft_limit),
                "adaptive_shrink_applied": bool(shrunk),
                "nodes_in_neighborhood": int(len(dist)),
                "distance_stats": {
                    "min": min(vals) if vals else None,
                    "max": max(vals) if vals else None,
                    "mean": round(sum(vals) / len(vals), 6) if vals else None,
                },
            }
        )

    return set(dist.keys()), dist
