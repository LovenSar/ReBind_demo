"""Phase7 按代可观测性：子树树形 JSON、代级清单路径。

每代独立目录：artifacts/generations/goal_{NN}_gen_{M}/
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set

from kp.kp_types import UnifiedGraph


def _write_json_atomic(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)
        fp.write("\n")
    tmp.replace(path)


def generation_dir(artifacts_dir: Path, goal_index: int, generation_index: int) -> Path:
    """返回单代产物目录：.../artifacts/generations/goal_01_gen_1/"""
    return artifacts_dir / "generations" / f"goal_{int(goal_index):02d}_gen_{int(generation_index)}"


def _node_names(graph: UnifiedGraph, va: int) -> List[str]:
    n = graph.nodes.get(int(va))
    if not n:
        return []
    return sorted(str(x) for x in (n.names or set()) if str(x).strip())


def build_nested_call_tree(
    graph: UnifiedGraph,
    root_va: int,
    allowed_nodes: Set[int],
    *,
    max_depth: int = 64,
) -> Dict[str, Any]:
    """沿 internal call 边从 root 展开嵌套树；环在子节点处以 cycle_ref 标记。"""
    root_va = int(root_va)

    def build(va: int, depth: int, stack: Set[int]) -> Dict[str, Any]:
        va = int(va)
        payload: Dict[str, Any] = {
            "va": f"0x{va:08X}",
            "names": _node_names(graph, va),
        }
        if va in stack:
            payload["cycle_ref"] = True
            return payload
        if depth >= max_depth:
            payload["truncated_depth"] = True
            return payload
        if va not in allowed_nodes:
            payload["outside_lambda"] = True
            return payload
        n = graph.nodes.get(va)
        if not n:
            payload["missing_node"] = True
            return payload
        callees = sorted(int(c) for c in (n.internal_callee_vas or set()) if int(c) in allowed_nodes)
        if not callees:
            return payload
        next_stack = set(stack)
        next_stack.add(va)
        payload["children"] = [build(c, depth + 1, next_stack) for c in callees]
        return payload

    return build(root_va, 0, set())


def build_forest_call_trees(
    graph: UnifiedGraph,
    root_vas: Sequence[int],
    allowed_nodes: Set[int],
    *,
    max_depth: int = 64,
) -> Dict[str, Any]:
    """多根时的森林（每根一棵 nested_call_tree）。"""
    trees: List[Dict[str, Any]] = []
    seen: Set[int] = set()
    for r in root_vas:
        ri = int(r)
        if ri in seen:
            continue
        seen.add(ri)
        trees.append(
            {
                "root_va": f"0x{ri:08X}",
                "tree": build_nested_call_tree(graph, ri, allowed_nodes, max_depth=max_depth),
            }
        )
    return {"format": "call_tree_forest", "roots": [f"0x{int(x):08X}" for x in root_vas], "trees": trees}


def write_subtree_tree_json(
    out_path: Path,
    *,
    graph: UnifiedGraph,
    goal_index: int,
    generation_index: int,
    label: str,
    root_vas: Sequence[int],
    allowed_nodes: Set[int],
    lambda_dist: Optional[Dict[int, float]],
    paths: Sequence[Dict[str, Any]],
) -> None:
    """写入子树树形 JSON + 路径样本（便于人工核对）。"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    allowed = set(int(x) for x in allowed_nodes)
    roots = [int(x) for x in root_vas]
    if len(roots) == 1:
        tree_block: Dict[str, Any] = {
            "format": "nested_call_tree",
            "root_va": f"0x{roots[0]:08X}",
            "tree": build_nested_call_tree(graph, roots[0], allowed),
        }
    else:
        tree_block = build_forest_call_trees(graph, roots, allowed)

    dist_out: Dict[str, float] = {}
    if lambda_dist:
        for k, v in sorted(lambda_dist.items()):
            dist_out[f"0x{int(k):08X}"] = round(float(v), 6)

    path_samples: List[Dict[str, Any]] = []
    for p in list(paths)[:40]:
        path_samples.append(
            {
                "depth": p.get("depth"),
                "path_vas": list(p.get("path_vas", []) or []),
                "path_names": list(p.get("path_names", []) or []),
                "path_gating_strength": p.get("path_gating_strength", 0),
                "leaf_reason": p.get("leaf_reason", ""),
            }
        )

    doc = {
        "goal_index": int(goal_index),
        "generation": int(generation_index),
        "label": str(label),
        "allowed_node_count": len(allowed),
        "lambda_dist": dist_out,
        "call_tree": tree_block,
        "dfs_paths_sample": path_samples,
    }
    _write_json_atomic(out_path, doc)


def write_generation_manifest(
    out_path: Path,
    *,
    goal_index: int,
    generation_index: int,
    label: str,
    wall_time_sec: float,
    llm_payload: Optional[Dict[str, Any]],
    dfs_stats: Optional[Dict[str, Any]],
    paths_count: int,
) -> None:
    """单代摘要：耗时、token、DFS 规模。"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    timing = (llm_payload or {}).get("timing") or {}
    usage = (llm_payload or {}).get("token_usage") or {}
    doc = {
        "goal_index": int(goal_index),
        "generation": int(generation_index),
        "label": str(label),
        "wall_time_sec_gen": round(float(wall_time_sec), 4),
        "llm_timing": timing,
        "llm_token_usage": usage,
        "dfs_stats": dfs_stats or {},
        "paths_count": int(paths_count),
        "llm_status": (llm_payload or {}).get("status"),
    }
    _write_json_atomic(out_path, doc)


def write_neighborhood_computation_json(
    out_path: Path,
    *,
    trace: Dict[str, Any],
    dist: Dict[int, float],
    max_dist_rows: int = 600,
) -> None:
    """邻域 Dijkstra 的完整轨迹 + 按距离排序的节点表（便于核对「裁剪」结果）。"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(((int(k), float(v)) for k, v in dist.items()), key=lambda x: (x[1], x[0]))
    table = [{"va": f"0x{va:08X}", "mixed_distance": round(d, 6)} for va, d in rows[: max(1, int(max_dist_rows))]]
    doc = {
        "trace": trace,
        "neighbor_list_by_distance": table,
        "truncated": len(rows) > int(max_dist_rows),
        "total_nodes": len(rows),
    }
    _write_json_atomic(out_path, doc)


def append_generations_index(artifacts_dir: Path, entry: Dict[str, Any]) -> None:
    """按 ``(goal_index, generation)`` 幂等更新 INDEX.json。"""
    idx_path = artifacts_dir / "generations" / "INDEX.json"
    idx_path.parent.mkdir(parents=True, exist_ok=True)
    data: List[Dict[str, Any]] = []
    if idx_path.exists():
        try:
            with idx_path.open("r", encoding="utf-8") as fp:
                raw = json.load(fp)
            if isinstance(raw, list):
                data = list(raw)
        except Exception:
            data = []
    new_entry = dict(entry)
    key = (new_entry.get("goal_index"), new_entry.get("generation"))
    if key[0] is not None and key[1] is not None:
        data = [
            row
            for row in data
            if (row.get("goal_index"), row.get("generation")) != key
        ]
    data.append(new_entry)
    data.sort(
        key=lambda row: (
            int(row.get("goal_index", 0) or 0),
            int(row.get("generation", 0) or 0),
        )
    )
    _write_json_atomic(idx_path, data)
