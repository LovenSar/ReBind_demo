"""kp_graph.py

Unified graph construction helpers.

Extracted from knowledge_propagation.py so the main workflow can run without
importing the legacy entrypoint.
"""

from __future__ import annotations

import sqlite3
from typing import Dict

from .kp_types import CALL_REF_TYPES, UnifiedFunctionNode, UnifiedGraph


def build_unified_graph(conn: sqlite3.Connection, binary_id: int) -> UnifiedGraph:
    """Build a cross-view unified dependency graph for one binary.

    - Aggregates all binary_views under the binary_id.
    - Merges functions across views by entry_va.
    - Aggregates pseudocode, string refs, external callees, and internal call edges.
    """

    cur = conn.cursor()

    # 1) Collect views for this binary
    cur.execute(
        "SELECT id, tool_id FROM binary_views WHERE binary_id = ?;",
        (int(binary_id),),
    )
    rows = cur.fetchall()
    if not rows:
        raise RuntimeError(f"binary_id={binary_id} 没有关联的 binary_views 记录。")

    view_to_tool: Dict[int, int] = {int(view_id): int(tool_id) for (view_id, tool_id) in rows}
    view_ids = list(view_to_tool.keys())

    cur.execute("SELECT id, name FROM tools;")
    tool_map: Dict[int, str] = {int(tid): str(name) for (tid, name) in cur.fetchall()}

    # 2) Merge functions by entry_va
    placeholders = ",".join("?" for _ in view_ids)
    cur.execute(
        f"SELECT id, view_id, entry_va, name "
        f"FROM functions WHERE view_id IN ({placeholders});",
        view_ids,
    )

    nodes: Dict[int, UnifiedFunctionNode] = {}
    function_id_to_va: Dict[int, int] = {}
    function_id_to_view: Dict[int, int] = {}
    func_tool: Dict[int, str] = {}

    for fid, view_id, entry_va, name in cur.fetchall():
        if entry_va is None:
            continue
        entry_va = int(entry_va)
        fid = int(fid)
        view_id = int(view_id)

        node = nodes.get(entry_va)
        if node is None:
            node = UnifiedFunctionNode(entry_va=entry_va, binary_id=int(binary_id))
            nodes[entry_va] = node

        function_id_to_va[fid] = entry_va
        function_id_to_view[fid] = view_id

        tool_id = view_to_tool.get(view_id)
        tool_name = "unknown"
        if tool_id is not None:
            tool_name = tool_map.get(int(tool_id), f"tool_{tool_id}")
            func_tool[fid] = tool_name

        tool_key = tool_name.lower()

        node.function_ids.add(fid)
        if name:
            node.names.add(str(name))
            node.names_by_tool.setdefault(tool_key, set()).add(str(name))

    if not nodes:
        raise RuntimeError(f"binary_id={binary_id} 下找不到任何函数。")

    # 3) Aggregate pseudocode per tool
    cur.execute(
        f"""
        SELECT pf.function_id, pf.prototype, pf.body
        FROM pseudo_functions AS pf
        JOIN functions AS f ON pf.function_id = f.id
        WHERE f.view_id IN ({placeholders});
        """,
        view_ids,
    )
    for fid, proto, body in cur.fetchall():
        fid = int(fid)
        entry_va = function_id_to_va.get(fid)
        if entry_va is None:
            continue
        node = nodes.get(entry_va)
        if node is None:
            continue

        view_id = function_id_to_view.get(fid)
        tool_id = view_to_tool.get(view_id) if view_id is not None else None
        tool_name = tool_map.get(tool_id, f"tool_{tool_id}") if tool_id is not None else "unknown"

        code = (proto or "") + "\n" + (body or "")
        if not code.strip():
            continue

        prev = node.pseudocodes.get(tool_name)
        if prev is None or len(code) > len(prev):
            node.pseudocodes[tool_name] = code

    # 4) Instruction count + choose a primary function_id
    cur.execute(
        f"""
        SELECT function_id, COUNT(*) AS cnt
        FROM instructions
        WHERE view_id IN ({placeholders})
        GROUP BY function_id;
        """,
        view_ids,
    )
    for fid, cnt in cur.fetchall():
        fid = int(fid)
        entry_va = function_id_to_va.get(fid)
        if entry_va is None:
            continue
        node = nodes.get(entry_va)
        if node is None:
            continue
        cnt = int(cnt or 0)
        if cnt > node.instr_count:
            node.instr_count = cnt
            node.primary_function_id = fid

    # 5) Aggregate xrefs: strings + calls + external API names
    cur.execute(
        f"""
        SELECT i.function_id,
               x.dst_va,
               x.dst_name,
               x.ref_type_raw,
               s.value
        FROM xrefs AS x
        JOIN instructions AS i
             ON x.view_id = i.view_id AND x.src_va = i.address_va
        LEFT JOIN strings AS s
             ON x.view_id = s.view_id AND x.dst_va = s.address_va
        WHERE x.view_id IN ({placeholders});
        """,
        view_ids,
    )

    for caller_fid, dst_va, dst_name, ref_type_raw, str_val in cur.fetchall():
        caller_fid = int(caller_fid)
        caller_va = function_id_to_va.get(caller_fid)
        if caller_va is None:
            continue
        node = nodes.get(caller_va)
        if node is None:
            continue

        # A) string refs
        if str_val:
            node.string_refs.add(str(str_val))

        # B) call edges
        if ref_type_raw in CALL_REF_TYPES:
            if dst_va is not None and int(dst_va) in nodes:
                callee_va = int(dst_va)
                if callee_va != caller_va:
                    node.internal_callee_vas.add(callee_va)
                    nodes[callee_va].caller_vas.add(caller_va)
            else:
                dst_name_norm = (dst_name or "").strip()
                if dst_name_norm:
                    lower = dst_name_norm.lower()
                    if not lower.startswith(("sub_", "loc_", "label_")):
                        node.external_callee_names.add(dst_name_norm)

    print(
        f"[Graph] binary_id={binary_id} 视图数={len(view_ids)}，"
        f"统一物理函数节点数={len(nodes)}"
    )

    return UnifiedGraph(binary_id=int(binary_id), nodes=nodes, tool_map=tool_map, func_tool=func_tool)
