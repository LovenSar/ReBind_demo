"""kp_graph.py

Unified graph construction helpers.

Extracted from knowledge_propagation.py so the main workflow can run without
importing the legacy entrypoint.
"""

from __future__ import annotations

import sqlite3
import time
from typing import Dict, Iterable, List, Optional, Set, Tuple

from .kp_types import CALL_REF_TYPES, UnifiedFunctionNode, UnifiedGraph


def _ensure_graph_indexes(conn: sqlite3.Connection) -> None:
    """Create a few indices that make unified graph building feasible on large DBs."""

    statements = (
        # Core filters used by build_unified_graph / phase queries
        "CREATE INDEX IF NOT EXISTS idx_binary_views_binary_id ON binary_views(binary_id);",
        "CREATE INDEX IF NOT EXISTS idx_strings_view_addr ON strings(view_id, address_va);",
        "CREATE INDEX IF NOT EXISTS idx_xrefs_view_src ON xrefs(view_id, src_va);",
        "CREATE INDEX IF NOT EXISTS idx_xrefs_view_dst ON xrefs(view_id, dst_va);",
        "CREATE INDEX IF NOT EXISTS idx_xrefs_view_ref ON xrefs(view_id, ref_type_raw);",
        "CREATE INDEX IF NOT EXISTS idx_functions_view_entry ON functions(view_id, entry_va);",
        "CREATE INDEX IF NOT EXISTS idx_instructions_view_addr ON instructions(view_id, address_va);",
        "CREATE INDEX IF NOT EXISTS idx_instructions_view_func ON instructions(view_id, function_id);",
        "CREATE INDEX IF NOT EXISTS idx_pseudo_functions_view_func ON pseudo_functions(view_id, function_id);",
        "CREATE INDEX IF NOT EXISTS idx_pseudo_functions_func ON pseudo_functions(function_id);",
    )

    try:
        conn.execute("PRAGMA busy_timeout = 5000;")
    except Exception:
        pass

    for stmt in statements:
        try:
            conn.execute(stmt)
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower():
                print(
                    "[Graph] 数据库被占用（database is locked），跳过索引创建（不影响正确性，但可能更慢）。"
                )
                return
            raise

    conn.commit()
    print("[Graph] Database indices verified/created.", flush=True)


def _iter_chunks(items: List[int], *, chunk_size: int) -> Iterable[List[int]]:
    if chunk_size <= 0:
        yield items
        return
    for i in range(0, len(items), chunk_size):
        yield items[i : i + chunk_size]


def _progress_every(
    processed: int,
    *,
    step: int,
    started: float,
    last_print: float,
    label: str,
) -> Tuple[bool, float]:
    if processed <= 0 or processed % step != 0:
        return False, last_print
    now = time.perf_counter()
    elapsed = max(1e-6, now - started)
    rate = processed / elapsed
    print(f"[Graph] {label}: {processed:,} rows ({rate:,.0f}/s)")
    return True, now


def hydrate_unified_xrefs_for_nodes(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    nodes: List[UnifiedFunctionNode],
    *,
    include_strings: bool = True,
    include_calls: bool = True,
    max_strings_per_node: int = 20,
    max_external_callees_per_node: int = 50,
    max_internal_callees_per_node: int = 200,
) -> None:
    """Lazy-hydrate xref-derived fields for a subset of unified nodes.

    This is the fast-path for large DBs: avoid scanning the whole `xrefs` table
    upfront, and only fill in strings / call edges for the functions being
    analyzed in the current batch.
    """

    if not nodes:
        return

    function_id_to_view = getattr(graph, "function_id_to_view_id", {}) or {}
    function_id_to_entry = getattr(graph, "function_id_to_entry_va", {}) or {}

    # Group requested function_ids by view_id so we can leverage idx_instructions_view_func(view_id, function_id).
    fids_by_view: Dict[int, Set[int]] = {}
    for node in nodes:
        for fid in node.function_ids:
            view_id = function_id_to_view.get(int(fid))
            if view_id is None:
                continue
            fids_by_view.setdefault(int(view_id), set()).add(int(fid))

    if not fids_by_view:
        return

    cur = conn.cursor()

    if include_strings and int(max_strings_per_node or 0) > 0:
        for view_id, fids in fids_by_view.items():
            fid_list = sorted(fids)
            # Keep a conservative chunk size to avoid hitting SQLite variable limits.
            for chunk in _iter_chunks(fid_list, chunk_size=800):
                placeholders = ",".join("?" for _ in chunk)
                cur.execute(
                    f"""
                    SELECT DISTINCT i.function_id, s.value
                    FROM instructions AS i
                    JOIN xrefs AS x
                         ON x.view_id = i.view_id AND x.src_va = i.address_va
                    JOIN strings AS s
                         ON s.view_id = x.view_id AND s.address_va = x.dst_va
                    WHERE i.view_id = ?
                      AND i.function_id IN ({placeholders});
                    """,
                    [int(view_id), *chunk],
                )
                for fid, value in cur:
                    entry_va = function_id_to_entry.get(int(fid))
                    if entry_va is None:
                        continue
                    node = graph.nodes.get(int(entry_va))
                    if node is None:
                        continue
                    if len(node.string_refs) >= int(max_strings_per_node):
                        continue
                    if value:
                        node.string_refs.add(str(value))

    if include_calls:
        call_types = sorted(CALL_REF_TYPES)
        call_placeholders = ",".join("?" for _ in call_types)
        for view_id, fids in fids_by_view.items():
            fid_list = sorted(fids)
            for chunk in _iter_chunks(fid_list, chunk_size=700):
                placeholders = ",".join("?" for _ in chunk)
                cur.execute(
                    f"""
                    SELECT DISTINCT i.function_id, x.dst_va, x.dst_name
                    FROM instructions AS i
                    JOIN xrefs AS x
                         ON x.view_id = i.view_id AND x.src_va = i.address_va
                    WHERE i.view_id = ?
                      AND i.function_id IN ({placeholders})
                      AND x.ref_type_raw IN ({call_placeholders});
                    """,
                    [int(view_id), *chunk, *call_types],
                )
                for caller_fid, dst_va, dst_name in cur:
                    caller_entry = function_id_to_entry.get(int(caller_fid))
                    if caller_entry is None:
                        continue
                    caller_node = graph.nodes.get(int(caller_entry))
                    if caller_node is None:
                        continue

                    if dst_va is not None and int(dst_va) in graph.nodes:
                        if len(caller_node.internal_callee_vas) >= int(max_internal_callees_per_node):
                            continue
                        callee_va = int(dst_va)
                        if callee_va != int(caller_entry):
                            caller_node.internal_callee_vas.add(callee_va)
                            graph.nodes[callee_va].caller_vas.add(int(caller_entry))
                        continue

                    dst_name_norm = (dst_name or "").strip()
                    if not dst_name_norm:
                        continue
                    if len(caller_node.external_callee_names) >= int(max_external_callees_per_node):
                        continue
                    lower = dst_name_norm.lower()
                    if lower.startswith(("sub_", "loc_", "label_")):
                        continue
                    caller_node.external_callee_names.add(dst_name_norm)


def build_unified_graph(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    include_string_xrefs: bool = True,
    include_call_xrefs: bool = True,
) -> UnifiedGraph:
    """Build a cross-view unified dependency graph for one binary.

    - Aggregates all binary_views under the binary_id.
    - Merges functions across views by entry_va.
    - Aggregates pseudocode, string refs, external callees, and internal call edges.
    """

    cur = conn.cursor()

    print("[Graph] Preparing indices for graph build (one-time, may take a while on first run)...", flush=True)
    _ensure_graph_indexes(conn)

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
    nodes: Dict[int, UnifiedFunctionNode] = {}
    function_id_to_va: Dict[int, int] = {}
    function_id_to_view: Dict[int, int] = {}
    func_tool: Dict[int, str] = {}

    print("[Graph] Collecting functions...", flush=True)
    for fid, view_id, entry_va, name in cur.execute(
        f"SELECT id, view_id, entry_va, name "
        f"FROM functions WHERE view_id IN ({placeholders});",
        view_ids,
    ):
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
    print("[Graph] Collecting pseudocode...", flush=True)
    cur.execute(
        f"""
        SELECT pf.function_id, pf.prototype, pf.body
        FROM pseudo_functions AS pf
        JOIN functions AS f ON pf.function_id = f.id
        WHERE f.view_id IN ({placeholders});
        """,
        view_ids,
    )
    for fid, proto, body in cur:
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
    print("[Graph] Counting instructions per function...", flush=True)
    cur.execute(
        f"""
        SELECT function_id, COUNT(*) AS cnt
        FROM instructions
        WHERE view_id IN ({placeholders})
        GROUP BY function_id;
        """,
        view_ids,
    )
    for fid, cnt in cur:
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
    if include_string_xrefs:
        print("[Graph] Aggregating string references...", flush=True)
        started = time.perf_counter()
        last_print = started
        processed = 0
        cur.execute(
            f"""
            SELECT i.function_id,
                   s.value
            FROM xrefs AS x
            JOIN instructions AS i
                 ON x.view_id = i.view_id AND x.src_va = i.address_va
            JOIN strings AS s
                 ON x.view_id = s.view_id AND x.dst_va = s.address_va
            WHERE x.view_id IN ({placeholders});
            """,
            view_ids,
        )
        for caller_fid, str_val in cur:
            processed += 1
            if str_val:
                caller_fid = int(caller_fid)
                caller_va = function_id_to_va.get(caller_fid)
                if caller_va is not None:
                    node = nodes.get(caller_va)
                    if node is not None:
                        node.string_refs.add(str(str_val))
            _, last_print = _progress_every(
                processed,
                step=50_000,
                started=started,
                last_print=last_print,
                label="string_xrefs",
            )

    if include_call_xrefs:
        print("[Graph] Aggregating call edges...", flush=True)
        started = time.perf_counter()
        last_print = started
        processed = 0
        call_types = sorted(CALL_REF_TYPES)
        call_placeholders = ",".join("?" for _ in call_types)
        params: Iterable[object] = [*view_ids, *call_types]
        cur.execute(
            f"""
            SELECT i.function_id,
                   x.dst_va,
                   x.dst_name
            FROM xrefs AS x
            JOIN instructions AS i
                 ON x.view_id = i.view_id AND x.src_va = i.address_va
            WHERE x.view_id IN ({placeholders})
              AND x.ref_type_raw IN ({call_placeholders});
            """,
            list(params),
        )
        for caller_fid, dst_va, dst_name in cur:
            processed += 1
            caller_fid = int(caller_fid)
            caller_va = function_id_to_va.get(caller_fid)
            if caller_va is None:
                continue
            node = nodes.get(caller_va)
            if node is None:
                continue

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

            _, last_print = _progress_every(
                processed,
                step=50_000,
                started=started,
                last_print=last_print,
                label="call_xrefs",
            )

    print(
        f"[Graph] binary_id={binary_id} 视图数={len(view_ids)}，"
        f"统一物理函数节点数={len(nodes)}"
    )

    return UnifiedGraph(
        binary_id=int(binary_id),
        nodes=nodes,
        tool_map=tool_map,
        func_tool=func_tool,
        function_id_to_entry_va=function_id_to_va,
        function_id_to_view_id=function_id_to_view,
    )
