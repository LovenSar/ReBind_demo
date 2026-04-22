"""uhsg_graph.py

Build a UHSG (Unified Heterogeneous Semantic Graph) from the existing
alignment SQLite database.  This bridges legacy tables (functions, xrefs,
strings, pseudo_functions, analysis_status, global_vars) with the new
UHSG node/edge model.

Usage:
    from kp.uhsg_graph import build_uhsg
    uhsg = build_uhsg(conn, binary_id=1)
    print(uhsg.summary())
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .kp_types import CALL_REF_TYPES, UnifiedGraph
from .uhsg_types import (
    UHSG,
    APIEntityNode,
    CrossViewConsensus,
    EdgeType,
    GlobalVarUHSGNode,
    NodeType,
    PredictionRecord,
    PredictionSource,
    StringNode,
    StructNode,
    TypeKind,
    TypeNode,
    UHSGEdge,
    UHSGNode,
    VariableNode,
)


# ────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────

def _va_hex(va: int) -> str:
    return f"{va:#x}"


def _func_nid(entry_va: int) -> str:
    return f"func:{_va_hex(entry_va)}"


def _var_nid(func_va: int, offset: str) -> str:
    return f"var:{_va_hex(func_va)}:{offset}"


def _type_nid(name: str) -> str:
    return f"type:{name}"


def _struct_nid(name: str) -> str:
    return f"struct:{name}"


def _api_nid(name: str) -> str:
    return f"api:{name}"


def _str_nid(va: int) -> str:
    return f"str:{_va_hex(va)}"


def _gvar_nid(va: int) -> str:
    return f"gvar:{_va_hex(va)}"


# ────────────────────────────────────────────────────────────────────
# Function-layer construction (from existing UnifiedGraph or raw DB)
# ────────────────────────────────────────────────────────────────────

def _populate_function_nodes(
    conn: sqlite3.Connection,
    uhsg: UHSG,
    binary_id: int,
) -> Dict[int, str]:
    """Create Function nodes from existing ``functions`` + ``binary_views`` tables.

    Returns mapping ``entry_va → node_id`` for later edge construction.
    """
    va_to_nid: Dict[int, str] = {}

    rows = conn.execute(
        """
        SELECT f.id, f.entry_va, f.name, f.view_id, bv.tool_id, t.name AS tool_name
        FROM functions f
        JOIN binary_views bv ON bv.id = f.view_id
        JOIN tools t ON t.id = bv.tool_id
        WHERE bv.binary_id = ?
        ORDER BY f.entry_va;
        """,
        (binary_id,),
    ).fetchall()

    grouped: Dict[int, Dict] = defaultdict(lambda: {
        "names": {},
        "function_ids": set(),
        "tool_names": set(),
    })

    for fid, entry_va, name, view_id, tool_id, tool_name in rows:
        entry_va = int(entry_va)
        g = grouped[entry_va]
        g["function_ids"].add(int(fid))
        g["tool_names"].add(tool_name)
        g["names"][tool_name] = name or ""

    for entry_va, info in grouped.items():
        nid = _func_nid(entry_va)
        node = UHSGNode(
            node_id=nid,
            node_type=NodeType.FUNCTION,
            attributes={
                "entry_va": entry_va,
                "binary_id": binary_id,
                "function_ids": sorted(info["function_ids"]),
                "names_by_tool": dict(info["names"]),
            },
        )
        for tool_name, name in info["names"].items():
            src = PredictionSource.GHIDRA if "ghidra" in tool_name.lower() else PredictionSource.IDA
            node.add_prediction(PredictionRecord(
                source=src,
                value=name,
                confidence=0.5,
            ))

        uhsg.add_node(node)
        va_to_nid[entry_va] = nid

    return va_to_nid


# ────────────────────────────────────────────────────────────────────
# Call edges
# ────────────────────────────────────────────────────────────────────

def _populate_call_edges(
    conn: sqlite3.Connection,
    uhsg: UHSG,
    binary_id: int,
    va_to_nid: Dict[int, str],
) -> int:
    """Create ``calls`` edges from xrefs with call-type ref_type_raw."""
    view_ids = [
        r[0]
        for r in conn.execute(
            "SELECT id FROM binary_views WHERE binary_id = ?", (binary_id,)
        ).fetchall()
    ]
    if not view_ids:
        return 0

    call_types = sorted(CALL_REF_TYPES)
    view_ph = ",".join("?" for _ in view_ids)
    call_ph = ",".join("?" for _ in call_types)

    rows = conn.execute(
        f"""
        SELECT DISTINCT src_f.entry_va, dst_f.entry_va
        FROM xrefs x
        JOIN instructions src_i ON src_i.view_id = x.view_id AND src_i.address_va = x.src_va
        JOIN functions src_f    ON src_f.id = src_i.function_id
        JOIN instructions dst_i ON dst_i.view_id = x.view_id AND dst_i.address_va = x.dst_va
        JOIN functions dst_f    ON dst_f.id = dst_i.function_id
        WHERE x.view_id IN ({view_ph})
          AND x.ref_type_raw IN ({call_ph})
          AND src_f.entry_va != dst_f.entry_va;
        """,
        [*view_ids, *call_types],
    ).fetchall()

    count = 0
    for src_va, dst_va in rows:
        src_va, dst_va = int(src_va), int(dst_va)
        src_nid = va_to_nid.get(src_va)
        dst_nid = va_to_nid.get(dst_va)
        if src_nid and dst_nid:
            uhsg.add_edge(UHSGEdge(
                source_id=src_nid,
                target_id=dst_nid,
                edge_type=EdgeType.CALLS,
            ))
            count += 1

    return count


# ────────────────────────────────────────────────────────────────────
# String nodes + string_ref edges
# ────────────────────────────────────────────────────────────────────

def _populate_strings(
    conn: sqlite3.Connection,
    uhsg: UHSG,
    binary_id: int,
    va_to_nid: Dict[int, str],
) -> Tuple[int, int]:
    """Create String nodes and ``string_ref`` edges."""
    view_ids = [
        r[0]
        for r in conn.execute(
            "SELECT id FROM binary_views WHERE binary_id = ?", (binary_id,)
        ).fetchall()
    ]
    if not view_ids:
        return 0, 0

    view_ph = ",".join("?" for _ in view_ids)
    str_rows = conn.execute(
        f"SELECT id, view_id, address_va, value FROM strings WHERE view_id IN ({view_ph})",
        view_ids,
    ).fetchall()

    str_va_to_nid: Dict[int, str] = {}
    node_count = 0
    for sid, vid, addr_va, val in str_rows:
        addr_va = int(addr_va) if addr_va else 0
        if addr_va == 0:
            continue
        nid = _str_nid(addr_va)
        if nid not in str_va_to_nid:
            sn = StringNode(
                node_id=nid,
                address_va=addr_va,
                value=val or "",
            )
            uhsg.add_node(sn)
            str_va_to_nid[addr_va] = nid
            node_count += 1

    call_types = sorted(CALL_REF_TYPES)
    call_ph = ",".join("?" for _ in call_types)
    edge_count = 0

    for addr_va, s_nid in str_va_to_nid.items():
        ref_rows = conn.execute(
            f"""
            SELECT DISTINCT f.entry_va
            FROM xrefs x
            JOIN instructions i ON i.view_id = x.view_id AND i.address_va = x.src_va
            JOIN functions f    ON f.id = i.function_id
            WHERE x.view_id IN ({view_ph})
              AND x.dst_va = ?
              AND x.ref_type_raw NOT IN ({call_ph});
            """,
            [*view_ids, addr_va, *call_types],
        ).fetchall()
        for (fva,) in ref_rows:
            fva = int(fva)
            f_nid = va_to_nid.get(fva)
            if f_nid:
                uhsg.add_edge(UHSGEdge(
                    source_id=f_nid,
                    target_id=s_nid,
                    edge_type=EdgeType.STRING_REF,
                ))
                edge_count += 1

    return node_count, edge_count


# ────────────────────────────────────────────────────────────────────
# Global variable nodes + global_ref edges
# ────────────────────────────────────────────────────────────────────

def _populate_global_vars(
    conn: sqlite3.Connection,
    uhsg: UHSG,
    binary_id: int,
    va_to_nid: Dict[int, str],
) -> Tuple[int, int]:
    """Create GlobalVar nodes from ``global_vars`` table (Phase3 output)."""
    try:
        rows = conn.execute(
            """
            SELECT address_va, name, guessed_type, confidence
            FROM global_vars
            WHERE binary_id = ?;
            """,
            (binary_id,),
        ).fetchall()
    except sqlite3.OperationalError:
        return 0, 0

    node_count = 0
    edge_count = 0

    for addr_va, name, guessed_type, conf in rows:
        addr_va = int(addr_va)
        nid = _gvar_nid(addr_va)
        gv = GlobalVarUHSGNode(
            node_id=nid,
            address_va=addr_va,
            inferred_type=guessed_type or "",
            confidence=float(conf) if conf else 0.0,
        )
        gv.attributes["name"] = name or ""
        uhsg.add_node(gv)
        node_count += 1

    for addr_va, name, _, _ in rows:
        addr_va = int(addr_va)
        g_nid = _gvar_nid(addr_va)
        ref_rows = conn.execute(
            """
            SELECT DISTINCT f.entry_va
            FROM xrefs x
            JOIN instructions i ON i.view_id = x.view_id AND i.address_va = x.src_va
            JOIN functions f    ON f.id = i.function_id
            JOIN binary_views bv ON bv.id = f.view_id
            WHERE bv.binary_id = ?
              AND x.dst_va = ?;
            """,
            (binary_id, addr_va),
        ).fetchall()
        for (fva,) in ref_rows:
            fva = int(fva)
            f_nid = va_to_nid.get(fva)
            if f_nid:
                uhsg.add_edge(UHSGEdge(
                    source_id=f_nid,
                    target_id=g_nid,
                    edge_type=EdgeType.GLOBAL_REF,
                ))
                edge_count += 1

    return node_count, edge_count


# ────────────────────────────────────────────────────────────────────
# API knowledge bridge
# ────────────────────────────────────────────────────────────────────

def _populate_api_entities(
    conn: sqlite3.Connection,
    uhsg: UHSG,
    va_to_nid: Dict[int, str],
    api_kg_dir: Optional[str] = None,
) -> Tuple[int, int]:
    """Create APIEntity nodes from uhsg_api_knowledge table or KG JSON files.

    If ``api_kg_dir`` is provided, loads entities from
    ``global_entity_index.json`` in that directory.
    """
    node_count = 0
    edge_count = 0

    api_name_to_nid: Dict[str, str] = {}

    try:
        rows = conn.execute(
            "SELECT DISTINCT api_name, return_type, description, related_structs, kg_entity_id "
            "FROM uhsg_api_knowledge;"
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []

    for api_name, ret_type, desc, rel_structs, kg_eid in rows:
        nid = _api_nid(api_name)
        if nid in api_name_to_nid:
            continue
        an = APIEntityNode(
            node_id=nid,
            api_name=api_name,
            return_type=ret_type or "",
            description=desc or "",
            kg_entity_id=kg_eid or "",
        )
        if rel_structs:
            try:
                an.related_structs = json.loads(rel_structs)
            except (json.JSONDecodeError, TypeError):
                pass
        uhsg.add_node(an)
        api_name_to_nid[api_name] = nid
        node_count += 1

    if api_kg_dir:
        kg_path = Path(api_kg_dir) / "global_entity_index.json"
        if kg_path.exists():
            with open(kg_path, "r", encoding="utf-8") as f:
                entity_index = json.load(f)
            for eid, info in entity_index.items():
                etype = (info.get("entity_type") or "").lower()
                ename = info.get("name", "")
                if etype == "function" and ename and _api_nid(ename) not in api_name_to_nid:
                    nid = _api_nid(ename)
                    an = APIEntityNode(
                        node_id=nid,
                        api_name=ename,
                        description=info.get("description", ""),
                        kg_entity_id=str(eid),
                    )
                    uhsg.add_node(an)
                    api_name_to_nid[ename] = nid
                    node_count += 1

    all_ext_callees: Set[str] = set()
    for node in uhsg.nodes(NodeType.FUNCTION):
        ext = node.attributes.get("external_callee_names", set())
        if isinstance(ext, (set, list)):
            all_ext_callees.update(ext)

    for api_name, a_nid in api_name_to_nid.items():
        for func_node in uhsg.nodes(NodeType.FUNCTION):
            ext = func_node.attributes.get("external_callee_names", set())
            if api_name in ext:
                uhsg.add_edge(UHSGEdge(
                    source_id=func_node.node_id,
                    target_id=a_nid,
                    edge_type=EdgeType.API_USAGE,
                ))
                edge_count += 1

    return node_count, edge_count


# ────────────────────────────────────────────────────────────────────
# Cross-view alias edges
# ────────────────────────────────────────────────────────────────────

def _populate_alias_edges(
    conn: sqlite3.Connection,
    uhsg: UHSG,
    binary_id: int,
    va_to_nid: Dict[int, str],
) -> int:
    """Create ``alias`` edges between Ghidra and IDA views of the same function.

    Two functions at the same ``entry_va`` from different tools are considered aliases.
    The edge carries a default weight; Phase A of CVINSP will later compute a
    proper ``agreement_score``.
    """
    view_tool = {}
    for r in conn.execute(
        """
        SELECT bv.id, t.name FROM binary_views bv
        JOIN tools t ON t.id = bv.tool_id
        WHERE bv.binary_id = ?;
        """,
        (binary_id,),
    ).fetchall():
        view_tool[int(r[0])] = r[1].lower()

    ghidra_views = {v for v, t in view_tool.items() if "ghidra" in t}
    ida_views = {v for v, t in view_tool.items() if "ida" in t}
    if not ghidra_views or not ida_views:
        return 0

    ghidra_funcs: Dict[int, int] = {}
    ida_funcs: Dict[int, int] = {}

    for r in conn.execute(
        "SELECT id, view_id, entry_va FROM functions WHERE view_id IN ({})".format(
            ",".join("?" for _ in ghidra_views | ida_views)
        ),
        list(ghidra_views | ida_views),
    ).fetchall():
        fid, vid, eva = int(r[0]), int(r[1]), int(r[2])
        if vid in ghidra_views:
            ghidra_funcs[eva] = fid
        elif vid in ida_views:
            ida_funcs[eva] = fid

    count = 0
    for eva in set(ghidra_funcs.keys()) & set(ida_funcs.keys()):
        nid = va_to_nid.get(eva)
        if nid:
            uhsg.add_edge(UHSGEdge(
                source_id=nid,
                target_id=nid,
                edge_type=EdgeType.ALIAS,
                metadata={
                    "ghidra_function_id": ghidra_funcs[eva],
                    "ida_function_id": ida_funcs[eva],
                },
            ))
            count += 1

    return count


# ────────────────────────────────────────────────────────────────────
# Main builder
# ────────────────────────────────────────────────────────────────────

def build_uhsg(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    api_kg_dir: Optional[str] = None,
    include_strings: bool = True,
    include_globals: bool = True,
    include_api: bool = True,
    verbose: bool = True,
) -> UHSG:
    """Build a complete UHSG from the alignment database.

    Parameters
    ----------
    conn : sqlite3.Connection
        Open connection to the alignment SQLite DB.
    binary_id : int
        Which binary to build the graph for.
    api_kg_dir : str, optional
        Path to ``Windows_API_PDF_OCR_Graph/json_output_v4/`` for API KG bridge.
    include_strings : bool
        Whether to include String nodes and string_ref edges.
    include_globals : bool
        Whether to include GlobalVar nodes and global_ref edges.
    include_api : bool
        Whether to populate API entity nodes.
    verbose : bool
        Print progress messages.

    Returns
    -------
    UHSG
        The fully populated heterogeneous graph.
    """
    t0 = time.perf_counter()
    uhsg = UHSG(binary_id=binary_id)

    if verbose:
        print(f"[UHSG] Building graph for binary_id={binary_id}…")

    va_to_nid = _populate_function_nodes(conn, uhsg, binary_id)
    if verbose:
        print(f"  Functions: {uhsg.node_count(NodeType.FUNCTION)}")

    call_count = _populate_call_edges(conn, uhsg, binary_id, va_to_nid)
    if verbose:
        print(f"  Call edges: {call_count}")

    if include_strings:
        sn, se = _populate_strings(conn, uhsg, binary_id, va_to_nid)
        if verbose:
            print(f"  Strings: {sn} nodes, {se} string_ref edges")

    if include_globals:
        gn, ge = _populate_global_vars(conn, uhsg, binary_id, va_to_nid)
        if verbose:
            print(f"  GlobalVars: {gn} nodes, {ge} global_ref edges")

    alias_count = _populate_alias_edges(conn, uhsg, binary_id, va_to_nid)
    if verbose:
        print(f"  Alias (cross-view) edges: {alias_count}")

    if include_api:
        an, ae = _populate_api_entities(conn, uhsg, va_to_nid, api_kg_dir)
        if verbose:
            print(f"  API entities: {an} nodes, {ae} api_usage edges")

    elapsed = time.perf_counter() - t0
    if verbose:
        s = uhsg.summary()
        print(f"[UHSG] Done in {elapsed:.2f}s — {s['total_nodes']} nodes, {s['total_edges']} edges")
        for nt, cnt in sorted(s["nodes_by_type"].items()):
            print(f"  {nt}: {cnt}")
        for et, cnt in sorted(s["edges_by_type"].items()):
            print(f"  {et}: {cnt}")

    return uhsg
