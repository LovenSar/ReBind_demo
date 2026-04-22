"""uhsg_consensus.py

Phase A of CVINSP: Cross-View Alignment Enhancement.

Computes agreement scores between Ghidra and IDA decompilation views for
each aligned function pair.  High agreement → high confidence for
auto-accept; low agreement → deeper analysis needed.

This module can be invoked standalone or as part of the full CVINSP pipeline.
"""

from __future__ import annotations

import re
import sqlite3
from collections import Counter
from typing import Dict, List, Optional, Set, Tuple

from .uhsg_types import CrossViewConsensus


# ────────────────────────────────────────────────────────────────────
# Token-level similarity helpers
# ────────────────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(r"[A-Za-z_]\w*|\d+|[^\s\w]")


def _tokenize(code: str) -> List[str]:
    """Tokenize pseudocode into identifier / number / punctuation tokens."""
    if not code:
        return []
    return _TOKEN_RE.findall(code)


def _jaccard(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / len(union)


def _token_jaccard(code_a: str, code_b: str) -> float:
    return _jaccard(set(_tokenize(code_a)), set(_tokenize(code_b)))


# ────────────────────────────────────────────────────────────────────
# Variable counting
# ────────────────────────────────────────────────────────────────────

_VAR_RE = re.compile(r"\b(?:a\d+|arg\d+|arg_\d+|v\d+|var_[0-9A-Fa-f]+)\b")


def _count_vars(code: str) -> int:
    if not code:
        return 0
    return len(set(_VAR_RE.findall(code)))


# ────────────────────────────────────────────────────────────────────
# Extract callee names from pseudocode
# ────────────────────────────────────────────────────────────────────

_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


def _extract_callees(code: str) -> Set[str]:
    if not code:
        return set()
    keywords = {"if", "for", "while", "switch", "return", "sizeof", "else"}
    return {m.group(1) for m in _CALL_RE.finditer(code)} - keywords


# ────────────────────────────────────────────────────────────────────
# Extract string literals from pseudocode
# ────────────────────────────────────────────────────────────────────

_STR_RE = re.compile(r'"([^"]*)"')


def _extract_strings(code: str) -> Set[str]:
    if not code:
        return set()
    return set(_STR_RE.findall(code))


# ────────────────────────────────────────────────────────────────────
# Core: compute consensus for one function pair
# ────────────────────────────────────────────────────────────────────

DEFAULT_WEIGHTS = {
    "pseudo_similarity": 0.30,
    "callee_overlap": 0.25,
    "string_ref_overlap": 0.20,
    "var_count_agreement": 0.15,
    "name_match": 0.10,
}


def compute_agreement(
    ghidra_pseudo: str,
    ida_pseudo: str,
    ghidra_name: str = "",
    ida_name: str = "",
    *,
    weights: Optional[Dict[str, float]] = None,
) -> CrossViewConsensus:
    """Compute cross-view agreement features and a weighted score.

    Returns a populated ``CrossViewConsensus`` (without ``entry_va`` set —
    caller is responsible for assigning that).
    """
    w = weights or DEFAULT_WEIGHTS

    pseudo_sim = _token_jaccard(ghidra_pseudo, ida_pseudo)
    callee_ov = _jaccard(_extract_callees(ghidra_pseudo), _extract_callees(ida_pseudo))
    string_ov = _jaccard(_extract_strings(ghidra_pseudo), _extract_strings(ida_pseudo))

    vc_g = _count_vars(ghidra_pseudo)
    vc_i = _count_vars(ida_pseudo)
    max_vc = max(vc_g, vc_i, 1)
    var_agree = 1.0 - abs(vc_g - vc_i) / max_vc

    name_g = (ghidra_name or "").strip().lower()
    name_i = (ida_name or "").strip().lower()
    name_match = 1.0 if name_g and name_g == name_i else 0.0
    if not name_g or not name_i:
        name_match = 0.5

    score = (
        w.get("pseudo_similarity", 0.3) * pseudo_sim
        + w.get("callee_overlap", 0.25) * callee_ov
        + w.get("string_ref_overlap", 0.2) * string_ov
        + w.get("var_count_agreement", 0.15) * var_agree
        + w.get("name_match", 0.1) * name_match
    )

    return CrossViewConsensus(
        entry_va=0,
        ghidra_name=ghidra_name,
        ida_name=ida_name,
        agreement_score=round(score, 4),
        variable_count_ghidra=vc_g,
        variable_count_ida=vc_i,
        pseudo_similarity=round(pseudo_sim, 4),
        callee_overlap=round(callee_ov, 4),
        string_ref_overlap=round(string_ov, 4),
    )


# ────────────────────────────────────────────────────────────────────
# Batch: compute consensus for all aligned functions in the DB
# ────────────────────────────────────────────────────────────────────

def compute_all_consensus(
    conn: sqlite3.Connection,
    binary_id: int,
    *,
    weights: Optional[Dict[str, float]] = None,
    write_to_db: bool = True,
    verbose: bool = True,
) -> List[CrossViewConsensus]:
    """Compute cross-view consensus for every function in *binary_id*.

    Reads Ghidra and IDA pseudocode from ``pseudo_functions``, pairs them
    by ``entry_va``, and produces one ``CrossViewConsensus`` per function.

    If ``write_to_db`` is True, results are upserted into
    ``uhsg_cross_view_consensus``.
    """
    view_tool: Dict[int, str] = {}
    for r in conn.execute(
        """
        SELECT bv.id, t.name FROM binary_views bv
        JOIN tools t ON t.id = bv.tool_id
        WHERE bv.binary_id = ?;
        """,
        (binary_id,),
    ).fetchall():
        view_tool[int(r[0])] = r[1].lower()

    ghidra_views = sorted(v for v, t in view_tool.items() if "ghidra" in t)
    ida_views = sorted(v for v, t in view_tool.items() if "ida" in t)

    if not ghidra_views or not ida_views:
        if verbose:
            print("[Consensus] Need both Ghidra and IDA views — skipping.")
        return []

    def _load_pseudos(view_ids: List[int]) -> Dict[int, Tuple[str, str]]:
        """Return {entry_va: (name, body)} for the given views."""
        ph = ",".join("?" for _ in view_ids)
        rows = conn.execute(
            f"""
            SELECT f.entry_va, f.name, pf.body
            FROM pseudo_functions pf
            JOIN functions f ON f.id = pf.function_id
            WHERE pf.view_id IN ({ph});
            """,
            view_ids,
        ).fetchall()
        result: Dict[int, Tuple[str, str]] = {}
        for eva, fname, body in rows:
            eva = int(eva)
            if eva not in result:
                result[eva] = (fname or "", body or "")
        return result

    ghidra_ps = _load_pseudos(ghidra_views)
    ida_ps = _load_pseudos(ida_views)

    common_vas = sorted(set(ghidra_ps.keys()) & set(ida_ps.keys()))
    if verbose:
        print(
            f"[Consensus] Ghidra funcs: {len(ghidra_ps)}, "
            f"IDA funcs: {len(ida_ps)}, aligned: {len(common_vas)}"
        )

    results: List[CrossViewConsensus] = []
    for eva in common_vas:
        g_name, g_body = ghidra_ps[eva]
        i_name, i_body = ida_ps[eva]
        cv = compute_agreement(g_body, i_body, g_name, i_name, weights=weights)
        cv.entry_va = eva
        results.append(cv)

    if write_to_db and results:
        try:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS uhsg_cross_view_consensus ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "entry_va INTEGER NOT NULL UNIQUE,"
                "ghidra_name TEXT, ida_name TEXT, llm_name TEXT,"
                "consensus_name TEXT, agreement_score REAL DEFAULT 0.0,"
                "name_source TEXT, type_agreement REAL DEFAULT 0.0,"
                "variable_count_ghidra INTEGER DEFAULT 0,"
                "variable_count_ida INTEGER DEFAULT 0,"
                "pseudo_similarity REAL DEFAULT 0.0,"
                "callee_overlap REAL DEFAULT 0.0,"
                "string_ref_overlap REAL DEFAULT 0.0);"
            )
        except sqlite3.OperationalError:
            pass

        for cv in results:
            conn.execute(
                """
                INSERT OR REPLACE INTO uhsg_cross_view_consensus
                (entry_va, ghidra_name, ida_name, agreement_score,
                 variable_count_ghidra, variable_count_ida,
                 pseudo_similarity, callee_overlap, string_ref_overlap)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    cv.entry_va,
                    cv.ghidra_name,
                    cv.ida_name,
                    cv.agreement_score,
                    cv.variable_count_ghidra,
                    cv.variable_count_ida,
                    cv.pseudo_similarity,
                    cv.callee_overlap,
                    cv.string_ref_overlap,
                ),
            )
        conn.commit()
        if verbose:
            print(f"[Consensus] Wrote {len(results)} records to uhsg_cross_view_consensus.")

    if verbose and results:
        scores = [cv.agreement_score for cv in results]
        avg = sum(scores) / len(scores)
        hi = sum(1 for s in scores if s >= 0.8)
        lo = sum(1 for s in scores if s < 0.5)
        print(
            f"[Consensus] avg={avg:.3f}, high(≥0.8)={hi} ({hi*100//len(scores)}%), "
            f"low(<0.5)={lo} ({lo*100//len(scores)}%)"
        )

    return results
