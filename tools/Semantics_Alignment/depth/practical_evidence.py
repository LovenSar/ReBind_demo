"""Evidence extensions for the Phase7 practical-accuracy entrypoint.

The core practical patch remains small and compatible with the legacy engine.
This module strengthens evidence collection without changing engine.py:

* only high-confidence existing semantics are injected;
* data/string/global/indirect relations are rendered as evidence;
* relation-name overlap contributes to the independent evidence score.
"""

from __future__ import annotations

from typing import Any, Dict, List, Set

from depth import practical_accuracy as base


_ORIGINAL_EVIDENCE_BLOCK = base.build_static_evidence_block
_ORIGINAL_EVIDENCE_SETS = base._evidence_sets


def _high_confidence_semantic_summary(va: int) -> str:
    cached = base._CONTEXT.semantic_cache.get(int(va))
    if cached is not None:
        return cached

    conn = base._CONTEXT.conn
    graph = base._CONTEXT.graph
    node = base._node(graph, va) if graph is not None else None
    if conn is None or node is None:
        base._CONTEXT.semantic_cache[int(va)] = ""
        return ""

    function_ids = sorted(int(x) for x in (getattr(node, "function_ids", set()) or set()))
    if not function_ids:
        base._CONTEXT.semantic_cache[int(va)] = ""
        return ""

    placeholders = ",".join("?" for _ in function_ids)
    threshold = int(base._CONTEXT.settings.min_profile_confidence)
    try:
        row = conn.execute(
            f"""
            SELECT summary_signature, semantic_summary, confidence_score
            FROM analysis_status
            WHERE function_id IN ({placeholders})
              AND confidence_score >= ?
            ORDER BY confidence_score DESC
            LIMIT 1
            """,
            [*function_ids, threshold],
        ).fetchone()
    except Exception:
        row = None

    if row:
        value = " | ".join(
            item
            for item in (
                base._clip(row[0], 180),
                base._clip(row[1], 260),
            )
            if item
        )
    else:
        value = ""
    base._CONTEXT.semantic_cache[int(va)] = value
    return value


def _relation_rows(va: int) -> List[str]:
    graph = base._CONTEXT.graph
    if graph is None:
        return []

    limit = int(getattr(base._CONTEXT.settings, "evidence_relation_limit", 8) or 8)
    rows: List[str] = []
    for neighbor_va, kinds in sorted(base._CONTEXT.mixed_adjacency.get(int(va), {}).items()):
        evidence_kinds = sorted(str(kind) for kind in (kinds or set()) if str(kind) != "call")
        if not evidence_kinds:
            continue
        neighbor = base._node(graph, int(neighbor_va))
        name = (
            base._display_name(neighbor, int(neighbor_va))
            if neighbor is not None
            else f"sub_{int(neighbor_va):08X}"
        )
        rows.append(f"{name}@0x{int(neighbor_va):08X}({','.join(evidence_kinds)})")
        if len(rows) >= limit:
            break
    return rows


def build_static_evidence_block(from_va: int, to_va: int) -> str:
    block = _ORIGINAL_EVIDENCE_BLOCK(int(from_va), int(to_va))
    relation_lines: List[str] = []
    for label, va in (("caller", int(from_va)), ("callee", int(to_va))):
        rows = _relation_rows(va)
        if rows:
            relation_lines.append(f"- {label}_evidence_relations: " + " | ".join(rows))
    if not relation_lines:
        return block
    return block + "\n" + "\n".join(relation_lines)


def _relation_tokens(entry_va: int) -> Set[str]:
    graph = base._CONTEXT.graph
    if graph is None:
        return set()

    parts: List[str] = []
    for neighbor_va, kinds in sorted(base._CONTEXT.mixed_adjacency.get(int(entry_va), {}).items()):
        if not any(str(kind) != "call" for kind in (kinds or set())):
            continue
        neighbor = base._node(graph, int(neighbor_va))
        if neighbor is None:
            continue
        parts.extend(str(x) for x in (getattr(neighbor, "names", set()) or set()))
        parts.extend(str(x) for x in (getattr(neighbor, "external_callee_names", set()) or set()))
    return base._tokens(" ".join(parts))


def _evidence_sets(entry_va: int) -> Dict[str, Set[str]]:
    result = dict(_ORIGINAL_EVIDENCE_SETS(int(entry_va)))
    result["relation"] = _relation_tokens(int(entry_va))
    return result


def score_profile_static_evidence(profile: Dict[str, Any]) -> Dict[str, Any]:
    try:
        entry_va = int(str(profile.get("entry_va") or "0"), 0)
    except ValueError:
        entry_va = 0

    profile_tokens = base._profile_tokens(profile)
    evidence = _evidence_sets(entry_va)
    node = base._node(base._CONTEXT.graph, entry_va) if base._CONTEXT.graph is not None else None
    symbol_tokens = base._tokens(str(profile.get("name") or ""))
    known_symbols = {
        frozenset(base._tokens(str(name)))
        for name in (getattr(node, "names", set()) or set())
        if base._tokens(str(name))
    }
    symbol_match = bool(symbol_tokens) and frozenset(symbol_tokens) in known_symbols
    overlaps = {
        kind: sorted(profile_tokens & tokens)
        for kind, tokens in evidence.items()
    }
    overlaps["symbol_name"] = sorted(symbol_tokens) if symbol_match else []
    weighted = {
        "api": 0.35,
        "string": 0.25,
        "relation": 0.20,
        "graph": 0.10,
        "existing": 0.10,
        "symbol_name": 0.20,
    }
    score = sum(weight for kind, weight in weighted.items() if overlaps.get(kind))
    independent = sum(
        1
        for kind in ("api", "string", "relation", "graph", "symbol_name")
        if overlaps.get(kind)
    )

    name = str(profile.get("name") or "").strip()
    signature = str(profile.get("summary_signature") or "").strip()
    summary = str(profile.get("semantic_summary") or "").strip()
    try:
        confidence = int(profile.get("confidence_score", 0) or 0)
    except Exception:
        confidence = 0

    quality = sum(
        (
            0.30 if name and not base._DEFAULT_NAME_RE.match(name) else 0.0,
            0.25 if signature else 0.0,
            0.25 if len(summary) >= 24 else 0.0,
            0.20 if confidence >= base._CONTEXT.settings.min_profile_confidence else 0.0,
        )
    )
    return {
        "entry_va": f"0x{entry_va:08X}",
        "score": round(float(score), 4),
        "quality": round(float(quality), 4),
        "independent_signal_count": int(independent),
        "overlaps": overlaps,
        "profile_tokens": sorted(profile_tokens)[:80],
    }


def install_evidence_extensions() -> None:
    if getattr(base, "_practical_evidence_extensions_installed", False):
        return
    base._semantic_summary = _high_confidence_semantic_summary
    base.build_static_evidence_block = build_static_evidence_block
    base._evidence_sets = _evidence_sets
    base.score_profile_static_evidence = score_profile_static_evidence
    base._practical_evidence_extensions_installed = True
