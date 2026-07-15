"""Practical accuracy patches for Phase7.

This module keeps the legacy engine intact and installs conservative runtime
patches from ``practical_engine.py``:

* function neighborhoods expand on directed call relations only;
* strings, globals and external APIs remain evidence instead of graph hops;
* deep-path prompts receive compact static-evidence summaries;
* profile replacement requires an independent static-evidence gate.
"""

from __future__ import annotations

import re
import sqlite3
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple


_DEFAULT_NAME_RE = re.compile(r"^(?:sub_|fun_|loc_)[0-9a-f]+$", re.IGNORECASE)
_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{2,}")
_STOP_TOKENS = {
    "the", "and", "for", "with", "from", "this", "that", "into", "return",
    "function", "handler", "helper", "process", "data", "buffer", "value",
    "unknown", "suspected", "logic", "internal", "external", "current",
}


@dataclass
class PracticalSettings:
    node_budget: int = 24
    evidence_threshold: float = 0.25
    min_evidence_signals: int = 1
    min_profile_confidence: int = 70
    evidence_neighbor_limit: int = 8
    evidence_string_limit: int = 10
    evidence_api_limit: int = 10
    evidence_global_limit: int = 8


@dataclass
class PracticalContext:
    graph: Any = None
    conn: Optional[sqlite3.Connection] = None
    func_to_globals: Dict[int, List[Tuple[int, int]]] = field(default_factory=dict)
    mixed_adjacency: Dict[int, Dict[int, Set[str]]] = field(default_factory=dict)
    settings: PracticalSettings = field(default_factory=PracticalSettings)
    original_prompt: Optional[Callable[..., str]] = None
    semantic_cache: Dict[int, str] = field(default_factory=dict)


_CONTEXT = PracticalContext()


def configure_practical_context(
    *,
    graph: Any = None,
    conn: Optional[sqlite3.Connection] = None,
    func_to_globals: Optional[Dict[int, List[Tuple[int, int]]]] = None,
    mixed_adjacency: Optional[Dict[int, Dict[int, Set[str]]]] = None,
    settings: Optional[PracticalSettings] = None,
) -> None:
    """Set runtime context. Tests may call this directly."""

    if graph is not None:
        _CONTEXT.graph = graph
    if conn is not None:
        _CONTEXT.conn = conn
    if func_to_globals is not None:
        _CONTEXT.func_to_globals = dict(func_to_globals)
    if mixed_adjacency is not None:
        _CONTEXT.mixed_adjacency = mixed_adjacency
    if settings is not None:
        _CONTEXT.settings = settings
    _CONTEXT.semantic_cache.clear()


def _clip(text: Any, limit: int) -> str:
    value = str(text or "").strip()
    if len(value) <= int(limit):
        return value
    return value[: max(0, int(limit) - 3)] + "..."


def _display_name(node: Any, va: int) -> str:
    names = sorted(str(x) for x in (getattr(node, "names", set()) or set()) if str(x).strip())
    meaningful = [name for name in names if not _DEFAULT_NAME_RE.match(name)]
    return (meaningful or names or [f"sub_{int(va):08X}"])[0]


def _node(graph: Any, va: int) -> Any:
    nodes = getattr(graph, "nodes", {}) or {}
    return nodes.get(int(va))


def _call_order(start_va: int, *, callers: bool, limit: int) -> List[Tuple[int, int]]:
    """Return directed BFS order as ``(va, hop)`` without the root."""

    graph = _CONTEXT.graph
    if graph is None or _node(graph, start_va) is None or limit <= 0:
        return []

    out: List[Tuple[int, int]] = []
    queue: deque[Tuple[int, int]] = deque([(int(start_va), 0)])
    seen: Set[int] = {int(start_va)}

    while queue and len(out) < int(limit):
        current, hop = queue.popleft()
        current_node = _node(graph, current)
        if current_node is None:
            continue
        raw = (
            getattr(current_node, "caller_vas", set())
            if callers
            else getattr(current_node, "internal_callee_vas", set())
        )
        for neighbor in sorted(int(x) for x in (raw or set())):
            if neighbor in seen or _node(graph, neighbor) is None:
                continue
            seen.add(neighbor)
            out.append((neighbor, hop + 1))
            queue.append((neighbor, hop + 1))
            if len(out) >= int(limit):
                break
    return out


def _fallback_call_order(
    adjacency: Dict[int, Dict[int, Set[str]]], start_va: int, limit: int
) -> List[Tuple[int, int]]:
    """Use call-only BFS when the directed graph is unavailable."""

    out: List[Tuple[int, int]] = []
    queue: deque[Tuple[int, int]] = deque([(int(start_va), 0)])
    seen: Set[int] = {int(start_va)}
    while queue and len(out) < int(limit):
        current, hop = queue.popleft()
        for neighbor, kinds in sorted(adjacency.get(current, {}).items()):
            if "call" not in (kinds or set()) or int(neighbor) in seen:
                continue
            seen.add(int(neighbor))
            out.append((int(neighbor), hop + 1))
            queue.append((int(neighbor), hop + 1))
            if len(out) >= int(limit):
                break
    return out


def call_budget_neighborhood(
    adjacency: Dict[int, Dict[int, Set[str]]],
    start_va: int,
    *,
    radius: float,
    weights: Dict[str, float],
    max_nodes: int = 0,
    adaptive_shrink: bool = True,
    trace_out: Optional[Dict[str, Any]] = None,
) -> Tuple[Set[int], Dict[int, float]]:
    """Build a bounded neighborhood using call relations only.

    ``radius`` is interpreted as a node budget in practical mode. The root uses
    one slot. Remaining slots are split between caller and callee sides. Unused
    capacity from one side is transferred to the other side.
    """

    del weights, adaptive_shrink
    root = int(start_va)
    requested = max(1, int(round(float(radius))))
    configured = max(1, int(_CONTEXT.settings.node_budget or requested))
    budget = configured
    if max_nodes and int(max_nodes) > 0:
        budget = min(budget, int(max_nodes))

    neighbor_budget = max(0, budget - 1)
    caller_quota = neighbor_budget // 2
    callee_quota = neighbor_budget - caller_quota

    if _CONTEXT.graph is not None and _node(_CONTEXT.graph, root) is not None:
        callers = _call_order(root, callers=True, limit=neighbor_budget)
        callees = _call_order(root, callers=False, limit=neighbor_budget)
        directed = True
    else:
        merged = _fallback_call_order(adjacency, root, neighbor_budget)
        callers = []
        callees = merged
        directed = False

    selected: List[Tuple[str, int, int]] = []
    used: Set[int] = {root}

    def take(side: str, rows: Sequence[Tuple[int, int]], count: int) -> None:
        for va, hop in rows:
            if len([x for x in selected if x[0] == side]) >= int(count):
                break
            if int(va) in used:
                continue
            used.add(int(va))
            selected.append((side, int(va), int(hop)))

    take("caller", callers, caller_quota)
    take("callee", callees, callee_quota)

    remaining = neighbor_budget - len(selected)
    if remaining > 0:
        leftovers: List[Tuple[int, str, int]] = []
        for side, rows in (("caller", callers), ("callee", callees)):
            for va, hop in rows:
                if int(va) not in used:
                    leftovers.append((int(hop), side, int(va)))
        leftovers.sort(key=lambda item: (item[0], item[1], item[2]))
        for hop, side, va in leftovers[:remaining]:
            used.add(int(va))
            selected.append((side, int(va), int(hop)))

    distances: Dict[int, float] = {root: 0.0}
    for _side, va, hop in selected:
        distances[int(va)] = float(hop)

    if trace_out is not None:
        trace_out.clear()
        trace_out.update(
            {
                "algorithm": "directed_call_node_budget",
                "description": (
                    "函数邻域只沿 caller/callee 调用关系扩展。"
                    "data/string/global/indirect 仅作为证据，不参与扩点。"
                ),
                "start_va_hex": f"0x{root:08X}",
                "radius_argument": float(radius),
                "node_budget": int(budget),
                "caller_quota": int(caller_quota),
                "callee_quota": int(callee_quota),
                "caller_selected": sum(1 for side, _va, _hop in selected if side == "caller"),
                "callee_selected": sum(1 for side, _va, _hop in selected if side == "callee"),
                "directed_graph_available": bool(directed),
                "nodes_in_neighborhood": int(len(distances)),
            }
        )
    return set(distances), distances


def _semantic_summary(va: int) -> str:
    cached = _CONTEXT.semantic_cache.get(int(va))
    if cached is not None:
        return cached
    conn = _CONTEXT.conn
    graph = _CONTEXT.graph
    node = _node(graph, va) if graph is not None else None
    if conn is None or node is None:
        _CONTEXT.semantic_cache[int(va)] = ""
        return ""

    function_ids = sorted(int(x) for x in (getattr(node, "function_ids", set()) or set()))
    if not function_ids:
        _CONTEXT.semantic_cache[int(va)] = ""
        return ""

    placeholders = ",".join("?" for _ in function_ids)
    try:
        row = conn.execute(
            f"""
            SELECT summary_signature, semantic_summary, confidence_score
            FROM analysis_status
            WHERE function_id IN ({placeholders})
            ORDER BY confidence_score DESC
            LIMIT 1
            """,
            function_ids,
        ).fetchone()
    except Exception:
        row = None
    if not row:
        value = ""
    else:
        value = " | ".join(x for x in (_clip(row[0], 180), _clip(row[1], 260)) if x)
    _CONTEXT.semantic_cache[int(va)] = value
    return value


def build_static_evidence_block(from_va: int, to_va: int) -> str:
    """Build a compact evidence block for a deep-path step."""

    graph = _CONTEXT.graph
    if graph is None:
        return "(静态证据上下文不可用)"

    settings = _CONTEXT.settings
    lines: List[str] = []
    for label, va in (("caller", int(from_va)), ("callee", int(to_va))):
        node = _node(graph, va)
        if node is None:
            continue
        lines.append(f"- {label}: {_display_name(node, va)} (0x{va:08X})")

        apis = sorted(str(x) for x in (getattr(node, "external_callee_names", set()) or set()))
        strings = sorted(str(x) for x in (getattr(node, "string_refs", set()) or set()))
        globals_rows = list(_CONTEXT.func_to_globals.get(int(va), []) or [])
        callers = sorted(int(x) for x in (getattr(node, "caller_vas", set()) or set()))
        callees = sorted(int(x) for x in (getattr(node, "internal_callee_vas", set()) or set()))

        if apis:
            lines.append(
                "  external_apis: "
                + ", ".join(_clip(x, 80) for x in apis[: settings.evidence_api_limit])
            )
        if strings:
            lines.append(
                "  strings: "
                + " | ".join(_clip(x, 120) for x in strings[: settings.evidence_string_limit])
            )
        if globals_rows:
            rendered = [f"0x{int(gva):08X}(refs={int(count)})" for gva, count in globals_rows]
            lines.append("  globals: " + ", ".join(rendered[: settings.evidence_global_limit]))

        neighbor_rows: List[str] = []
        for neighbor_va in (callers + callees)[: settings.evidence_neighbor_limit]:
            neighbor = _node(graph, neighbor_va)
            if neighbor is None:
                continue
            text = f"{_display_name(neighbor, neighbor_va)}@0x{neighbor_va:08X}"
            summary = _semantic_summary(neighbor_va)
            if summary:
                text += f" [{_clip(summary, 180)}]"
            neighbor_rows.append(text)
        if neighbor_rows:
            lines.append("  call_neighbors: " + " | ".join(neighbor_rows))

        current_summary = _semantic_summary(va)
        if current_summary:
            lines.append("  existing_semantics: " + _clip(current_summary, 320))

    return "\n".join(lines) if lines else "(无可用静态证据)"


def practical_deep_path_step_prompt(**kwargs: Any) -> str:
    """Wrap the legacy prompt and inject independently collected evidence."""

    original = _CONTEXT.original_prompt
    if original is None:
        raise RuntimeError("practical prompt patch was not installed")
    base = original(**kwargs)
    try:
        from_va = int(str(kwargs.get("from_va") or "0"), 0)
        to_va = int(str(kwargs.get("to_va") or "0"), 0)
    except ValueError:
        from_va = to_va = 0

    evidence = build_static_evidence_block(from_va, to_va)
    insert = f"""
[独立静态证据]
{evidence}

[证据约束]
- 只能把伪代码、调用点、API、字符串、全局变量和已有高置信语义当作事实。
- 无法由证据支持的输入类型、协议、加密算法、文件格式和安全结论必须标记为 UNKNOWN。
- evidence 字段必须引用上面的具体证据，不得只重复推断结果。
""".strip()
    marker = "[输出要求]"
    if marker in base:
        return base.replace(marker, insert + "\n\n" + marker, 1)
    return base + "\n\n" + insert


def _tokens(value: Any) -> Set[str]:
    raw = str(value or "")
    parts: Set[str] = set()
    for match in _TOKEN_RE.findall(raw):
        for token in re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", match).lower().split("_"):
            if len(token) >= 3 and token not in _STOP_TOKENS:
                parts.add(token)
    return parts


def _profile_tokens(profile: Dict[str, Any]) -> Set[str]:
    return _tokens(
        " ".join(
            str(profile.get(key) or "")
            for key in ("name", "summary_signature", "semantic_summary", "structured_analysis")
        )
    )


def _evidence_sets(entry_va: int) -> Dict[str, Set[str]]:
    graph = _CONTEXT.graph
    node = _node(graph, entry_va) if graph is not None else None
    if node is None:
        return {"api": set(), "string": set(), "graph": set(), "existing": set()}

    api_tokens = _tokens(" ".join(str(x) for x in (getattr(node, "external_callee_names", set()) or set())))
    string_tokens = _tokens(" ".join(str(x) for x in (getattr(node, "string_refs", set()) or set())))

    graph_parts: List[str] = []
    for neighbor_va in sorted(
        set(getattr(node, "caller_vas", set()) or set())
        | set(getattr(node, "internal_callee_vas", set()) or set())
    )[:16]:
        neighbor = _node(graph, int(neighbor_va))
        if neighbor is not None:
            graph_parts.extend(str(x) for x in (getattr(neighbor, "names", set()) or set()))
            graph_parts.extend(str(x) for x in (getattr(neighbor, "external_callee_names", set()) or set()))
    existing_parts = list(str(x) for x in (getattr(node, "names", set()) or set()))
    existing_parts.append(_semantic_summary(entry_va))
    return {
        "api": api_tokens,
        "string": string_tokens,
        "graph": _tokens(" ".join(graph_parts)),
        "existing": _tokens(" ".join(existing_parts)),
    }


def score_profile_static_evidence(profile: Dict[str, Any]) -> Dict[str, Any]:
    """Score how strongly a profile is supported by non-LLM static evidence."""

    try:
        entry_va = int(str(profile.get("entry_va") or "0"), 0)
    except ValueError:
        entry_va = 0
    profile_tokens = _profile_tokens(profile)
    evidence = _evidence_sets(entry_va)

    overlaps = {
        kind: sorted(profile_tokens & tokens)
        for kind, tokens in evidence.items()
    }
    weighted = {
        "api": 0.45,
        "string": 0.30,
        "graph": 0.15,
        "existing": 0.10,
    }
    score = sum(weight for kind, weight in weighted.items() if overlaps[kind])
    independent = sum(1 for kind in ("api", "string", "graph") if overlaps[kind])

    name = str(profile.get("name") or "").strip()
    signature = str(profile.get("summary_signature") or "").strip()
    summary = str(profile.get("semantic_summary") or "").strip()
    try:
        confidence = int(profile.get("confidence_score", 0) or 0)
    except Exception:
        confidence = 0
    quality = sum(
        (
            0.30 if name and not _DEFAULT_NAME_RE.match(name) else 0.0,
            0.25 if signature else 0.0,
            0.25 if len(summary) >= 24 else 0.0,
            0.20 if confidence >= _CONTEXT.settings.min_profile_confidence else 0.0,
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


def _profile_is_weak(profile: Dict[str, Any]) -> bool:
    name = str(profile.get("name") or "").strip()
    signature = str(profile.get("summary_signature") or "").strip()
    summary = str(profile.get("semantic_summary") or "").strip()
    return (not name or bool(_DEFAULT_NAME_RE.match(name))) and not signature and not summary


def select_profile_with_static_gate(
    old_profile: Dict[str, Any],
    new_profile: Dict[str, Any],
    compare_result: Dict[str, Any],
    *,
    min_delta: float,
) -> Dict[str, Any]:
    """Select a profile only after LLM preference and static evidence agree."""

    choose = str(compare_result.get("choose") or "old").strip().lower()
    try:
        old_score = float(compare_result.get("old_score", 0.0) or 0.0)
        new_score = float(compare_result.get("new_score", 0.0) or 0.0)
    except Exception:
        old_score = new_score = 0.0
    delta = new_score - old_score

    evidence = score_profile_static_evidence(new_profile)
    settings = _CONTEXT.settings
    evidence_pass = (
        float(evidence["score"]) >= float(settings.evidence_threshold)
        and int(evidence["independent_signal_count"]) >= int(settings.min_evidence_signals)
    )
    weak_old_fallback = (
        _profile_is_weak(old_profile)
        and float(evidence["quality"]) >= 0.80
        and int(evidence["independent_signal_count"]) >= 1
    )
    status_ok = str(new_profile.get("status") or "").strip().lower() == "ok"

    selected = "old"
    reasons: List[str] = []
    if choose != "new":
        reasons.append("llm_did_not_choose_new")
    if delta < float(min_delta):
        reasons.append("delta_below_threshold")
    if not status_ok:
        reasons.append("new_profile_not_ok")
    if not (evidence_pass or weak_old_fallback):
        reasons.append("static_evidence_gate_failed")

    if choose == "new" and delta >= float(min_delta) and status_ok and (evidence_pass or weak_old_fallback):
        selected = "new"

    selected_profile = dict(new_profile if selected == "new" else old_profile)
    return {
        "selected": selected,
        "selected_profile": selected_profile,
        "old_score": old_score,
        "new_score": new_score,
        "delta": round(float(delta), 6),
        "threshold": float(min_delta),
        "evidence_gate": {
            **evidence,
            "required_score": float(settings.evidence_threshold),
            "required_independent_signals": int(settings.min_evidence_signals),
            "passed": bool(evidence_pass),
            "weak_old_fallback": bool(weak_old_fallback),
            "rejection_reasons": reasons,
        },
    }


def _filter_call_adjacency(
    adjacency: Dict[int, Dict[int, Set[str]]]
) -> Dict[int, Dict[int, Set[str]]]:
    filtered: Dict[int, Dict[int, Set[str]]] = {}
    for va, neighbors in adjacency.items():
        rows: Dict[int, Set[str]] = {}
        for neighbor, kinds in neighbors.items():
            if "call" in (kinds or set()):
                rows[int(neighbor)] = {"call"}
        if rows:
            filtered[int(va)] = rows
    return filtered


def rank_nodes_by_call_evidence(
    graph: Any,
    adjacency: Dict[int, Dict[int, Set[str]]],
    nodes: Iterable[int],
    goal_structs: Sequence[str],
    limit: int,
) -> List[int]:
    """Prefer call-connected nodes that expose APIs, strings or globals."""

    del adjacency, goal_structs
    scored: List[Tuple[int, int, int, int]] = []
    for raw_va in set(int(x) for x in nodes):
        node = _node(graph, raw_va)
        if node is None:
            continue
        call_degree = len(getattr(node, "caller_vas", set()) or set()) + len(
            getattr(node, "internal_callee_vas", set()) or set()
        )
        evidence_count = len(getattr(node, "external_callee_names", set()) or set())
        evidence_count += len(getattr(node, "string_refs", set()) or set())
        evidence_count += len(_CONTEXT.func_to_globals.get(int(raw_va), []) or [])
        instr_count = int(getattr(node, "instr_count", 0) or 0)
        scored.append((int(evidence_count), int(call_degree), int(instr_count), int(raw_va)))
    scored.sort(reverse=True)
    return [row[3] for row in scored[: max(1, int(limit or 1))]]


def install_practical_patches(engine_module: Any, settings: PracticalSettings) -> None:
    """Install conservative patches into the imported legacy engine module."""

    from depth import deep_path_step

    if getattr(engine_module, "_practical_accuracy_installed", False):
        configure_practical_context(settings=settings)
        return

    original_build = engine_module._build_mixed_graph
    original_auto_goals = engine_module._pick_auto_goals
    original_manual_goals = engine_module._pick_manual_goals
    original_estimate_generations = engine_module._estimate_max_generations

    def patched_build(conn: sqlite3.Connection, graph: Any, *, include_indirect_edges: Dict[int, Set[int]]):
        adjacency, func_to_globals, stats = original_build(
            conn,
            graph,
            include_indirect_edges=include_indirect_edges,
        )
        configure_practical_context(
            graph=graph,
            conn=conn,
            func_to_globals=func_to_globals,
            mixed_adjacency=adjacency,
            settings=settings,
        )
        stats = dict(stats)
        stats["practical_accuracy_mode"] = True
        stats["path_expansion"] = "directed_call_edges_only"
        stats["lambda_semantics"] = "node_budget"
        stats["evidence_only_edges"] = ["data", "string", "global", "indirect"]
        return adjacency, func_to_globals, stats

    def patched_auto_goals(graph: Any, adjacency: Dict[int, Dict[int, Set[str]]], **kwargs: Any):
        return original_auto_goals(graph, _filter_call_adjacency(adjacency), **kwargs)

    def patched_manual_goals(graph: Any, adjacency: Dict[int, Dict[int, Set[str]]], **kwargs: Any):
        return original_manual_goals(graph, _filter_call_adjacency(adjacency), **kwargs)

    def patched_estimate_generations(graph: Any, adjacency: Dict[int, Dict[int, Set[str]]], goal_va: int, user_max: int):
        return original_estimate_generations(
            graph,
            _filter_call_adjacency(adjacency),
            goal_va,
            user_max,
        )

    _CONTEXT.original_prompt = deep_path_step.deep_path_step_prompt
    _CONTEXT.settings = settings

    engine_module._build_mixed_graph = patched_build
    engine_module._mixed_neighborhood = call_budget_neighborhood
    engine_module._select_profile = select_profile_with_static_gate
    engine_module._rank_nodes_for_compare = rank_nodes_by_call_evidence
    engine_module._pick_auto_goals = patched_auto_goals
    engine_module._pick_manual_goals = patched_manual_goals
    engine_module._estimate_max_generations = patched_estimate_generations
    deep_path_step.deep_path_step_prompt = practical_deep_path_step_prompt
    engine_module._practical_accuracy_installed = True
