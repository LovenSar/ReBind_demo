"""kp_types.py

Shared data structures and common regex/constants for the Semantics Alignment pipeline.

This module is intentionally dependency-light so it can be imported by phase modules
without creating circular imports with the main entrypoint.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Optional, Set


# =========================
# Common constants / patterns
# =========================

CALL_REF_TYPES: Set[str] = {
    # Ghidra
    "UNCONDITIONAL_CALL",
    "COMPUTED_CALL",
    # IDA numeric encodings seen in DB
    "17",
    "19",
    "21",
}

# Phase4: default local variable names (a1/v1/var_10 etc)
GENERIC_LVAR_PATTERN = re.compile(r"\b(?:a\d+|arg\d+|arg_\d+|v\d+|var_[0-9A-Fa-f]+)\b")

# sub_xxxx name pattern
SUBFUNC_NAME_PATTERN = re.compile(r"\bsub_[0-9A-Fa-f]+\b")

# default-address style function names: sub_401000 / fun_0010E210 / loc_80483F0
DEFAULT_FUNC_NAME_PATTERN = re.compile(r"^(?:sub_|fun_|loc_)[0-9A-Fa-f]+$")


def count_effective_pseudocode_lines(code: str) -> int:
    """Count effective pseudocode lines (exclude blanks and single-brace lines)."""

    if not code:
        return 0
    lines = []
    for raw in code.splitlines():
        s = raw.strip()
        if not s:
            continue
        if s in ("{", "}"):
            continue
        lines.append(s)
    return len(lines)


def find_generic_lvar_names(code: str) -> Set[str]:
    """Find default-looking local variable names inside pseudocode."""

    if not code:
        return set()
    return {m.group(0) for m in GENERIC_LVAR_PATTERN.finditer(code)}


# Backward-compatible aliases (keep old underscore names used in knowledge_propagation)
_count_effective_pseudocode_lines = count_effective_pseudocode_lines
_find_generic_lvar_names = find_generic_lvar_names


# =========================
# Data structures
# =========================


@dataclass
class FunctionNode:
    """Single function node in a per-view dependency graph."""

    id: int
    view_id: int
    entry_va: int
    name: str
    instr_count: int = 0
    internal_callees: Set[int] = field(default_factory=set)
    external_callees: Set[int] = field(default_factory=set)
    external_callee_names: Set[str] = field(default_factory=set)
    callers: Set[int] = field(default_factory=set)
    string_ids: Set[int] = field(default_factory=set)


@dataclass
class FunctionGraph:
    """Function dependency graph for a single binary_view."""

    view_id: int
    functions: Dict[int, FunctionNode]
    string_values: Dict[int, str]
    symbol_names: Dict[int, str]


@dataclass
class UnifiedFunctionNode:
    """Cross-view unified node for the same physical function."""

    entry_va: int
    binary_id: int
    function_ids: Set[int] = field(default_factory=set)
    names: Set[str] = field(default_factory=set)
    names_by_tool: Dict[str, Set[str]] = field(default_factory=dict)
    instr_count: int = 0
    primary_function_id: Optional[int] = None
    pseudocodes: Dict[str, str] = field(default_factory=dict)
    internal_callee_vas: Set[int] = field(default_factory=set)
    external_callee_names: Set[str] = field(default_factory=set)
    string_refs: Set[str] = field(default_factory=set)
    caller_vas: Set[int] = field(default_factory=set)


@dataclass
class UnifiedGraph:
    """Cross-view unified dependency graph (grouped by binary_id)."""

    binary_id: int
    nodes: Dict[int, UnifiedFunctionNode]
    tool_map: Dict[int, str]
    func_tool: Dict[int, str]
    # Performance helpers (built once in kp_graph, reused by scoring/hydration)
    function_id_to_entry_va: Dict[int, int] = field(default_factory=dict)
    function_id_to_view_id: Dict[int, int] = field(default_factory=dict)


@dataclass
class GlobalVarNode:
    """Phase3 global variable node (grouped by address_va)."""

    address_va: int
    names: Set[str] = field(default_factory=set)
    readers: Set[int] = field(default_factory=set)
    writers: Set[int] = field(default_factory=set)


@dataclass
class ValidationTask:
    """Phase2 validation task for top-down traversal."""

    entry_va: int
    priority: float
    path_confidence: float

    def __lt__(self, other: "ValidationTask") -> bool:
        # heapq is min-heap; invert for higher priority first
        return self.priority > other.priority
