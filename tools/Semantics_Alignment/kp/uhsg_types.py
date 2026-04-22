"""uhsg_types.py

Unified Heterogeneous Semantic Graph (UHSG) data structures.

Extends the existing kp_types.py node/edge model with multi-type nodes
(Variable, Type, Struct, APIEntity) and typed edges, enabling cross-view
neuro-symbolic propagation across functions, types, and API knowledge.

Backward compatible: all existing UnifiedGraph / UnifiedFunctionNode code
continues to work unchanged.  UHSG wraps the legacy graph as its function
layer and adds new node/edge layers on top.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# ────────────────────────────────────────────────────────────────────
# Enums
# ────────────────────────────────────────────────────────────────────

class NodeType(enum.Enum):
    FUNCTION = "function"
    VARIABLE = "variable"
    TYPE = "type"
    STRUCT = "struct"
    API_ENTITY = "api_entity"
    STRING = "string"
    GLOBAL_VAR = "global_var"


class EdgeType(enum.Enum):
    CALLS = "calls"
    DATA_FLOW = "data_flow"
    TYPE_OF = "type_of"
    FIELD_OF = "field_of"
    API_USAGE = "api_usage"
    STRING_REF = "string_ref"
    GLOBAL_REF = "global_ref"
    ALIAS = "alias"
    CONSTRAINT = "constraint"


class PredictionSource(enum.Enum):
    GHIDRA = "ghidra"
    IDA = "ida"
    LLM = "llm"
    CONSTRAINT = "constraint"
    API_KG = "api_kg"
    CONSENSUS = "consensus"


class TypeKind(enum.Enum):
    PRIMITIVE = "primitive"
    POINTER = "pointer"
    STRUCT = "struct"
    ENUM = "enum"
    TYPEDEF = "typedef"
    ARRAY = "array"
    FUNCTION_PTR = "function_ptr"
    UNKNOWN = "unknown"


# ────────────────────────────────────────────────────────────────────
# Prediction tracking
# ────────────────────────────────────────────────────────────────────

@dataclass
class PredictionRecord:
    """Single prediction from one source at one round."""

    source: PredictionSource
    value: str
    confidence: float
    round_number: int = 0
    reasoning: Optional[str] = None


# ────────────────────────────────────────────────────────────────────
# UHSG Nodes
# ────────────────────────────────────────────────────────────────────

@dataclass
class UHSGNode:
    """Base node in the Unified Heterogeneous Semantic Graph.

    ``node_id`` format by type:
        function   → "func:<entry_va_hex>"
        variable   → "var:<func_entry_va_hex>:<offset_or_reg>"
        type       → "type:<canonical_name>"
        struct     → "struct:<name>"
        api_entity → "api:<api_name>"
        string     → "str:<address_va_hex>"
        global_var → "gvar:<address_va_hex>"
    """

    node_id: str
    node_type: NodeType
    attributes: Dict[str, Any] = field(default_factory=dict)
    predictions: Dict[str, PredictionRecord] = field(default_factory=dict)
    confidence: float = 0.0
    is_frozen: bool = False

    def add_prediction(self, record: PredictionRecord) -> None:
        key = f"{record.source.value}:r{record.round_number}"
        self.predictions[key] = record
        if record.confidence > self.confidence:
            self.confidence = record.confidence

    def best_prediction(self) -> Optional[PredictionRecord]:
        if not self.predictions:
            return None
        return max(self.predictions.values(), key=lambda p: p.confidence)


def _make_variable_node(
    function_entry_va: int = 0,
    offset_or_reg: str = "",
    original_name: str = "",
    inferred_name: str = "",
    inferred_type: str = "",
    constraint_type: str = "",
    final_type: str = "",
    **kwargs: Any,
) -> "VariableNode":
    nid = kwargs.pop("node_id", "") or f"var:{function_entry_va:#x}:{offset_or_reg}"
    node = VariableNode(node_id=nid, node_type=NodeType.VARIABLE, **kwargs)
    node.function_entry_va = function_entry_va
    node.offset_or_reg = offset_or_reg
    node.original_name = original_name
    node.inferred_name = inferred_name
    node.inferred_type = inferred_type
    node.constraint_type = constraint_type
    node.final_type = final_type
    return node


@dataclass
class VariableNode(UHSGNode):
    """A local variable inside a function.

    Prefer using ``_make_variable_node()`` factory or set fields after init.
    """

    function_entry_va: int = 0
    offset_or_reg: str = ""
    original_name: str = ""
    inferred_name: str = ""
    inferred_type: str = ""
    constraint_type: str = ""
    final_type: str = ""


@dataclass
class TypeNode(UHSGNode):
    """A recovered or known type."""

    name: str = ""
    kind: TypeKind = TypeKind.UNKNOWN
    size_bytes: int = 0


@dataclass
class StructNode(UHSGNode):
    """A recovered or known struct/union/class layout."""

    name: str = ""
    fields: List[Dict[str, Any]] = field(default_factory=list)
    total_size: int = 0


@dataclass
class APIEntityNode(UHSGNode):
    """An entity from the Windows API Knowledge Graph."""

    api_name: str = ""
    params: List[Dict[str, str]] = field(default_factory=list)
    return_type: str = ""
    description: str = ""
    related_structs: List[str] = field(default_factory=list)
    kg_entity_id: str = ""


@dataclass
class StringNode(UHSGNode):
    """A string constant referenced by functions."""

    address_va: int = 0
    value: str = ""
    encoding: str = "utf-8"


@dataclass
class GlobalVarUHSGNode(UHSGNode):
    """A global variable in the UHSG (wraps legacy GlobalVarNode)."""

    address_va: int = 0
    readers: Set[int] = field(default_factory=set)
    writers: Set[int] = field(default_factory=set)
    inferred_type: str = ""


# ────────────────────────────────────────────────────────────────────
# UHSG Edges
# ────────────────────────────────────────────────────────────────────

@dataclass
class UHSGEdge:
    """Typed, weighted edge between two UHSG nodes."""

    source_id: str
    target_id: str
    edge_type: EdgeType
    weight: float = 1.0
    confidence: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.source_id, self.target_id, self.edge_type.value)


# ────────────────────────────────────────────────────────────────────
# Cross-View Consensus
# ────────────────────────────────────────────────────────────────────

@dataclass
class CrossViewConsensus:
    """Agreement record between Ghidra and IDA views for one function."""

    entry_va: int
    ghidra_name: str = ""
    ida_name: str = ""
    llm_name: str = ""
    consensus_name: str = ""
    agreement_score: float = 0.0
    name_source: str = ""
    type_agreement: float = 0.0
    variable_count_ghidra: int = 0
    variable_count_ida: int = 0
    pseudo_similarity: float = 0.0
    callee_overlap: float = 0.0
    string_ref_overlap: float = 0.0


# ────────────────────────────────────────────────────────────────────
# Constraint Log Entry
# ────────────────────────────────────────────────────────────────────

@dataclass
class ConstraintLogEntry:
    """One constraint propagation event."""

    rule_name: str
    source_func_va: int
    target_func_va: int
    variable_name: str = ""
    old_value: str = ""
    new_value: str = ""
    confidence_delta: float = 0.0
    round_number: int = 0


# ────────────────────────────────────────────────────────────────────
# UHSG Container
# ────────────────────────────────────────────────────────────────────

@dataclass
class UHSG:
    """Top-level Unified Heterogeneous Semantic Graph container.

    Manages nodes by type and edges by type, providing O(1) lookup by
    ``node_id`` and efficient iteration by ``NodeType`` or ``EdgeType``.
    """

    binary_id: int = 0

    _nodes: Dict[str, UHSGNode] = field(default_factory=dict)
    _nodes_by_type: Dict[NodeType, Dict[str, UHSGNode]] = field(default_factory=dict)
    _edges: Dict[Tuple[str, str, str], UHSGEdge] = field(default_factory=dict)
    _adj: Dict[str, List[UHSGEdge]] = field(default_factory=dict)
    _rev_adj: Dict[str, List[UHSGEdge]] = field(default_factory=dict)

    # ── Node operations ──

    def add_node(self, node: UHSGNode) -> None:
        self._nodes[node.node_id] = node
        bucket = self._nodes_by_type.setdefault(node.node_type, {})
        bucket[node.node_id] = node

    def get_node(self, node_id: str) -> Optional[UHSGNode]:
        return self._nodes.get(node_id)

    def nodes(self, node_type: Optional[NodeType] = None):
        if node_type is not None:
            return self._nodes_by_type.get(node_type, {}).values()
        return self._nodes.values()

    def node_count(self, node_type: Optional[NodeType] = None) -> int:
        if node_type is not None:
            return len(self._nodes_by_type.get(node_type, {}))
        return len(self._nodes)

    # ── Edge operations ──

    def add_edge(self, edge: UHSGEdge) -> None:
        self._edges[edge.key] = edge
        self._adj.setdefault(edge.source_id, []).append(edge)
        self._rev_adj.setdefault(edge.target_id, []).append(edge)

    def get_edge(self, source_id: str, target_id: str, edge_type: EdgeType) -> Optional[UHSGEdge]:
        return self._edges.get((source_id, target_id, edge_type.value))

    def edges(self, edge_type: Optional[EdgeType] = None):
        if edge_type is not None:
            return [e for e in self._edges.values() if e.edge_type == edge_type]
        return self._edges.values()

    def edge_count(self, edge_type: Optional[EdgeType] = None) -> int:
        if edge_type is not None:
            return sum(1 for e in self._edges.values() if e.edge_type == edge_type)
        return len(self._edges)

    def neighbors(
        self,
        node_id: str,
        edge_type: Optional[EdgeType] = None,
        direction: str = "out",
    ) -> List[Tuple[UHSGEdge, UHSGNode]]:
        """Return (edge, neighbor_node) pairs.

        ``direction``: "out" (follow edge direction), "in" (reverse), "both".
        """
        results: List[Tuple[UHSGEdge, UHSGNode]] = []
        if direction in ("out", "both"):
            for e in self._adj.get(node_id, []):
                if edge_type is not None and e.edge_type != edge_type:
                    continue
                n = self._nodes.get(e.target_id)
                if n is not None:
                    results.append((e, n))
        if direction in ("in", "both"):
            for e in self._rev_adj.get(node_id, []):
                if edge_type is not None and e.edge_type != edge_type:
                    continue
                n = self._nodes.get(e.source_id)
                if n is not None:
                    results.append((e, n))
        return results

    # ── Summary ──

    def summary(self) -> Dict[str, Any]:
        node_counts = {
            nt.value: len(bucket) for nt, bucket in self._nodes_by_type.items()
        }
        edge_counts: Dict[str, int] = {}
        for e in self._edges.values():
            edge_counts[e.edge_type.value] = edge_counts.get(e.edge_type.value, 0) + 1
        return {
            "binary_id": self.binary_id,
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "nodes_by_type": node_counts,
            "edges_by_type": edge_counts,
        }
