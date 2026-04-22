"""uhsg_constraints.py

Phase C of CVINSP: Datalog-style Constraint Propagation Engine.

A lightweight forward-chaining rule engine that propagates type constraints,
naming hints, and structural consistency checks across the UHSG until a
fixed point is reached.

Rules are Python callables registered into the engine.  Each rule takes the
current UHSG state and yields ``ConstraintLogEntry`` objects for every new
inference produced.  The engine iterates rounds until no rule produces new
facts or the round budget is exhausted.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .uhsg_types import (
    UHSG,
    ConstraintLogEntry,
    EdgeType,
    NodeType,
    PredictionRecord,
    PredictionSource,
    UHSGEdge,
)


# ────────────────────────────────────────────────────────────────────
# Rule registry
# ────────────────────────────────────────────────────────────────────

RuleFunc = Callable[["ConstraintEngine", UHSG, int], List[ConstraintLogEntry]]


@dataclass
class RegisteredRule:
    name: str
    func: RuleFunc
    priority: int = 0


class ConstraintEngine:
    """Forward-chaining constraint propagation engine on a UHSG.

    Usage::

        engine = ConstraintEngine(max_rounds=10, min_confidence=0.7)
        engine.register_builtin_rules()
        log = engine.run(uhsg)
        print(f"Converged in {engine.last_rounds} rounds, {len(log)} inferences.")
    """

    def __init__(
        self,
        *,
        max_rounds: int = 10,
        min_confidence: float = 0.7,
        decay_factor: float = 0.9,
        verbose: bool = True,
    ):
        self.max_rounds = max_rounds
        self.min_confidence = min_confidence
        self.decay_factor = decay_factor
        self.verbose = verbose

        self._rules: List[RegisteredRule] = []
        self.last_rounds: int = 0
        self.full_log: List[ConstraintLogEntry] = []

    # ── Registration ──

    def register(self, name: str, func: RuleFunc, priority: int = 0) -> None:
        self._rules.append(RegisteredRule(name=name, func=func, priority=priority))
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def register_builtin_rules(self) -> None:
        self.register("TYPE_PROPAGATION", rule_type_propagation, priority=100)
        self.register("API_TYPE_INJECTION", rule_api_type_injection, priority=90)
        self.register("RETURN_TYPE_PROPAGATION", rule_return_type_propagation, priority=80)
        self.register("GLOBAL_TYPE_CONSISTENCY", rule_global_type_consistency, priority=70)
        self.register("NAMING_HINT_PROPAGATION", rule_naming_hint_propagation, priority=60)

    # ── Execution ──

    def run(self, uhsg: UHSG) -> List[ConstraintLogEntry]:
        """Run all rules until fixed point or budget exhausted."""
        t0 = time.perf_counter()
        self.full_log = []
        self.last_rounds = 0

        for round_num in range(1, self.max_rounds + 1):
            self.last_rounds = round_num
            round_inferences: List[ConstraintLogEntry] = []

            for rule in self._rules:
                try:
                    entries = rule.func(self, uhsg, round_num)
                    round_inferences.extend(entries)
                except Exception as exc:
                    if self.verbose:
                        print(f"  [Constraint] Rule {rule.name} error: {exc}")

            self.full_log.extend(round_inferences)

            if self.verbose:
                print(
                    f"  [Constraint] Round {round_num}: "
                    f"{len(round_inferences)} new inferences "
                    f"(total {len(self.full_log)})"
                )

            if not round_inferences:
                if self.verbose:
                    print(f"  [Constraint] Fixed point reached at round {round_num}.")
                break

        elapsed = time.perf_counter() - t0
        if self.verbose:
            print(
                f"[Constraint] Done in {elapsed:.2f}s — "
                f"{self.last_rounds} rounds, {len(self.full_log)} total inferences."
            )
        return self.full_log


# ────────────────────────────────────────────────────────────────────
# Built-in rules
# ────────────────────────────────────────────────────────────────────

def rule_type_propagation(
    engine: ConstraintEngine,
    uhsg: UHSG,
    round_num: int,
) -> List[ConstraintLogEntry]:
    """R1: If F1 calls F2 and we know a parameter type in F1,
    propagate it to the corresponding parameter in F2."""
    entries: List[ConstraintLogEntry] = []

    for call_edge in uhsg.edges(EdgeType.CALLS):
        caller = uhsg.get_node(call_edge.source_id)
        callee = uhsg.get_node(call_edge.target_id)
        if not caller or not callee:
            continue

        caller_va = caller.attributes.get("entry_va", 0)
        callee_va = callee.attributes.get("entry_va", 0)

        caller_vars = [
            (e, n) for e, n in uhsg.neighbors(caller.node_id, EdgeType.DATA_FLOW, "out")
            if n.node_type == NodeType.VARIABLE
        ]
        callee_vars = [
            (e, n) for e, n in uhsg.neighbors(callee.node_id, EdgeType.DATA_FLOW, "out")
            if n.node_type == NodeType.VARIABLE
        ]

        for _, c_var in caller_vars:
            type_edges = uhsg.neighbors(c_var.node_id, EdgeType.TYPE_OF, "out")
            for te, type_node in type_edges:
                if te.confidence < engine.min_confidence:
                    continue

                for _, t_var in callee_vars:
                    existing_types = uhsg.neighbors(t_var.node_id, EdgeType.TYPE_OF, "out")
                    existing_type_names = {
                        tn.attributes.get("name", "") for _, tn in existing_types
                    }
                    src_type_name = type_node.attributes.get("name", "")

                    if src_type_name and src_type_name not in existing_type_names:
                        new_conf = te.confidence * engine.decay_factor
                        uhsg.add_edge(UHSGEdge(
                            source_id=t_var.node_id,
                            target_id=type_node.node_id,
                            edge_type=EdgeType.TYPE_OF,
                            confidence=new_conf,
                            metadata={"propagated_from": caller.node_id, "round": round_num},
                        ))
                        t_var.add_prediction(PredictionRecord(
                            source=PredictionSource.CONSTRAINT,
                            value=src_type_name,
                            confidence=new_conf,
                            round_number=round_num,
                            reasoning=f"Type propagated from {caller.node_id} via call edge",
                        ))
                        entries.append(ConstraintLogEntry(
                            rule_name="TYPE_PROPAGATION",
                            source_func_va=caller_va,
                            target_func_va=callee_va,
                            variable_name=t_var.attributes.get("name", t_var.node_id),
                            old_value="",
                            new_value=src_type_name,
                            confidence_delta=new_conf,
                            round_number=round_num,
                        ))

    return entries


def rule_api_type_injection(
    engine: ConstraintEngine,
    uhsg: UHSG,
    round_num: int,
) -> List[ConstraintLogEntry]:
    """R2: If a function calls a known API, inject parameter types from the KG."""
    entries: List[ConstraintLogEntry] = []

    for api_edge in uhsg.edges(EdgeType.API_USAGE):
        func_node = uhsg.get_node(api_edge.source_id)
        api_node = uhsg.get_node(api_edge.target_id)
        if not func_node or not api_node:
            continue

        api_params = api_node.attributes.get("params", [])
        if not api_params:
            params_from_node = getattr(api_node, "params", [])
            if params_from_node:
                api_params = params_from_node

        func_va = func_node.attributes.get("entry_va", 0)
        api_name = getattr(api_node, "api_name", "") or api_node.attributes.get("api_name", "")

        for param_info in api_params:
            param_type = param_info.get("type", "")
            param_name = param_info.get("name", "")
            if not param_type:
                continue

            type_nid = f"type:{param_type}"
            if not uhsg.get_node(type_nid):
                from .uhsg_types import TypeNode, TypeKind
                tn = TypeNode(node_id=type_nid, name=param_type, kind=TypeKind.UNKNOWN)
                uhsg.add_node(tn)

            entries.append(ConstraintLogEntry(
                rule_name="API_TYPE_INJECTION",
                source_func_va=func_va,
                target_func_va=func_va,
                variable_name=param_name,
                old_value="",
                new_value=param_type,
                confidence_delta=0.95,
                round_number=round_num,
            ))

    return entries


def rule_return_type_propagation(
    engine: ConstraintEngine,
    uhsg: UHSG,
    round_num: int,
) -> List[ConstraintLogEntry]:
    """R3: If callee has a known return type, propagate to the call-site variable in caller."""
    entries: List[ConstraintLogEntry] = []

    for call_edge in uhsg.edges(EdgeType.CALLS):
        callee = uhsg.get_node(call_edge.target_id)
        caller = uhsg.get_node(call_edge.source_id)
        if not callee or not caller:
            continue

        ret_type = callee.attributes.get("return_type", "")
        if not ret_type:
            best = callee.best_prediction() if hasattr(callee, "best_prediction") else None
            if best and "return" in (best.reasoning or "").lower():
                ret_type = best.value

        if ret_type:
            caller_va = caller.attributes.get("entry_va", 0)
            callee_va = callee.attributes.get("entry_va", 0)
            entries.append(ConstraintLogEntry(
                rule_name="RETURN_TYPE_PROPAGATION",
                source_func_va=callee_va,
                target_func_va=caller_va,
                variable_name="<return_value>",
                old_value="",
                new_value=ret_type,
                confidence_delta=0.85 * engine.decay_factor,
                round_number=round_num,
            ))

    return entries


def rule_global_type_consistency(
    engine: ConstraintEngine,
    uhsg: UHSG,
    round_num: int,
) -> List[ConstraintLogEntry]:
    """R4: Global variables accessed by multiple functions should have consistent types."""
    entries: List[ConstraintLogEntry] = []

    for gvar in uhsg.nodes(NodeType.GLOBAL_VAR):
        accessors = uhsg.neighbors(gvar.node_id, EdgeType.GLOBAL_REF, "in")
        if len(accessors) < 2:
            continue

        type_votes: Dict[str, float] = {}
        for edge, func_node in accessors:
            predicted_type = gvar.attributes.get("inferred_type", "")
            if predicted_type:
                type_votes[predicted_type] = type_votes.get(predicted_type, 0) + edge.confidence

        if len(type_votes) > 1:
            winner = max(type_votes.items(), key=lambda x: x[1])
            gvar_va = getattr(gvar, "address_va", 0) or gvar.attributes.get("address_va", 0)
            for t, score in type_votes.items():
                if t != winner[0]:
                    entries.append(ConstraintLogEntry(
                        rule_name="GLOBAL_TYPE_CONSISTENCY",
                        source_func_va=gvar_va,
                        target_func_va=gvar_va,
                        variable_name=gvar.node_id,
                        old_value=t,
                        new_value=winner[0],
                        confidence_delta=winner[1] - score,
                        round_number=round_num,
                    ))

    return entries


def rule_naming_hint_propagation(
    engine: ConstraintEngine,
    uhsg: UHSG,
    round_num: int,
) -> List[ConstraintLogEntry]:
    """R5: If a callee is successfully named, propagate semantic hints to the caller."""
    entries: List[ConstraintLogEntry] = []

    for call_edge in uhsg.edges(EdgeType.CALLS):
        callee = uhsg.get_node(call_edge.target_id)
        caller = uhsg.get_node(call_edge.source_id)
        if not callee or not caller:
            continue

        callee_best = callee.best_prediction() if hasattr(callee, "best_prediction") else None
        if not callee_best or callee_best.confidence < engine.min_confidence:
            continue

        caller_best = caller.best_prediction() if hasattr(caller, "best_prediction") else None
        if caller_best and caller_best.confidence >= engine.min_confidence:
            continue

        callee_va = callee.attributes.get("entry_va", 0)
        caller_va = caller.attributes.get("entry_va", 0)
        entries.append(ConstraintLogEntry(
            rule_name="NAMING_HINT_PROPAGATION",
            source_func_va=callee_va,
            target_func_va=caller_va,
            variable_name="<function_name>",
            old_value="",
            new_value=f"calls_{callee_best.value}",
            confidence_delta=callee_best.confidence * 0.3,
            round_number=round_num,
        ))

    return entries
