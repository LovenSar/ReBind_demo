"""Phase: Deepest path step-by-step LLM polling.

This module encapsulates the LLM workflow for:
1) selecting the deepest/longest path from DFS outputs,
2) polling LLM step-by-step for input/condition chain inference.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from kp.kp_deep_path import display_name, get_pseudocode_by_va, parse_va
from kp.kp_llm import build_chat_request, call_llm_analyze_function
from kp.kp_types import UnifiedGraph
from pmt.prompts import deep_path_step_prompt


def _truncate_text(text: str, max_chars: int) -> str:
    s = str(text or "").strip()
    if int(max_chars) <= 0 or len(s) <= int(max_chars):
        return s
    keep = max(32, int(max_chars) - 3)
    return s[:keep] + "..."


def _pick_deepest_longest_path(paths: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    best: Optional[Dict[str, Any]] = None
    best_key: Optional[Tuple[int, int, int]] = None
    for p in paths:
        depth = int(p.get("depth", 0) or 0)
        path_len = len(p.get("path_vas", []) or [])
        gate = int(p.get("path_gating_strength", 0) or 0)
        key = (depth, path_len, gate)
        if best is None or key > (best_key or (-1, -1, -1)):
            best = p
            best_key = key
    return best


def _edge_prompt_block(edge: Dict[str, Any], *, max_sites: int = 2, max_guards: int = 3) -> str:
    sites = list(edge.get("call_sites", []) or [])
    if not sites:
        return "(无可用调用点上下文)"

    lines: List[str] = []
    for idx, site in enumerate(sites[: max(1, int(max_sites))], 1):
        guards = [str(g).strip() for g in (site.get("guards", []) or []) if str(g).strip()]
        envs = [str(x).strip() for x in (site.get("env_signals", []) or []) if str(x).strip()]
        call_line = _truncate_text(str(site.get("call_line", "") or ""), 260)
        lines.append(
            f"- callsite#{idx} line={site.get('line_number', '?')}\n"
            f"  call: {call_line or '(empty)'}\n"
            f"  guards: {guards[: max(1, int(max_guards))] if guards else '(none)'}\n"
            f"  env_signals: {envs if envs else '(none)'}"
        )
    return "\n".join(lines)


def run_llm_poll_on_deepest_path(
    *,
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    paths: Sequence[Dict[str, Any]],
    llm_settings: Any,
    max_attempts: int,
    code_chars: int,
    max_steps: int,
    dry_run: bool,
    verbose: bool = False,
    prompt_preview_chars: int = 1800,
    raw_response_chars: int = 2000,
    log_file: Optional[str] = None,
) -> Dict[str, Any]:
    log_path: Optional[Path] = None
    if log_file:
        try:
            log_path = Path(str(log_file)).expanduser().resolve()
            log_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            log_path = None

    def _append_log(event: Dict[str, Any]) -> None:
        if not log_path:
            return
        try:
            payload = dict(event)
            payload.setdefault("ts", datetime.utcnow().isoformat(timespec="seconds") + "Z")
            with log_path.open("a", encoding="utf-8") as fp:
                fp.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception:
            pass

    best = _pick_deepest_longest_path(paths)
    if not best:
        _append_log({"type": "summary", "status": "skipped", "reason": "no_paths"})
        return {"status": "skipped", "reason": "no_paths"}

    path_names = list(best.get("path_names", []) or [])
    path_vas = list(best.get("path_vas", []) or [])
    edge_conditions = list(best.get("edge_conditions", []) or [])
    if len(path_vas) < 2:
        _append_log({"type": "summary", "status": "skipped", "reason": "best_path_too_short"})
        return {"status": "skipped", "reason": "best_path_too_short", "selected_path": best}

    total_steps = min(len(path_vas) - 1, len(edge_conditions))
    if int(max_steps) > 0:
        total_steps = min(total_steps, int(max_steps))
    if total_steps <= 0:
        _append_log({"type": "summary", "status": "skipped", "reason": "no_edges_for_best_path"})
        return {"status": "skipped", "reason": "no_edges_for_best_path", "selected_path": best}

    _append_log(
        {
            "type": "start",
            "status": "started",
            "selected_path": {
                "entry_va": best.get("entry_va"),
                "entry_name": best.get("entry_name"),
                "depth": best.get("depth"),
                "path_vas": path_vas,
                "path_names": path_names,
                "path_gating_strength": best.get("path_gating_strength", 0),
                "leaf_reason": best.get("leaf_reason", ""),
            },
            "total_steps": int(total_steps),
            "dry_run": bool(dry_run),
            "llm_model": getattr(llm_settings, "model", ""),
            "llm_temperature": getattr(llm_settings, "temperature", ""),
            "llm_max_tokens": getattr(llm_settings, "max_tokens", ""),
        }
    )

    pseudo_cache: Dict[int, str] = {}
    previous_steps: List[Dict[str, Any]] = []
    step_results: List[Dict[str, Any]] = []

    for i in range(total_steps):
        from_va_s = str(path_vas[i])
        to_va_s = str(path_vas[i + 1])
        from_va = parse_va(from_va_s)
        to_va = parse_va(to_va_s)
        from_name = str(path_names[i] if i < len(path_names) else display_name(graph, from_va))
        to_name = str(path_names[i + 1] if (i + 1) < len(path_names) else display_name(graph, to_va))
        edge = dict(edge_conditions[i] if i < len(edge_conditions) else {})

        caller_code = _truncate_text(
            get_pseudocode_by_va(conn, graph, from_va, pseudo_cache),
            max(200, int(code_chars or 1200)),
        )
        callee_code = _truncate_text(
            get_pseudocode_by_va(conn, graph, to_va, pseudo_cache),
            max(200, int(code_chars or 1200)),
        )

        prompt = deep_path_step_prompt(
            step_index=i + 1,
            total_steps=total_steps,
            path_names=path_names,
            path_vas=path_vas,
            from_name=from_name,
            from_va=from_va_s,
            to_name=to_name,
            to_va=to_va_s,
            edge=edge,
            edge_block=_edge_prompt_block(edge),
            caller_code=caller_code,
            callee_code=callee_code,
            previous_steps=previous_steps,
        )
        _append_log(
            {
                "type": "step_prompt",
                "step_index": i + 1,
                "total_steps": total_steps,
                "from": from_name,
                "from_va": from_va_s,
                "to": to_name,
                "to_va": to_va_s,
                "edge_status": edge.get("status", ""),
                "edge_aggregated_env_signals": edge.get("aggregated_env_signals", []),
                "edge_gating_strength": edge.get("gating_strength", 0),
                "prompt": prompt,
            }
        )

        if verbose:
            print(
                f"[DeepDFS][LLM][Step {i+1}/{total_steps}] "
                f"{from_name}({from_va_s}) -> {to_name}({to_va_s}) "
                f"edge_status={edge.get('status','')}"
            )
            print(
                f"[DeepDFS][LLM][Step {i+1}] "
                f"model={getattr(llm_settings, 'model', '')} "
                f"temperature={getattr(llm_settings, 'temperature', '')} "
                f"max_tokens={getattr(llm_settings, 'max_tokens', '')} "
                f"max_attempts={max_attempts}"
            )
            print(
                f"[DeepDFS][LLM][Step {i+1}] Prompt预览:\n"
                f"{_truncate_text(prompt, max(200, int(prompt_preview_chars or 1800)))}"
            )

        if dry_run:
            item = {
                "step_index": i + 1,
                "from": from_name,
                "to": to_name,
                "status": "dry_run",
                "prompt_preview": _truncate_text(prompt, 1200),
            }
            step_results.append(item)
            _append_log({"type": "step_dry_run", "step_index": i + 1, "item": item})
            previous_steps.append(
                {
                    "step_index": i + 1,
                    "likely_initial_input": "",
                    "gate_condition": "",
                    "required_state_now": "",
                }
            )
            continue

        conversation, request_kwargs = build_chat_request(prompt, llm_settings)
        _append_log(
            {
                "type": "step_request",
                "step_index": i + 1,
                "request_kwargs": request_kwargs,
            }
        )

        def _on_raw_text(raw: str) -> None:
            if not verbose:
                pass
            else:
                preview = _truncate_text(str(raw or ""), max(200, int(raw_response_chars or 2000)))
                print(f"[DeepDFS][LLM][Step {i+1}] 原始回复预览:\n{preview}")
            _append_log(
                {
                    "type": "step_raw_response",
                    "step_index": i + 1,
                    "raw_text": str(raw or ""),
                }
            )

        result = call_llm_analyze_function(
            conversation=conversation,
            request_kwargs=request_kwargs,
            api_settings=llm_settings.api_settings,
            max_attempts=max(1, int(max_attempts or 1)),
            on_raw_text=_on_raw_text if verbose else None,
        )
        if not isinstance(result, dict) or not result:
            if verbose:
                print(f"[DeepDFS][LLM][Step {i+1}] 解析失败，result={result!r}")
            item = {
                "step_index": i + 1,
                "from": from_name,
                "to": to_name,
                "status": "llm_failed",
                "raw_result": result,
            }
            step_results.append(item)
            _append_log({"type": "step_parse_failed", "step_index": i + 1, "result": result, "item": item})
            previous_steps.append(
                {
                    "step_index": i + 1,
                    "likely_initial_input": "",
                    "gate_condition": "",
                    "required_state_now": "",
                }
            )
            continue

        try:
            confidence = float(result.get("confidence", 0.0) or 0.0)
        except Exception:
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        item = {
            "step_index": i + 1,
            "from": str(result.get("from") or from_name),
            "to": str(result.get("to") or to_name),
            "likely_initial_input": str(result.get("likely_initial_input") or "").strip(),
            "required_state_now": str(result.get("required_state_now") or "").strip(),
            "gate_condition": str(result.get("gate_condition") or "").strip(),
            "condition_relation_with_previous": str(result.get("condition_relation_with_previous") or "UNKNOWN").strip().upper(),
            "reasoning": str(result.get("reasoning") or "").strip(),
            "evidence": [str(x).strip() for x in (result.get("evidence") or []) if str(x).strip()],
            "confidence": confidence,
            "status": "ok",
        }
        if verbose:
            print(
                f"[DeepDFS][LLM][Step {i+1}] 解析结果: "
                f"init_input={item['likely_initial_input']!r}, "
                f"gate={item['gate_condition']!r}, "
                f"state={item['required_state_now']!r}, "
                f"relation={item['condition_relation_with_previous']}, "
                f"reasoning={item['reasoning']!r}, "
                f"confidence={item['confidence']:.2f}"
            )
        step_results.append(item)
        _append_log({"type": "step_result", "step_index": i + 1, "item": item})
        previous_steps.append(
            {
                "step_index": i + 1,
                "likely_initial_input": item["likely_initial_input"],
                "required_state_now": item["required_state_now"],
                "gate_condition": item["gate_condition"],
            }
        )

    initial_input = ""
    for s in step_results:
        candidate = str(s.get("likely_initial_input") or "").strip()
        if candidate:
            initial_input = candidate
            break

    condition_chain = [
        {
            "step_index": s.get("step_index"),
            "from": s.get("from") or "",
            "to": s.get("to") or "",
            "gate_condition": s.get("gate_condition") or "",
            "required_state_now": s.get("required_state_now") or "",
            "relation": s.get("condition_relation_with_previous") or "UNKNOWN",
            "reasoning": s.get("reasoning") or "",
            "confidence": s.get("confidence", 0.0),
            "status": s.get("status", ""),
        }
        for s in step_results
    ]

    avg_conf = 0.0
    ok_steps = [s for s in step_results if s.get("status") == "ok"]
    if ok_steps:
        avg_conf = sum(float(s.get("confidence", 0.0) or 0.0) for s in ok_steps) / float(len(ok_steps))

    final_payload = {
        "status": "dry_run" if dry_run else "ok",
        "selected_path": {
            "entry_va": best.get("entry_va"),
            "entry_name": best.get("entry_name"),
            "depth": best.get("depth"),
            "path_vas": path_vas,
            "path_names": path_names,
            "path_gating_strength": best.get("path_gating_strength", 0),
            "leaf_reason": best.get("leaf_reason", ""),
        },
        "most_likely_initial_input": initial_input,
        "avg_step_confidence": round(avg_conf, 4),
        "steps": step_results,
        "condition_chain": condition_chain,
    }
    _append_log({"type": "summary", "status": final_payload.get("status", "ok"), "result": final_payload})
    return final_payload
