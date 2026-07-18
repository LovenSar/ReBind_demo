"""Phase: Deepest path step-by-step LLM polling.

This module encapsulates the LLM workflow for:
1) selecting the deepest/longest path from DFS outputs,
2) polling LLM step-by-step for input/condition chain inference.
"""

from __future__ import annotations

import json
import hashlib
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from kp.kp_deep_path import display_name, get_pseudocode_by_va, parse_va
from kp.kp_llm import build_chat_request, call_llm_analyze_function
from kp.kp_types import UnifiedGraph
from pmt.prompts import deep_path_step_prompt


class LLMStepCheckpointError(RuntimeError):
    """LLM 结果已产生但逐步 checkpoint 落盘失败。"""


def _truncate_text(text: str, max_chars: int) -> str:
    s = str(text or "").strip()
    if int(max_chars) <= 0 or len(s) <= int(max_chars):
        return s
    keep = max(32, int(max_chars) - 3)
    return s[:keep] + "..."


def _redact_sensitive(value: Any, key: str = "") -> Any:
    low = str(key or "").lower()
    if any(token in low for token in ("api_key", "authorization", "token", "secret", "password")):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(k): _redact_sensitive(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_sensitive(v) for v in value]
    return value


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


def _sum_usage_rows(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    pt = ct = tt = 0
    successful_calls = 0
    for r in rows:
        try:
            pt += int(r.get("prompt_tokens") or 0)
            ct += int(r.get("completion_tokens") or 0)
            tt += int(r.get("total_tokens") or 0)
        except Exception:
            continue
        if str(r.get("status") or "ok") == "ok":
            successful_calls += 1
    if tt <= 0 and (pt > 0 or ct > 0):
        tt = pt + ct
    return {
        "prompt_tokens": pt,
        "completion_tokens": ct,
        "total_tokens": tt,
        "api_calls": len(rows),
        "successful_api_calls": successful_calls,
        "failed_api_calls": len(rows) - successful_calls,
    }


def _sum_step_usage(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    pt = ct = tt = calls = successful_calls = failed_calls = 0
    for row in rows:
        usage = row.get("usage") or {}
        if not isinstance(usage, dict):
            continue
        pt += int(usage.get("prompt_tokens") or 0)
        ct += int(usage.get("completion_tokens") or 0)
        tt += int(usage.get("total_tokens") or 0)
        calls += int(usage.get("api_calls") or 0)
        successful_calls += int(usage.get("successful_api_calls") or 0)
        failed_calls += int(usage.get("failed_api_calls") or 0)
    if tt <= 0 and (pt > 0 or ct > 0):
        tt = pt + ct
    return {
        "prompt_tokens": pt,
        "completion_tokens": ct,
        "total_tokens": tt,
        "api_calls": calls,
        "successful_api_calls": successful_calls,
        "failed_api_calls": failed_calls,
    }


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
    progress: bool = True,
    progress_label: str = "",
    prompt_preview_chars: int = 1800,
    raw_response_chars: int = 2000,
    log_file: Optional[str] = None,
    resume_state: Optional[Dict[str, Any]] = None,
    on_step_checkpoint: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    log_path: Optional[Path] = None
    if log_file:
        try:
            log_path = Path(str(log_file)).expanduser().resolve()
            log_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            log_path = None

    run_started = datetime.now(timezone.utc).isoformat()
    t_run0 = time.perf_counter()
    usage_collect: List[Dict[str, Any]] = []

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

    resumed_by_index: Dict[int, Dict[str, Any]] = {}
    if isinstance(resume_state, dict):
        prior_path = [str(x) for x in (resume_state.get("path_vas") or [])]
        if prior_path == [str(x) for x in path_vas]:
            for row in resume_state.get("completed_steps", []) or []:
                if not isinstance(row, dict):
                    continue
                try:
                    step_index = int(row.get("step_index", 0) or 0)
                except (TypeError, ValueError):
                    continue
                if 1 <= step_index <= total_steps:
                    resumed_by_index[step_index] = dict(row)

    plab = str(progress_label or "").strip()
    if progress and not verbose:
        print(
            f"[Phase7][LLM] {plab + ' ' if plab else ''}深路径轮询: {total_steps} 步"
            f"{'' if dry_run else '（调用 API）'}",
            flush=True,
        )

    _append_log(
        {
            "type": "session_start",
            "status": "started",
            "ts_wall": run_started,
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
            "resumed_steps": len(resumed_by_index),
            "dry_run": bool(dry_run),
            "llm_model": getattr(llm_settings, "model", ""),
            "llm_temperature": getattr(llm_settings, "temperature", ""),
            "llm_max_tokens": getattr(llm_settings, "max_tokens", ""),
        }
    )

    pseudo_cache: Dict[int, str] = {}
    previous_steps: List[Dict[str, Any]] = []
    step_results: List[Dict[str, Any]] = []

    def _checkpoint_current() -> None:
        if on_step_checkpoint is None:
            return
        try:
            on_step_checkpoint(
                {
                    "path_vas": [str(x) for x in path_vas],
                    "total_steps": int(total_steps),
                    "completed_steps": [dict(x) for x in step_results],
                }
            )
        except Exception as exc:
            raise LLMStepCheckpointError(str(exc)) from exc

    for i in range(total_steps):
        from_va_s = str(path_vas[i])
        to_va_s = str(path_vas[i + 1])
        from_va = parse_va(from_va_s)
        to_va = parse_va(to_va_s)
        from_name = str(path_names[i] if i < len(path_names) else display_name(graph, from_va))
        to_name = str(path_names[i + 1] if (i + 1) < len(path_names) else display_name(graph, to_va))
        edge = dict(edge_conditions[i] if i < len(edge_conditions) else {})

        cached = resumed_by_index.get(i + 1)
        if cached is not None:
            same_edge = (
                str(cached.get("from_va") or "") == from_va_s
                and str(cached.get("to_va") or "") == to_va_s
            )
            if same_edge:
                step_results.append(cached)
                previous_steps.append(
                    {
                        "step_index": i + 1,
                        "likely_initial_input": str(cached.get("likely_initial_input") or ""),
                        "required_state_now": str(cached.get("required_state_now") or ""),
                        "gate_condition": str(cached.get("gate_condition") or ""),
                    }
                )
                _append_log({"type": "step_resumed", "step_index": i + 1, "item": cached})
                continue

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
        prompt_event = {
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
            "prompt_chars": len(prompt),
            "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
        }
        if verbose:
            prompt_event["prompt"] = prompt
        _append_log(prompt_event)

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
            if progress and not verbose:
                print(
                    f"[Phase7][LLM] {plab + ' ' if plab else ''}dry_run step {i + 1}/{total_steps} "
                    f"{from_name}->{to_name}",
                    flush=True,
                )
            item = {
                "step_index": i + 1,
                "from": from_name,
                "from_va": from_va_s,
                "to": to_name,
                "to_va": to_va_s,
                "status": "dry_run",
                "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0, "api_calls": 0},
                "usage_records": [],
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
            _checkpoint_current()
            continue

        if progress and not verbose:
            print(
                f"[Phase7][LLM] {plab + ' ' if plab else ''}API 请求 step {i + 1}/{total_steps} "
                f"{from_name}->{to_name} ...",
                flush=True,
            )

        conversation, request_kwargs = build_chat_request(prompt, llm_settings)
        step_usage_before = len(usage_collect)
        t_step0 = time.perf_counter()
        request_summary = _redact_sensitive(
            {k: v for k, v in request_kwargs.items() if k != "messages"}
        )
        request_summary["messages"] = [
            {"role": str(m.get("role") or ""), "content_chars": len(str(m.get("content") or ""))}
            for m in conversation
        ]
        request_event: Dict[str, Any] = {
            "type": "step_request",
            "step_index": i + 1,
            "request_summary": request_summary,
        }
        if verbose:
            request_event["request_kwargs"] = _redact_sensitive(request_kwargs)
        _append_log(request_event)

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
            usage_collect=usage_collect,
        )
        step_elapsed = time.perf_counter() - t_step0
        step_usage_slice = usage_collect[step_usage_before:]
        step_usage = _sum_usage_rows(step_usage_slice)
        _append_log(
            {
                "type": "step_llm_metrics",
                "step_index": i + 1,
                "elapsed_sec": round(float(step_elapsed), 4),
                "usage": step_usage,
                "usage_raw": step_usage_slice,
            }
        )
        if progress and not verbose:
            print(
                f"[Phase7][LLM] step {i + 1}/{total_steps} 完成 "
                f"{step_elapsed:.2f}s tok={step_usage.get('total_tokens', 0)}",
                flush=True,
            )
        if not isinstance(result, dict) or not result:
            if verbose:
                print(f"[DeepDFS][LLM][Step {i+1}] 解析失败，result={result!r}")
            item = {
                "step_index": i + 1,
                "from": from_name,
                "from_va": from_va_s,
                "to": to_name,
                "to_va": to_va_s,
                "status": "llm_failed",
                "raw_result": result,
                "elapsed_sec": round(float(step_elapsed), 4),
                "usage": step_usage,
                "usage_records": step_usage_slice,
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
            _checkpoint_current()
            continue

        try:
            confidence = float(result.get("confidence", 0.0) or 0.0)
        except Exception:
            confidence = 0.0
        confidence = max(0.0, min(1.0, confidence))

        item = {
            "step_index": i + 1,
            "from": str(result.get("from") or from_name),
            "from_va": from_va_s,
            "to": str(result.get("to") or to_name),
            "to_va": to_va_s,
            "likely_initial_input": str(result.get("likely_initial_input") or "").strip(),
            "required_state_now": str(result.get("required_state_now") or "").strip(),
            "gate_condition": str(result.get("gate_condition") or "").strip(),
            "condition_relation_with_previous": str(result.get("condition_relation_with_previous") or "UNKNOWN").strip().upper(),
            "reasoning": str(result.get("reasoning") or "").strip(),
            "evidence": [str(x).strip() for x in (result.get("evidence") or []) if str(x).strip()],
            "confidence": confidence,
            "status": "ok",
            "elapsed_sec": round(float(step_elapsed), 4),
            "usage": step_usage,
            "usage_records": step_usage_slice,
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
        _checkpoint_current()

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

    run_ended = datetime.now(timezone.utc).isoformat()
    wall_sec = time.perf_counter() - t_run0
    total_usage = _sum_step_usage(step_results)
    all_usage_records: List[Dict[str, Any]] = []
    for step in step_results:
        for row in step.get("usage_records", []) or []:
            if isinstance(row, dict):
                all_usage_records.append(dict(row))
    timing_block = {
        "started_at": run_started,
        "ended_at": run_ended,
        "wall_time_sec": round(float(wall_sec), 4),
    }
    if progress and not verbose:
        print(
            f"[Phase7][LLM] {plab + ' ' if plab else ''}轮询结束 "
            f"wall={wall_sec:.2f}s tok={total_usage.get('total_tokens', 0)}",
            flush=True,
        )
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
        "timing": timing_block,
        "token_usage": total_usage,
        "usage_records": all_usage_records,
    }
    _append_log(
        {
            "type": "summary",
            "status": final_payload.get("status", "ok"),
            "timing": timing_block,
            "token_usage": final_payload.get("token_usage"),
            "result": final_payload,
        }
    )
    return final_payload
