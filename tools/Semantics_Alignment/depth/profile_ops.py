"""depth/profile_ops.py

LLM 分析结果（Profile）的读写、比较与回填操作。

从 engine.py 拆分而来，封装：
- 备份 Profile 加载
- LLM 调用（带 trace 日志）
- 单节点语义分析
- Profile 比较与优选
- 回填 DB
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from kp.kp_llm import build_chat_request, call_llm_analyze_function
from kp.kp_sync import extract_func_name as _extract_name_from_signature
from kp.kp_types import UnifiedGraph, UnifiedFunctionNode
from kp.kp_unified_prompt import build_unified_prompt
from depth.goal_collector import _semantic_richness
from depth.run_management import _now_iso, _append_jsonl


# ──────────────────────────────────────────────────────────────────────────────
# 备份 Profile 加载
# ──────────────────────────────────────────────────────────────────────────────

def _load_backup_profile(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    analysis_info: Dict[int, dict],
    entry_va: int,
) -> Dict[str, Any]:
    """从 DB 加载指定函数的当前（旧）分析结果作为备份 Profile。"""
    va = int(entry_va)
    node = graph.nodes.get(va)
    if not node:
        return {"entry_va": f"0x{va:08X}", "exists": False}

    ida_names = sorted(node.names_by_tool.get("ida", set())) if node.names_by_tool else []
    default_name = ida_names[0] if ida_names else (sorted(node.names)[0] if node.names else f"sub_{va:08X}")

    chosen_info: Optional[dict] = None
    chosen_fid: Optional[int] = None
    ida_fids = [fid for fid in node.function_ids if str(graph.func_tool.get(int(fid), "")).lower() == "ida"]
    if ida_fids:
        for fid in ida_fids:
            info = analysis_info.get(int(fid))
            if info:
                chosen_info = info
                chosen_fid = int(fid)
                break
    if chosen_info is None:
        for fid in sorted(node.function_ids):
            info = analysis_info.get(int(fid))
            if info:
                chosen_info = info
                chosen_fid = int(fid)
                break

    profile = {
        "entry_va": f"0x{va:08X}",
        "name": default_name,
        "function_id": int(chosen_fid) if chosen_fid is not None else None,
        "analysis_state": str((chosen_info or {}).get("analysis_state") or "PENDING"),
        "summary_signature": str((chosen_info or {}).get("summary_signature") or ""),
        "semantic_summary": str((chosen_info or {}).get("semantic_summary") or ""),
        "structured_analysis": str((chosen_info or {}).get("structured_analysis") or ""),
        "confidence_score": int((chosen_info or {}).get("confidence_score") or 0),
        "annotation_status": int((chosen_info or {}).get("annotation_status") or 0),
    }

    if chosen_fid is not None:
        cur = conn.cursor()
        try:
            cur.execute(
                """
                SELECT function_id, analysis_state, confidence_score, summary_signature,
                       semantic_summary, phase1_pending, phase2_pending,
                       lvar_optimized, annotation_status, structured_analysis
                FROM analysis_status
                WHERE function_id = ?;
                """,
                (int(chosen_fid),),
            )
            row = cur.fetchone()
            if row:
                profile["analysis_status_row"] = {
                    "function_id": int(row[0]),
                    "analysis_state": row[1],
                    "confidence_score": int(row[2] or 0),
                    "summary_signature": row[3] or "",
                    "semantic_summary": row[4] or "",
                    "phase1_pending": int(row[5] or 0),
                    "phase2_pending": int(row[6] or 0),
                    "lvar_optimized": int(row[7] or 0),
                    "annotation_status": int(row[8] or 0),
                    "structured_analysis": row[9] or "",
                }
        except Exception:
            pass

    return profile


# ──────────────────────────────────────────────────────────────────────────────
# LLM 调用（带 trace 日志）
# ──────────────────────────────────────────────────────────────────────────────

def _redact_request_data(value: Any, key: str = "") -> Any:
    """递归脱敏请求参数，原始 LLM 日志也绝不写入认证信息。"""
    key_lower = str(key or "").lower()
    if any(token in key_lower for token in ("api_key", "authorization", "token", "secret", "password")):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(k): _redact_request_data(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_request_data(item) for item in value]
    return value


def _call_llm_with_trace(
    *,
    prompt: str,
    llm_settings: Any,
    max_attempts: int,
    llm_trace_file: Optional[Path],
    trace_label: str,
    trace_meta: Optional[Dict[str, Any]] = None,
    log_raw_llm: bool = False,
) -> Any:
    """调用 LLM 并把请求/响应摘要写入 trace JSONL。"""
    conversation, request_kwargs = build_chat_request(prompt, llm_settings)
    prompt_text = str(prompt or "")
    prompt_sha = hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()
    meta = dict(trace_meta or {})

    if llm_trace_file is not None:
        event: Dict[str, Any] = {
            "ts": _now_iso(),
            "stage": str(trace_label),
            "event": "request",
            "meta": meta,
            "model": str(getattr(llm_settings, "model", "")),
            "temperature": getattr(llm_settings, "temperature", None),
            "max_tokens": getattr(llm_settings, "max_tokens", None),
            "max_attempts": int(max(1, int(max_attempts or 1))),
            "prompt_chars": len(prompt_text),
            "prompt_sha256": prompt_sha,
        }
        if log_raw_llm:
            event["prompt"] = prompt_text
            event["conversation"] = conversation
            event["request_kwargs"] = _redact_request_data(request_kwargs)
        else:
            event["request_keys"] = sorted(request_kwargs.keys())
        _append_jsonl(llm_trace_file, event)

    raw_holder: Dict[str, str] = {"raw": ""}

    def _on_raw_text(raw: str) -> None:
        raw_holder["raw"] = str(raw or "")

    result = call_llm_analyze_function(
        conversation=conversation,
        request_kwargs=request_kwargs,
        api_settings=llm_settings.api_settings,
        max_attempts=max(1, int(max_attempts or 1)),
        on_raw_text=_on_raw_text if log_raw_llm else None,
    )

    if llm_trace_file is not None:
        response_event: Dict[str, Any] = {
            "ts": _now_iso(),
            "stage": str(trace_label),
            "event": "response",
            "meta": meta,
            "ok": isinstance(result, dict) and bool(result),
            "result_type": type(result).__name__,
        }
        if log_raw_llm:
            response_event["raw_text"] = raw_holder.get("raw", "")
            response_event["result"] = result
        else:
            if isinstance(result, dict):
                response_event["result_keys"] = sorted(result.keys())
            else:
                response_event["result_preview"] = str(result)[:240]
        _append_jsonl(llm_trace_file, response_event)

    return result


# ──────────────────────────────────────────────────────────────────────────────
# 单节点语义分析
# ──────────────────────────────────────────────────────────────────────────────

def _analyze_node_semantics_with_llm(
    *,
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    analysis_info: Dict[int, dict],
    entry_va: int,
    llm_settings: Any,
    max_attempts: int,
    dry_run: bool,
    llm_trace_file: Optional[Path] = None,
    log_raw_llm: bool = False,
) -> Dict[str, Any]:
    """对单个函数节点进行 LLM 语义分析，返回 profile 字典。"""
    va = int(entry_va)
    node = graph.nodes.get(va)
    if not node:
        return {"entry_va": f"0x{va:08X}", "status": "missing_node"}

    if dry_run:
        return {"entry_va": f"0x{va:08X}", "status": "dry_run"}

    prompt = build_unified_prompt(
        conn=conn,
        graph=graph,
        node=node,
        analysis_info=analysis_info,
        max_disasm_lines=180,
        max_pseudo_chars_per_tool=3200,
        max_strings=20,
    )
    result = _call_llm_with_trace(
        prompt=prompt,
        llm_settings=llm_settings,
        max_attempts=max_attempts,
        llm_trace_file=llm_trace_file,
        trace_label="analyze_node",
        trace_meta={"entry_va": f"0x{va:08X}"},
        log_raw_llm=bool(log_raw_llm),
    )
    if not isinstance(result, dict) or not result:
        return {"entry_va": f"0x{va:08X}", "status": "llm_failed", "raw": result}

    signature = str(result.get("signature") or "").strip()
    summary = str(result.get("summary") or "").strip()
    confidence = 0.0
    try:
        confidence = float(result.get("confidence", 0.0) or 0.0)
    except Exception:
        confidence = 0.0

    return {
        "entry_va": f"0x{va:08X}",
        "status": "ok",
        "name": _extract_name_from_signature(signature),
        "summary_signature": signature,
        "semantic_summary": summary,
        "structured_analysis": json.dumps(
            {
                "tags": result.get("tags") or [],
                "notes": result.get("notes") or "",
                "libfunction": result.get("libfunction", 0),
            },
            ensure_ascii=False,
        ),
        "confidence_score": int(max(0.0, min(1.0, confidence)) * 100.0),
        "raw": result,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Profile 比较与优选
# ──────────────────────────────────────────────────────────────────────────────

def _llm_compare_profiles(
    *,
    old_profile: Dict[str, Any],
    new_profile: Dict[str, Any],
    llm_settings: Any,
    max_attempts: int,
    dry_run: bool,
    llm_trace_file: Optional[Path] = None,
    log_raw_llm: bool = False,
) -> Dict[str, Any]:
    """让 LLM 比较同一函数的新旧两份 Profile，选择更优的一份。"""
    if dry_run:
        return {"status": "dry_run", "choose": "old", "old_score": 0.0, "new_score": 0.0, "reason": "dry_run"}

    prompt = (
        "你是二进制语义恢复裁决器。请比较同一函数的旧语义与新语义，选择更适合逆向分析的一方。\n"
        "比较时必须综合全部字段：name, summary_signature, semantic_summary, structured_analysis, confidence_score。\n"
        "只返回 JSON："
        "{\"choose\":\"old|new\",\"old_score\":0.0,\"new_score\":0.0,\"reason\":\"...\"}\n\n"
        f"[OLD]\n{json.dumps(old_profile, ensure_ascii=False, indent=2)}\n\n"
        f"[NEW]\n{json.dumps(new_profile, ensure_ascii=False, indent=2)}"
    )
    result = _call_llm_with_trace(
        prompt=prompt,
        llm_settings=llm_settings,
        max_attempts=max_attempts,
        llm_trace_file=llm_trace_file,
        trace_label="compare_profiles",
        trace_meta={"entry_va": str(old_profile.get("entry_va") or "")},
        log_raw_llm=bool(log_raw_llm),
    )
    if not isinstance(result, dict) or not result:
        return {"status": "llm_failed", "choose": "old", "old_score": 0.0, "new_score": 0.0, "reason": "llm_failed", "raw": result}

    choose = str(result.get("choose") or "old").strip().lower()
    if choose not in {"old", "new"}:
        choose = "old"

    def _f(v: Any) -> float:
        try:
            return float(v)
        except Exception:
            return 0.0

    return {
        "status": "ok",
        "choose": choose,
        "old_score": _f(result.get("old_score", 0.0)),
        "new_score": _f(result.get("new_score", 0.0)),
        "reason": str(result.get("reason") or ""),
        "raw": result,
    }


def _select_profile(
    old_profile: Dict[str, Any],
    new_profile: Dict[str, Any],
    compare_result: Dict[str, Any],
    *,
    min_delta: float,
) -> Dict[str, Any]:
    """根据 LLM 比较结果和最小分差阈值，决定选 old 还是 new。"""
    choose = str(compare_result.get("choose") or "old").strip().lower()
    old_score = float(compare_result.get("old_score", 0.0) or 0.0)
    new_score = float(compare_result.get("new_score", 0.0) or 0.0)

    selected = "old"
    if choose == "new" and (new_score - old_score) >= float(min_delta):
        selected = "new"

    selected_profile = dict(new_profile if selected == "new" else old_profile)
    return {
        "selected": selected,
        "selected_profile": selected_profile,
        "old_score": old_score,
        "new_score": new_score,
        "delta": round(new_score - old_score, 6),
        "threshold": float(min_delta),
    }


def _rank_nodes_for_compare(
    graph: UnifiedGraph,
    adjacency: Dict[int, Dict[int, Set[str]]],
    nodes: Iterable[int],
    goal_structs: Sequence[str],
    limit: int,
) -> List[int]:
    """对路径节点按丰富度排序，取 top-k 进行新旧 Profile 比较。"""
    scored: List[Tuple[int, int, int]] = []
    for va in set(int(x) for x in nodes if int(x) in graph.nodes):
        node = graph.nodes[int(va)]
        xref = len(adjacency.get(int(va), {}))
        rich = _semantic_richness(node, goal_structs)
        scored.append((int(xref), int(rich), int(va)))
    scored.sort(reverse=True)
    return [int(x[2]) for x in scored[: max(1, int(limit or 1))]]


# ──────────────────────────────────────────────────────────────────────────────
# 路径节点收集
# ──────────────────────────────────────────────────────────────────────────────

def _collect_path_nodes(paths: Sequence[Dict[str, Any]], parse_va_fn: Any) -> Set[int]:
    """从路径列表中提取所有节点的 entry_va。"""
    out: Set[int] = set()
    for p in paths:
        for s in p.get("path_vas", []) or []:
            try:
                out.add(int(parse_va_fn(str(s))))
            except Exception:
                continue
    return out


# ──────────────────────────────────────────────────────────────────────────────
# DB 回填
# ──────────────────────────────────────────────────────────────────────────────

def _profile_to_analysis_state(profile: Dict[str, Any]) -> str:
    """根据 profile 内容推断应写入 DB 的 analysis_state 值。"""
    structured = profile.get("structured_analysis")
    parsed_struct: Dict[str, Any] = {}
    if isinstance(structured, dict):
        parsed_struct = structured
    else:
        raw = str(structured or "").strip()
        if raw:
            try:
                import json as _json
                obj = _json.loads(raw)
                if isinstance(obj, dict):
                    parsed_struct = obj
            except Exception:
                parsed_struct = {}

    raw_lib = parsed_struct.get("libfunction", 0)
    try:
        is_lib = int(raw_lib) != 0
    except Exception:
        is_lib = bool(raw_lib)

    if is_lib:
        return "LOCKED"

    name = str(profile.get("name") or "").strip()
    signature = str(profile.get("summary_signature") or "").strip()
    if name and signature:
        return "ANALYZED"
    return "PENDING"


def _update_analysis_status_with_fallback(
    conn: sqlite3.Connection,
    function_id: int,
    profile: Dict[str, Any],
) -> str:
    """将 profile 写入 analysis_status 表，自动降级兼容旧 schema。

    Returns:
        使用的 schema 模式字符串（"full" / "no_phase_flags" / "basic"）。
    """
    import sqlite3 as _sqlite3

    fid = int(function_id)
    state = _profile_to_analysis_state(profile)
    try:
        confidence = int(profile.get("confidence_score", 0) or 0)
    except Exception:
        confidence = 0
    confidence = max(0, min(100, int(confidence)))
    signature = str(profile.get("summary_signature") or "")
    summary = str(profile.get("semantic_summary") or "")
    structured = str(profile.get("structured_analysis") or "")

    attempts: List[Tuple[str, str, Tuple[Any, ...]]] = [
        (
            "full",
            """
            UPDATE analysis_status
            SET analysis_state = ?,
                confidence_score = ?,
                summary_signature = ?,
                semantic_summary = ?,
                structured_analysis = ?,
                phase1_pending = 0,
                phase2_pending = 1,
                lvar_optimized = 0,
                annotation_status = 0
            WHERE function_id = ?;
            """,
            (state, confidence, signature, summary, structured, fid),
        ),
        (
            "no_phase_flags",
            """
            UPDATE analysis_status
            SET analysis_state = ?,
                confidence_score = ?,
                summary_signature = ?,
                semantic_summary = ?,
                structured_analysis = ?,
                annotation_status = 0
            WHERE function_id = ?;
            """,
            (state, confidence, signature, summary, structured, fid),
        ),
        (
            "basic",
            """
            UPDATE analysis_status
            SET analysis_state = ?,
                confidence_score = ?,
                summary_signature = ?,
                semantic_summary = ?
            WHERE function_id = ?;
            """,
            (state, confidence, signature, summary, fid),
        ),
    ]

    last_error: Optional[Exception] = None
    for schema_mode, sql, params in attempts:
        try:
            conn.execute(sql, params)
            return schema_mode
        except _sqlite3.OperationalError as exc:
            last_error = exc
            continue

    if last_error:
        raise last_error
    raise RuntimeError(f"update analysis_status failed for function_id={fid}")


def _apply_selected_profiles_to_db(
    conn: sqlite3.Connection,
    compare_items: Sequence[Dict[str, Any]],
    *,
    max_rows: int,
    min_confidence: int,
) -> Dict[str, Any]:
    """批量将 selected=new 的 Profile 回填到 analysis_status 表。"""
    planned: List[Dict[str, Any]] = []
    skipped: List[Dict[str, Any]] = []

    for item in compare_items:
        entry_va = str(item.get("entry_va") or "")
        old_profile = item.get("old_profile") if isinstance(item.get("old_profile"), dict) else {}
        new_profile = item.get("new_profile") if isinstance(item.get("new_profile"), dict) else {}
        selection = item.get("selection") if isinstance(item.get("selection"), dict) else {}

        selected = str(selection.get("selected") or "old").strip().lower()
        if selected != "new":
            skipped.append({"entry_va": entry_va, "reason": "selected_old"})
            continue

        if str(new_profile.get("status") or "").strip().lower() != "ok":
            skipped.append({"entry_va": entry_va, "reason": "new_profile_not_ok"})
            continue

        selected_profile = selection.get("selected_profile")
        if not isinstance(selected_profile, dict):
            selected_profile = dict(new_profile)

        fid_raw = selected_profile.get("function_id")
        if fid_raw is None:
            fid_raw = old_profile.get("function_id")
        try:
            fid = int(fid_raw)
        except Exception:
            skipped.append({"entry_va": entry_va, "reason": "missing_function_id"})
            continue

        selected_profile = dict(selected_profile)
        selected_profile["function_id"] = int(fid)
        try:
            confidence_score = int(selected_profile.get("confidence_score", 0) or 0)
        except Exception:
            confidence_score = 0
        confidence_score = max(0, min(100, int(confidence_score)))
        if confidence_score < int(min_confidence):
            skipped.append({"entry_va": entry_va, "reason": f"confidence_below_threshold({confidence_score}<{int(min_confidence)})"})
            continue

        planned.append({"entry_va": entry_va, "function_id": int(fid), "profile": selected_profile})

    max_rows = max(0, int(max_rows or 0))
    if max_rows > 0 and len(planned) > max_rows:
        for item in planned[max_rows:]:
            skipped.append({"entry_va": str(item.get("entry_va") or ""), "reason": f"apply_max_rows_limit({max_rows})"})
        planned = planned[:max_rows]

    if not planned:
        return {
            "enabled": True, "status": "skipped", "reason": "no_applicable_rows",
            "planned_count": 0, "applied_count": 0, "skipped_count": len(skipped),
            "applied_items": [], "skipped_items": skipped,
        }

    applied: List[Dict[str, Any]] = []
    try:
        conn.execute("BEGIN")
        for item in planned:
            entry_va = str(item.get("entry_va") or "")
            fid = int(item["function_id"])
            profile = item["profile"]
            schema_mode = _update_analysis_status_with_fallback(conn, fid, profile)
            applied.append({
                "entry_va": entry_va,
                "function_id": int(fid),
                "schema_mode": schema_mode,
                "analysis_state": _profile_to_analysis_state(profile),
                "confidence_score": int(max(0, min(100, int(profile.get("confidence_score", 0) or 0)))),
            })
        conn.commit()
    except Exception as exc:
        conn.rollback()
        return {
            "enabled": True, "status": "failed", "reason": "db_write_failed", "error": str(exc),
            "planned_count": len(planned), "applied_count": 0, "skipped_count": len(skipped),
            "applied_items": [], "skipped_items": skipped,
        }

    return {
        "enabled": True, "status": "applied", "reason": "ok",
        "planned_count": len(planned), "applied_count": len(applied), "skipped_count": len(skipped),
        "applied_items": applied, "skipped_items": skipped,
    }
