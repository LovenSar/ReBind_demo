"""Phase 1: Unified knowledge propagation (LLM analysis).

Extracted from knowledge_propagation.py.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any, Dict, List, Optional

from kp.kp_ida import wait_for_ida_server
from kp.kp_llm import build_chat_request, call_llm_analyze_function
from kp.kp_sync import _extract_name_from_signature, _make_name_unique, _sync_with_ida_and_update_db
from kp.kp_types import DEFAULT_FUNC_NAME_PATTERN, UnifiedFunctionNode, UnifiedGraph
from kp.kp_unified_prompt import build_unified_batch_prompt, build_unified_prompt

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None


logger = logging.getLogger(__name__)


def _coerce_libfunction_flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(value) != 0
    if isinstance(value, str):
        s = value.strip().lower()
        return s in {"1", "true", "yes", "y", "lib", "libfunction"}
    return False


def _apply_unified_llm_result(
    *,
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    node: UnifiedFunctionNode,
    result: Dict[str, Any],
    ida_sync: bool = False,
    ida_url: Optional[str] = None,
) -> None:
    signature = str(result.get("signature", "")).strip() or None
    summary = str(result.get("summary", "")).strip() or None
    confidence = result.get("confidence")
    try:
        confidence_score = int(float(confidence) * 100) if confidence is not None else 0
    except (TypeError, ValueError):
        confidence_score = 0

    if signature and node.function_ids:
        raw_name = _extract_name_from_signature(signature, fallback="") or ""
        if raw_name:
            if DEFAULT_FUNC_NAME_PATTERN.fullmatch(raw_name):
                logger.info("[Phase1] entry_va=0x%08X LLM 返回默认风格函数名 %s，保留现有命名。", node.entry_va, raw_name)
            else:
                ref_fid = next(iter(node.function_ids))
                unique_name = _make_name_unique(conn, raw_name, ref_fid)
                if unique_name != raw_name:
                    logger.info("[Phase1] entry_va=0x%08X 函数名发生去重调整: %s -> %s", node.entry_va, raw_name, unique_name)
                signature = signature.replace(raw_name, unique_name)

    libfunction = _coerce_libfunction_flag(result.get("libfunction"))
    if libfunction:
        confidence_score = 0
        print("[LLM] 模型判断为库函数/运行时，跳过后续视图查找与同步。")
        logger.info("[Phase1] entry_va=0x%08X 被标记为库函数，设置为 LOCKED 并停止后续尝试。", node.entry_va)

    tags = result.get("tags") or []
    notes = result.get("notes") or ""

    print("\n[LLM RESULT]")
    print("signature:", signature)
    print("summary  :", summary)
    print("libfunction:", 1 if libfunction else 0)
    print("confidence_score:", confidence_score)
    if tags:
        print("tags     :", tags)
    if notes:
        print("notes    :", notes)

    cur = conn.cursor()
    analysis_state = "LOCKED" if libfunction else "ANALYZED"
    for fid in node.function_ids:
        cur.execute(
            """
            UPDATE analysis_status
            SET analysis_state = ?,
                confidence_score = ?,
                summary_signature = ?,
                semantic_summary = ?
            WHERE function_id = ?;
            """,
            (analysis_state, confidence_score, signature, summary, int(fid)),
        )
    conn.commit()

    if ida_sync and signature and requests is not None:
        try:
            _sync_with_ida_and_update_db(
                conn=conn,
                graph=graph,
                node=node,
                entry_va=node.entry_va,
                signature=signature,
                summary=summary or "",
                ida_url=ida_url or "http://127.0.0.1:12345",
                enforce_non_sub=False,
            )
        except Exception as exc:
            print(f"[IDA-Sync] 同步到 IDA 失败: {exc}")


def analyze_one_unified_function(
    *,
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entry_va: int,
    analysis_info: Dict[int, dict],
    llm_settings: Any,
    dry_run: bool = False,
    ida_sync: bool = False,
    ida_url: Optional[str] = None,
    max_disasm_lines: int = 200,
    max_pseudo_chars_per_tool: int = 4000,
    max_strings: int = 20,
) -> None:
    if ida_sync and ida_url:
        wait_for_ida_server(ida_url or "http://127.0.0.1:12345")

    node = graph.nodes[entry_va]
    prompt = build_unified_prompt(
        conn,
        graph,
        node,
        analysis_info,
        max_disasm_lines=max_disasm_lines,
        max_pseudo_chars_per_tool=max_pseudo_chars_per_tool,
        max_strings=max_strings,
    )
    conversation, request_kwargs = build_chat_request(prompt, llm_settings)

    print("=" * 80)
    print(
        f"[TARGET] entry_va=0x{node.entry_va:08X}, "
        f"names={','.join(sorted(node.names)) if node.names else '(unnamed)'}, "
        f"function_ids={sorted(node.function_ids)}"
    )

    if dry_run:
        print("\n[DRY-RUN] 本轮不会调用 LLM。以下是请求参数：\n")
        print(json.dumps(request_kwargs, ensure_ascii=False, indent=2))
        print("\n[DRY-RUN] 构造的 Prompt:\n")
        print(prompt)
        print("\n[DRY-RUN] 如需实际调用 LLM，请去掉 --dry-run 参数。")
        return

    result = call_llm_analyze_function(conversation=conversation, request_kwargs=request_kwargs, api_settings=llm_settings.api_settings)

    if not result:
        msg = "[LLM] 本物理函数 LLM 返回内容非法或多次尝试失败，保持 PENDING 状态以便后续重试。"
        print(msg)
        logger.warning("[Phase1] %s entry_va=0x%08X, function_ids=%s", msg, node.entry_va, sorted(node.function_ids))
        return

    _apply_unified_llm_result(conn=conn, graph=graph, node=node, result=result, ida_sync=ida_sync, ida_url=ida_url)


def analyze_unified_batch(
    *,
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    nodes: List[UnifiedFunctionNode],
    analysis_info: Dict[int, dict],
    llm_settings: Any,
    prompt: Optional[str] = None,
    estimated_tokens: Optional[int] = None,
    dry_run: bool = False,
    ida_sync: bool = False,
    ida_url: Optional[str] = None,
) -> None:
    if not nodes:
        return

    if prompt is None:
        prompt = build_unified_batch_prompt(conn, graph, nodes, analysis_info)

    conversation, request_kwargs = build_chat_request(prompt, llm_settings)

    print("=" * 80)
    target_list = ", ".join(f"0x{n.entry_va:08X}" for n in nodes)
    print(f"[TARGET-BATCH] size={len(nodes)} entries=[{target_list}]")
    if estimated_tokens is not None:
        print(f"[TARGET-BATCH] 预估 prompt tokens ≈ {estimated_tokens}, max_tokens={llm_settings.max_tokens}")

    if ida_sync and ida_url:
        wait_for_ida_server(ida_url or "http://127.0.0.1:12345")

    if dry_run:
        print("\n[DRY-RUN] 本轮不会调用 LLM。以下是请求参数：\n")
        print(json.dumps(request_kwargs, ensure_ascii=False, indent=2))
        print("\n[DRY-RUN] 构造的 Prompt:\n")
        print(prompt)
        print("\n[DRY-RUN] 如需实际调用 LLM，请去掉 --dry-run 参数。")
        return

    result_list = call_llm_analyze_function(
        conversation=conversation,
        request_kwargs=request_kwargs,
        api_settings=llm_settings.api_settings,
        expect_array=True,
        expected_size=len(nodes),
    )

    if not result_list or not isinstance(result_list, list):
        msg = "[LLM] 本批次返回内容非法或多次尝试失败，保持 PENDING 状态以便后续重试。"
        print(msg)
        logger.warning("[Phase1-Batch] %s targets=%s", msg, target_list)
        return

    for node, result in zip(nodes, result_list):
        if not isinstance(result, dict):
            logger.warning("[Phase1-Batch] 跳过 entry_va=0x%08X，原因：返回值不是对象：%r", node.entry_va, result)
            continue

        _apply_unified_llm_result(conn=conn, graph=graph, node=node, result=result, ida_sync=ida_sync, ida_url=ida_url)
