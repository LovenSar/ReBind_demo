"""Phase 2: Top-down call-chain validation.

Extracted from knowledge_propagation.py.
"""

from __future__ import annotations

import heapq
import json
import logging
import re
import sqlite3
import sys
import time
from typing import Any, Dict, List, Optional, Set

from tqdm import tqdm

from dynamic_batching import yield_dynamic_batch
from kp.kp_ida import wait_for_ida_server
from kp.kp_llm import build_chat_request, call_llm_analyze_function, estimate_token_usage
from kp.kp_sync import _sync_with_ida_and_update_db
from kp.kp_types import DEFAULT_FUNC_NAME_PATTERN, UnifiedGraph, ValidationTask


logger = logging.getLogger(__name__)


def _get_any_function_id_for_va(graph: UnifiedGraph, entry_va: int) -> Optional[int]:
    node = graph.nodes.get(entry_va)
    if not node:
        return None
    ida_fids = [fid for fid in node.function_ids if graph.func_tool.get(fid, "").lower() == "ida"]
    if ida_fids:
        return ida_fids[0]
    return next(iter(node.function_ids)) if node.function_ids else None


def _get_entry_points_for_validation(conn: sqlite3.Connection, graph: UnifiedGraph, min_confidence: int = 80) -> List[int]:
    entry_vas: Set[int] = set()

    for va, node in graph.nodes.items():
        for name in node.names:
            lower = name.lower()
            if any(key in lower for key in ("main", "entry", "start")):
                entry_vas.add(va)
                break

    cur = conn.cursor()
    fid_to_va: Dict[int, int] = {}
    cur.execute("SELECT id, entry_va FROM functions;")
    for fid, entry_va in cur.fetchall():
        fid_to_va[int(fid)] = int(entry_va)

    cur.execute("SELECT function_id FROM analysis_status WHERE confidence_score >= ?;", (min_confidence,))
    for (fid,) in cur.fetchall():
        va = fid_to_va.get(int(fid))
        if va in graph.nodes:
            entry_vas.add(va)

    return sorted(entry_vas)


def _get_call_site_snippet(conn: sqlite3.Connection, graph: UnifiedGraph, caller_va: int, callee_names: Set[str], max_snippets: int = 3) -> str:
    node = graph.nodes.get(caller_va)
    if not node:
        return ""

    fid = _get_any_function_id_for_va(graph, caller_va)
    if fid is None:
        return ""

    cur = conn.cursor()
    cur.execute(
        "SELECT prototype, body FROM pseudo_functions WHERE function_id = ? ORDER BY id LIMIT 1;",
        (fid,),
    )
    row = cur.fetchone()
    if not row:
        return ""

    proto, body = row
    code = ((proto or "") + "\n" + (body or "")).strip()
    if not code:
        return ""

    lines = code.splitlines()
    snippets: List[str] = []
    callee_patterns = [re.escape(name) for name in callee_names if name]
    if not callee_patterns:
        return ""

    pattern = re.compile("|".join(callee_patterns))
    for idx, line in enumerate(lines):
        if pattern.search(line):
            start = max(0, idx - 1)
            end = min(len(lines), idx + 2)
            snippets.append("\n".join(lines[start:end]))
            if len(snippets) >= max_snippets:
                break

    return "\n...\n".join(snippets)


def build_validation_context(conn: sqlite3.Connection, graph: UnifiedGraph, entry_va: int) -> str:
    node = graph.nodes[entry_va]

    fid = _get_any_function_id_for_va(graph, entry_va)
    current_sig = ""
    current_summary = ""
    if fid is not None:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT summary_signature, semantic_summary
            FROM analysis_status
            WHERE function_id = ?;
            """,
            (fid,),
        )
        row = cur.fetchone()
        if row:
            current_sig = row[0] or ""
            current_summary = row[1] or ""

    display_name = next(iter(sorted(node.names)), f"sub_{entry_va:08X}") if node.names else f"sub_{entry_va:08X}"

    caller_snippets: List[str] = []
    for caller_va in sorted(node.caller_vas):
        snippet = _get_call_site_snippet(conn, graph, caller_va, node.names)
        caller_name = (
            next(iter(sorted(graph.nodes[caller_va].names)), f"sub_{caller_va:08X}")
            if caller_va in graph.nodes
            else f"sub_{caller_va:08X}"
        )
        if snippet:
            caller_snippets.append(f"[Caller {caller_name} @ 0x{caller_va:08X}]\n{snippet}")
        if len(caller_snippets) >= 5:
            break

    if not caller_snippets:
        caller_section = "(没有可用的调用者伪代码片段，用第一阶段结果作轻量校验。)"
    else:
        caller_section = "\n\n".join(caller_snippets)

    callee_lines: List[str] = []
    for callee_va in sorted(node.internal_callee_vas):
        callee = graph.nodes.get(callee_va)
        if not callee:
            continue
        callee_name = next(iter(sorted(callee.names)), f"sub_{callee_va:08X}") if callee.names else f"sub_{callee_va:08X}"
        callee_lines.append(f"- {callee_name} @ 0x{callee_va:08X}")
        if len(callee_lines) >= 8:
            break
    callee_section = "\n".join(callee_lines) if callee_lines else "(无内部调用或信息不足)"

    return (
        f"当前目标函数：{display_name} (@ 0x{entry_va:08X})\n\n"
        f"[第一阶段分析结果]\nSignature: {current_sig}\nSummary: {current_summary}\n\n"
        f"[调用者如何使用该函数（Caller Context）]\n{caller_section}\n\n"
        f"[该函数内部调用了哪些子函数（Callee List）]\n{callee_section}"
    ).strip()


def build_validation_prompt(conn: sqlite3.Connection, graph: UnifiedGraph, entry_va: int) -> str:
    context = build_validation_context(conn, graph, entry_va)
    prompt = f"""
你是一名进行“第二阶段 Top-down 校验”的逆向工程专家。

{context}

[任务]
1. 根据调用者的使用方式（参数含义、返回值用途等），评估当前名称 / Signature 是否合理。
2. 如果名称过于泛泛（如 sub_XXXXXX）、或与实际用途明显不符，请给出一个更精准的新名称。
3. 如果当前名称基本合理，可以选择确认。

请严格返回 JSON：
{{
  "action": "RENAME" 或 "CONFIRM",
  "new_name": "新的函数名（仅当 action 为 RENAME 时有效）",
  "confidence": 0.0 ~ 1.0,
  "reasoning": "简要说明你做出该判断的理由"
}}
"""
    return prompt.strip()


def build_validation_batch_prompt(conn: sqlite3.Connection, graph: UnifiedGraph, entry_vas: List[int]) -> str:
    lines: List[str] = []
    lines.append("你是一名进行‘第二阶段 Top-down 校验’的逆向工程专家。")
    lines.append("请对以下多个函数的命名/签名进行校验。返回一个 JSON 数组，长度必须等于条目数量，顺序完全一致。")
    lines.append('数组中每个对象字段：{"entry_va":"0x...","action":"RENAME"|"CONFIRM","new_name":"...","confidence":0.0-1.0,"reasoning":"..."}。')
    lines.append("仅当当前名称为默认风格(sub_/fun_/loc_)且你有更好建议时选择 RENAME。")

    for idx, va in enumerate(entry_vas, 1):
        ctx = build_validation_context(conn, graph, va)
        lines.append(f"\n[Item {idx}/{len(entry_vas)}] entry_va=0x{va:08X}\n{ctx}")

    return "\n".join(lines)


def _apply_validation_llm_result(conn: sqlite3.Connection, graph: UnifiedGraph, entry_va: int, result: Dict[str, Any], ida_sync: bool, ida_url: str) -> Optional[float]:
    node = graph.nodes[entry_va]
    display_name = next(iter(sorted(node.names)), f"sub_{entry_va:08X}") if node.names else f"sub_{entry_va:08X}"

    action = str(result.get("action", "")).strip().upper()
    new_name_raw = str(result.get("new_name", "")).strip()
    reasoning = str(result.get("reasoning", "")).strip()
    conf_val = result.get("confidence")
    try:
        confidence = float(conf_val) if conf_val is not None else 0.8
    except (TypeError, ValueError):
        confidence = 0.8

    current_name = display_name
    final_name = current_name

    if action == "RENAME" and new_name_raw:
        candidate = new_name_raw
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", candidate) and len(candidate) <= 255:
            final_name = candidate
        else:
            print("[VALIDATION] LLM 提议的新名称不符合标识符规范，忽略本次改名。")

    if final_name != current_name:
        print(f"[VALIDATION] 应用二次改名：{current_name} -> {final_name}")
        fid = _get_any_function_id_for_va(graph, entry_va)
        signature = ""
        if fid is not None:
            cur = conn.cursor()
            cur.execute("SELECT summary_signature FROM analysis_status WHERE function_id = ?;", (fid,))
            row = cur.fetchone()
            if row:
                signature = row[0] or ""

        if signature and current_name in signature:
            signature = signature.replace(current_name, final_name)

        _sync_with_ida_and_update_db(
            conn=conn,
            graph=graph,
            node=node,
            entry_va=entry_va,
            signature=signature,
            summary=f"[validation] {reasoning}",
            ida_url=ida_url,
        )

    cur = conn.cursor()
    for fid in node.function_ids:
        cur.execute("UPDATE analysis_status SET analysis_state = 'LOCKED' WHERE function_id = ?;", (int(fid),))
    conn.commit()

    return max(0.0, min(1.0, confidence))


def validate_one_function(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entry_va: int,
    llm_settings: Any,
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
    max_attempts: int = 3,
) -> Optional[float]:
    if ida_sync and ida_url:
        wait_for_ida_server(ida_url)

    node = graph.nodes[entry_va]
    display_name = next(iter(sorted(node.names)), f"sub_{entry_va:08X}") if node.names else f"sub_{entry_va:08X}"

    prompt = build_validation_prompt(conn, graph, entry_va)
    conversation, request_kwargs = build_chat_request(prompt, llm_settings)

    print("=" * 80)
    print(f"[VALIDATION] entry_va=0x{entry_va:08X}, name={display_name}")

    if dry_run:
        print("\n[VALIDATION DRY-RUN] 请求参数：")
        print(json.dumps(request_kwargs, ensure_ascii=False, indent=2))
        print("\n[VALIDATION DRY-RUN] Prompt 预览：")
        print(prompt[:2000])
        return 1.0

    result = call_llm_analyze_function(
        conversation=conversation,
        request_kwargs=request_kwargs,
        api_settings=llm_settings.api_settings,
        max_attempts=max_attempts,
    )

    if not result:
        print("[VALIDATION] 本函数在多次尝试后仍未获得合法 JSON，暂时跳过该节点。")
        return None

    return _apply_validation_llm_result(conn=conn, graph=graph, entry_va=entry_va, result=result, ida_sync=ida_sync, ida_url=ida_url)


def run_validation_phase(
    *,
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    llm_settings: Any,
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
    batch_size: int = 10,
) -> None:
    if ida_sync and ida_url:
        wait_for_ida_server(ida_url)

    entry_vas = _get_entry_points_for_validation(conn, graph)
    if not entry_vas:
        print("[Validation] 未找到合适的入口点，跳过第二阶段。")
        return

    print(f"[Validation] 入口点数量: {len(entry_vas)}")

    queue: List[ValidationTask] = []
    visited: Set[int] = set()

    cur = conn.cursor()

    def _is_locked(entry_va: int) -> bool:
        node = graph.nodes.get(entry_va)
        if not node or not node.function_ids:
            return False
        placeholders = ",".join("?" for _ in node.function_ids)
        cur.execute(
            f"""
            SELECT COUNT(*)
            FROM analysis_status
            WHERE analysis_state = 'LOCKED'
              AND function_id IN ({placeholders});
            """,
            tuple(node.function_ids),
        )
        (cnt,) = cur.fetchone()
        return cnt > 0

    for va in entry_vas:
        if va in visited:
            continue
        heapq.heappush(queue, ValidationTask(entry_va=va, priority=100.0, path_confidence=1.0))
        visited.add(va)

    initial_total = len(entry_vas)
    pbar = tqdm(total=initial_total, desc="Phase 2: Validation", unit="func") if initial_total > 0 else None

    processed = 0
    failed_primary: List[int] = []
    batch_target = max(1, int(batch_size) if batch_size else 1)

    while queue:
        to_validate: List[int] = []

        while queue and len(to_validate) < batch_target:
            task = heapq.heappop(queue)
            entry_va = task.entry_va

            if _is_locked(entry_va):
                node = graph.nodes.get(entry_va)
                if node:
                    posterior_conf = 0.9
                    for callee_va in node.internal_callee_vas:
                        if callee_va in visited or callee_va not in graph.nodes:
                            continue
                        visited.add(callee_va)
                        heapq.heappush(queue, ValidationTask(entry_va=callee_va, priority=posterior_conf * 100.0, path_confidence=posterior_conf))
                        if pbar is not None:
                            pbar.total += 1
                            pbar.refresh()
                if pbar is not None:
                    pbar.update(1)
                continue

            node = graph.nodes.get(entry_va)
            if not node:
                if pbar is not None:
                    pbar.update(1)
                continue

            current_name = next(iter(sorted(node.names)), f"sub_{entry_va:08X}") if node.names else f"sub_{entry_va:08X}"
            is_default_name = bool(DEFAULT_FUNC_NAME_PATTERN.fullmatch(current_name))

            if not is_default_name:
                posterior_conf = 1.0
                if pbar is not None:
                    pbar.update(1)

                if posterior_conf > 0.6:
                    for callee_va in node.internal_callee_vas:
                        if callee_va in visited or callee_va not in graph.nodes:
                            continue
                        visited.add(callee_va)
                        heapq.heappush(queue, ValidationTask(entry_va=callee_va, priority=posterior_conf * 100.0, path_confidence=posterior_conf))
                        if pbar is not None:
                            pbar.total += 1
                            pbar.refresh()
                continue

            to_validate.append(entry_va)

        if not to_validate:
            continue

        def _builder(vs: List[int]) -> str:
            return build_validation_batch_prompt(conn, graph, vs)

        for batch in yield_dynamic_batch(
            to_validate,
            prompt_builder=_builder,
            max_prompt_tokens=llm_settings.max_tokens,
            token_estimator=estimate_token_usage,
            initial_batch_size=len(to_validate),
            min_batch_size=1,
        ):
            if dry_run:
                for entry_va in batch.items:
                    node = graph.nodes.get(entry_va)
                    if pbar is not None:
                        pbar.update(1)
                    posterior_conf = 1.0
                    if not node or posterior_conf <= 0.6:
                        continue
                    for callee_va in node.internal_callee_vas:
                        if callee_va in visited or callee_va not in graph.nodes:
                            continue
                        visited.add(callee_va)
                        heapq.heappush(queue, ValidationTask(entry_va=callee_va, priority=posterior_conf * 100.0, path_confidence=posterior_conf))
                        if pbar is not None:
                            pbar.total += 1
                            pbar.refresh()
                continue

            conversation, request_kwargs = build_chat_request(batch.prompt, llm_settings)
            result_list = call_llm_analyze_function(
                conversation=conversation,
                request_kwargs=request_kwargs,
                api_settings=llm_settings.api_settings,
                expect_array=True,
                expected_size=len(batch.items),
                max_attempts=3,
            )

            if not result_list or not isinstance(result_list, list):
                for entry_va in batch.items:
                    failed_primary.append(entry_va)
                    if pbar is not None:
                        pbar.update(1)
                continue

            for entry_va, res in zip(batch.items, result_list):
                node = graph.nodes.get(entry_va)
                if pbar is not None:
                    pbar.update(1)

                if not node or not isinstance(res, dict):
                    failed_primary.append(entry_va)
                    continue

                posterior_conf = _apply_validation_llm_result(conn=conn, graph=graph, entry_va=entry_va, result=res, ida_sync=ida_sync, ida_url=ida_url)
                if posterior_conf is None:
                    failed_primary.append(entry_va)
                    continue

                processed += 1
                if posterior_conf <= 0.6:
                    continue

                for callee_va in node.internal_callee_vas:
                    if callee_va in visited or callee_va not in graph.nodes:
                        continue
                    visited.add(callee_va)
                    heapq.heappush(queue, ValidationTask(entry_va=callee_va, priority=posterior_conf * 100.0, path_confidence=posterior_conf))
                    if pbar is not None:
                        pbar.total += 1
                        pbar.refresh()

    if pbar is not None:
        pbar.close()

    print(f"[Validation] 第二阶段首次遍历共处理物理函数数量：{processed}")

    if not dry_run and failed_primary:
        still_failed: List[int] = []
        for entry_va in failed_primary:
            node = graph.nodes.get(entry_va)
            name = next(iter(sorted(node.names)), f"sub_{entry_va:08X}") if node and node.names else f"sub_{entry_va:08X}"
            print(f"\n[VALIDATION-RETRY] 针对首次失败的函数再次尝试：{name} @ 0x{entry_va:08X}")
            posterior_conf = validate_one_function(
                conn=conn,
                graph=graph,
                entry_va=entry_va,
                llm_settings=llm_settings,
                ida_sync=ida_sync,
                ida_url=ida_url,
                dry_run=dry_run,
                max_attempts=7,
            )
            if posterior_conf is None:
                still_failed.append(entry_va)

        if still_failed:
            print("\n[Validation] 以下函数在两轮校验中都未能获得合法 JSON 输出，已跳过，可考虑后续人工处理：")
            for entry_va in still_failed:
                node = graph.nodes.get(entry_va)
                name = next(iter(sorted(node.names)), f"sub_{entry_va:08X}") if node and node.names else f"sub_{entry_va:08X}"
                print(f"  - 0x{entry_va:08X} {name}")
