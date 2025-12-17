"""Phase 4: Local variable readability improvements.

This module is extracted from knowledge_propagation.py.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from typing import Any, Dict, List, Optional, Set, Tuple

from tqdm import tqdm

from dynamic_batching import yield_dynamic_batch
from kp.kp_config import _get_cfg_float, _get_cfg_int
from kp.kp_ida import wait_for_ida_server
from kp.kp_llm import build_chat_request, call_llm_analyze_function, estimate_token_usage
from kp.kp_schema import ensure_analysis_rows_for_binary, ensure_analysis_schema, load_analysis_info
from kp.kp_types import (
    DEFAULT_FUNC_NAME_PATTERN,
    SUBFUNC_NAME_PATTERN,
    UnifiedFunctionNode,
    UnifiedGraph,
    _count_effective_pseudocode_lines,
    _find_generic_lvar_names,
)

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None


logger = logging.getLogger(__name__)


def build_local_var_prompt(
    node: UnifiedFunctionNode,
    code: str,
    signature: str,
    summary: str,
) -> str:
    """Construct Phase4 single-function prompt."""
    display_name = "/".join(sorted(node.names)) if node.names else f"sub_{node.entry_va:08X}"

    prompt = f"""
你是一个代码重构专家。当前任务是优化反编译代码的可读性，重点是**重命名局部变量和函数参数**。

函数：{display_name}
Signature: {signature}
Summary: {summary}

[伪代码]
{code}

[任务]
1. **强制要求**：分析函数的形参（a1, a2, a3, arg1...），必须根据 Signature 和函数体内的使用方式赋予有意义的名字（如 env, packet_buf, size）。这是最高优先级。
2. **尽力而为**：分析函数内部局部变量（v1, v2, var_10...），根据逻辑上下文推断含义并重命名（如 index, status, temp_ptr）。
3. 请适度激进一些：
    - 如果 a1 明显是源缓冲区，可以重命名为 src_buf；
    - 如果 v5 明显是循环变量，可以重命名为 i 或 idx；
    - 如果 v8 接收了函数返回值并用于判断，可以重命名为 ret_val 或 status。
4. 如果变量名已经具有清晰语义（如 file_name、buffer_ptr），请不要修改它。
5. 如果确实无法推断任何变量含义，请返回空 JSON。

请严格返回 JSON 对象，格式为 \"旧名字\": \"新名字\" 的映射：
{{
  \"a1\": \"socket_fd\",
  \"a2\": \"buffer_ptr\",
  \"v5\": \"loop_idx\",
  \"v12\": \"bytes_received\"
}}
"""
    return prompt.strip()


def build_local_var_batch_prompt(items: List[Dict[str, Any]]) -> str:
    """Phase4 batch prompt (JSON array; order must match input)."""

    lines: List[str] = []
    lines.append("你是一个代码重构专家。当前任务是优化反编译代码的可读性。")
    lines.append("**核心原则：必须优先重命名函数形参（a1, a2...），其次尽力重命名内部变量（v1, v2...）。**")
    lines.append("请对以下多个函数分别给出变量重命名建议。返回一个 JSON 数组，长度必须等于条目数量，顺序完全一致。")
    lines.append("数组中每个元素格式：{\"entry_va\":\"0x...\",\"renames\":{\"old\":\"new\",...}}。")
    lines.append("若无法推断任何变量含义，请返回 renames 为 {}（空对象）。不要输出除 JSON 数组之外的任何文字。")

    for idx, item in enumerate(items, 1):
        node: UnifiedFunctionNode = item["node"]
        code = item.get("code", "") or ""
        signature = item.get("signature", "") or ""
        summary = item.get("summary", "") or ""
        display_name = "/".join(sorted(node.names)) if node.names else f"sub_{node.entry_va:08X}"

        lines.append(f"\n[Function {idx}/{len(items)}] {display_name} entry_va=0x{node.entry_va:08X}")
        lines.append(f"Signature: {signature}")
        lines.append(f"Summary: {summary}")
        lines.append("[Pseudocode]")
        lines.append(code)

    return "\n".join(lines)


def _prepare_lvar_candidate(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    node: UnifiedFunctionNode,
    analysis_info: Dict[int, dict],
    ida_sync: bool,
    allowed_fids: Optional[Set[int]] = None,
    min_pseudo_lines: int = 0,
    allow_unanalyzed: bool = False,
) -> Optional[Dict[str, Any]]:
    """Prepare a Phase4 candidate item."""

    preferred_tool = "ida" if ida_sync else None
    candidates: List[Dict[str, Any]] = []

    cur = conn.cursor()

    for fid in node.function_ids:
        if allowed_fids is not None and fid not in allowed_fids:
            continue

        info = analysis_info.get(fid) or {}
        state = (info.get("analysis_state") or "")
        if not allow_unanalyzed:
            if not info:
                continue
            if state not in ("ANALYZED", "LOCKED"):
                continue

        score = int(info.get("confidence_score", 0) or 0)
        tool_name = (graph.func_tool.get(fid, "") or "").lower()

        cur.execute("SELECT body FROM pseudo_functions WHERE function_id = ? LIMIT 1;", (int(fid),))
        row = cur.fetchone()
        if not row or not row[0]:
            continue
        code = row[0]
        line_cnt = _count_effective_pseudocode_lines(code)
        if min_pseudo_lines and line_cnt < int(min_pseudo_lines):
            continue

        signature = (info.get("summary_signature") or "") if info else ""
        summary = (info.get("semantic_summary") or "") if info else ""
        candidates.append(
            {
                "fid": int(fid),
                "score": score,
                "tool": tool_name,
                "signature": signature,
                "summary": summary,
                "code": code,
                "line_cnt": line_cnt,
            }
        )

    if not candidates:
        return None

    chosen: Optional[Dict[str, Any]] = None
    if preferred_tool:
        ida_candidates = [c for c in candidates if preferred_tool in (c.get("tool") or "")]
        if ida_candidates:
            ida_candidates.sort(
                key=lambda c: (int(c.get("score", 0) or 0), int(c.get("line_cnt", 0) or 0)),
                reverse=True,
            )
            chosen = ida_candidates[0]

    if chosen is None:
        candidates.sort(
            key=lambda c: (int(c.get("score", 0) or 0), int(c.get("line_cnt", 0) or 0)),
            reverse=True,
        )
        chosen = candidates[0]

    best_fid = int(chosen["fid"])
    best_conf = int(chosen.get("score", 0) or 0)
    signature = chosen.get("signature", "") or ""
    summary = chosen.get("summary", "") or ""
    original_code = chosen.get("code", "") or ""

    return {
        "node": node,
        "entry_va": node.entry_va,
        "best_fid": best_fid,
        "score": best_conf,
        "tool": chosen.get("tool") or "unknown",
        "signature": signature,
        "summary": summary,
        "code": original_code,
    }


def _clean_lvar_rename_map(rename_map: Dict[str, Any]) -> Dict[str, str]:
    clean_map: Dict[str, str] = {}
    for k, v in rename_map.items():
        if isinstance(k, str) and isinstance(v, str) and k != v:
            if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", v):
                clean_map[k] = v
    return clean_map


def apply_local_var_renames(code: str, rename_map: Dict[str, str]) -> str:
    """Apply rename_map to pseudocode text using word boundaries."""
    if not rename_map:
        return code

    new_code = code
    sorted_keys = sorted(rename_map.keys(), key=len, reverse=True)

    for old_name in sorted_keys:
        new_name = rename_map[old_name]
        if old_name == new_name:
            continue
        pattern = r"\b" + re.escape(old_name) + r"\b"
        new_code = re.sub(pattern, new_name, new_code)

    return new_code


def _sync_lvars_with_ida(entry_va: int, rename_map: Dict[str, str], ida_url: str) -> Optional[str]:
    """Sync local variable renames to IDA; return updated pseudocode if provided."""
    if requests is None or not rename_map:
        return None

    payload = {"action": "rename_lvar", "ea": entry_va, "renames": rename_map}

    try:
        resp = requests.post(ida_url, json=payload, timeout=10.0)
    except Exception as exc:
        logger.warning(f"[IDA-Sync-Lvar] 同步局部变量失败 0x{entry_va:08X}: {exc}")
        return None

    if resp.status_code != 200:
        logger.warning("[IDA-Sync-Lvar] HTTP %s when syncing lvars for 0x%08X: %s", resp.status_code, entry_va, resp.text[:200])
        return None

    try:
        data = resp.json()
    except Exception as exc:
        logger.warning("[IDA-Sync-Lvar] 解析 IDA 返回的 JSON 失败 0x%08X: %s; body=%s", entry_va, exc, resp.text[:200])
        return None

    if data.get("status") != "ok":
        logger.warning("[IDA-Sync-Lvar] IDA 返回错误 0x%08X: %s", entry_va, data)
        return None

    updated_code = data.get("updated_pseudocode")
    if isinstance(updated_code, str) and updated_code.strip():
        logger.info("[IDA-Sync-Lvar] 0x%08X 返回更新伪代码，长度=%d", entry_va, len(updated_code))
        return updated_code

    return None


def _save_and_refresh_pseudocode(entry_va: int, ida_url: str, wait_seconds: float = 1.0) -> Optional[str]:
    """Local copy: force-save and refresh pseudocode (kept for Phase4 persistence checks)."""
    if requests is None:
        return None
    try:
        requests.post(ida_url, json={"action": "save_database"}, timeout=15.0)
    except Exception:
        pass
    if wait_seconds and wait_seconds > 0:
        import time

        time.sleep(float(wait_seconds))

    try:
        resp = requests.post(ida_url, json={"action": "get_pseudocode", "ea": int(entry_va)}, timeout=10.0)
        if resp.status_code != 200:
            return None
        data = resp.json()
        if not isinstance(data, dict) or data.get("status") != "ok":
            return None
        code = data.get("pseudocode")
        return code if isinstance(code, str) else None
    except Exception:
        return None


def _verify_lvar_persistence(
    conn: sqlite3.Connection,
    function_id: int,
    entry_va: int,
    ida_url: str,
    rename_map: Dict[str, str],
    initial_code: Optional[str],
    max_retries: int = 3,
    wait_seconds: float = 1.0,
) -> Tuple[Optional[str], Set[str]]:
    """After sync, save IDB and refetch pseudocode to verify persistence."""
    latest_code = initial_code
    remaining = _find_generic_lvar_names(latest_code or "")

    if requests is None:
        return latest_code, remaining

    cur = conn.cursor()

    for attempt in range(1, max_retries + 1):
        refreshed = _save_and_refresh_pseudocode(entry_va, ida_url, wait_seconds)
        if refreshed:
            latest_code = refreshed
            cur.execute("UPDATE pseudo_functions SET body = ? WHERE function_id = ?;", (refreshed, function_id))
            conn.commit()

        remaining = _find_generic_lvar_names(latest_code or "")
        if not remaining:
            break

        if attempt < max_retries and rename_map:
            _sync_lvars_with_ida(entry_va, rename_map, ida_url)

    return latest_code, remaining


def _apply_lvar_result_for_candidate(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    item: Dict[str, Any],
    rename_map: Dict[str, Any],
    ida_sync: bool,
    ida_url: str,
    verify_max_retries: int = 3,
    verify_wait_seconds: float = 1.0,
) -> bool:
    """Apply Phase4 rename map for a candidate (with optional IDA sync + verify)."""

    node: UnifiedFunctionNode = item["node"]
    best_fid: int = int(item["best_fid"])
    original_code: str = item.get("code", "") or ""

    clean_map = _clean_lvar_rename_map(rename_map)
    changed = False
    total_renamed = 0
    updated_code: Optional[str] = None

    cur = conn.cursor()

    if not clean_map:
        print(f"[LVAR] 0x{node.entry_va:08X} LLM 未提供有效的重命名建议。")
    else:
        print(f"[LVAR] 0x{node.entry_va:08X} 应用重命名: {json.dumps(clean_map, ensure_ascii=False)}")
        new_code = apply_local_var_renames(original_code, clean_map)
        cur.execute("UPDATE pseudo_functions SET body = ? WHERE function_id = ?;", (new_code, best_fid))
        conn.commit()
        changed = True
        total_renamed = len(clean_map)

        if ida_sync and ida_url:
            updated = _sync_lvars_with_ida(node.entry_va, clean_map, ida_url)
            if updated:
                updated_code = updated
                cur.execute("UPDATE pseudo_functions SET body = ? WHERE function_id = ?;", (updated, best_fid))
                conn.commit()

    cur.execute("SELECT body FROM pseudo_functions WHERE function_id = ? LIMIT 1;", (best_fid,))
    row2 = cur.fetchone()
    if row2 and row2[0]:
        final_code = row2[0]
    else:
        if updated_code is not None:
            final_code = updated_code
        elif changed:
            final_code = new_code
        else:
            final_code = original_code

    remaining_generics = _find_generic_lvar_names(final_code or "")
    if changed and ida_sync and clean_map:
        verified_code, remaining_generics = _verify_lvar_persistence(
            conn=conn,
            function_id=best_fid,
            entry_va=node.entry_va,
            ida_url=ida_url,
            rename_map=clean_map,
            initial_code=final_code,
            max_retries=max(1, int(verify_max_retries or 1)),
            wait_seconds=float(verify_wait_seconds or 0.0),
        )
        if verified_code:
            final_code = verified_code

    mark_optimized = True
    try:
        cur.execute("UPDATE analysis_status SET lvar_optimized = ? WHERE function_id = ?;", (1 if mark_optimized else 0, best_fid))
        conn.commit()
    except Exception as exc:
        logger.warning("更新 lvar_optimized 状态失败 function_id=%s: %s", best_fid, exc)

    if remaining_generics:
        generic_list = sorted(remaining_generics)
        generic_preview = ", ".join(generic_list[:8]) + (", ..." if len(generic_list) > 8 else "")
    else:
        generic_preview = ""

    if changed:
        print(f"[LVAR] 0x{node.entry_va:08X} 局部变量重命名完成，共修改 {total_renamed} 个标识符，已标记为已检查。")
    else:
        if generic_preview:
            print(f"[LVAR] 0x{node.entry_va:08X} 未进行局部变量重命名，已标记为已检查。仍检测到默认变量名：{generic_preview}")
        else:
            print(f"[LVAR] 0x{node.entry_va:08X} 未进行局部变量重命名，已标记为已检查。")

    return changed


def analyze_local_var_batch(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    items: List[Dict[str, Any]],
    llm_settings: Any,
    ida_sync: bool,
    ida_url: str,
    ida_connect_max_wait_seconds: float = 120.0,
    verify_max_retries: int = 3,
    verify_wait_seconds: float = 1.0,
    dry_run: bool = False,
    prompt: Optional[str] = None,
) -> int:
    """Analyze a batch and apply renames; returns number of changed functions."""

    if not items:
        return 0

    if prompt is None:
        prompt = build_local_var_batch_prompt(items)
    conversation, request_kwargs = build_chat_request(prompt, llm_settings)

    print("=" * 80)
    print(f"[LVAR-BATCH] size={len(items)}")

    if dry_run:
        print("\n[LVAR-BATCH DRY-RUN] Prompt 预览：")
        print(prompt[:2000])
        return 0

    result_list = call_llm_analyze_function(
        conversation=conversation,
        request_kwargs=request_kwargs,
        api_settings=llm_settings.api_settings,
        expect_array=True,
        expected_size=len(items),
        return_raw_on_error=True,
    )

    if isinstance(result_list, dict) and "_raw_text" in result_list:
        raw_text = result_list.get("_raw_text", "")
        raw_err = result_list.get("_raw_error", "")
        print(
            "[LVAR-BATCH] JSON 解析失败，跳过该批次以便后续重试。\n"
            f"[LVAR-BATCH-ERROR] {raw_err}\n"
            f"[LVAR-BATCH-RAW]\n{'-' * 40}\n{raw_text}\n{'-' * 40}"
        )
        return 0

    if not result_list or not isinstance(result_list, list):
        return 0

    changed_count = 0

    ida_sync_active = bool(ida_sync)

    for item, res in zip(items, result_list):
        node: UnifiedFunctionNode = item["node"]
        entry_va = int(item.get("entry_va", node.entry_va))

        if not isinstance(res, dict):
            print(f"[LVAR] 0x{entry_va:08X} 跳过：返回值不是 JSON 对象。")
            continue

        if "renames" in res and isinstance(res.get("renames"), dict):
            renames_obj = res.get("renames")  # type: ignore[assignment]
        else:
            renames_obj = {k: v for k, v in res.items() if isinstance(k, str) and k != "entry_va"}

        if ida_sync_active and ida_url:
            ok = wait_for_ida_server(ida_url, max_wait_seconds=float(ida_connect_max_wait_seconds or 0.0) or None)
            if not ok:
                print(
                    f"[IDA-Sync] IDA 服务器不可用，跳过本批次后续的 IDA 同步（仅更新 DB）。"
                    f" ida_url={ida_url}, entry_va=0x{entry_va:08X}"
                )
                ida_sync_active = False

        changed = _apply_lvar_result_for_candidate(
            conn=conn,
            graph=graph,
            item=item,
            rename_map=renames_obj,
            ida_sync=ida_sync_active,
            ida_url=ida_url,
            verify_max_retries=verify_max_retries,
            verify_wait_seconds=verify_wait_seconds,
        )
        if changed:
            changed_count += 1

    return changed_count


def run_local_var_phase(
    *,
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    llm_settings: Any,
    ida_sync: bool,
    ida_url: str,
    semantics_config: Optional[Dict[str, Any]] = None,
    dry_run: bool = False,
    batch_size: int = 3,
    only_sub: bool = False,
    ida_only: bool = True,
    min_pseudo_lines: int = 6,
    exclude_import_export: bool = True,
) -> None:
    """Phase4 entry: optimize local variable names."""

    ida_connect_max_wait_seconds = _get_cfg_float(semantics_config, ("pipeline", "ida_sync", "connect_max_wait_seconds"), 120.0)

    ida_sync_active = bool(ida_sync)
    if ida_sync_active and ida_url:
        ok = wait_for_ida_server(ida_url, max_wait_seconds=float(ida_connect_max_wait_seconds or 0.0) or None)
        if not ok:
            print(
                f"[IDA-Sync] 启动阶段无法连接到 IDA 服务器，Phase4 将自动降级为离线模式（仅更新 DB）。 ida_url={ida_url}"
            )
            ida_sync_active = False

    ensure_analysis_schema(conn)
    ensure_analysis_rows_for_binary(conn, graph.binary_id)
    analysis_info = load_analysis_info(conn)

    cur = conn.cursor()
    cur.execute("SELECT function_id FROM analysis_status WHERE lvar_optimized = 1;")
    optimized_fids: Set[int] = {int(row[0]) for row in cur.fetchall()}

    def _ida_name_is_sub(entry_va: int) -> bool:
        node = graph.nodes.get(entry_va)
        if not node or not node.function_ids:
            return False

        placeholders = ",".join("?" for _ in node.function_ids)
        cur2 = conn.cursor()
        cur2.execute(
            f"""
            SELECT f.name, COALESCE(t.name, '') AS tool_name
            FROM functions AS f
            JOIN binary_views AS bv ON f.view_id = bv.id
            JOIN tools AS t ON bv.tool_id = t.id
            WHERE f.id IN ({placeholders});
            """,
            tuple(node.function_ids),
        )

        ida_seen = False
        for nm, tool_name in cur2.fetchall():
            tool_lower = (tool_name or "").lower()
            if tool_lower != "ida":
                continue
            ida_seen = True
            name = (nm or "").strip()
            if SUBFUNC_NAME_PATTERN.fullmatch(name):
                return True

        if ida_seen:
            return False

        if node.names:
            any_sub = any(SUBFUNC_NAME_PATTERN.fullmatch((n or "").strip()) for n in node.names)
            any_semantic = any(n and not DEFAULT_FUNC_NAME_PATTERN.fullmatch((n or "").strip()) for n in node.names)
            return bool(any_sub and not any_semantic)

        return False

    def _load_ida_phase4_eligible_fids() -> Dict[int, Set[int]]:
        cur0 = conn.cursor()
        cur0.execute(
            """
            SELECT f.entry_va,
                   f.id AS function_id,
                   pf.body,
                   COALESCE(s.kind, '') AS sym_kind,
                   COALESCE(s.source, '') AS sym_source,
                   COALESCE(s.is_external, 0) AS sym_is_external
            FROM functions AS f
            JOIN binary_views AS bv ON f.view_id = bv.id
            JOIN tools AS t ON bv.tool_id = t.id
            LEFT JOIN symbols AS s ON f.source_symbol_id = s.id
            LEFT JOIN pseudo_functions AS pf ON pf.function_id = f.id
            WHERE bv.binary_id = ? AND LOWER(t.name) = 'ida';
            """,
            (int(graph.binary_id),),
        )

        eligible: Dict[int, Set[int]] = {}
        for entry_va, fid, body, sym_kind, sym_source, sym_is_external in cur0.fetchall():
            entry_va_i = int(entry_va)
            fid_i = int(fid)
            code = body or ""
            if not code:
                continue

            if exclude_import_export:
                if (sym_kind or "").strip().lower() == "import":
                    continue
                if int(sym_is_external or 0) != 0:
                    continue
                if "export" in (sym_source or "").strip().lower():
                    continue

            if min_pseudo_lines and _count_effective_pseudocode_lines(code) < int(min_pseudo_lines):
                continue

            eligible.setdefault(entry_va_i, set()).add(fid_i)
        return eligible

    ida_eligible_fids_by_entry: Optional[Dict[int, Set[int]]] = None
    if ida_only:
        ida_eligible_fids_by_entry = _load_ida_phase4_eligible_fids()
        print(
            f"[Phase 4] IDA 过滤：eligible_entry={len(ida_eligible_fids_by_entry)} "
            f"(min_lines={min_pseudo_lines}, exclude_import_export={exclude_import_export})"
        )

    candidates: List[Tuple[int, int]] = []
    for entry_va, node in graph.nodes.items():
        max_score = 0
        already_optimized = False
        has_analyzed = False

        if ida_eligible_fids_by_entry is not None:
            allowed = ida_eligible_fids_by_entry.get(int(entry_va))
            if not allowed:
                continue
            for fid in allowed:
                if fid in optimized_fids:
                    already_optimized = True
                info = analysis_info.get(fid)
                if info:
                    max_score = max(max_score, info.get("confidence_score", 0))
                    if info.get("analysis_state") in ("ANALYZED", "LOCKED"):
                        has_analyzed = True
        else:
            for fid in node.function_ids:
                if fid in optimized_fids:
                    already_optimized = True
                info = analysis_info.get(fid)
                if info:
                    max_score = max(max_score, info.get("confidence_score", 0))
                    if info.get("analysis_state") in ("ANALYZED", "LOCKED"):
                        has_analyzed = True

        if only_sub and not _ida_name_is_sub(int(entry_va)):
            continue

        if already_optimized:
            continue

        if ida_eligible_fids_by_entry is not None:
            candidates.append((int(entry_va), int(max_score)))
        else:
            if has_analyzed:
                candidates.append((int(entry_va), int(max_score)))

    candidates.sort(key=lambda x: x[1], reverse=True)

    print(f"[Phase 4] Local Variable Renaming: 目标函数数量 {len(candidates)}")

    verify_max_retries = _get_cfg_int(semantics_config, ("pipeline", "phase4_lvar", "verify_max_retries"), 3)
    verify_wait_seconds = _get_cfg_float(semantics_config, ("pipeline", "phase4_lvar", "verify_wait_seconds"), 1.0)

    pbar = tqdm(total=len(candidates), desc="Phase 4: Local Vars", unit="func")

    processed_count = 0
    batch_target = max(1, int(batch_size) if batch_size else 1)
    prepared: List[Dict[str, Any]] = []

    def _builder(items: List[Dict[str, Any]]) -> str:
        return build_local_var_batch_prompt(items)

    for entry_va, score in candidates:
        node = graph.nodes[entry_va]
        pbar.set_description(f"Phase 4: 0x{entry_va:08X} (score={score})")

        allowed_fids: Optional[Set[int]] = None
        allow_unanalyzed = False
        min_lines = 0
        if ida_eligible_fids_by_entry is not None:
            allowed_fids = ida_eligible_fids_by_entry.get(int(entry_va))
            allow_unanalyzed = True
            min_lines = int(min_pseudo_lines or 0)

        item = _prepare_lvar_candidate(
            conn=conn,
            graph=graph,
            node=node,
            analysis_info=analysis_info,
            ida_sync=ida_sync_active,
            allowed_fids=allowed_fids,
            min_pseudo_lines=min_lines,
            allow_unanalyzed=allow_unanalyzed,
        )
        if item is None:
            pbar.update(1)
            continue

        prepared.append(item)

        if len(prepared) < batch_target:
            continue

        for batch in yield_dynamic_batch(
            prepared,
            prompt_builder=_builder,
            max_prompt_tokens=llm_settings.max_tokens,
            token_estimator=estimate_token_usage,
            initial_batch_size=len(prepared),
            min_batch_size=1,
        ):
            if batch.estimated_tokens > llm_settings.max_tokens and len(batch.items) == 1:
                logger.warning(
                    "[Phase4] 单函数 Prompt 预估已超过 max_tokens: estimated=%d, max=%d",
                    batch.estimated_tokens,
                    llm_settings.max_tokens,
                )

            changed_in_batch = analyze_local_var_batch(
                conn=conn,
                graph=graph,
                items=batch.items,
                llm_settings=llm_settings,
                ida_sync=ida_sync_active,
                ida_url=ida_url,
                ida_connect_max_wait_seconds=ida_connect_max_wait_seconds,
                verify_max_retries=verify_max_retries,
                verify_wait_seconds=verify_wait_seconds,
                dry_run=dry_run,
                prompt=batch.prompt,
            )
            processed_count += changed_in_batch
            pbar.update(len(batch.items))

        prepared = []

    if prepared:
        for batch in yield_dynamic_batch(
            prepared,
            prompt_builder=_builder,
            max_prompt_tokens=llm_settings.max_tokens,
            token_estimator=estimate_token_usage,
            initial_batch_size=len(prepared),
            min_batch_size=1,
        ):
            changed_in_batch = analyze_local_var_batch(
                conn=conn,
                graph=graph,
                items=batch.items,
                llm_settings=llm_settings,
                ida_sync=ida_sync_active,
                ida_url=ida_url,
                ida_connect_max_wait_seconds=ida_connect_max_wait_seconds,
                verify_max_retries=verify_max_retries,
                verify_wait_seconds=verify_wait_seconds,
                dry_run=dry_run,
                prompt=batch.prompt,
            )
            processed_count += changed_in_batch
            pbar.update(len(batch.items))

    pbar.close()
    print(f"[Phase 4] 完成，共优化了 {processed_count} 个函数的局部变量。")
