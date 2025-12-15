"""Phase 5: Deep annotation injection.

Injects per-line comments into pseudocode bodies (DB) and optionally syncs them
back to IDA via idat_server.

This module is extracted from knowledge_propagation.py to keep the entrypoint thin.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

from tqdm import tqdm

from kp.kp_config import _get_cfg_int, _get_cfg_section
from kp.kp_ida import wait_for_ida_server
from kp.kp_llm import build_chat_request, call_llm_analyze_function
from kp.kp_schema import ensure_analysis_rows_for_binary, ensure_analysis_schema, load_analysis_info
from kp.kp_types import UnifiedFunctionNode, UnifiedGraph, _count_effective_pseudocode_lines
from kp.kp_unified_prompt import _build_unified_prompt_body
from pmt import prompts as pmt_prompts

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None


logger = logging.getLogger(__name__)


def _sanitize_line_comment(text: Any) -> str:
    s = ("" if text is None else str(text)).strip()
    if not s:
        return ""
    s = re.sub(r"^\s*//+\s*", "", s)
    s = s.replace("\r", " ").replace("\n", " ").strip()
    if len(s) > 200:
        s = s[:200] + "..."
    codey_tokens = sum(1 for ch in s if ch in "{};()[]=<>")
    if codey_tokens >= 6 and len(s) > 60:
        return ""
    return s


def _normalize_line_comments_map(obj: Any) -> Dict[str, str]:
    if not isinstance(obj, dict) or not obj:
        return {}
    out: Dict[str, str] = {}
    for k, v in obj.items():
        try:
            idx = int(str(k).strip())
        except Exception:
            continue
        if idx <= 0:
            continue
        c = _sanitize_line_comment(v)
        if not c:
            continue
        out[str(idx)] = c
    return out


def _fetch_ida_function_snapshot(
    entry_va: int,
    ida_url: str,
    timeout_sec: float = 10.0,
) -> Optional[Dict[str, Any]]:
    if requests is None:
        return None
    try:
        resp = requests.post(
            ida_url,
            json={"action": "get_function_info", "ea": int(entry_va), "include_disasm": True},
            timeout=float(timeout_sec),
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if not isinstance(data, dict) or data.get("status") != "ok":
            return None
        return data
    except Exception:
        return None


def _append_line_comment(line: str, comment: str) -> str:
    if not comment:
        return line
    stripped = line.rstrip("\r\n")
    s = stripped.rstrip()
    if not s:
        return line
    if s in ("{", "}"):
        return line

    c = _sanitize_line_comment(comment)
    if not c:
        return line

    if "//" in s:
        return stripped + " | " + c
    return stripped + "  // " + c


def apply_line_comments_to_code(code: str, line_comments: Dict[str, Any]) -> str:
    if not code:
        return code
    if not isinstance(line_comments, dict) or not line_comments:
        return code

    lines = code.splitlines()

    normalized: Dict[int, str] = {}
    for k, v in line_comments.items():
        try:
            idx = int(str(k).strip())
        except Exception:
            continue
        if idx <= 0:
            continue
        normalized[idx] = _sanitize_line_comment(v)

    if not normalized:
        return code

    out: List[str] = []
    for i, ln in enumerate(lines, 1):
        comment = normalized.get(i, "")
        out.append(_append_line_comment(ln, comment))
    return "\n".join(out)


def _pick_preferred_pseudocode(node: UnifiedFunctionNode) -> Tuple[str, str]:
    if not node.pseudocodes:
        return "", ""

    def _find_by_tool(target: str) -> Optional[Tuple[str, str]]:
        for tool_name, code in node.pseudocodes.items():
            if (tool_name or "").lower() == target and (code or "").strip():
                return tool_name, code
        return None

    picked = _find_by_tool("ida") or _find_by_tool("ghidra")
    if picked:
        return picked

    for tool_name, code in sorted(node.pseudocodes.items(), key=lambda kv: (kv[0] or "")):
        if (code or "").strip():
            return tool_name, code
    return "", ""


def _build_annotation_context_summary(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    node: UnifiedFunctionNode,
    analysis_info: Dict[int, dict],
    max_disasm_lines: int = 60,
    max_pseudo_chars_per_tool: int = 1200,
    max_strings: int = 20,
) -> str:
    _display_name, body_lines = _build_unified_prompt_body(
        conn=conn,
        graph=graph,
        node=node,
        analysis_info=analysis_info,
        max_disasm_lines=max(0, int(max_disasm_lines or 0)),
        max_pseudo_chars_per_tool=max(0, int(max_pseudo_chars_per_tool or 0)),
        max_strings=max_strings,
    )

    kept: List[str] = []
    for line in body_lines:
        if line.startswith("\n[代表视图的函数反汇编"):
            break
        if line.startswith("\n[多视图伪代码"):
            break
        kept.append(line)

    text = "\n".join(kept).strip()
    return text or "(无额外上下文)"


def _pseudo_body_already_annotated(body: str) -> bool:
    if not body:
        return False
    head = body[:1500]
    return head.count("//") >= 3


def run_annotation_phase(
    *,
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    llm_settings: Any,
    ida_sync: bool,
    ida_url: str,
    semantics_config: Optional[Dict[str, Any]] = None,
    dry_run: bool = False,
    batch_size: int = 5,
    min_pseudo_lines: int = 6,
    max_code_chars: int = 8000,
) -> None:
    """Run Phase 5.

    Rule: only annotate functions whose effective pseudocode lines >= min_pseudo_lines.

    Writes:
    - pseudo_functions.body: append line comments
    - analysis_status.annotation_status: 1 success / 2 failed
    - analysis_status.structured_analysis: metadata JSON text (if provided)
    """

    _ = batch_size  # reserved

    min_pseudo_lines = _get_cfg_int(
        semantics_config,
        ("pipeline", "phase5_annotation", "min_pseudo_lines"),
        int(min_pseudo_lines),
    )
    max_code_chars = _get_cfg_int(
        semantics_config,
        ("pipeline", "phase5_annotation", "max_code_chars"),
        int(max_code_chars),
    )

    ann_ctx_max_disasm_lines = _get_cfg_int(
        semantics_config,
        ("pipeline", "prompt_limits", "annotation_context_max_disasm_lines"),
        60,
    )
    ann_ctx_max_pseudo_chars = _get_cfg_int(
        semantics_config,
        ("pipeline", "prompt_limits", "annotation_context_max_pseudo_chars_per_tool"),
        1200,
    )
    ann_ctx_max_strings = _get_cfg_int(
        semantics_config,
        ("pipeline", "prompt_limits", "annotation_context_max_strings"),
        20,
    )
    ida_snapshot_max_disasm = _get_cfg_int(
        semantics_config,
        ("pipeline", "prompt_limits", "ida_snapshot_max_disasm_lines"),
        400,
    )

    llm_single_max_lines = _get_cfg_int(
        semantics_config,
        ("pipeline", "phase5_annotation", "llm_chunking", "single_max_lines"),
        80,
    )
    llm_medium_max_lines = _get_cfg_int(
        semantics_config,
        ("pipeline", "phase5_annotation", "llm_chunking", "medium_max_lines"),
        160,
    )
    llm_medium_chunk_size = _get_cfg_int(
        semantics_config,
        ("pipeline", "phase5_annotation", "llm_chunking", "medium_chunk_size"),
        120,
    )
    llm_large_chunk_size = _get_cfg_int(
        semantics_config,
        ("pipeline", "phase5_annotation", "llm_chunking", "large_chunk_size"),
        80,
    )

    ida_sync_chunk_size = _get_cfg_int(
        semantics_config,
        ("pipeline", "phase5_annotation", "ida_sync_chunk_size"),
        120,
    )

    if ida_sync and ida_url:
        wait_for_ida_server(ida_url)

    ensure_analysis_schema(conn)
    ensure_analysis_rows_for_binary(conn, graph.binary_id)

    analysis_info = load_analysis_info(conn)
    cur = conn.cursor()

    entry_candidates: List[Tuple[int, int]] = []
    for entry_va, node in graph.nodes.items():
        _tool, code = _pick_preferred_pseudocode(node)
        code = (code or "").strip()
        if not code:
            continue

        eff_lines = _count_effective_pseudocode_lines(code)
        if min_pseudo_lines and eff_lines < int(min_pseudo_lines):
            continue

        any_pending = False
        for fid in node.function_ids:
            info = analysis_info.get(int(fid)) or {}
            if int(info.get("annotation_status", 0) or 0) == 0:
                any_pending = True
                break
        if not any_pending:
            continue

        entry_candidates.append((int(entry_va), int(eff_lines)))

    if not entry_candidates:
        print("[Phase 5] 没有需要注释的函数。")
        return

    entry_candidates.sort(key=lambda x: int(x[1] or 0), reverse=True)
    print(
        f"[Phase 5] 启动逐行伪代码注释注入：候选 {len(entry_candidates)} 个物理函数 "
        f"(min_pseudo_lines={min_pseudo_lines})"
    )

    pbar = tqdm(total=len(entry_candidates), desc="Phase 5: Annotation", unit="func")

    for entry_va, eff_lines in entry_candidates:
        node = graph.nodes.get(int(entry_va))
        if not node:
            pbar.update(1)
            continue

        pending_fids: List[int] = []
        for fid in sorted(int(x) for x in node.function_ids):
            info = analysis_info.get(int(fid)) or {}
            if int(info.get("annotation_status", 0) or 0) == 0:
                pending_fids.append(int(fid))

        if not pending_fids:
            pbar.update(1)
            continue

        tool_name, code = _pick_preferred_pseudocode(node)
        code = (code or "").strip()
        if not code:
            pbar.update(1)
            continue

        if min_pseudo_lines and _count_effective_pseudocode_lines(code) < int(min_pseudo_lines):
            pbar.update(1)
            continue

        if max_code_chars and len(code) > int(max_code_chars):
            code = code[: int(max_code_chars) - 3] + "..."

        display_name = "/".join(sorted(node.names)) if node.names else f"sub_{entry_va:08X}"
        pbar.set_description(f"Phase 5: 0x{entry_va:08X} (lines={eff_lines})")

        context_summary = _build_annotation_context_summary(
            conn=conn,
            graph=graph,
            node=node,
            analysis_info=analysis_info,
            max_disasm_lines=ann_ctx_max_disasm_lines,
            max_pseudo_chars_per_tool=ann_ctx_max_pseudo_chars,
            max_strings=ann_ctx_max_strings,
        )

        ida_snapshot: Optional[Dict[str, Any]] = None
        ida_numbered_code = code
        ida_disasm_text = ""
        ida_line_eas_text = ""
        ida_line_eas_payload: Dict[str, int] = {}

        if ida_sync and ida_url:
            ida_snapshot = _fetch_ida_function_snapshot(int(entry_va), ida_url)

        if isinstance(ida_snapshot, dict):
            pseudo_lines = ida_snapshot.get("pseudocode_lines")
            if isinstance(pseudo_lines, list) and pseudo_lines:
                lines_for_prompt: List[str] = []
                for item in pseudo_lines:
                    if not isinstance(item, dict):
                        continue
                    txt = str(item.get("text") or "")
                    lines_for_prompt.append(txt)
                    try:
                        no = int(item.get("no") or 0)
                        pea = int(item.get("ea") or 0)
                    except Exception:
                        no, pea = 0, 0
                    if no > 0 and pea > 0:
                        ida_line_eas_payload[str(no)] = int(pea)
                ida_numbered_code = "\n".join(lines_for_prompt).strip() or code

            line_eas_obj = ida_snapshot.get("line_eas")
            if isinstance(line_eas_obj, dict) and line_eas_obj:
                parts: List[str] = []
                for k, v in line_eas_obj.items():
                    try:
                        idx = int(str(k).strip())
                        vea = int(v)
                    except Exception:
                        continue
                    if idx <= 0 or vea <= 0:
                        continue
                    parts.append(f"{idx:03d}: 0x{vea:X}")
                if parts:
                    ida_line_eas_text = "\n".join(parts)

            disasm_obj = ida_snapshot.get("disassembly")
            if isinstance(disasm_obj, list) and disasm_obj:
                dparts: List[str] = []
                limit = max(0, int(ida_snapshot_max_disasm or 0))
                if limit <= 0:
                    limit = 400
                for ins in disasm_obj[:limit]:
                    if not isinstance(ins, dict):
                        continue
                    try:
                        dea = int(ins.get("ea") or 0)
                    except Exception:
                        dea = 0
                    txt = str(ins.get("text") or "").strip()
                    if not txt:
                        continue
                    if dea > 0:
                        dparts.append(f"0x{dea:X}: {txt}")
                    else:
                        dparts.append(txt)
                if dparts:
                    ida_disasm_text = "\n".join(dparts)

        all_lines = (ida_numbered_code or "").splitlines()
        chunk_size = 0
        if len(all_lines) > int(llm_medium_max_lines or 160):
            chunk_size = max(1, int(llm_large_chunk_size or 80))
        elif len(all_lines) > int(llm_single_max_lines or 80):
            chunk_size = max(1, int(llm_medium_chunk_size or 120))

        merged_line_comments: Dict[str, str] = {}
        metadata_obj: Dict[str, Any] = {}

        def _make_prompt(chunk_lines: List[str], start_line_no: int, include_extras: bool) -> str:
            base = int(start_line_no) if start_line_no > 0 else 1
            numbered = "\n".join(f"{(base + i - 1):03d}: {ln}" for i, ln in enumerate(chunk_lines, 1))

            extra_sections = ""
            if include_extras and ida_line_eas_text.strip():
                extra_sections += "\n\n[伪代码行号 -> 代表性地址(来自 IDA)]\n" + ida_line_eas_text.strip()
            if include_extras and ida_disasm_text.strip():
                extra_sections += "\n\n[最新反汇编(来自 IDA)]\n" + ida_disasm_text.strip()

            return pmt_prompts.line_annotation_prompt(
                node_name=f"{display_name} ({tool_name})",
                context_summary=context_summary,
                numbered_code=numbered,
                extra_sections=extra_sections,
            )

        if chunk_size == 0:
            prompt = _make_prompt(all_lines, 1, True)
            conversation, request_kwargs = build_chat_request(prompt, llm_settings)

            if dry_run:
                print("=" * 80)
                print(f"[Phase 5][DRY-RUN] entry_va=0x{entry_va:08X} name={display_name}")
                print(prompt)
                pbar.update(1)
                continue

            try:
                result = call_llm_analyze_function(
                    conversation=conversation,
                    request_kwargs=request_kwargs,
                    api_settings=llm_settings.api_settings,
                    return_raw_on_error=True,
                )
            except Exception as exc:
                logger.warning("[Phase 5] LLM 调用异常 entry_va=0x%08X: %s", entry_va, exc)
                result = {}

            if isinstance(result, dict) and "_raw_text" not in result:
                merged_line_comments = _normalize_line_comments_map(result.get("line_comments"))
                meta = result.get("metadata")
                if isinstance(meta, dict):
                    metadata_obj = meta
        else:
            total_chunks = (len(all_lines) + chunk_size - 1) // chunk_size
            for cidx in range(total_chunks):
                start = cidx * chunk_size
                end = min(len(all_lines), start + chunk_size)
                chunk_lines = all_lines[start:end]
                start_no = start + 1

                chunk_prompt = _make_prompt(chunk_lines, start_no, include_extras=(cidx == 0))
                conversation, request_kwargs = build_chat_request(chunk_prompt, llm_settings)

                if dry_run:
                    print("=" * 80)
                    print(
                        f"[Phase 5][DRY-RUN] entry_va=0x{entry_va:08X} name={display_name} "
                        f"chunk={cidx+1}/{total_chunks} lines={start_no}-{end}"
                    )
                    print(chunk_prompt)
                    continue

                try:
                    chunk_result = call_llm_analyze_function(
                        conversation=conversation,
                        request_kwargs=request_kwargs,
                        api_settings=llm_settings.api_settings,
                        return_raw_on_error=True,
                    )
                except Exception as exc:
                    logger.warning(
                        "[Phase 5] LLM 调用异常 entry_va=0x%08X chunk=%d/%d: %s",
                        entry_va,
                        cidx + 1,
                        total_chunks,
                        exc,
                    )
                    chunk_result = {}

                if not isinstance(chunk_result, dict) or "_raw_text" in chunk_result:
                    merged_line_comments = {}
                    break

                cmts = _normalize_line_comments_map(chunk_result.get("line_comments"))
                if cmts:
                    merged_line_comments.update(cmts)

                if not metadata_obj:
                    meta = chunk_result.get("metadata")
                    if isinstance(meta, dict):
                        metadata_obj = meta

            if dry_run:
                pbar.update(1)
                continue

        if not merged_line_comments:
            try:
                placeholders = ",".join("?" for _ in pending_fids)
                if placeholders:
                    cur.execute(
                        f"UPDATE analysis_status SET annotation_status = 2 WHERE function_id IN ({placeholders});",
                        tuple(pending_fids),
                    )
                    conn.commit()
            except Exception:
                pass
            pbar.update(1)
            continue

        structured_json = json.dumps(metadata_obj, ensure_ascii=False)

        try:
            updated_any = False
            for fid in pending_fids:
                cur.execute("SELECT body FROM pseudo_functions WHERE function_id = ? LIMIT 1;", (int(fid),))
                row = cur.fetchone()
                if not row:
                    continue
                body = row[0] or ""

                if min_pseudo_lines and _count_effective_pseudocode_lines(body) < int(min_pseudo_lines):
                    continue
                if _pseudo_body_already_annotated(body):
                    updated_any = True
                    continue

                new_body = apply_line_comments_to_code(body, merged_line_comments)
                cur.execute("UPDATE pseudo_functions SET body = ? WHERE function_id = ?;", (new_body, int(fid)))
                updated_any = True

            placeholders = ",".join("?" for _ in pending_fids)
            if placeholders:
                cur.execute(
                    f"""
                    UPDATE analysis_status
                    SET annotation_status = 1,
                        structured_analysis = ?
                    WHERE function_id IN ({placeholders});
                    """,
                    (structured_json, *tuple(pending_fids)),
                )

            conn.commit()

            for fid in pending_fids:
                if int(fid) in analysis_info:
                    analysis_info[int(fid)]["annotation_status"] = 1

            if not updated_any:
                logger.info(
                    "[Phase 5] entry_va=0x%08X 没有可更新的 pseudo_functions 记录，已仅写入 analysis_status。",
                    entry_va,
                )
        except Exception as exc:
            logger.warning("[Phase 5] 写库失败 entry_va=0x%08X: %s", entry_va, exc)
            try:
                placeholders = ",".join("?" for _ in pending_fids)
                if placeholders:
                    cur.execute(
                        f"UPDATE analysis_status SET annotation_status = 2 WHERE function_id IN ({placeholders});",
                        tuple(pending_fids),
                    )
                    conn.commit()
            except Exception:
                pass
            pbar.update(1)
            continue

        if ida_sync and ida_url and requests is not None:
            try:
                items: List[Tuple[int, str]] = []
                for k, v in (merged_line_comments or {}).items():
                    try:
                        ln = int(str(k).strip())
                    except Exception:
                        continue
                    if ln <= 0:
                        continue
                    txt = _sanitize_line_comment(v)
                    if not txt:
                        continue
                    items.append((ln, txt))
                items.sort(key=lambda x: x[0])

                if items:
                    chunk_n = max(1, int(ida_sync_chunk_size or 120))
                    total_chunks = (len(items) + chunk_n - 1) // chunk_n
                    for cidx in range(total_chunks):
                        part = items[cidx * chunk_n : (cidx + 1) * chunk_n]
                        if not part:
                            continue
                        part_comments: Dict[str, str] = {str(ln): txt for ln, txt in part}
                        part_line_eas: Dict[str, int] = {}
                        for ln, _txt in part:
                            ea_val = ida_line_eas_payload.get(str(ln))
                            if ea_val:
                                part_line_eas[str(ln)] = int(ea_val)

                        payload = {
                            "action": "set_pseudocode_line_comments",
                            "ea": int(entry_va),
                            "line_comments": part_comments,
                            "line_eas": part_line_eas,
                        }
                        resp = requests.post(ida_url, json=payload, timeout=10.0)
                        if resp.status_code != 200:
                            logger.info(
                                "[Phase 5] IDA 行注释同步 chunk=%d/%d HTTP %s: %s",
                                cidx + 1,
                                total_chunks,
                                resp.status_code,
                                (resp.text or "")[:200],
                            )
            except Exception as exc:
                logger.info(
                    "[Phase 5] IDA 行注释同步失败（可忽略） entry_va=0x%08X: %s",
                    entry_va,
                    exc,
                )

        pbar.update(1)

    pbar.close()
    print("[Phase 5] 注释阶段完成。")
