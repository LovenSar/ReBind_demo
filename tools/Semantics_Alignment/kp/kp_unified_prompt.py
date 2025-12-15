"""kp_unified_prompt.py

Unified (multi-view) prompt builders used by Phase1 and Phase5 context summary.

Moved out of the main entrypoint to keep `knowledge_propagation.py` thin and to
avoid circular imports when phases are split into separate modules.
"""

from __future__ import annotations

import sqlite3
from typing import Dict, List, Optional, Set, Tuple

from .kp_types import SUBFUNC_NAME_PATTERN, UnifiedFunctionNode, UnifiedGraph


def _build_unified_prompt_body(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    node: UnifiedFunctionNode,
    analysis_info: Dict[int, dict],
    max_disasm_lines: int = 200,
    max_pseudo_chars_per_tool: int = 4000,
    max_strings: int = 20,
) -> Tuple[str, List[str]]:
    """Collect the per-function context body reused by single/batch prompts."""

    cur = conn.cursor()

    # 1) analyzed callee summaries (grouped by entry_va)
    callee_summaries: List[str] = []
    for callee_va in sorted(node.internal_callee_vas):
        callee = graph.nodes.get(callee_va)
        if not callee:
            continue

        chosen_info: Optional[dict] = None
        for fid in callee.function_ids:
            info = analysis_info.get(fid)
            if info and info.get("analysis_state") in ("ANALYZED", "LOCKED"):
                chosen_info = info
                break
        if not chosen_info:
            continue

        callee_name = (
            next(iter(sorted(callee.names)), f"sub_{callee_va:08X}")
            if callee.names
            else f"sub_{callee_va:08X}"
        )
        sig = chosen_info.get("summary_signature") or ""
        summary = chosen_info.get("semantic_summary") or ""
        callee_summaries.append(
            f"- {callee_name} @ 0x{callee_va:08X}\n"
            f"  signature: {sig}\n"
            f"  summary  : {summary}"
        )

    # 2) external APIs
    ext_names = sorted(set(node.external_callee_names))

    # 3) strings
    string_texts: List[str] = []
    for raw in list(sorted(node.string_refs))[: max(0, int(max_strings or 0))]:
        clean = " ".join((raw or "").split())
        if len(clean) > 120:
            clean = clean[:117] + "..."
        string_texts.append(clean)

    # extra naming hints (when IDA is sub_ but DB has other names)
    name_hints: List[str] = []
    ida_has_sub = False
    if node.function_ids:
        placeholders = ",".join("?" for _ in node.function_ids)
        cur.execute(
            f"""
            SELECT f.name, COALESCE(t.name, '') AS tool_name
            FROM functions AS f
            JOIN binary_views AS bv ON f.view_id = bv.id
            JOIN tools AS t ON bv.tool_id = t.id
            WHERE f.id IN ({placeholders});
            """,
            tuple(node.function_ids),
        )
        for nm, tool_name in cur.fetchall():
            clean_name = (nm or "").strip()
            tool_lower = (tool_name or "").lower()
            if not clean_name:
                continue
            if tool_lower == "ida" and SUBFUNC_NAME_PATTERN.fullmatch(clean_name):
                ida_has_sub = True
                continue
            if not SUBFUNC_NAME_PATTERN.fullmatch(clean_name):
                name_hints.append(clean_name)

    if ida_has_sub and name_hints:
        unique_hints: List[str] = []
        seen_hint: Set[str] = set()
        for hint in name_hints:
            if hint in seen_hint:
                continue
            seen_hint.add(hint)
            unique_hints.append(hint)
            if len(unique_hints) >= 5:
                break
        string_texts.append("[DB hint] " + ", ".join(unique_hints))

    # 4) representative disasm
    disasm_text = ""
    if node.primary_function_id is not None:
        cur.execute(
            """
            SELECT index_in_function, raw_line
            FROM instructions
            WHERE function_id = ?
            ORDER BY index_in_function
            LIMIT ?;
            """,
            (node.primary_function_id, int(max_disasm_lines or 0)),
        )
        disasm_lines = [row[1] for row in cur.fetchall() if row[1]]
        disasm_text = "\n".join(disasm_lines)
    if not disasm_text:
        disasm_text = "(无可用反汇编指令，可能该函数为空或尚未导出。)"

    # 5) multi-view pseudocode
    if node.pseudocodes:
        decomp_sections: List[str] = []
        for tool_name, code in sorted(node.pseudocodes.items()):
            truncated = code
            if len(truncated) > int(max_pseudo_chars_per_tool or 0):
                truncated = truncated[: int(max_pseudo_chars_per_tool) - 3] + "..."
            decomp_sections.append(f"--- Decompilation from {tool_name} ---\n{truncated}")
        decompilation_text = "\n\n".join(decomp_sections)
    else:
        decompilation_text = "No decompilation available from any tool."

    display_name = "/".join(sorted(node.names)) if node.names else f"sub_{node.entry_va:08X}"

    lines: List[str] = []
    lines.append(
        f"当前物理函数：{display_name} @ 0x{node.entry_va:08X} "
        f"(instr_count={node.instr_count}, "
        f"internal_callees={len(node.internal_callee_vas)}, "
        f"external_apis={len(ext_names)}, "
        f"strings={len(string_texts)}, "
        f"views={len(node.function_ids)})"
    )

    if callee_summaries:
        lines.append("\n[已知子函数语义（跨视图统一）]\n" + "\n".join(callee_summaries))

    if ext_names:
        lines.append("\n[调用的外部 API / 导入函数（聚合自多个工具）]\n" + ", ".join(ext_names))

    if string_texts:
        lines.append(
            "\n[函数中引用的关键字符串示例（聚合自多个工具）]\n" + "\n".join(f"- {s}" for s in string_texts)
        )

    lines.append("\n[代表视图的函数反汇编（部分）]\n" + disasm_text)
    lines.append("\n[多视图伪代码（可能互相矛盾，请综合判断）]\n" + decompilation_text)

    return display_name, lines


def build_unified_prompt(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    node: UnifiedFunctionNode,
    analysis_info: Dict[int, dict],
    max_disasm_lines: int = 200,
    max_pseudo_chars_per_tool: int = 4000,
    max_strings: int = 20,
) -> str:
    display_name, body_lines = _build_unified_prompt_body(
        conn=conn,
        graph=graph,
        node=node,
        analysis_info=analysis_info,
        max_disasm_lines=max_disasm_lines,
        max_pseudo_chars_per_tool=max_pseudo_chars_per_tool,
        max_strings=max_strings,
    )

    lines: List[str] = []
    lines.append(
        "你是一个精通逆向工程和 C/C++ 的安全分析专家。"
        "现在你要在多视图（IDA + Ghidra 等）下，对同一个物理函数进行语义分析。"
    )
    lines.append(
        "不同反编译器可能存在各自的幻觉或错误，你需要对比多视图输出，"
        "抓住它们的一致部分，并利用上下文信息（字符串 / API / 已知子函数）推断真实语义。"
    )
    lines.append(
        "请额外判断该函数是否属于标准库/编译器运行时/纯导入包装：如果是，请在返回 JSON 中设置 libfunction=1，"
        "并在 summary/notes 中说明依据；若不是则设为 0 继续正常描述。"
    )
    lines.append(
        "【命名规则 - 重要】"
        "1. 绝对禁止返回 'sub_XXXX'、'fun_XXXX'、'loc_XXXX' 等无意义的默认地址命名；"
        "也不要使用 'func_xxx'、'fn_xxx'、'sub_xxx' 这类过于泛化、没有语义的信息。"
        "2. 必须根据伪代码逻辑推断有语义的函数名，例如 'parse_http_header'、'encrypt_aes_block'。"
        "3. 如果无法完全确定，请使用带有描述性的保守命名，如 'suspected_logging_helper'、'unknown_logic_buffer_process'。"
        "4. 函数名必须使用 snake_case（下划线命名法），并尽量体现具体职责。"
    )
    lines.append(
        "你最终必须只输出一个 JSON 对象，字段为："
        '{'
        '"signature": string, '
        '"summary": string, '
        '"confidence": number, '
        '"libfunction": 0 或 1, '
        '"tags": [string, ...], '
        '"notes": string'
        '}. '
        "不要输出多余文字，也不要使用 Markdown 代码块。"
    )

    lines.append("")
    lines.extend(body_lines)
    _ = display_name
    return "\n".join(lines)


def build_unified_batch_prompt(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    nodes: List[UnifiedFunctionNode],
    analysis_info: Dict[int, dict],
    max_disasm_lines: int = 200,
    max_pseudo_chars_per_tool: int = 4000,
    max_strings: int = 20,
) -> str:
    lines: List[str] = []
    lines.append("你是一个精通逆向工程和 C/C++ 的安全分析专家，现在需要一次性分析多个物理函数。")
    lines.append(
        "不同反编译器可能存在各自的幻觉或错误，你需要对比多视图输出，抓住一致的部分，结合上下文信息推断真实语义。"
    )
    lines.append(
        "请返回一个 JSON 数组，长度必须等于下方提供的函数数量，顺序完全一致。"
        "数组中每个元素的字段："
        '{'
        '"entry_va": "0x????????", '
        '"signature": string, '
        '"summary": string, '
        '"confidence": number, '
        '"libfunction": 0 或 1, '
        '"tags": [string, ...], '
        '"notes": string'
        '}. '
        "不要输出除 JSON 数组之外的任何文字或 Markdown。"
    )
    lines.append("若判断为标准库/编译器运行时/纯导入包装，请设置 libfunction=1 并在 summary/notes 中说明依据；否则设为 0。")
    lines.append(
        "【命名规则 - 重要】"
        "1. 绝对禁止返回 'sub_XXXX'、'fun_XXXX'、'loc_XXXX' 等无意义的默认地址命名；"
        "也不要使用 'func_xxx'、'fn_xxx'、'sub_xxx' 这类过于泛化、没有语义的信息。"
        "2. 必须根据伪代码逻辑推断有语义的函数名，例如 'parse_http_header'、'encrypt_aes_block'。"
        "3. 如果无法完全确定，请使用带有描述性的保守命名，如 'suspected_logging_helper'、'unknown_logic_buffer_process'。"
        "4. 函数名必须使用 snake_case（下划线命名法），并尽量体现具体职责。"
    )

    for idx, node in enumerate(nodes, 1):
        display_name, body_lines = _build_unified_prompt_body(
            conn=conn,
            graph=graph,
            node=node,
            analysis_info=analysis_info,
            max_disasm_lines=max_disasm_lines,
            max_pseudo_chars_per_tool=max_pseudo_chars_per_tool,
            max_strings=max_strings,
        )
        lines.append("")
        lines.append(f"[Function {idx}/{len(nodes)}] {display_name} entry_va=0x{node.entry_va:08X}")
        lines.extend(body_lines)

    return "\n".join(lines)
