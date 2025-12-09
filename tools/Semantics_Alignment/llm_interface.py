#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
llm_interface.py

封装所有LLM交互逻辑,包括prompt构建和API调用。
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests  # type: ignore
except ImportError:
    requests = None

# 导入共享数据结构和配置
from common_utils import (
    LLMSettings,
    UnifiedFunctionNode,
    UnifiedGraph,
    GlobalVarNode,
    EMPTY_RESPONSE_RETRY_TIMEOUT,
    DEFAULT_API_KEY_ENV,
)

logger = logging.getLogger(__name__)


# =========================
# LLM API 客户端初始化
# =========================


def require_openai(api_settings: Dict[str, Any]) -> Any:
    """
    延迟导入 openai 并返回一个兼容 openai>=1.0.0 的 client；
    若检测到旧版 SDK，则回退到模块级 API。
    """
    try:
        import openai  # type: ignore
    except ImportError as exc:  # pragma: no cover - 依赖环境
        raise RuntimeError(
            "未安装 openai 库，请先执行：pip install openai"
        ) from exc

    api_key_env = api_settings.get("key_env_var") or DEFAULT_API_KEY_ENV
    api_key = os.environ.get(api_key_env)
    if not api_key:
        raise RuntimeError(
            f"环境变量 {api_key_env} 未设置，无法调用 OpenAI LLM。"
        )

    # 新版 openai (>=1.0.0): 使用 OpenAI 客户端
    if hasattr(openai, "OpenAI"):
        client_kwargs: Dict[str, Any] = {"api_key": api_key}
        base_url = api_settings.get("base_url")
        if base_url:
            client_kwargs["base_url"] = base_url
        organization = api_settings.get("organization")
        if organization:
            client_kwargs["organization"] = organization
        # 其他字段（如 proxy）由上游 requests 处理，这里不强行映射
        return openai.OpenAI(**client_kwargs)  # type: ignore[attr-defined]

    # 旧版 openai (<1.0.0): 保持向后兼容
    openai.api_key = api_key  # type: ignore[attr-defined]

    attr_map: Dict[str, str] = {
        "base_url": "api_base",
        "type": "api_type",
        "version": "api_version",
        "organization": "organization",
        "proxy": "proxy",
    }
    for config_key, attr_name in attr_map.items():
        value = api_settings.get(config_key)
        if value:
            setattr(openai, attr_name, value)  # type: ignore[attr-defined]

    return openai


# =========================
# Prompt 构建函数
# =========================


def _build_name_alignment_prompt(
    entry_va: int,
    db_name: str,
    ida_name: str,
    db_code: str,
    ida_code: str,
) -> str:
    """构造提示，要求 LLM 在 DB 与 IDA 命名/伪代码差异时选择更可信的名字来源。"""
    db_preview = (db_code or "").strip()
    ida_preview = (ida_code or "").strip()
    if len(db_preview) > 1200:
        db_preview = db_preview[:1200] + "..."
    if len(ida_preview) > 1200:
        ida_preview = ida_preview[:1200] + "..."

    prompt = f"""
你是一名逆向工程专家，现在需要对同一个函数在对齐数据库与 IDA .i64 中的差异进行裁决，并给出最终的函数名来源。

函数地址: 0x{entry_va:08X}

[数据库视图]
name: {db_name}
code:
{db_preview}

[IDA 视图]
name: {ida_name}
code:
{ida_preview}

任务：
1) 在两个候选名字中选择更可信的最终名字（通常更有语义的名字更好；如果其中一个是 sub_ 前缀，优先另一个；如两者都为 sub_，可保留更稳定的形式）。
2) 判断伪代码应以哪个来源为准（db 或 ida），考虑可读性与完整性。

请只返回一个 JSON 对象：
{{
  "final_name": "...",
  "source": "db" 或 "ida"  // 表示伪代码以哪个来源为准
}}
不要输出其他文字。
"""
    return prompt.strip()


def build_prompt_for_function(
    conn: sqlite3.Connection,
    graph: Any,  # FunctionGraph
    node: Any,  # FunctionNode
    analysis_info: Dict[int, dict],
    max_disasm_lines: int = 200,
    max_pseudo_chars: int = 4000,
    max_strings: int = 20,
) -> str:
    """
    构造发给 LLM 的 Prompt。

    内容包括：
      - 当前函数的基本信息（名称、地址、指令数）；
      - 已知子函数（ANALYZED/LOCKED）的签名 + 语义摘要；
      - 外部 API 调用列表；
      - 该函数引用的字符串（做适当截断）；
      - 反汇编文本（部分）；
      - 伪代码（如果存在）。
    """
    cur = conn.cursor()

    # 1) 已分析的子函数信息
    callee_summaries: List[str] = []
    for callee_id in sorted(node.internal_callees):
        info = analysis_info.get(callee_id)
        if not info:
            continue
        if info.get("analysis_state") not in ("ANALYZED", "LOCKED"):
            continue
        callee = graph.functions.get(callee_id)
        if not callee:
            continue
        sig = info.get("summary_signature") or ""
        summary = info.get("semantic_summary") or ""
        callee_summaries.append(
            f"- {callee.name} @ 0x{callee.entry_va:08X}\n"
            f"  signature: {sig}\n"
            f"  summary  : {summary}"
        )

    # 2) 外部 API 调用信息
    ext_names: List[str] = []
    for sid in sorted(node.external_callees):
        nm = graph.symbol_names.get(sid)
        if nm:
            ext_names.append(nm)
    # 加入无法解析为 symbol 的名字
    for nm in sorted(node.external_callee_names):
        if nm and nm not in {e.lower() for e in ext_names}:
            ext_names.append(nm)

    # 3) 字符串引用
    string_texts: List[str] = []
    for sid in list(sorted(node.string_ids))[:max_strings]:
        val = graph.string_values.get(sid)
        if not val:
            continue
        # 简单清洗，避免换行过多
        clean = " ".join(val.split())
        if len(clean) > 120:
            clean = clean[:117] + "..."
        string_texts.append(clean)

    # 4) 反汇编文本
    cur.execute(
        """
        SELECT index_in_function, raw_line
        FROM instructions
        WHERE function_id = ?
        ORDER BY index_in_function
        LIMIT ?;
        """,
        (node.id, max_disasm_lines),
    )
    disasm_lines = [row[1] for row in cur.fetchall() if row[1]]
    disasm_text = "\n".join(disasm_lines)

    # 5) 伪代码（如果有）
    cur.execute(
        """
        SELECT prototype, body
        FROM pseudo_functions
        WHERE function_id = ?
        ORDER BY id
        LIMIT 1;
        """,
        (node.id,),
    )
    row = cur.fetchone()
    pseudo_text = ""
    if row:
        proto, body = row
        proto = proto or ""
        body = body or ""
        pseudo_text = proto + "\n" + body
        if len(pseudo_text) > max_pseudo_chars:
            pseudo_text = pseudo_text[: max_pseudo_chars - 3] + "..."

    # 6) 组合 Prompt（中文说明 + 英文结构，便于 LLM 理解）
    lines: List[str] = []
    lines.append(
        "你是一个精通逆向工程和 C/C++ 的安全分析专家。"
        "现在请你根据给定的反汇编和伪代码，对一个函数进行语义分析。"
    )
    lines.append(
        "请重点利用以下信息："
        "1) 已经确认语义的子函数；"
        "2) 调用的外部 API；"
        "3) 函数中出现的关键字符串；"
        "再结合反汇编 / 伪代码，推断当前函数的功能、输入输出、重要副作用。"
    )
    lines.append(
        "请额外判断该函数是否属于标准库/编译器运行时/纯导入包装。如果是，请在返回 JSON 中设置 libfunction=1，"
        "并可在 summary/notes 中简述原因；否则设为 0 继续给出正常分析。"
    )
    lines.append(
        "你最终只需输出一个 JSON 对象，字段为："
        '{'
        '"signature": string, '
        '"summary": string, '
        '"confidence": number, '
        '"libfunction": 0 或 1, '
        '"tags": [string, ...], '
        '"notes": string'
        '}. '
        "如果该函数是标准库/运行时/纯导入包装，请将 libfunction 设为 1，否则设为 0。"
        "不要输出多余文字，也不要使用 Markdown 代码块。"
    )

    lines.append("")
    lines.append(
        f"当前函数：{node.name} @ 0x{node.entry_va:08X} "
        f"(instr_count={node.instr_count}, "
        f"internal_callees={len(node.internal_callees)}, "
        f"external_apis={len(ext_names)}, "
        f"strings={len(string_texts)})"
    )

    if callee_summaries:
        lines.append("\n[已知子函数语义]\n" + "\n".join(callee_summaries))

    if ext_names:
        lines.append("\n[调用的外部 API / 导入函数]\n" + ", ".join(sorted(set(ext_names))))

    if string_texts:
        lines.append("\n[函数中引用的关键字符串示例]\n" + "\n".join(f"- {s}" for s in string_texts))

    lines.append("\n[函数反汇编（部分）]\n" + disasm_text)

    if pseudo_text.strip():
        lines.append(
            "\n[反编译得到的伪代码（可能不完全正确，仅作参考）]\n"
            + pseudo_text
        )

    return "\n".join(lines)


def build_unified_prompt(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    node: UnifiedFunctionNode,
    analysis_info: Dict[int, dict],
    max_disasm_lines: int = 200,
    max_pseudo_chars_per_tool: int = 4000,
    max_strings: int = 20,
) -> str:
    """
    为跨视图统一节点构造 Prompt：
      - 聚合 Ghidra / IDA 的伪代码，多视图并列展示；
      - 使用统一的字符串 / 外部 API / 内部调用信息；
      - 使用"已知子函数"的签名和摘要作为知识传播的输入。
    """
    cur = conn.cursor()

    # 1) 已分析的子函数语义（按 entry_va 聚合）
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

        callee_name = next(iter(sorted(callee.names)), f"sub_{callee_va:08X}") if callee.names else f"sub_{callee_va:08X}"
        sig = chosen_info.get("summary_signature") or ""
        summary = chosen_info.get("semantic_summary") or ""
        callee_summaries.append(
            f"- {callee_name} @ 0x{callee_va:08X}\n"
            f"  signature: {sig}\n"
            f"  summary  : {summary}"
        )

    # 2) 外部 API 调用信息（聚合后去重）
    ext_names = sorted(set(node.external_callee_names))

    # 3) 字符串引用（取若干条，做简单清洗）
    string_texts: List[str] = []
    for raw in list(sorted(node.string_refs))[:max_strings]:
        clean = " ".join((raw or "").split())
        if len(clean) > 120:
            clean = clean[:117] + "..."
        string_texts.append(clean)

    # 4) 代表视图的反汇编文本
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
            (node.primary_function_id, max_disasm_lines),
        )
        disasm_lines = [row[1] for row in cur.fetchall() if row[1]]
        disasm_text = "\n".join(disasm_lines)
    if not disasm_text:
        disasm_text = "(无可用反汇编指令，可能该函数为空或尚未导出。)"

    # 5) 多视图伪代码对比
    if node.pseudocodes:
        decomp_sections: List[str] = []
        for tool_name, code in sorted(node.pseudocodes.items()):
            truncated = code
            if len(truncated) > max_pseudo_chars_per_tool:
                truncated = truncated[: max_pseudo_chars_per_tool - 3] + "..."
            decomp_sections.append(
                f"--- Decompilation from {tool_name} ---\n{truncated}"
            )
        decompilation_text = "\n\n".join(decomp_sections)
    else:
        decompilation_text = "No decompilation available from any tool."

    # 6) 统一函数名
    display_name = "/".join(sorted(node.names)) if node.names else f"sub_{node.entry_va:08X}"

    # 7) 组合 Prompt
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
            "\n[函数中引用的关键字符串示例（聚合自多个工具）]\n"
            + "\n".join(f"- {s}" for s in string_texts)
        )

    lines.append("\n[代表视图的函数反汇编（部分）]\n" + disasm_text)
    lines.append("\n[多视图伪代码（可能互相矛盾，请综合判断）]\n" + decompilation_text)

    return "\n".join(lines)


def build_validation_prompt(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entry_va: int,
    _get_any_function_id_for_va: Any,  # 函数引用
    _get_call_site_snippet: Any,  # 函数引用
) -> str:
    """
    第二阶段：基于调用链的"Top-down Validation" Prompt。
    上下文包括：
      - 当前函数第一阶段的 signature / summary；
      - 上游调用者的调用点代码片段；
      - 下游被调用者的名称与摘要占位。
    """
    node = graph.nodes[entry_va]

    # 当前函数第一阶段分析结果
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

    # 上游调用者视角
    caller_snippets: List[str] = []
    for caller_va in sorted(node.caller_vas):
        snippet = _get_call_site_snippet(conn, graph, caller_va, node.names)
        caller_name = next(iter(sorted(graph.nodes[caller_va].names)), f"sub_{caller_va:08X}") if caller_va in graph.nodes else f"sub_{caller_va:08X}"
        if snippet:
            caller_snippets.append(f"[Caller {caller_name} @ 0x{caller_va:08X}]\n{snippet}")
        if len(caller_snippets) >= 5:
            break

    if not caller_snippets:
        caller_section = "(没有可用的调用者伪代码片段，用第一阶段结果作轻量校验。)"
    else:
        caller_section = "\n\n".join(caller_snippets)

    # 下游被调用者列表（仅列出名称，减少 token）
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

    prompt = f"""
你是一名进行"第二阶段 Top-down 校验"的逆向工程专家。

当前目标函数：{display_name} (@ 0x{entry_va:08X})

[第一阶段分析结果]
Signature: {current_sig}
Summary: {current_summary}

[调用者如何使用该函数（Caller Context）]
{caller_section}

[该函数内部调用了哪些子函数（Callee List）]
{callee_section}

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


def build_global_var_prompt(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    var_node: GlobalVarNode,
    analysis_info: Dict[int, dict],
    _get_global_use_snippet: Any,  # 函数引用
) -> str:
    """
    构造第三阶段全局变量重命名 / 类型推断的 Prompt。
    上下文：若干高置信度访问者函数 + 访问代码片段。
    """
    addr = var_node.address_va
    current_names = sorted(var_node.names) or [f"byte_{addr:08X}"]
    display_name = current_names[0]

    # 选出代表性的访问者：优先已锁定 / 高置信度的函数
    access_funcs: List[Tuple[float, int, str, str]] = []  # (score, entry_va, name, snippet)

    all_users = list(var_node.writers | var_node.readers)
    for entry_va in all_users:
        fn = graph.nodes.get(entry_va)
        if not fn:
            continue
        # 函数名
        fn_name = next(iter(sorted(fn.names)), f"sub_{entry_va:08X}") if fn.names else f"sub_{entry_va:08X}"

        # 取代表 function_id 的分析信息
        best_info = None
        best_conf = 0.0
        for fid in fn.function_ids:
            info = analysis_info.get(fid)
            if not info:
                continue
            st = (info.get("analysis_state") or "").upper()
            base = float(info.get("confidence_score") or 0) / 100.0
            if st == "LOCKED":
                base = max(base, 0.9)
            if base > best_conf:
                best_conf = base
                best_info = info

        if best_conf <= 0.0:
            continue

        snippet = _get_global_use_snippet(conn, graph, entry_va, var_node)
        if not snippet:
            continue

        access_funcs.append((best_conf, entry_va, fn_name, snippet))

    if not access_funcs:
        # 没有可靠上下文，仅做轻量提示
        usage_section = "(没有找到可靠的函数访问上下文，仅基于名称和地址做轻量推断。)"
    else:
        # 按置信度降序，截断前若干条
        access_funcs.sort(key=lambda x: x[0], reverse=True)
        lines: List[str] = []
        for conf, entry_va, fn_name, snippet in access_funcs[:6]:
            lines.append(
                f"[Function {fn_name} @ 0x{entry_va:08X}, confidence={conf:.2f}]\n{snippet}"
            )
        usage_section = "\n\n".join(lines)

    prompt = f"""
你是一名擅长从访问模式推断"全局变量语义"的逆向工程专家。

当前全局变量：0x{addr:08X}
当前名称候选：{", ".join(current_names)}

[访问上下文（函数如何读写该变量）]
{usage_section}

[任务]
1. 结合上述访问模式，推断该全局变量的"语义名称"（例如 g_LoginRetryCount, g_AppConfig）。
2. 推断一个合理的 C 类型（例如 int, bool, HANDLE, struct APP_CONFIG * 等）。
3. 给出你的置信度与简要理由。

请严格返回 JSON：
{{
  "name": "g_VarName",
  "type": "int 或 struct APP_CONFIG *",
  "confidence": 0.0 ~ 1.0,
  "reason": "简要说明理由"
}}
"""
    return prompt.strip()


def build_local_var_prompt(
    node: UnifiedFunctionNode,
    code: str,
    signature: str,
    summary: str,
) -> str:
    """
    构造第四阶段 Prompt：请求 LLM 识别并重命名局部变量。
    """
    display_name = "/".join(sorted(node.names)) if node.names else f"sub_{node.entry_va:08X}"

    prompt = f"""
你是一个代码重构专家。当前任务是优化反编译代码的可读性，重点是**重命名局部变量和函数参数**。

函数：{display_name}
Signature: {signature}
Summary: {summary}

[伪代码]
{code}

[任务]
1. 分析伪代码逻辑，识别无意义的默认命名：
   - 重点关注参数：a1, a2, a3, arg1, arg2...
   - 重点关注局部变量：v1, v2, v3, var_C, var_10...
2. 根据上下文推断它们的实际含义，并赋予有意义的变量名（如 index, user_id, connection_handle）。
3. 请适度激进一些：
   - 如果 a1 明显是源缓冲区，可以重命名为 src_buf；
   - 如果 v5 明显是循环变量，可以重命名为 i 或 idx；
   - 如果 v8 接收了函数返回值并用于判断，可以重命名为 ret_val 或 status。
4. 如果变量名已经具有清晰语义（如 file_name、buffer_ptr），请不要修改它。
5. 如果确实无法推断任何变量含义，请返回空 JSON。

请严格返回 JSON 对象，格式为 "旧名字": "新名字" 的映射：
{{
  "a1": "socket_fd",
  "a2": "buffer_ptr",
  "v5": "loop_idx",
  "v12": "bytes_received"
}}
"""
    return prompt.strip()


# =========================
# LLM 调用与请求构建
# =========================


def build_chat_request(prompt: str, llm_settings: LLMSettings) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    """构造要发送给 ChatCompletion 的消息与请求参数。"""

    conversation: List[Dict[str, str]] = [
        {
            "role": "system",
            "content": (
                "You are an expert reverse engineer. "
                "You must respond with a single valid JSON object only."
            ),
        },
        {"role": "user", "content": prompt},
    ]

    request_kwargs: Dict[str, Any] = dict(llm_settings.chat_completion_kwargs)
    request_kwargs.update(
        {
            "model": llm_settings.model,
            "temperature": llm_settings.temperature,
            "max_tokens": llm_settings.max_tokens,
            "messages": conversation,
        }
    )

    return conversation, request_kwargs


def call_llm_analyze_function(
    conversation: List[Dict[str, str]],
    request_kwargs: Dict[str, Any],
    api_settings: Dict[str, Any],
    max_attempts: int = 3,
    return_raw_on_error: bool = False,
) -> dict:
    """
    调用 OpenAI ChatCompletion，让模型对单个函数进行分析。
    期望返回一个 JSON 对象，字段：
      - signature: C 风格函数声明 / 原型
      - summary: 一句话或一小段语义描述
      - confidence: 0.0 ~ 1.0 的置信度
      - tags: 若干关键词
      - notes: 可选补充说明
    """
    client = require_openai(api_settings)

    last_error: Optional[str] = None

    try:
        logger.debug(
            "LLM request payload: %s",
            json.dumps(request_kwargs, ensure_ascii=False, indent=2),
        )
    except Exception:
        logger.debug("LLM request payload (repr): %r", request_kwargs)

    for attempt in range(1, max_attempts + 1):
        text_str = ""
        attempt_start = time.time()
        while True:
            try:
                # 兼容 openai 新旧两种调用方式
                if hasattr(client, "chat") and hasattr(client.chat, "completions"):
                    # openai>=1.0.0: 使用 client.chat.completions.create
                    logger.debug(
                        "LLM request (attempt %d/%d, new API): model=%s, temp=%s, max_tokens=%s, prompt_chars=%d",
                        attempt,
                        max_attempts,
                        request_kwargs.get("model"),
                        request_kwargs.get("temperature"),
                        request_kwargs.get("max_tokens"),
                        len(
                            "".join(
                                str(m.get("content", ""))
                                for m in request_kwargs.get("messages", [])
                            )
                        ),
                    )
                    resp = client.chat.completions.create(**request_kwargs)  # type: ignore[attr-defined]
                    text = resp.choices[0].message.content or ""  # type: ignore[union-attr]
                elif hasattr(client, "ChatCompletion"):
                    # 旧版 openai: 模块级 ChatCompletion.create
                    logger.debug(
                        "LLM request (attempt %d/%d, old API): model=%s, temp=%s, max_tokens=%s, prompt_chars=%d",
                        attempt,
                        max_attempts,
                        request_kwargs.get("model"),
                        request_kwargs.get("temperature"),
                        request_kwargs.get("max_tokens"),
                        len(
                            "".join(
                                str(m.get("content", ""))
                                for m in request_kwargs.get("messages", [])
                            )
                        ),
                    )
                    resp = client.ChatCompletion.create(**request_kwargs)  # type: ignore[attr-defined]
                    text = resp["choices"][0]["message"]["content"]  # type: ignore[index]
                else:  # pragma: no cover - 极端情况
                    last_error = "当前 openai 客户端不支持 ChatCompletion 接口"
                    break
            except Exception as exc:  # 网络 / API 失败
                last_error = f"LLM 调用失败({attempt}/{max_attempts}): {exc}"
                logger.warning("%s", last_error)
                break

            text_str = (text or "").strip()
            # 若模型返回 Markdown 代码块包裹的 JSON，先尝试剥离 ``` 包围
            if text_str.startswith("```"):
                lines = text_str.splitlines()
                if lines and lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                text_str = "\n".join(lines).strip()

            if text_str:
                break

            if time.time() - attempt_start >= EMPTY_RESPONSE_RETRY_TIMEOUT:
                last_error = (
                    f"LLM 多次返回空字符串，已重试 {EMPTY_RESPONSE_RETRY_TIMEOUT:.0f} 秒仍未成功。"
                )
                logger.warning("%s", last_error)
                break

            logger.info(
                "LLM 暂无回复内容，正在快速重试（超时 %.0f 秒）...",
                EMPTY_RESPONSE_RETRY_TIMEOUT,
            )
            continue

        if not text_str:
            continue

        logger.debug(
            "LLM raw response (attempt %d/%d): %s",
            attempt,
            max_attempts,
            text_str,
        )

        start = text_str.find("{")
        end = text_str.rfind("}")
        if start != -1 and end != -1 and end > start:
            text_str_json = text_str[start : end + 1]
        else:
            text_str_json = text_str

        try:
            data = json.loads(text_str_json)
        except json.JSONDecodeError:
            last_error = (
                f"LLM 返回内容无法解析为 JSON({attempt}/{max_attempts})：{text_str_json!r}"
            )
            # 根据需要，将原始文本返回给调用方用于调试
            if return_raw_on_error and attempt == max_attempts:
                logger.warning(
                    "%s\n完整的 LLM 回复：%s",
                    last_error,
                    text_str,
                )
                return {"_raw_error": last_error, "_raw_text": text_str}
            logger.warning(
                "%s\n完整的 LLM 回复：%s",
                last_error,
                text_str,
            )
            continue

        if not isinstance(data, dict):
            last_error = (
                f"LLM 返回的 JSON 不是对象({attempt}/{max_attempts})：{data!r}"
            )
            logger.warning("%s", last_error)
            continue

        return data

    # 多次尝试仍失败时，返回空 dict，让上层决定如何处理（加入重试队列或跳过）
    if last_error:
        logger.error(
            "在 %d 次尝试后仍未获得合法 JSON：%s", max_attempts, last_error
        )
    return {}


# =========================
# 辅助工具函数
# =========================


def _coerce_libfunction_flag(value: Any) -> bool:
    """将 LLM 返回的 libfunction 字段转换为布尔值。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return int(value) != 0
    if isinstance(value, str):
        s = value.strip().lower()
        return s in {"1", "true", "yes", "y", "lib", "libfunction"}
    return False


def _extract_name_from_signature(signature: str, fallback: str) -> Optional[str]:
    """
    从 LLM 提供的 C 风格 signature 中提取函数名。
    简单启发式：取 '(' 之前最后一个 token。
    """
    sig = signature.strip()
    if not sig:
        return fallback or None
    try:
        before_paren = sig.split("(", 1)[0].strip()
        if not before_paren:
            return fallback or None
        tokens = before_paren.split()
        name = tokens[-1]
        # 去掉星号等修饰符
        name = name.strip("*&")
        if not name:
            return fallback or None
        return name
    except Exception:
        return fallback or None


def _resolve_name_collision_with_llm(
    base_name: str,
    current_ea: int,
    existing_ea: int,
    current_snippets: dict,
    existing_snippets: dict,
    llm_settings: LLMSettings,
) -> Optional[str]:
    """
    在命名冲突时，附带双方的伪代码/汇编交给 LLM 决定：
    - 如果能判断出更合适的名字，返回该名字；
    - 如果建议使用基础名加后缀，返回 None（外层会追加 _0/_1）。
    期望 LLM 返回 JSON：{"resolved_name": "...", "use_suffix": true/false, "reason": "..."}
    """
    prompt = f"""
你是逆向辅助命名助手。现在有两个函数命名冲突，基础名为 {base_name}。
请比较两个函数的伪代码和汇编，给出一个更合适的最终名称，或明确要求使用基础名加数字后缀。
输出必须是 JSON，格式：{{"resolved_name": "<字符串或留空>", "use_suffix": <true/false>, "reason": "<简短理由>"}}
如果无法区分，设置 use_suffix 为 true。

函数A (current): entry_va=0x{current_ea:08X}
伪代码:
{current_snippets.get('pseudocode','')}

汇编:
{current_snippets.get('asm','')}

函数B (existing): entry_va=0x{existing_ea:08X}
伪代码:
{existing_snippets.get('pseudocode','')}

汇编:
{existing_snippets.get('asm','')}
"""

    conversation, request_kwargs = build_chat_request(prompt, llm_settings)

    try:
        result = call_llm_analyze_function(
            conversation=conversation,
            request_kwargs=request_kwargs,
            api_settings=llm_settings.api_settings,
            return_raw_on_error=True,
        )
    except Exception:
        return None

    if isinstance(result, dict) and "_raw_text" in result:
        return None
    if not isinstance(result, dict):
        return None

    resolved = result.get("resolved_name")
    if resolved:
        return str(resolved)

    use_suffix = result.get("use_suffix")
    if isinstance(use_suffix, bool) and use_suffix:
        return None

    return None
