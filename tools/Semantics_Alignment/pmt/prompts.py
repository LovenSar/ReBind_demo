from __future__ import annotations

import json
from typing import Any, Dict, List, Sequence, Tuple


def name_alignment_prompt(
    entry_va: int,
    db_name: str,
    ida_name: str,
    db_code: str,
    ida_code: str,
) -> str:
    """DB 与 IDA 伪代码/命名不一致时的裁决 Prompt。"""

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


def resolve_name_collision_prompt(
    base_name: str,
    current_ea: int,
    existing_ea: int,
    current_pseudocode: str,
    current_asm: str,
    existing_pseudocode: str,
    existing_asm: str,
) -> str:
    """命名冲突时，用双方伪代码/汇编让 LLM 做裁决。"""

    prompt = f"""
你是逆向辅助命名助手。现在有两个函数命名冲突，基础名为 {base_name}。
请比较两个函数的伪代码和汇编，给出一个更合适的最终名称，或明确要求使用基础名加数字后缀。
输出必须是 JSON，格式：{{"resolved_name": "<字符串或留空>", "use_suffix": <true/false>, "reason": "<简短理由>"}}
如果无法区分，设置 use_suffix 为 true。

函数A (current): entry_va=0x{current_ea:08X}
伪代码:
{current_pseudocode}

汇编:
{current_asm}

函数B (existing): entry_va=0x{existing_ea:08X}
伪代码:
{existing_pseudocode}

汇编:
{existing_asm}
"""
    return prompt.strip()


def validation_single_prompt(context: str) -> str:
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


def validation_batch_prompt(items: Sequence[Tuple[int, str]]) -> str:
    lines: List[str] = []
    lines.append("你是一名进行‘第二阶段 Top-down 校验’的逆向工程专家。")
    lines.append(
        "请对以下多个函数的命名/签名进行校验。返回一个 JSON 数组，长度必须等于条目数量，顺序完全一致。"
    )
    lines.append(
        '数组中每个对象字段：{"entry_va":"0x...","action":"RENAME"|"CONFIRM","new_name":"...","confidence":0.0-1.0,"reasoning":"..."}。'
    )
    lines.append("仅当当前名称为默认风格(sub_/fun_/loc_)且你有更好建议时选择 RENAME。")

    for idx, (va, ctx) in enumerate(items, 1):
        lines.append(f"\n[Item {idx}/{len(items)}] entry_va=0x{va:08X}\n{ctx}")

    return "\n".join(lines)


def deep_path_step_prompt(
    *,
    step_index: int,
    total_steps: int,
    path_names: Sequence[str],
    path_vas: Sequence[str],
    from_name: str,
    from_va: str,
    to_name: str,
    to_va: str,
    edge: Dict[str, Any],
    edge_block: str,
    caller_code: str,
    callee_code: str,
    previous_steps: Sequence[Dict[str, Any]],
) -> str:
    prev_json = json.dumps(list(previous_steps), ensure_ascii=False, indent=2) if previous_steps else "[]"
    path_text = " -> ".join(f"{n}({v})" for n, v in zip(path_names, path_vas))

    prompt = f"""
你是逆向工程分析员。现在要对一条“最深调用路径”做逐层条件推断。

[目标]
推断：
1) 程序最开始可能需要什么输入（参数/环境/文件/网络/系统状态）；
2) 在当前这一步 from -> to，最可能的进入条件是什么；
3) 该条件与前序条件如何衔接（通常是 AND，也可能 UNKNOWN）。

[整条路径]
{path_text}

[当前层]
step_index={step_index}/{total_steps}
from={from_name} ({from_va})
to={to_name} ({to_va})

[当前边证据]
status={edge.get("status", "")}
aggregated_env_signals={edge.get("aggregated_env_signals", [])}
gating_strength={edge.get("gating_strength", 0)}
{edge_block}

[caller伪代码截断]
{caller_code or "(empty)"}

[callee伪代码截断]
{callee_code or "(empty)"}

[前序层已推断结果]
{prev_json}

[输出要求]
只返回一个 JSON 对象，字段如下：
{{
  "step_index": {step_index},
  "from": "{from_name}",
  "to": "{to_name}",
  "likely_initial_input": "从程序入口开始最可能触发这条路径的初始输入（可逐步修正）",
  "required_state_now": "走到当前层时必须满足的状态/上下文",
  "gate_condition": "当前 from->to 的关键分支条件（尽量可执行/可验证）",
  "condition_relation_with_previous": "AND|OR|UNKNOWN",
  "reasoning": "简要解释你为什么给出该条件（只写结论性理由，不要输出冗长过程）",
  "evidence": ["证据1", "证据2"],
  "confidence": 0.0
}}
"""
    return prompt.strip()


def global_var_single_prompt(
    addr: int,
    current_names: Sequence[str],
    usage_section: str,
) -> str:
    prompt = f"""
你是一名擅长从访问模式推断“全局变量语义”的逆向工程专家。

当前全局变量：0x{addr:08X}
当前名称候选：{", ".join(list(current_names) or [f"byte_{addr:08X}"])}

[访问上下文（函数如何读写该变量）]
{usage_section}

[任务]
1. 结合上述访问模式，推断该全局变量的“语义名称”（例如 g_LoginRetryCount, g_AppConfig）。
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


def global_var_batch_prompt(items: Sequence[Tuple[int, str]]) -> str:
    lines: List[str] = []
    lines.append("你是一名擅长从访问模式推断‘全局变量语义’的逆向工程专家。")
    lines.append("请分析以下多个全局变量，返回一个 JSON 数组，长度必须等于条目数量，顺序完全一致。")
    lines.append(
        '数组中每个对象字段：{"address_va":"0x...","name":"g_VarName","type":"...","confidence":0.0-1.0,"reason":"..."}。'
    )

    for idx, (addr, ctx) in enumerate(items, 1):
        lines.append(f"\n[Item {idx}/{len(items)}] address_va=0x{addr:08X}\n{ctx}")

    return "\n".join(lines)


def unified_common_header_lines() -> List[str]:
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
    return lines


def unified_single_json_contract_line() -> str:
    return (
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


def unified_batch_json_contract_lines() -> List[str]:
    lines: List[str] = []
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
    lines.append(
        "若判断为标准库/编译器运行时/纯导入包装，请设置 libfunction=1 并在 summary/notes 中说明依据；否则设为 0。"
    )
    # 复用命名规则最后一段（保持与单函数版一致）
    lines.append(unified_common_header_lines()[-1])
    return lines


def unified_batch_intro_lines() -> List[str]:
    return [
        "你是一个精通逆向工程和 C/C++ 的安全分析专家，现在需要一次性分析多个物理函数。",
        "不同反编译器可能存在各自的幻觉或错误，你需要对比多视图输出，抓住一致的部分，结合上下文信息推断真实语义。",
    ]


def single_view_common_header_lines() -> List[str]:
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
    return lines


def single_view_json_contract_line() -> str:
    return (
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


def local_var_single_prompt(
    display_name: str,
    signature: str,
    summary: str,
    code: str,
) -> str:
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

请严格返回 JSON 对象，格式为 "旧名字": "新名字" 的映射：
{{
  "a1": "socket_fd",
  "a2": "buffer_ptr",
  "v5": "loop_idx",
  "v12": "bytes_received"
}}
"""
    return prompt.strip()


def local_var_batch_prompt(items: Sequence[Dict[str, Any]]) -> str:
    """items: 每个元素包含 display_name/entry_va/signature/summary/code。"""
    lines: List[str] = []
    lines.append("你是一个代码重构专家。当前任务是优化反编译代码的可读性。")
    lines.append("**核心原则：必须优先重命名函数形参（a1, a2...），其次尽力重命名内部变量（v1, v2...）。**")
    lines.append(
        "请对以下多个函数分别给出变量重命名建议。返回一个 JSON 数组，长度必须等于条目数量，顺序完全一致。"
    )
    lines.append("数组中每个元素格式：{\"entry_va\":\"0x...\",\"renames\":{\"old\":\"new\",...}}。")
    lines.append("若无法推断任何变量含义，请返回 renames 为 {}（空对象）。不要输出除 JSON 数组之外的任何文字。")

    for idx, item in enumerate(items, 1):
        display_name = str(item.get("display_name") or "(unknown)")
        entry_va = int(item.get("entry_va") or 0)
        signature = str(item.get("signature") or "")
        summary = str(item.get("summary") or "")
        code = str(item.get("code") or "")

        lines.append(f"\n[Function {idx}/{len(items)}] {display_name} entry_va=0x{entry_va:08X}")
        lines.append(f"Signature: {signature}")
        lines.append(f"Summary: {summary}")
        lines.append("[Pseudocode]")
        lines.append(code)

    return "\n".join(lines)


def annotation_prompt(node_name: str, code: str, context_summary: str) -> str:
    node_name = (node_name or "").strip() or "(unknown)"
    context_summary = (context_summary or "(无额外上下文)").strip()
    code = (code or "").strip()

    prompt = f"""
你是一名资深的逆向工程与安全分析专家。请分析以下函数的反编译伪代码，并生成高质量的函数头部注释与结构化元数据。

目标函数: {node_name}

[上下文信息]
{context_summary}

[伪代码]
{code}

[分析任务]
请进行深度的代码行为分析，重点关注数据流与副作用。你需要完成两件事：

1) 生成头部注释 (Header Comment)
   生成一段标准的 C 语言函数头部注释（block comment, 形如 /* ... */），必须包含：
   - @brief: 一句话总结函数核心功能。
   - @param: 推断每个形参的含义、类型、取值范围/约束（按出现顺序）。
   - @return: 返回值的具体含义（成功/失败、错误码、指针语义等）。
   - @note (Logic): 用条目化方式简述对形参的关键处理流程/算法步骤。
   - @warning (Side Effects): 指出是否修改全局变量/静态变量、是否执行系统调用（IO/Net/Registry）、是否分配/释放内存、是否加密/解密。
   - @algo: 识别核心算法特征（如 CRC32/AES/哈希/链表遍历/排序/解析器状态机等）。
   - @struct: 若参数疑似结构体指针，推断关键字段偏移含义（例如 a1[4] 可能是 size）。

2) 生成结构化元数据 (JSON)
   提取上述分析关键点，便于数据库检索。

[输出格式]
请严格返回一个 JSON 对象，且不要输出任何额外文字或 Markdown 代码块：
{{
  "header_comment": "/* ... */",
  "metadata": {{
    "algorithm_type": "加密/解析/校验/内存管理/日志/网络/文件/其他",
    "side_effects": ["..."],
    "critical_vars": {{"v5": "loop_counter", "v12": "decoded_buffer"}},
    "is_danger": true
  }}
}}
"""
    return prompt.strip()


def line_annotation_prompt(
    node_name: str,
    context_summary: str,
    numbered_code: str,
    extra_sections: str,
    max_comment_count: int | None = None,
) -> str:
    node_name = (node_name or "").strip() or "(unknown)"
    context_summary = (context_summary or "(无额外上下文)").strip()
    max_comment_count_hint = ""
    if max_comment_count is not None and int(max_comment_count) > 0:
        max_comment_count_hint = f"（建议不超过 {int(max_comment_count)} 条）"

    prompt = f"""
你是一名资深的逆向工程与安全分析专家。请对下列反编译伪代码进行“逐行注释”。

目标函数: {node_name}

[上下文信息]
{context_summary}

[伪代码（已编号）]
{numbered_code}
{extra_sections}

[任务]
1) 只对「[伪代码（已编号）]」这一段中形如 "NNN: <code>" 的编号伪代码行生成注释；不要为任何额外段落生成注释（例如“行号->地址”“反汇编”等）。
2) 只选择关键语义行（分支、关键调用、解析/格式化、边界检查等），无需逐行覆盖；跳过重复/低信息操作（如连续的标志位读写/赋值）。
3) 空行、仅包含大括号的行（"{{" 或 "}}"）可以不注释。
4) 注释要“贴着代码行”，不要写头部大段注释。
5) 不要编造不存在的系统调用；无法确定时用“疑似/可能”。
6) line_comments 的 key 必须使用该行在「[伪代码（已编号）]」中显示的行号（NNN）；如果编号不是从 1 开始（分段/子片段），也必须保持原编号，不要重新从 1 编号（允许去掉前导 0）。
7) line_comments 的 value 必须是“纯自然语言注释文本”，不要包含任何代码片段，也不要以 "//" 开头。
8) 每条注释尽量短（建议 <= 30 中文字），不要换行。
9) 注释数量控制在合理范围{max_comment_count_hint}。

[输出格式]
请严格返回一个 JSON 对象（不要输出任何额外文字或 Markdown）：
{{
    "line_comments": {{
        "001": "...",
        "002": "...",
        "081": "..."
    }},
    "metadata": {{
        "algorithm_type": "加密/解析/校验/内存管理/日志/网络/文件/其他",
        "side_effects": ["..."],
        "critical_vars": {{"v5": "loop_counter"}},
        "is_danger": false
    }}
}}
"""
    return prompt.strip()


def ea_annotation_prompt(
    node_name: str,
    context_summary: str,
    numbered_code: str,
    extra_sections: str,
    max_comment_count: int | None = None,
) -> str:
    node_name = (node_name or "").strip() or "(unknown)"
    context_summary = (context_summary or "(无额外上下文)").strip()
    max_comment_count_hint = ""
    if max_comment_count is not None and int(max_comment_count) > 0:
        max_comment_count_hint = f"（建议不超过 {int(max_comment_count)} 条）"

    prompt = f"""
你是一名资深的逆向工程与安全分析专家。

目标：为 IDA 9.2 / Hex-Rays 生成“按地址定位”的伪代码行尾注释。
说明：注释写入方式类似：
    tl = treeloc_t(); tl.ea = <EA>; tl.itp = ITP_SEMI; cfunc.set_user_cmt(tl, comment)

因此：你必须按“汇编地址 EA”来输出注释，而不是按伪代码行号输出注释。

目标函数: {node_name}

[上下文信息]
{context_summary}

[伪代码（已编号，仅用于理解，不要按行号输出）]
{numbered_code}
{extra_sections}

[任务]
1) 结合反汇编/伪代码，为关键“可定位语句”生成简短行尾注释；无需逐行覆盖，优先关键语义/分支/关键调用，跳过重复或低信息操作（如连续的标志位读写/赋值）。
2) 每条注释尽量短（建议 <= 30 中文字），不要换行。
3) 不要编造不存在的系统调用；无法确定时用“疑似/可能”。
4) value 必须是纯自然语言注释文本，不要包含任何代码片段，也不要以 "//" 开头。
5) 若提供了“伪代码行号 -> 代表性地址(来自 IDA)”映射：你只能使用该映射中出现的 EA 作为 key。
    若未提供映射：才允许使用反汇编段中每行开头出现的 EA。
6) 若多个伪代码行映射到同一 EA：请将它们的注释合并为该 EA 的一条注释（用“ | ”分隔）。
7) 注释数量控制在合理范围{max_comment_count_hint}。

[输出格式]
请严格返回一个 JSON 对象（不要输出任何额外文字或 Markdown）：
{{
    "ea_comments": {{
        "0x401000": "...",
        "0x401005": "..."
    }},
    "metadata": {{
        "algorithm_type": "加密/解析/校验/内存管理/日志/网络/文件/其他",
        "side_effects": ["..."],
        "critical_vars": {{"v5": "loop_counter"}},
        "is_danger": false
    }}
}}

注意：严禁输出 line_comments 字段；key 必须是地址 EA。
"""
    return prompt.strip()
