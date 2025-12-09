#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
graph_builder.py

依赖图构建和优先级评分系统。
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Dict, List, Optional, Set, Tuple

from common_utils import (
    FunctionNode,
    FunctionGraph,
    UnifiedFunctionNode,
    UnifiedGraph,
)

logger = logging.getLogger(__name__)


# =========================
# 常量定义
# =========================

CALL_REF_TYPES: Set[str] = {
    # Ghidra
    "UNCONDITIONAL_CALL",
    "COMPUTED_CALL",
    # IDA 数字编码（在对齐数据库中看到的典型值）
    "17",
    "19",
    "21",
}


# =========================
# 图构建函数
# =========================

def build_function_graph(conn: sqlite3.Connection, view_id: int) -> FunctionGraph:
    """
    从 SQLite 中构建指定 view_id 的函数依赖图。
    - 利用 instructions 表将 src_va 映射到 caller function_id；
    - 利用 xrefs 表识别：
        * 函数间调用（call edges）
        * 对字符串的引用（strings）
    """
    cur = conn.cursor()

    # 1) 初始化所有函数节点
    cur.execute(
        "SELECT id, entry_va, name FROM functions WHERE view_id = ?;",
        (view_id,),
    )
    functions: Dict[int, FunctionNode] = {}
    for fid, entry_va, name in cur.fetchall():
        functions[fid] = FunctionNode(
            id=fid,
            view_id=view_id,
            entry_va=entry_va,
            name=name or "",
        )
    if not functions:
        raise RuntimeError(f"view_id={view_id} 下找不到任何函数。")

    # 2) 指令地址 -> 函数 的映射，同时统计每个函数的指令条数
    src_func_by_va: Dict[int, int] = {}
    cur.execute(
        "SELECT function_id, address_va FROM instructions WHERE view_id = ?;",
        (view_id,),
    )
    for function_id, address_va in cur.fetchall():
        if address_va is None:
            continue
        src_func_by_va[address_va] = function_id
        fn = functions.get(function_id)
        if fn:
            fn.instr_count += 1

    # 3) entry_va -> 函数 的映射（用于通过 xrefs.dst_va 找到内部函数）
    func_by_entry_va: Dict[int, int] = {
        fn.entry_va: fid for fid, fn in functions.items()
    }

    # 4) strings: address -> (id, value)，以及 id -> value
    string_by_addr: Dict[int, Tuple[int, str]] = {}
    string_values: Dict[int, str] = {}
    cur.execute(
        "SELECT id, address_va, value FROM strings WHERE view_id = ?;",
        (view_id,),
    )
    for sid, addr_va, value in cur.fetchall():
        if addr_va is None:
            continue
        string_by_addr[addr_va] = (sid, value or "")
        string_values[sid] = value or ""

    # 5) 符号：name(lower) -> [(id, is_external, kind)]
    symbol_by_name: Dict[str, List[Tuple[int, int, str]]] = {}
    symbol_names: Dict[int, str] = {}
    cur.execute(
        "SELECT id, name, COALESCE(is_external, 0), COALESCE(kind, '') "
        "FROM symbols WHERE view_id = ?;",
        (view_id,),
    )
    for sid, name, is_external, kind in cur.fetchall():
        nm = (name or "").strip()
        if not nm:
            continue
        nm_lower = nm.lower()
        symbol_by_name.setdefault(nm_lower, []).append((sid, int(is_external), kind))
        symbol_names[sid] = nm

    # 6) 遍历所有 xrefs，填充：
    #    - internal_callees / external_callees / external_callee_names
    #    - string_ids
    cur.execute(
        "SELECT src_va, dst_va, dst_name, ref_type_raw "
        "FROM xrefs WHERE view_id = ?;",
        (view_id,),
    )
    for src_va, dst_va, dst_name, ref_type_raw in cur.fetchall():
        caller_id = src_func_by_va.get(src_va)
        if caller_id is None:
            continue
        fn = functions.get(caller_id)
        if fn is None:
            continue

        # 字符串引用：dst_va 对应 strings.address_va
        if dst_va is not None:
            string_entry = string_by_addr.get(dst_va)
            if string_entry is not None:
                sid, _ = string_entry
                fn.string_ids.add(sid)

        # 函数调用：按 xrefs.ref_type_raw 标记
        if ref_type_raw in CALL_REF_TYPES:
            callee_id: Optional[int] = None
            callee_symbol_id: Optional[int] = None

            # 优先用 dst_va 匹配内部函数入口地址
            if dst_va is not None:
                callee_id = func_by_entry_va.get(dst_va)

            # 如果没匹配到内部函数，再尝试按名称匹配外部符号
            if callee_id is None:
                dst_name_norm = (dst_name or "").strip().lower()
                if dst_name_norm:
                    candidates = symbol_by_name.get(dst_name_norm) or []
                    chosen: Optional[Tuple[int, int, str]] = None
                    # 优先选择 is_external=1 或 kind in ('import', 'function')
                    for sid, is_ext, kind in candidates:
                        kind_norm = (kind or "").strip().lower()
                        if is_ext or kind_norm in ("import", "function"):
                            chosen = (sid, is_ext, kind)
                            break
                    if chosen is None and candidates:
                        chosen = candidates[0]
                    if chosen is not None:
                        callee_symbol_id = chosen[0]
                        fn.external_callees.add(callee_symbol_id)
                        fn.external_callee_names.add(dst_name_norm)
                    else:
                        # 没找到符号记录，仍然保留名字，便于 LLM 提示
                        fn.external_callee_names.add(dst_name_norm)
            else:
                # 内部函数调用
                fn.internal_callees.add(callee_id)

    # 7) 构建反向边：callers
    for caller_id, fn in functions.items():
        for callee_id in fn.internal_callees:
            callee = functions.get(callee_id)
            if callee is not None:
                callee.callers.add(caller_id)

    return FunctionGraph(
        view_id=view_id,
        functions=functions,
        string_values=string_values,
        symbol_names=symbol_names,
    )


def build_unified_graph(conn: sqlite3.Connection, binary_id: int) -> UnifiedGraph:
    """
    为某个 binary_id 构建跨视图统一依赖图：
    - 聚合该二进制的所有 binary_views；
    - 按 entry_va 合并不同视图的函数为统一节点；
    - 聚合伪代码、字符串引用、外部 API 调用、内部调用关系等。
    """
    cur = conn.cursor()

    # 1) 获取该二进制关联的所有视图及工具
    cur.execute(
        "SELECT id, tool_id FROM binary_views WHERE binary_id = ?;",
        (binary_id,),
    )
    rows = cur.fetchall()
    if not rows:
        raise RuntimeError(f"binary_id={binary_id} 没有关联的 binary_views 记录。")

    view_to_tool: Dict[int, int] = {view_id: tool_id for (view_id, tool_id) in rows}
    view_ids = list(view_to_tool.keys())

    cur.execute("SELECT id, name FROM tools;")
    tool_map: Dict[int, str] = {tid: name for (tid, name) in cur.fetchall()}

    # 2) 按 entry_va 聚合所有视图中的函数
    placeholders = ",".join("?" for _ in view_ids)
    cur.execute(
        f"SELECT id, view_id, entry_va, name "
        f"FROM functions WHERE view_id IN ({placeholders});",
        view_ids,
    )

    nodes: Dict[int, UnifiedFunctionNode] = {}
    function_id_to_va: Dict[int, int] = {}
    function_id_to_view: Dict[int, int] = {}
    func_tool: Dict[int, str] = {}

    for fid, view_id, entry_va, name in cur.fetchall():
        if entry_va is None:
            continue
        node = nodes.get(entry_va)
        if node is None:
            node = UnifiedFunctionNode(entry_va=entry_va, binary_id=binary_id)
            nodes[entry_va] = node

        node.function_ids.add(fid)
        if name:
            node.names.add(name)
        function_id_to_va[fid] = entry_va
        function_id_to_view[fid] = view_id
        tool_id = view_to_tool.get(view_id)
        if tool_id is not None:
            func_tool[fid] = tool_map.get(tool_id, f"tool_{tool_id}")

    if not nodes:
        raise RuntimeError(f"binary_id={binary_id} 下找不到任何函数。")

    # 3) 聚合伪代码（按工具名区分）
    cur.execute(
        f"""
        SELECT pf.function_id, pf.prototype, pf.body
        FROM pseudo_functions AS pf
        JOIN functions AS f ON pf.function_id = f.id
        WHERE f.view_id IN ({placeholders});
        """,
        view_ids,
    )
    for fid, proto, body in cur.fetchall():
        entry_va = function_id_to_va.get(fid)
        if entry_va is None:
            continue
        node = nodes.get(entry_va)
        if node is None:
            continue

        view_id = function_id_to_view.get(fid)
        tool_id = view_to_tool.get(view_id) if view_id is not None else None
        tool_name = tool_map.get(tool_id, f"tool_{tool_id}") if tool_id is not None else "unknown"

        code = (proto or "") + "\n" + (body or "")
        if not code.strip():
            continue

        # 同一工具可能存在多份伪代码，保留内容更丰富的版本
        prev = node.pseudocodes.get(tool_name)
        if prev is None or len(code) > len(prev):
            node.pseudocodes[tool_name] = code

    # 4) 统计指令条数，并为每个统一节点指定一个"代表函数"
    cur.execute(
        f"""
        SELECT function_id, COUNT(*) AS cnt
        FROM instructions
        WHERE view_id IN ({placeholders})
        GROUP BY function_id;
        """,
        view_ids,
    )
    for fid, cnt in cur.fetchall():
        entry_va = function_id_to_va.get(fid)
        if entry_va is None:
            continue
        node = nodes.get(entry_va)
        if node is None:
            continue
        if cnt > node.instr_count:
            node.instr_count = cnt
            node.primary_function_id = fid

    # 5) 聚合 XREFs：字符串引用 + 调用关系 + 外部 API 名称
    cur.execute(
        f"""
        SELECT i.function_id,
               x.dst_va,
               x.dst_name,
               x.ref_type_raw,
               s.value
        FROM xrefs AS x
        JOIN instructions AS i
             ON x.view_id = i.view_id AND x.src_va = i.address_va
        LEFT JOIN strings AS s
             ON x.view_id = s.view_id AND x.dst_va = s.address_va
        WHERE x.view_id IN ({placeholders});
        """,
        view_ids,
    )

    for caller_fid, dst_va, dst_name, ref_type_raw, str_val in cur.fetchall():
        caller_va = function_id_to_va.get(caller_fid)
        if caller_va is None:
            continue
        node = nodes.get(caller_va)
        if node is None:
            continue

        # A. 字符串引用：任何视图发现的字符串都算数
        if str_val:
            node.string_refs.add(str_val)

        # B. 函数调用：仅在 CALL_REF_TYPES 中的 xref 视为调用边
        if ref_type_raw in CALL_REF_TYPES:
            # 内部函数调用：dst_va 命中我们已有的统一节点
            if dst_va in nodes:
                if dst_va != caller_va:
                    node.internal_callee_vas.add(dst_va)
                    nodes[dst_va].caller_vas.add(caller_va)
            else:
                # 外部 API / 导入函数：聚合名称（过滤掉明显的内部标签名）
                dst_name_norm = (dst_name or "").strip()
                if dst_name_norm:
                    lower = dst_name_norm.lower()
                    if not (lower.startswith(("sub_", "loc_", "label_"))):
                        node.external_callee_names.add(dst_name_norm)

    print(
        f"[Graph] binary_id={binary_id} 视图数={len(view_ids)}，"
        f"统一物理函数节点数={len(nodes)}"
    )
    return UnifiedGraph(binary_id=binary_id, nodes=nodes, tool_map=tool_map, func_tool=func_tool)


# =========================
# 评分计算函数
# =========================

def compute_function_scores(
    graph: FunctionGraph,
    analysis_info: Dict[int, dict],
) -> Dict[int, int]:
    """
    为指定 view 的所有函数计算启发式评分。

    评分核心思想：
      - 调用外部 API 的函数：极大加分；
      - 引用语义字符串的函数：较大加分；
      - 叶子函数（无 internal_callees）：加分（更容易分析）；
      - 被多处调用的函数：加分（工具函数 / 核心逻辑）；
      - 指令条数过少或过多会略微调整；
      - 已知子函数越多（ANALYZED/LOCKED），分数越高，体现知识向上传播。
    """
    analyzed_ids: Set[int] = {
        fid
        for fid, info in analysis_info.items()
        if info.get("analysis_state") in ("ANALYZED", "LOCKED")
    }

    scores: Dict[int, int] = {}

    for fid, node in graph.functions.items():
        n_ext_apis = len(node.external_callees) or len(node.external_callee_names)
        n_strings = len(node.string_ids)
        n_internal = len(node.internal_callees)
        n_callers = len(node.callers)
        n_instr = node.instr_count

        score = 0

        # 1) 外部 API 调用：Wrapper / Shim / 系统交互逻辑
        if n_ext_apis > 0:
            score += 200 + 40 * min(n_ext_apis, 5)

        # 2) 字符串引用：业务逻辑函数通常包含提示 / 日志 / 错误信息
        if n_strings > 0:
            score += 120 + 15 * min(n_strings, 5)

        # 3) 叶子函数（无内部调用）：通常是纯逻辑 / 算法，更容易分析
        if n_internal == 0:
            score += 60
        else:
            score += max(0, 40 - n_internal * 4)

        # 4) 被多少地方调用：越多越像"重要工具函数"
        score += min(n_callers * 6, 40)

        # 5) 指令条数：太小或太大都略微调整
        if n_instr == 0:
            score -= 20
        elif n_instr <= 30:
            score += 15
        elif n_instr <= 150:
            score += 5
        else:
            score -= min((n_instr - 150) // 50 * 5, 40)

        # 6) 已知子函数数量：知识传播的关键
        analyzed_callees = len(node.internal_callees & analyzed_ids)
        score += analyzed_callees * 25

        scores[fid] = score

    return scores


def update_scores_in_db(
    conn: sqlite3.Connection,
    scores: Dict[int, int],
) -> None:
    """将最新评分写回 analysis_status.confidence_score。"""
    cur = conn.cursor()
    rows = [(score, fid) for fid, score in scores.items()]
    cur.executemany(
        "UPDATE analysis_status SET confidence_score = ? WHERE function_id = ?;",
        rows,
    )
    conn.commit()


def compute_unified_scores(
    graph: UnifiedGraph,
    analysis_info: Dict[int, dict],
) -> Dict[int, int]:
    """
    为跨视图统一图中的每个物理函数（按 entry_va）计算启发式评分。

    与单视图版本逻辑类似，只是统计对象换成了 UnifiedFunctionNode。
    """
    # 哪些 entry_va 的物理函数已经被分析过（任一视图上的 function_id 为 ANALYZED/LOCKED 即视为已知）
    analyzed_entry_vas: Set[int] = set()
    for entry_va, node in graph.nodes.items():
        for fid in node.function_ids:
            info = analysis_info.get(fid)
            if info and info.get("analysis_state") in ("ANALYZED", "LOCKED"):
                analyzed_entry_vas.add(entry_va)
                break

    scores: Dict[int, int] = {}

    for entry_va, node in graph.nodes.items():
        n_ext_apis = len(node.external_callee_names)
        n_strings = len(node.string_refs)
        n_internal = len(node.internal_callee_vas)
        n_callers = len(node.caller_vas)
        n_instr = node.instr_count

        score = 0

        # 1) 外部 API 调用：Wrapper / Shim / 系统交互逻辑
        apis_contrib = 0
        if n_ext_apis > 0:
            apis_contrib = 200 + 40 * min(n_ext_apis, 5)
            score += apis_contrib

        # 2) 字符串引用：业务逻辑函数通常包含提示 / 日志 / 错误信息
        strings_contrib = 0
        if n_strings > 0:
            strings_contrib = 120 + 15 * min(n_strings, 5)
            score += strings_contrib

        # 3) 叶子函数（无内部调用）：通常是纯逻辑 / 算法，更容易分析
        internal_contrib = 0
        if n_internal == 0:
            internal_contrib = 60
            score += internal_contrib
        else:
            internal_contrib = max(0, 40 - n_internal * 4)
            score += internal_contrib

        # 4) 被多少地方调用：越多越像"重要工具函数"
        callers_contrib = min(n_callers * 6, 40)
        score += callers_contrib

        # 5) 指令条数：太小或太大都略微调整
        instr_contrib = 0
        if n_instr == 0:
            instr_contrib = -20
        elif n_instr <= 30:
            instr_contrib = 15
        elif n_instr <= 150:
            instr_contrib = 5
        else:
            instr_contrib = -min((n_instr - 150) // 50 * 5, 40)
        score += instr_contrib

        # 6) 已知子函数数量：知识传播的关键
        analyzed_callees = len(node.internal_callee_vas & analyzed_entry_vas)
        callees_contrib = analyzed_callees * 25
        score += callees_contrib

        scores[entry_va] = score

        if logger.isEnabledFor(logging.DEBUG):
            name = (
                "/".join(sorted(node.names))
                if node.names
                else f"sub_{entry_va:08X}"
            )
            logger.debug(
                "[Phase1-Score] 0x%08X (%s): APIs=%d(+%d), strings=%d(+%d), "
                "internal=%d(+%d), callers=%d(+%d), instr=%d(+%d), "
                "analyzed_callees=%d(+%d) => total=%d",
                entry_va,
                name,
                n_ext_apis,
                apis_contrib,
                n_strings,
                strings_contrib,
                n_internal,
                internal_contrib,
                n_callers,
                callers_contrib,
                n_instr,
                instr_contrib,
                analyzed_callees,
                callees_contrib,
                score,
            )

    return scores


def update_unified_scores_in_db(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    scores: Dict[int, int],
) -> None:
    """
    将统一节点的评分写回 analysis_status.confidence_score。
    同一物理函数的多个 function_id 共用同一个 score。
    """
    cur = conn.cursor()
    rows: List[Tuple[int, int]] = []
    for entry_va, score in scores.items():
        node = graph.nodes.get(entry_va)
        if not node:
            continue
        for fid in node.function_ids:
            rows.append((score, fid))

    if rows:
        cur.executemany(
            "UPDATE analysis_status SET confidence_score = ? WHERE function_id = ?;",
            rows,
        )
        conn.commit()


# =========================
# 辅助函数
# =========================

def _get_any_function_id_for_va(graph: UnifiedGraph, entry_va: int) -> Optional[int]:
    """从统一图节点中任选一个 function_id，优先选择 IDA 视图。"""
    node = graph.nodes.get(entry_va)
    if not node:
        return None
    ida_fids = [fid for fid in node.function_ids if graph.func_tool.get(fid, "").lower() == "ida"]
    if ida_fids:
        return ida_fids[0]
    return next(iter(node.function_ids)) if node.function_ids else None


def resolve_view_id(
    conn: sqlite3.Connection,
    explicit_view_id: Optional[int],
    tool_name: Optional[str],
) -> int:
    """
    根据命令行参数解析要分析的 binary_views.id：
      - 如果显式提供 --view-id，则直接使用；
      - 否则，如果提供了 --tool（ghidra / ida），优先选择对应工具的视图；
      - 否则：如果存在 IDA 视图，则优先用 IDA；否则使用首个视图。
    """
    cur = conn.cursor()
    if explicit_view_id is not None:
        cur.execute(
            "SELECT id FROM binary_views WHERE id = ?;",
            (explicit_view_id,),
        )
        row = cur.fetchone()
        if not row:
            raise RuntimeError(f"binary_views 中不存在 id={explicit_view_id} 的视图。")
        return explicit_view_id

    tool_id: Optional[int] = None
    if tool_name:
        cur.execute("SELECT id FROM tools WHERE name = ?;", (tool_name,))
        row = cur.fetchone()
        if not row:
            raise RuntimeError(f"tools 表中不存在 name={tool_name!r} 的记录。")
        tool_id = int(row[0])

    # 按工具名筛选
    if tool_id is not None:
        cur.execute(
            "SELECT id FROM binary_views WHERE tool_id = ? ORDER BY id LIMIT 1;",
            (tool_id,),
        )
        row = cur.fetchone()
        if row:
            return int(row[0])
        raise RuntimeError(f"未找到 tool_id={tool_id} 对应的 binary_view。")

    # 默认优先使用 IDA 视图
    cur.execute(
        """
        SELECT bv.id
        FROM binary_views AS bv
        JOIN tools AS t ON bv.tool_id = t.id
        WHERE t.name = 'ida'
        ORDER BY bv.id
        LIMIT 1;
        """
    )
    row = cur.fetchone()
    if row:
        return int(row[0])

    # 回退：使用第一个视图
    cur.execute("SELECT id FROM binary_views ORDER BY id LIMIT 1;")
    row = cur.fetchone()
    if not row:
        raise RuntimeError("binary_views 表为空，数据库中没有任何视图。")

    return int(row[0])
