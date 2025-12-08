#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
knowledge_propagation.py

基于 alignment_loader.py 生成的 SQLite 数据库，实现一个简化版的
“LLM + 依赖图知识传播（Knowledge Propagation on Dependency Graph）” 流程。

核心能力：
1. 从 demo.db 中按 view_id 构建函数级依赖图（调用关系 + 字符串引用）。
2. 为每个函数计算一个启发式“信息熵 / 分析优先级”评分：
   - 叶子函数（无内部被调用者）优先；
   - 调用外部 API 的函数优先；
   - 引用语义字符串的函数优先；
   - 被很多地方调用的“工具函数”加分；
3. 维护 analysis_status 表：
   - function_id
   - analysis_state: PENDING / ANALYZED / LOCKED
   - confidence_score: 当前函数的优先级/置信度（整型分数）
   - summary_signature: LLM 给出的函数原型 / 签名
   - semantic_summary: LLM 给出的自然语言语义描述
4. 迭代式知识传播：
   - 每一轮从 PENDING 中选出“得分最高”的函数 F；
   - 将 F 的反汇编 / 伪代码 / 外部 API / 字符串，以及
     “所有已分析子函数（ANALYZED/LOCKED）的签名 + 语义摘要”打包给 LLM；
   - LLM 输出 JSON（函数签名 + 语义摘要等），写回 analysis_status；
   - 由于子函数变成“已知”，其所有父函数的动态评分在下一轮会提升，
     从而实现沿依赖图的知识传播与波浪式推进。

注意：
- 本脚本默认使用 OpenAI ChatCompletion 接口（兼容老版 openai 库），
  需要环境变量 OPENAI_API_KEY 已经配置好。
- 你也可以加上 --dry-run 仅做评分和排序，不实际调用 LLM。
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sqlite3
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import heapq
import re

import yaml
from tqdm import tqdm

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - 可选依赖
    requests = None


logger = logging.getLogger(__name__)


# 超时：连续收到空响应时持续重试的最长等待时间（秒）
EMPTY_RESPONSE_RETRY_TIMEOUT = 30.0


# =========================
# 数据结构定义
# =========================


def setup_logging(log_path: Path) -> None:
    """
    初始化日志系统：
    - 文件：DEBUG 及以上写入 log_path；
    - 控制台：INFO 及以上，简洁输出。
    多次调用时只在第一次生效，避免重复添加 handler。
    """
    root = logging.getLogger()
    if root.handlers:
        return

    log_path.parent.mkdir(parents=True, exist_ok=True)

    root.setLevel(logging.DEBUG)

    # 文件日志：详细记录
    fh = logging.FileHandler(str(log_path), encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    # 控制台日志：简要输出
    ch = logging.StreamHandler(stream=sys.stderr)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(message)s"))

    root.addHandler(fh)
    root.addHandler(ch)


def wait_for_ida_server(ida_url: str) -> None:
    """
    检查与 idat_server 的连接情况。
    - 若可用：立即返回；
    - 若断开：进入循环，每 30 秒自动重试一次；
      在等待过程中，若用户按下回车，则立即触发一次重试。
    """
    if requests is None:
        # 未安装 requests 时无法主动探测，直接返回，由后续 HTTP 调用自行报错
        return

    while True:
        try:
            resp = requests.post(
                ida_url,
                json={"action": "ping"},
                timeout=3.0,
            )
            if resp.status_code == 200:
                return
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            msg = (
                f"[IDA-Sync] 无法连接到 IDA 服务器 {ida_url}: {exc}。"
                " 将在 30 秒后自动重试，按回车可立即重试，Ctrl+C 终止。"
            )
            print(msg)
            logger.warning("%s", msg)

            # 等待 30 秒或用户按下回车
            user_triggered: List[Optional[bool]] = [None]

            def _wait_input() -> None:
                try:
                    input()
                    user_triggered[0] = True
                except EOFError:
                    user_triggered[0] = False

            t: Optional[threading.Thread] = None
            if sys.stdin and sys.stdin.isatty():
                t = threading.Thread(target=_wait_input, daemon=True)
                t.start()

            start = time.time()
            while True:
                if user_triggered[0] is not None:
                    break
                if time.time() - start >= 30.0:
                    break
                time.sleep(0.2)
            # 跳出等待后，回到 while 顶部再次尝试 ping


@dataclass
class FunctionNode:
    """单个函数在依赖图中的节点信息。"""

    id: int
    view_id: int
    entry_va: int
    name: str
    instr_count: int = 0
    internal_callees: Set[int] = field(default_factory=set)  # 调用的内部函数（functions.id）
    external_callees: Set[int] = field(default_factory=set)  # 调用的外部符号（symbols.id）
    external_callee_names: Set[str] = field(default_factory=set)  # 解析不到 symbols.id 时使用
    callers: Set[int] = field(default_factory=set)  # 调用该函数的父函数（functions.id）
    string_ids: Set[int] = field(default_factory=set)  # 引用到的字符串（strings.id）


@dataclass
class FunctionGraph:
    """某个 binary_view 下的函数依赖图。"""

    view_id: int
    # function_id -> FunctionNode
    functions: Dict[int, FunctionNode]
    # strings.id -> 文本
    string_values: Dict[int, str]
    # symbols.id -> 名称
    symbol_names: Dict[int, str]


@dataclass
class UnifiedFunctionNode:
    """
    跨视图统一节点：代表二进制中的同一个物理函数。
    聚合 Ghidra / IDA 等多个视图的信息。
    """

    entry_va: int
    binary_id: int
    # 映射回数据库的 functions.id（可能包含多个）
    function_ids: Set[int] = field(default_factory=set)
    # 不同视图下的函数名集合
    names: Set[str] = field(default_factory=set)
    # 统一后的指令条数（目前取各视图中的最大值）
    instr_count: int = 0
    # 选作“代表视图”的函数 id（用于抽取反汇编）
    primary_function_id: Optional[int] = None
    # 伪代码：tool_name -> 代码文本
    pseudocodes: Dict[str, str] = field(default_factory=dict)
    # 聚合的调用与引用关系（使用 entry_va 作为内部函数标识）
    internal_callee_vas: Set[int] = field(default_factory=set)
    external_callee_names: Set[str] = field(default_factory=set)
    string_refs: Set[str] = field(default_factory=set)
    caller_vas: Set[int] = field(default_factory=set)


@dataclass
class UnifiedGraph:
    """跨视图统一依赖图（按 binary_id 聚合所有视图）。"""

    binary_id: int
    # entry_va -> UnifiedFunctionNode
    nodes: Dict[int, UnifiedFunctionNode]
    # tool_id -> tool_name
    tool_map: Dict[int, str]
    # function_id -> tool_name（便于快速判断某个 functions 记录来自 IDA 还是 Ghidra）
    func_tool: Dict[int, str]


@dataclass
class GlobalVarNode:
    """第三阶段：全局变量节点（按 address_va 聚合多视图符号与引用）。"""

    address_va: int
    names: Set[str] = field(default_factory=set)
    readers: Set[int] = field(default_factory=set)  # entry_va set
    writers: Set[int] = field(default_factory=set)  # entry_va set


@dataclass
class ValidationTask:
    """跨视图统一依赖图中的校验任务（第二阶段 Top-down 校验）。"""

    entry_va: int
    priority: float          # 优先级：越大越先处理
    path_confidence: float   # 调用路径上传递下来的置信度（0.0 ~ 1.0）

    def __lt__(self, other: "ValidationTask") -> bool:
        # heapq 是小顶堆，这里反转一下使 priority 大的优先
        return self.priority > other.priority


# =========================
# SQLite schema 扩展：analysis_status
# =========================


def ensure_analysis_schema(conn: sqlite3.Connection) -> None:
    """
    确保存在 analysis_status 表，用于记录 LLM 的分析结果和当前状态。

    该表设计与之前讨论保持一致：
      - analysis_state: 'PENDING' / 'ANALYZED' / 'LOCKED'
      - confidence_score: 当前启发式评分（可被多次更新）
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analysis_status (
            function_id       INTEGER PRIMARY KEY,
            analysis_state    TEXT,     -- 'PENDING', 'ANALYZED', 'LOCKED'
            confidence_score  INTEGER,  -- 动态计算的分数
            summary_signature TEXT,     -- LLM 生成的函数签名 / 原型
            semantic_summary  TEXT,     -- LLM 生成的语义摘要
            FOREIGN KEY(function_id) REFERENCES functions(id)
        );
        """
    )
    conn.commit()


def ensure_analysis_rows_for_view(conn: sqlite3.Connection, view_id: int) -> None:
    """
    为指定 view_id 下的所有 functions 补齐 analysis_status 记录。
    """
    cur = conn.cursor()
    cur.execute("SELECT id FROM functions WHERE view_id = ?;", (view_id,))
    all_function_ids = {row[0] for row in cur.fetchall()}

    cur.execute("SELECT function_id FROM analysis_status;")
    existing_ids = {row[0] for row in cur.fetchall()}

    missing = sorted(all_function_ids - existing_ids)
    if not missing:
        return

    cur.executemany(
        """
        INSERT INTO analysis_status(function_id, analysis_state, confidence_score, summary_signature, semantic_summary)
        VALUES (?, 'PENDING', 0, NULL, NULL);
        """,
        [(fid,) for fid in missing],
    )
    conn.commit()


def ensure_analysis_rows_for_binary(conn: sqlite3.Connection, binary_id: int) -> None:
    """
    为指定 binary_id 下 *所有视图* 的 functions 补齐 analysis_status 记录。

    这样在跨视图统一分析时，只要某个物理函数（entry_va）被 LLM 分析过，
    就可以同时把结果写回所有视图对应的 functions 记录。
    """
    cur = conn.cursor()
    cur.execute(
        """
        SELECT f.id
        FROM functions AS f
        JOIN binary_views AS bv ON f.view_id = bv.id
        WHERE bv.binary_id = ?;
        """,
        (binary_id,),
    )
    all_function_ids = {row[0] for row in cur.fetchall()}

    cur.execute("SELECT function_id FROM analysis_status;")
    existing_ids = {row[0] for row in cur.fetchall()}

    missing = sorted(all_function_ids - existing_ids)
    if not missing:
        return

    cur.executemany(
        """
        INSERT INTO analysis_status(function_id, analysis_state, confidence_score, summary_signature, semantic_summary)
        VALUES (?, 'PENDING', 0, NULL, NULL);
        """,
        [(fid,) for fid in missing],
    )
    conn.commit()


def load_analysis_info(conn: sqlite3.Connection) -> Dict[int, dict]:
    """
    读取所有函数的 analysis_status，返回 dict[function_id] -> {state, score, signature, summary}。
    """
    cur = conn.cursor()
    cur.execute(
        """
        SELECT function_id, analysis_state, confidence_score,
               summary_signature, semantic_summary
        FROM analysis_status;
        """
    )
    info: Dict[int, dict] = {}
    for fid, state, score, sig, summary in cur.fetchall():
        info[fid] = {
            "analysis_state": state or "PENDING",
            "confidence_score": int(score or 0),
            "summary_signature": sig,
            "semantic_summary": summary,
        }
    return info


# =========================
# 依赖图构建
# =========================


CALL_REF_TYPES: Set[str] = {
    # Ghidra
    "UNCONDITIONAL_CALL",
    "COMPUTED_CALL",
    # IDA 数字编码（在 demo.db 中看到的典型值）
    "17",
    "19",
    "21",
}


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

    # 4) 统计指令条数，并为每个统一节点指定一个“代表函数”
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


# LLM 配置与设置
DEFAULT_LLM_MODEL = "gpt-4.1-mini"
DEFAULT_LLM_TEMPERATURE = 0.1
DEFAULT_LLM_MAX_TOKENS = 512
DEFAULT_API_KEY_ENV = "OPENAI_API_KEY"
SEMANTICS_CONFIG_FILE = Path(__file__).parent / "config.yaml"
WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
DOTENV_PATH = WORKSPACE_ROOT / ".env"


@dataclass
class LLMSettings:
    """LLM 参数与 OpenAI API 设置。"""

    model: str
    temperature: float
    max_tokens: int
    api_settings: Dict[str, Any]
    chat_completion_kwargs: Dict[str, Any]


def load_semantics_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """读取与解析 Semantics Alignment 的 YAML 配置文件。"""

    if config_path:
        path = Path(config_path)
    else:
        path = SEMANTICS_CONFIG_FILE

    if not path.exists():
        if config_path:
            raise FileNotFoundError(f"配置文件不存在: {path}")
        return {}

    try:
        with path.open("r", encoding="utf-8") as fp:
            data = yaml.safe_load(fp)
    except yaml.YAMLError as exc:
        raise RuntimeError(f"无法解析配置文件 {path}：{exc}") from exc

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise RuntimeError(f"配置文件 {path} 必须是一个字典结构。")

    return data


def load_dotenv(path: Path) -> Dict[str, str]:
    """从 .env 文件中读取键值并返回字典。"""

    if not path.exists():
        return {}

    env: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env[key.strip()] = value.strip().strip('"')
    return env


def build_llm_settings(
    config: Dict[str, Any],
    model: Optional[str],
    temperature: Optional[float],
    max_tokens: Optional[int],
) -> LLMSettings:
    """合并命令行参数与 config.yaml 中的 LLM 配置。"""

    llm_section = config.get("llm") or {}
    if not isinstance(llm_section, dict):
        llm_section = {}

    def _coerce_float(value: Any, default: float) -> float:
        if value is None:
            return default
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def _coerce_int(value: Any, default: int) -> int:
        if value is None:
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    final_model = model or llm_section.get("model") or DEFAULT_LLM_MODEL
    final_temperature = (
        temperature
        if temperature is not None
        else _coerce_float(llm_section.get("temperature"), DEFAULT_LLM_TEMPERATURE)
    )
    final_max_tokens = (
        max_tokens
        if max_tokens is not None
        else _coerce_int(llm_section.get("max_tokens"), DEFAULT_LLM_MAX_TOKENS)
    )

    api_section = llm_section.get("api") or {}
    if not isinstance(api_section, dict):
        api_section = {}

    api_settings: Dict[str, Any] = {k: v for k, v in api_section.items() if v is not None}
    api_settings.setdefault("key_env_var", DEFAULT_API_KEY_ENV)

    raw_chat_kwargs = llm_section.get("chat_completion_kwargs") or {}
    chat_kwargs: Dict[str, Any] = dict(raw_chat_kwargs) if isinstance(raw_chat_kwargs, dict) else {}

    return LLMSettings(
        model=final_model,
        temperature=final_temperature,
        max_tokens=final_max_tokens,
        api_settings=api_settings,
        chat_completion_kwargs=chat_kwargs,
    )
# =========================
# 评分策略（信息熵 / 分析优先级）
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

        # 4) 被多少地方调用：越多越像“重要工具函数”
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

        # 4) 被多少地方调用：越多越像“重要工具函数”
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
                "Score for 0x%08X (%s): APIs=%d(+%d), strings=%d(+%d), "
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


def ensure_global_vars_schema(conn: sqlite3.Connection) -> None:
    """确保存在 global_vars 表，用于记录全局变量的分析结果。"""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS global_vars (
            address_va      INTEGER PRIMARY KEY,
            name            TEXT,
            guessed_type    TEXT,
            analysis_state  TEXT,
            confidence_score INTEGER,
            reasoning       TEXT
        );
        """
    )
    conn.commit()


def _get_entry_points_for_validation(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    min_confidence: int = 80,
) -> List[int]:
    """
    第二阶段入口点选择策略：
    1) 名称中包含 main/start/entry 的函数；
    2) 第一阶段 confidence_score 大于给定阈值的函数。
    """
    entry_vas: Set[int] = set()

    # 1) 名字匹配
    for va, node in graph.nodes.items():
        for name in node.names:
            lower = name.lower()
            if any(key in lower for key in ("main", "entry", "start")):
                entry_vas.add(va)
                break

    # 2) 高置信度函数
    cur = conn.cursor()
    cur.execute(
        """
        SELECT function_id, confidence_score
        FROM analysis_status
        WHERE confidence_score >= ?;
        """,
        (min_confidence,),
    )
    fid_to_va: Dict[int, int] = {}
    # 预先构建 function_id -> entry_va 映射
    cur.execute("SELECT id, entry_va FROM functions;")
    for fid, entry_va in cur.fetchall():
        fid_to_va[int(fid)] = int(entry_va)

    cur.execute(
        "SELECT function_id FROM analysis_status WHERE confidence_score >= ?;",
        (min_confidence,),
    )
    for (fid,) in cur.fetchall():
        va = fid_to_va.get(int(fid))
        if va in graph.nodes:
            entry_vas.add(va)

    return sorted(entry_vas)


def _get_any_function_id_for_va(graph: UnifiedGraph, entry_va: int) -> Optional[int]:
    """从统一图节点中任选一个 function_id，优先选择 IDA 视图。"""
    node = graph.nodes.get(entry_va)
    if not node:
        return None
    ida_fids = [fid for fid in node.function_ids if graph.func_tool.get(fid, "").lower() == "ida"]
    if ida_fids:
        return ida_fids[0]
    return next(iter(node.function_ids)) if node.function_ids else None


def _get_call_site_snippet(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    caller_va: int,
    callee_names: Set[str],
    max_snippets: int = 3,
) -> str:
    """
    从 caller 的伪代码中找到包含 callee 名称的调用点附近几行代码，用于第二阶段 Prompt。
    """
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


def build_global_var_graph(
    conn: sqlite3.Connection,
    binary_id: int,
    graph: UnifiedGraph,
) -> Dict[int, GlobalVarNode]:
    """
    构建全局变量 -> 读写函数 的引用图，只考虑与指定 binary_id 关联的视图。
    """
    cur = conn.cursor()

    cur.execute(
        "SELECT id FROM binary_views WHERE binary_id = ?;",
        (binary_id,),
    )
    view_rows = cur.fetchall()
    if not view_rows:
        return {}
    view_ids = [row[0] for row in view_rows]
    placeholders = ",".join("?" for _ in view_ids)

    # 1) 按 address_va 聚合所有视图中的全局 data 符号
    globals_by_addr: Dict[int, GlobalVarNode] = {}
    cur.execute(
        f"""
        SELECT view_id, address_va, name, kind, COALESCE(is_global, 0)
        FROM symbols
        WHERE view_id IN ({placeholders}) AND address_va IS NOT NULL;
        """,
        view_ids,
    )
    for view_id, addr_va, name, kind, is_global in cur.fetchall():
        if addr_va is None:
            continue
        addr = int(addr_va)
        k = (kind or "").strip().lower()
        # 仅关注全局 data 对象
        if int(is_global or 0) != 1 and k not in ("data", "object", "obj"):
            continue
        node = globals_by_addr.get(addr)
        if node is None:
            node = GlobalVarNode(address_va=addr)
            globals_by_addr[addr] = node
        if name:
            node.names.add(str(name))

    if not globals_by_addr:
        return {}

    # 2) 函数映射：view_id,address_va -> function_id；function_id -> entry_va
    addr_to_func: Dict[Tuple[int, int], int] = {}
    cur.execute(
        f"""
        SELECT view_id, function_id, address_va
        FROM instructions
        WHERE view_id IN ({placeholders});
        """,
        view_ids,
    )
    for view_id, fid, addr_va in cur.fetchall():
        if addr_va is None:
            continue
        addr_to_func[(int(view_id), int(addr_va))] = int(fid)

    func_to_entry: Dict[int, int] = {}
    cur.execute(
        f"""
        SELECT id, entry_va
        FROM functions
        WHERE view_id IN ({placeholders});
        """,
        view_ids,
    )
    for fid, entry_va in cur.fetchall():
        func_to_entry[int(fid)] = int(entry_va)

    # 3) 遍历 xrefs，找出指向全局变量地址的读写引用
    cur.execute(
        f"""
        SELECT view_id, src_va, dst_va, ref_type_raw
        FROM xrefs
        WHERE view_id IN ({placeholders}) AND dst_va IS NOT NULL;
        """,
        view_ids,
    )
    for view_id, src_va, dst_va, ref_type_raw in cur.fetchall():
        if dst_va is None:
            continue
        addr = int(dst_va)
        node = globals_by_addr.get(addr)
        if node is None:
            continue

        func_id = addr_to_func.get((int(view_id), int(src_va)))
        if func_id is None:
            continue
        entry_va = func_to_entry.get(func_id)
        if entry_va is None or entry_va not in graph.nodes:
            continue

        access_kind = (ref_type_raw or "").strip().upper()
        if access_kind in ("WRITE", "READ_WRITE"):
            node.writers.add(entry_va)
        else:
            node.readers.add(entry_va)

    return globals_by_addr


def build_validation_prompt(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entry_va: int,
) -> str:
    """
    第二阶段：基于调用链的“Top-down Validation” Prompt。
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
你是一名进行“第二阶段 Top-down 校验”的逆向工程专家。

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


def validate_one_function(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entry_va: int,
    llm_settings: LLMSettings,
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
    max_attempts: int = 3,
) -> Optional[float]:
    """
    对单个物理函数执行第二阶段 Top-down 校验。
    返回该节点的“后验置信度”（用于向下传播）。
    """
    node = graph.nodes[entry_va]
    display_name = next(iter(sorted(node.names)), f"sub_{entry_va:08X}") if node.names else f"sub_{entry_va:08X}"

    prompt = build_validation_prompt(conn, graph, entry_va)
    conversation, request_kwargs = build_chat_request(prompt, llm_settings)

    print("=" * 80)
    print(f"[VALIDATION] entry_va=0x{entry_va:08X}, name={display_name}")
    logger.info(
        "[Phase2] VALIDATION TARGET entry_va=0x%08X, name=%s",
        entry_va,
        display_name,
    )

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
        msg = "[VALIDATION] 本函数在多次尝试后仍未获得合法 JSON，暂时跳过该节点。"
        print(msg)
        logger.warning(
            "[Phase2] %s entry_va=0x%08X, name=%s",
            msg,
            entry_va,
            display_name,
        )
        return None

    action = str(result.get("action", "")).strip().upper()
    new_name_raw = str(result.get("new_name", "")).strip()
    reasoning = str(result.get("reasoning", "")).strip()
    conf_val = result.get("confidence")
    try:
        confidence = float(conf_val) if conf_val is not None else 0.8
    except (TypeError, ValueError):
        confidence = 0.8

    print("\n[VALIDATION RESULT]")
    print("action    :", action)
    print("new_name  :", new_name_raw)
    print("confidence:", confidence)
    if reasoning:
        print("reasoning :", reasoning)

    logger.info(
        "[Phase2] RESULT entry_va=0x%08X, name=%s, action=%s, new_name=%s, confidence=%s",
        entry_va,
        display_name,
        action,
        new_name_raw,
        confidence,
    )

    # 确定当前名称
    current_name = display_name
    final_name = current_name

    if action == "RENAME" and new_name_raw:
        candidate = new_name_raw
        # 简单校验：必须是合法 C 标识符，且不过长
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", candidate) and len(candidate) <= 255:
            final_name = candidate
        else:
            print("[VALIDATION] LLM 提议的新名称不符合标识符规范，忽略本次改名。")

    if final_name != current_name:
        print(f"[VALIDATION] 应用二次改名：{current_name} -> {final_name}")
        # 利用现有的 IDA 同步 + demo.db 更新逻辑
        # 这里复用第一阶段的签名（若有），否则使用空串
        fid = _get_any_function_id_for_va(graph, entry_va)
        signature = ""
        if fid is not None:
            cur = conn.cursor()
            cur.execute(
                "SELECT summary_signature FROM analysis_status WHERE function_id = ?;",
                (fid,),
            )
            row = cur.fetchone()
            if row:
                signature = row[0] or ""
        # 如果 signature 中包含旧名字，尝试替换为新名字
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

    # 将该节点对应的 analysis_status 标记为 LOCKED，表示已通过第二阶段校验
    cur = conn.cursor()
    for fid in node.function_ids:
        cur.execute(
            """
            UPDATE analysis_status
            SET analysis_state = 'LOCKED'
            WHERE function_id = ?;
            """,
            (fid,),
        )
    conn.commit()

    # 返回后验置信度（裁剪到 [0,1]）
    return max(0.0, min(1.0, confidence))


def run_validation_phase(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    llm_settings: LLMSettings,
    max_functions: Optional[int],
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
) -> None:
    """
    第二阶段：基于调用链的 Top-down 校验。
    从入口点（main / 高置信度函数）出发，沿调用链向下传播校验任务。
    """
    # 若需要与 IDA 同步，先确保 idat_server 可用
    if ida_sync and ida_url:
        wait_for_ida_server(ida_url)
    entry_vas = _get_entry_points_for_validation(conn, graph)
    if not entry_vas:
        print("[Validation] 未找到合适的入口点，跳过第二阶段。")
        return

    print(f"[Validation] 入口点数量: {len(entry_vas)}")

    # 初始化优先级队列（支持断点续工：对已 LOCKED 的节点跳过 LLM 但继续向下传播）
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
        heapq.heappush(
            queue,
            ValidationTask(entry_va=va, priority=100.0, path_confidence=1.0),
        )
        visited.add(va)

    # 进度条采用“Expanding Horizon”模式：
    # 初始 total 为入口点数量，发现新的待校验函数（首次加入队列）时动态增加 total。
    initial_total = len(entry_vas)
    pbar = tqdm(
        total=initial_total,
        desc="Phase 2: Validation",
        unit="func",
    ) if initial_total > 0 else None

    processed = 0
    failed_primary: List[int] = []
    while queue:
        if max_functions is not None and max_functions > 0 and processed >= max_functions:
            break

        task = heapq.heappop(queue)
        entry_va = task.entry_va

        # 已经 LOCKED 的节点：跳过 LLM，仅用于向下传播
        if _is_locked(entry_va):
            node = graph.nodes.get(entry_va)
            if node:
                # 假定较高置信度，继续向下传播
                posterior_conf = 0.9
                for callee_va in node.internal_callee_vas:
                    if callee_va in visited or callee_va not in graph.nodes:
                        continue
                    visited.add(callee_va)
                    heapq.heappush(
                        queue,
                        ValidationTask(
                            entry_va=callee_va,
                            priority=posterior_conf * 100.0,
                            path_confidence=posterior_conf,
                        ),
                    )
                    # 新发现的待校验节点，扩展进度条总量
                    if pbar is not None:
                        pbar.total += 1
                        pbar.refresh()
            # 这个节点本身在本轮视为“已处理”（来自断点续工），应更新进度条
            if pbar is not None:
                pbar.update(1)
            if pbar is not None:
                pbar.set_description(f"Phase 2: Skip LOCKED 0x{entry_va:08X}")
            continue

        if pbar is not None:
            pbar.set_description(f"Phase 2: 0x{entry_va:08X}")

        posterior_conf = validate_one_function(
            conn=conn,
            graph=graph,
            entry_va=entry_va,
            llm_settings=llm_settings,
            ida_sync=ida_sync,
            ida_url=ida_url,
            dry_run=dry_run,
            max_attempts=3,
        )
        processed += 1
        if pbar is not None:
            pbar.update(1)

        if posterior_conf is None:
            failed_primary.append(entry_va)
            continue

        # 置信度不足则不向下传播
        if posterior_conf <= 0.6:
            continue

        node = graph.nodes[entry_va]
        for callee_va in node.internal_callee_vas:
            if callee_va in visited or callee_va not in graph.nodes:
                continue
            visited.add(callee_va)
            heapq.heappush(
                queue,
                ValidationTask(
                    entry_va=callee_va,
                    priority=posterior_conf * 100.0,
                    path_confidence=posterior_conf,
                ),
            )
            # 新发现的待校验节点，扩展进度条总量
            if pbar is not None:
                pbar.total += 1
                pbar.refresh()

    if pbar is not None:
        pbar.close()

    print(f"[Validation] 第二阶段首次遍历共处理物理函数数量：{processed}")
    logger.info(
        "[Phase2] 首次遍历共处理物理函数数量：%d（包含成功与失败节点）",
        processed,
    )

    # 对首次遍历中 JSON 解析失败的节点，再进行一轮集中重试（每个最多 7 次）
    if not dry_run and failed_primary:
        msg = (
            f"[Validation] 有 {len(failed_primary)} 个函数在首次校验时 LLM 返回非法 JSON，"
            "将对这些函数进行第二轮最多 7 次重试。"
        )
        print(msg)
        logger.info("[Phase2] %s", msg)
        still_failed: List[int] = []
        for entry_va in failed_primary:
            node = graph.nodes.get(entry_va)
            name = (
                next(iter(sorted(node.names)), f"sub_{entry_va:08X}")
                if node and node.names
                else f"sub_{entry_va:08X}"
            )
            print(
                "\n[VALIDATION-RETRY] 针对首次失败的函数再次尝试："
                f"{name} @ 0x{entry_va:08X}"
            )
            logger.info(
                "[Phase2] RETRY entry_va=0x%08X, name=%s", entry_va, name
            )
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
            print(
                "\n[Validation] 以下函数在两轮校验中都未能获得合法 JSON 输出，"
                "已跳过，可考虑后续人工处理："
            )
            logger.warning(
                "[Phase2] 以下函数在两轮校验中都未能获得合法 JSON 输出，建议人工检查。"
            )
            for entry_va in still_failed:
                node = graph.nodes.get(entry_va)
                name = (
                    next(iter(sorted(node.names)), f"sub_{entry_va:08X}")
                    if node and node.names
                    else f"sub_{entry_va:08X}"
                )
                print(f"  - 0x{entry_va:08X} {name}")
                logger.warning(
                    "[Phase2] FAILED entry_va=0x%08X, name=%s", entry_va, name
                )


def compute_global_var_scores(
    graph: UnifiedGraph,
    globals_by_addr: Dict[int, GlobalVarNode],
    analysis_info: Dict[int, dict],
) -> Dict[int, int]:
    """
    为每个全局变量计算优先级评分：
      - 被越多高置信度函数访问，分数越高；
      - 写访问权重高于读访问。
    """
    scores: Dict[int, int] = {}

    for addr, node in globals_by_addr.items():
        users = node.readers | node.writers
        if not users:
            continue

        total_score = 0.0
        for entry_va in users:
            fn = graph.nodes.get(entry_va)
            if not fn:
                continue
            # 选择该物理函数上“最靠谱”的一个 function_id 作为代表
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
            if best_conf <= 0.0:
                continue

            weight = 2.0 if entry_va in node.writers else 1.0
            total_score += weight * best_conf

        # 轻微增加引用函数数目的影响
        total_score += 0.1 * len(users)
        if total_score > 0.0:
            scores[addr] = int(total_score * 100)

    return scores


def _get_global_use_snippet(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entry_va: int,
    var_node: GlobalVarNode,
    max_snippets: int = 2,
) -> str:
    """从函数伪代码中提取访问指定全局变量的代码片段。"""
    node = graph.nodes.get(entry_va)
    if not node:
        return ""

    fid = _get_any_function_id_for_va(graph, entry_va)
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
    patterns: List[str] = []
    # 变量现有名字
    for nm in var_node.names:
        if nm:
            patterns.append(re.escape(nm))
    # 地址形式
    patterns.append(re.escape(f"0x{var_node.address_va:X}"))

    pattern = re.compile("|".join(patterns))
    snippets: List[str] = []
    for idx, line in enumerate(lines):
        if pattern.search(line):
            start = max(0, idx - 1)
            end = min(len(lines), idx + 2)
            snippets.append("\n".join(lines[start:end]))
            if len(snippets) >= max_snippets:
                break

    return "\n...\n".join(snippets)


def build_global_var_prompt(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    var_node: GlobalVarNode,
    analysis_info: Dict[int, dict],
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
你是一名擅长从访问模式推断“全局变量语义”的逆向工程专家。

当前全局变量：0x{addr:08X}
当前名称候选：{", ".join(current_names)}

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


def analyze_one_global_var(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    var_node: GlobalVarNode,
    analysis_info: Dict[int, dict],
    llm_settings: LLMSettings,
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
) -> float:
    """
    对单个全局变量执行第三阶段分析，返回后验置信度。
    """
    addr = var_node.address_va

    if ida_sync and ida_url:
        wait_for_ida_server(ida_url or "http://127.0.0.1:12345")
    prompt = build_global_var_prompt(conn, graph, var_node, analysis_info)
    conversation, request_kwargs = build_chat_request(prompt, llm_settings)

    print("=" * 80)
    print(f"[GLOBAL] address=0x{addr:08X}, names={sorted(var_node.names)}")

    if dry_run:
        print("\n[GLOBAL DRY-RUN] 请求参数：")
        print(json.dumps(request_kwargs, ensure_ascii=False, indent=2))
        print("\n[GLOBAL DRY-RUN] Prompt 预览：")
        print(prompt[:2000])
        return 1.0

    result = call_llm_analyze_function(
        conversation=conversation,
        request_kwargs=request_kwargs,
        api_settings=llm_settings.api_settings,
    )

    if not result:
        print(
            "[GLOBAL] 本全局变量 LLM 返回内容非法或多次尝试失败，保持 PENDING 状态以便后续重试。"
        )
        return 0.0

    name = str(result.get("name", "")).strip()
    type_str = str(result.get("type", "")).strip() or None
    reason = str(result.get("reason", "")).strip()
    conf_val = result.get("confidence")
    try:
        confidence = float(conf_val) if conf_val is not None else 0.8
    except (TypeError, ValueError):
        confidence = 0.8

    print("\n[GLOBAL RESULT]")
    print("name      :", name)
    print("type      :", type_str)
    print("confidence:", confidence)
    if reason:
        print("reason    :", reason)

    # 合法性检查
    if not name or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name) or len(name) > 255:
        print("[GLOBAL] 提议的变量名不符合标识符规范，跳过改名。")
        final_name = next(iter(sorted(var_node.names)), f"g_{addr:08X}") if var_node.names else f"g_{addr:08X}"
        apply_rename = False
    else:
        final_name = name
        apply_rename = True

    ensure_global_vars_schema(conn)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO global_vars(address_va, name, guessed_type, analysis_state, confidence_score, reasoning)
        VALUES(?, ?, ?, 'ANALYZED', ?, ?)
        ON CONFLICT(address_va) DO UPDATE SET
            name = excluded.name,
            guessed_type = excluded.guessed_type,
            analysis_state = excluded.analysis_state,
            confidence_score = excluded.confidence_score,
            reasoning = excluded.reasoning;
        """,
        (addr, final_name, type_str, int(confidence * 100), reason),
    )

    # 同步 symbols 名称
    cur.execute(
        "UPDATE symbols SET name = ? WHERE address_va = ?;",
        (final_name, addr),
    )
    conn.commit()

    if apply_rename and ida_sync:
        _sync_global_with_ida_and_update_db(
            conn=conn,
            address_va=addr,
            new_name=final_name,
            type_str=type_str,
            ida_url=ida_url,
        )

    return max(0.0, min(1.0, confidence))


def run_global_var_phase(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    llm_settings: LLMSettings,
    max_globals: Optional[int],
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
) -> None:
    """
    第三阶段：全局变量重命名与类型推断。
    """
    if ida_sync and ida_url:
        wait_for_ida_server(ida_url)
    globals_by_addr = build_global_var_graph(conn, graph.binary_id, graph)
    if not globals_by_addr:
        print("[GLOBAL] 未发现可分析的全局变量，跳过第三阶段。")
        return

    analysis_info = load_analysis_info(conn)
    scores = compute_global_var_scores(graph, globals_by_addr, analysis_info)
    if not scores:
        print("[GLOBAL] 无高优先级全局变量，跳过第三阶段。")
        return

    # 按分数降序选择
    ordered_addrs = sorted(scores.keys(), key=lambda a: scores[a], reverse=True)

    # 断点续工：过滤掉已经 ANALYZED 的全局变量
    ensure_global_vars_schema(conn)
    cur = conn.cursor()
    cur.execute(
        "SELECT address_va FROM global_vars WHERE analysis_state = 'ANALYZED';"
    )
    analyzed_addrs = {row[0] for row in cur.fetchall()}

    pending_addrs = [addr for addr in ordered_addrs if addr not in analyzed_addrs]
    if not pending_addrs:
        print("[GLOBAL] 所有高优先级全局变量均已 ANALYZED，跳过第三阶段。")
        return

    target_count = len(pending_addrs)
    if max_globals is not None and max_globals > 0:
        target_count = min(target_count, max_globals)

    print(
        f"[GLOBAL] 总计发现 {len(ordered_addrs)} 个高优先级全局变量，"
        f"其中 {len(pending_addrs)} 个尚未分析，本次计划处理 {target_count} 个。"
    )

    pbar = tqdm(total=target_count, desc="Phase 3: Globals", unit="var")
    processed = 0

    for addr in pending_addrs:
        if processed >= target_count:
            break
        node = globals_by_addr[addr]
        score = scores.get(addr, 0)
        pbar.set_description(
            f"Phase 3: 0x{addr:08X} (score={score})"
        )
        print(
            f"\n[GLOBAL] 选择全局变量 0x{addr:08X} (score={score}, names={sorted(node.names)})"
        )
        analyze_one_global_var(
            conn=conn,
            graph=graph,
            var_node=node,
            analysis_info=analysis_info,
            llm_settings=llm_settings,
            ida_sync=ida_sync,
            ida_url=ida_url,
            dry_run=dry_run,
        )
        processed += 1
        pbar.update(1)

    pbar.close()
    print(f"[GLOBAL] 第三阶段共处理全局变量数量：{processed}")


# =========================
# LLM 调用与 Prompt 构造
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


def build_prompt_for_function(
    conn: sqlite3.Connection,
    graph: FunctionGraph,
    node: FunctionNode,
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
        "你最终只需输出一个 JSON 对象，字段为："
        '{'
        '"signature": string, '
        '"summary": string, '
        '"confidence": number, '
        '"tags": [string, ...], '
        '"notes": string'
        '}. '
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


def call_llm_analyze_function(
    conversation: List[Dict[str, str]],
    request_kwargs: Dict[str, Any],
    api_settings: Dict[str, Any],
    max_attempts: int = 3,
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


def _sync_global_with_ida_and_update_db(
    conn: sqlite3.Connection,
    address_va: int,
    new_name: str,
    type_str: Optional[str],
    ida_url: str,
) -> None:
    """
    将全局变量改名/类型信息同步到 idat_server，并更新 demo.db 中 symbols/global_vars。
    """
    if requests is None or not new_name:
        logger.info(
            "[IDA-Sync] requests 未安装或 new_name 为空，跳过全局变量同步。 addr=0x%08X",
            address_va,
        )
        return

    payload = {
        "action": "rename_global",
        "ea": address_va,
        "name": new_name,
        "type": type_str or "",
    }

    logger.info(
        "[IDA-Sync] 尝试同步全局变量 0x%08X -> %s 到 IDA (%s)",
        address_va,
        new_name,
        ida_url,
    )
    logger.debug("[IDA-Sync] rename_global payload: %s", payload)

    try:
        resp = requests.post(ida_url, json=payload, timeout=10.0)
    except Exception as exc:
        logger.error("[IDA-Sync] 全局变量同步失败: %s", exc)
        return

    if resp.status_code != 200:
        logger.error(
            "[IDA-Sync] rename_global HTTP %s: %s",
            resp.status_code,
            resp.text[:200],
        )
        return

    try:
        data = resp.json()
    except Exception:
        data = {}
    logger.info(
        "[IDA-Sync] rename_global 响应: %s",
        data or resp.text[:200],
    )

    # 同步 demo.db 中 symbols 表的名字
    cur = conn.cursor()
    cur.execute(
        "UPDATE symbols SET name = ? WHERE address_va = ?;",
        (new_name, address_va),
    )
    conn.commit()
    logger.debug(
        "[IDA-Sync] 已在 demo.db 中将 symbols.address_va=0x%08X 更新为 name=%s",
        address_va,
        new_name,
    )


def _prompt_run_validation_with_timeout(timeout_sec: int = 5) -> bool:
    """
    带倒计时的简易交互：
    - 在单独线程中等待用户输入；
    - 主线程每秒打印一次提示，最多等待 timeout_sec 秒；
    - 若在超时前用户输入 N/NO/n/no，则返回 False；
    - 若无输入或输入其他内容，则返回 True（默认继续第二阶段）。
    """
    if not sys.stdin or not sys.stdin.isatty():
        # 非交互环境：默认执行第二阶段
        print("[Validation] 非交互环境，默认执行第二阶段调用链校验。")
        return True

    user_input: List[Optional[str]] = [None]

    def _input_worker() -> None:
        try:
            s = input(
                "是否执行第二阶段“调用链逻辑流校验”？\n"
                "输入 N / NO / n / no 以跳过，直接回车或其他内容继续（默认继续）："
            )
            user_input[0] = s.strip()
        except EOFError:
            user_input[0] = None

    t = threading.Thread(target=_input_worker, daemon=True)
    t.start()

    for remaining in range(timeout_sec, 0, -1):
        if user_input[0] is not None:
            break
        print(
            f"[Validation] {remaining} 秒后自动进入第二阶段（按提示可取消）...",
            flush=True,
        )
        time.sleep(1)

    # 如果在超时前还没有输入，尝试再读取一次（避免刚好在最后一秒输入）
    if user_input[0] is None and t.is_alive():
        # 再给出极短时间让输入线程收尾
        time.sleep(0.2)

    answer = (user_input[0] or "").strip().lower()
    if answer in ("n", "no"):
        print("[Validation] 用户选择跳过第二阶段调用链校验。")
        return False

    print("[Validation] 进入第二阶段调用链逻辑流校验。")
    return True


def _sync_with_ida_and_update_db(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    node: UnifiedFunctionNode,
    entry_va: int,
    signature: str,
    summary: str,
    ida_url: str,
) -> None:
    """
    调用在 idat 中运行的 HTTP 服务（idat_server.py），对物理函数进行重命名，
    并使用返回的最新伪代码刷新 demo.db 中对应 IDA 视图的 pseudo_functions / functions。
    """
    if requests is None:
        logger.info(
            "[IDA-Sync] 未安装 requests，跳过函数同步。pip install requests 可启用。"
        )
        return

    # 选出 IDA 视图上的 function_id（如果存在），优先同步该视图的伪代码
    ida_function_id: Optional[int] = None
    for fid in node.function_ids:
        tool_name = graph.func_tool.get(fid, "")
        if tool_name.lower() == "ida":
            ida_function_id = fid
            break
    if ida_function_id is None:
        # 没有 IDA 视图，仅更新数据库名字即可
        logger.info(
            "[IDA-Sync] 未找到 IDA 视图对应的 function_id，仅更新 demo.db。 entry_va=0x%08X",
            entry_va,
        )
        return

    # 提取一个尽量合理的函数名
    fallback_name = (
        next(iter(sorted(node.names)), f"sub_{entry_va:08X}")
        if node.names
        else f"sub_{entry_va:08X}"
    )
    final_name = _extract_name_from_signature(signature, fallback=fallback_name)
    if not final_name:
        logger.warning(
            "[IDA-Sync] 无法从 signature 中提取函数名，跳过同步。 entry_va=0x%08X, signature=%r",
            entry_va,
            signature,
        )
        return

    full_comment = (
        f"[Unified-LLM]\nName: {final_name}\nSignature: {signature}\nSummary: {summary}"
    )
    payload = {
        "action": "rename_and_sync",
        "ea": entry_va,
        "name": final_name,
        "comment": full_comment,
    }

    logger.info(
        "[IDA-Sync] 尝试同步函数到 IDA: ea=0x%08X, name=%s (%s)",
        entry_va,
        final_name,
        ida_url,
    )
    logger.debug("[IDA-Sync] rename_and_sync payload: %s", payload)

    try:
        resp = requests.post(ida_url, json=payload, timeout=10.0)
    except Exception as exc:
        logger.error("[IDA-Sync] 连接 IDA 失败: %s", exc)
        return

    if resp.status_code != 200:
        logger.error(
            "[IDA-Sync] HTTP %s: %s",
            resp.status_code,
            resp.text[:200],
        )
        return

    try:
        data = resp.json()
    except Exception as exc:
        logger.error(
            "[IDA-Sync] 解析 IDA 响应失败: %s; body=%s",
            exc,
            resp.text[:200],
        )
        return

    if data.get("status") != "ok":
        logger.error("[IDA-Sync] IDA 返回错误: %s", data)
        return

    updated_code = data.get("updated_pseudocode") or ""
    logger.info(
        "[IDA-Sync] 成功同步到 IDA，返回伪代码长度: %d 字符。",
        len(updated_code),
    )

    cur = conn.cursor()

    # 更新 IDA 视图对应的 pseudo_functions 记录
    if updated_code:
        cur.execute(
            """
            UPDATE pseudo_functions
            SET body = ?, prototype = ?, name = ?
            WHERE function_id = ?;
            """,
            (updated_code, signature, final_name, ida_function_id),
        )

    # 所有视图的 functions 记录统一使用新名字，便于后续分析
    for fid in node.function_ids:
        cur.execute("UPDATE functions SET name = ? WHERE id = ?;", (final_name, fid))

    conn.commit()
    logger.debug(
        "[IDA-Sync] demo.db 已更新为最新名字与伪代码。entry_va=0x%08X, name=%s",
        entry_va,
        final_name,
    )


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
      - 使用“已知子函数”的签名和摘要作为知识传播的输入。
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
        "你最终必须只输出一个 JSON 对象，字段为："
        '{'
        '"signature": string, '
        '"summary": string, '
        '"confidence": number, '
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


def analyze_one_function(
    conn: sqlite3.Connection,
    graph: FunctionGraph,
    function_id: int,
    analysis_info: Dict[int, dict],
    llm_settings: LLMSettings,
    dry_run: bool = False,
) -> None:
    """
    对单个函数执行一次“LLM + 知识传播”分析，并把结果写回 analysis_status。

    llm_settings 控制 OpenAI API 的参数（模型、温度、token 限制、Base URL 等）。
    dry_run=True 时，只打印 Prompt 和基本信息，不调用 LLM、不写数据库。
    """
    node = graph.functions[function_id]
    prompt = build_prompt_for_function(conn, graph, node, analysis_info)
    conversation, request_kwargs = build_chat_request(prompt, llm_settings)

    print("=" * 80)
    print(
        f"[TARGET] function_id={function_id}, name={node.name}, "
        f"entry_va=0x{node.entry_va:08X}"
    )
    logger.info(
        "[Phase1-Single] TARGET function_id=%d, name=%s, entry_va=0x%08X",
        function_id,
        node.name,
        node.entry_va,
    )

    if dry_run:
        print("\n[DRY-RUN] 本轮不会调用 LLM。以下是请求参数：\n")
        print(json.dumps(request_kwargs, ensure_ascii=False, indent=2))
        print("\n[DRY-RUN] 构造的 Prompt:\n")
        print(prompt)
        print("\n[DRY-RUN] 如需实际调用 LLM，请去掉 --dry-run 参数。")
        return

    result = call_llm_analyze_function(
        conversation=conversation,
        request_kwargs=request_kwargs,
        api_settings=llm_settings.api_settings,
    )

    if not result:
        msg = "[LLM] 本函数 LLM 返回内容非法或多次尝试失败，保持 PENDING 状态以便后续重试。"
        print(msg)
        logger.warning(
            "[Phase1-Single] %s function_id=%d, entry_va=0x%08X",
            msg,
            function_id,
            node.entry_va,
        )
        return

    signature = str(result.get("signature", "")).strip() or None
    summary = str(result.get("summary", "")).strip() or None
    confidence = result.get("confidence")
    try:
        confidence_score = int(float(confidence) * 100) if confidence is not None else 0
    except (TypeError, ValueError):
        confidence_score = 0

    tags = result.get("tags") or []
    notes = result.get("notes") or ""

    print("\n[LLM RESULT]")
    print("signature:", signature)
    print("summary  :", summary)
    print("confidence_score:", confidence_score)
    if tags:
        print("tags     :", tags)
    if notes:
        print("notes    :", notes)

    cur = conn.cursor()
    cur.execute(
        """
        UPDATE analysis_status
        SET analysis_state = 'ANALYZED',
            confidence_score = ?,
            summary_signature = ?,
            semantic_summary = ?
        WHERE function_id = ?;
        """,
        (confidence_score, signature, summary, function_id),
    )
    conn.commit()


def analyze_one_unified_function(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entry_va: int,
    analysis_info: Dict[int, dict],
    llm_settings: LLMSettings,
    dry_run: bool = False,
    ida_sync: bool = False,
    ida_url: Optional[str] = None,
) -> None:
    """
    对一个“物理函数”（按 entry_va 聚合的 UnifiedFunctionNode）执行一次 LLM 分析，
    并将结果写回所有关联的 functions.id 上的 analysis_status 记录。
    """
    # 在启用 IDA 同步的情况下，先确认 idat_server 在线
    if ida_sync and ida_url:
        wait_for_ida_server(ida_url or "http://127.0.0.1:12345")

    node = graph.nodes[entry_va]
    prompt = build_unified_prompt(conn, graph, node, analysis_info)
    conversation, request_kwargs = build_chat_request(prompt, llm_settings)

    print("=" * 80)
    print(
        f"[TARGET] entry_va=0x{node.entry_va:08X}, "
        f"names={','.join(sorted(node.names)) if node.names else '(unnamed)'}, "
        f"function_ids={sorted(node.function_ids)}"
    )
    logger.info(
        "[Phase1] TARGET entry_va=0x%08X, names=%s, function_ids=%s",
        node.entry_va,
        ",".join(sorted(node.names)) if node.names else "(unnamed)",
        sorted(node.function_ids),
    )

    if dry_run:
        print("\n[DRY-RUN] 本轮不会调用 LLM。以下是请求参数：\n")
        print(json.dumps(request_kwargs, ensure_ascii=False, indent=2))
        print("\n[DRY-RUN] 构造的 Prompt:\n")
        print(prompt)
        print("\n[DRY-RUN] 如需实际调用 LLM，请去掉 --dry-run 参数。")
        return

    result = call_llm_analyze_function(
        conversation=conversation,
        request_kwargs=request_kwargs,
        api_settings=llm_settings.api_settings,
    )

    if not result:
        msg = "[LLM] 本物理函数 LLM 返回内容非法或多次尝试失败，保持 PENDING 状态以便后续重试。"
        print(msg)
        logger.warning(
            "[Phase1] %s entry_va=0x%08X, function_ids=%s",
            msg,
            node.entry_va,
            sorted(node.function_ids),
        )
        return

    signature = str(result.get("signature", "")).strip() or None
    summary = str(result.get("summary", "")).strip() or None
    confidence = result.get("confidence")
    try:
        confidence_score = int(float(confidence) * 100) if confidence is not None else 0
    except (TypeError, ValueError):
        confidence_score = 0

    tags = result.get("tags") or []
    notes = result.get("notes") or ""

    print("\n[LLM RESULT]")
    print("signature:", signature)
    print("summary  :", summary)
    print("confidence_score:", confidence_score)
    if tags:
        print("tags     :", tags)
    if notes:
        print("notes    :", notes)

    logger.info(
        "[Phase1] RESULT entry_va=0x%08X, signature=%r, confidence_score=%d",
        node.entry_va,
        signature,
        confidence_score,
    )

    cur = conn.cursor()
    for fid in node.function_ids:
        cur.execute(
            """
            UPDATE analysis_status
            SET analysis_state = 'ANALYZED',
                confidence_score = ?,
                summary_signature = ?,
                semantic_summary = ?
            WHERE function_id = ?;
            """,
            (confidence_score, signature, summary, fid),
        )
    conn.commit()

    # 可选：将结果同步到正在运行的 IDA(idat_server)，并用返回的最新伪代码刷新 demo.db
    if ida_sync and signature and requests is not None:
        try:
            _sync_with_ida_and_update_db(
                conn=conn,
                graph=graph,
                node=node,
                entry_va=entry_va,
                signature=signature,
                summary=summary or "",
                ida_url=ida_url or "http://127.0.0.1:12345",
            )
        except Exception as exc:  # 同步失败不应影响主流程
            print(f"[IDA-Sync] 同步到 IDA 失败: {exc}")


# =========================
# 视图选择与主循环
# =========================


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


def main(argv: Optional[Iterable[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description=(
            "基于 SQLite 对齐数据库，执行“LLM + 依赖图知识传播”函数级分析。"
        )
    )
    parser.add_argument(
        "--db",
        required=True,
        help="输入的 SQLite 数据库路径，例如 tmp/demo.db",
    )
    parser.add_argument(
        "--view-id",
        type=int,
        help="binary_views.id，限制分析到某个视图；默认自动选择（优先 IDA）。",
    )
    parser.add_argument(
        "--tool",
        choices=["ghidra", "ida"],
        help="按工具名选择视图（与 --view-id 二选一）。",
    )
    parser.add_argument(
        "--config",
        help="Semantics Alignment 的配置文件路径，默认为 tools/Semantics_Alignment/config.yaml。",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="用于分析的 LLM 模型名称，优先级：命令行 > config.yaml > gpt-4.1-mini。",
    )
    parser.add_argument(
        "--max-functions",
        type=int,
        default=3,
        help="本次运行最多分析多少个函数（按动态优先级迭代选择）。",
    )
    parser.add_argument(
        "--max-globals",
        type=int,
        default=0,
        help=(
            "第三阶段最多处理多少个全局变量（0 表示不限制，按优先级从高到低遍历）。"
        ),
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=None,
        help="LLM temperature，优先级：命令行 > config.yaml > 0.1。",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=None,
        help="LLM 回复的最大 token 数，优先级：命令行 > config.yaml > 512。",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="跳过第二阶段调用链逻辑流校验。",
    )
    parser.add_argument(
        "--skip-global",
        action="store_true",
        help="跳过第三阶段全局变量重命名与类型推断。",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="仅构建依赖图并计算评分，不实际调用 LLM。",
    )
    parser.add_argument(
        "--ida-sync",
        action="store_true",
        help="在每个物理函数分析完成后，尝试通过 HTTP 同步到正在运行的 idat_server，并用返回的伪代码刷新 demo.db。",
    )
    parser.add_argument(
        "--ida-url",
        default="http://127.0.0.1:12345",
        help="IDA 同步服务的 URL（默认: http://127.0.0.1:12345）。",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    config_arg = args.config
    semantics_config = load_semantics_config(config_arg)
    dotenv_values = load_dotenv(DOTENV_PATH)
    if dotenv_values:
        for env_key, env_value in dotenv_values.items():
            os.environ.setdefault(env_key, env_value)
        print(f"加载 .env 环境变量文件: {DOTENV_PATH}")
    llm_settings = build_llm_settings(
        semantics_config,
        args.model,
        args.temperature,
        args.max_tokens,
    )
    config_source = Path(config_arg) if config_arg else SEMANTICS_CONFIG_FILE

    db_path = Path(args.db).resolve()
    if not db_path.exists():
        raise SystemExit(f"数据库文件不存在：{db_path}")

    conn = sqlite3.connect(str(db_path))
    try:
        # 选择一个“锚点视图”，并基于该视图所属的 binary_id 做跨视图统一分析
        view_id = resolve_view_id(conn, args.view_id, args.tool)
        cur = conn.cursor()
        cur.execute("SELECT binary_id FROM binary_views WHERE id = ?;", (view_id,))
        row = cur.fetchone()
        if not row:
            raise RuntimeError(f"未在 binary_views 中找到 id={view_id} 对应的记录。")
        binary_id = int(row[0])

        print(f"使用的数据库: {db_path}")
        print(f"锚点视图 view_id: {view_id}")
        print(f"跨视图统一分析的 binary_id: {binary_id}")
        print(f"使用的 LLM 配置文件: {config_source}")
        print(
            f"LLM 模型: {llm_settings.model}, temperature={llm_settings.temperature}, "
            f"max_tokens={llm_settings.max_tokens}"
        )
        api_base_url = llm_settings.api_settings.get("base_url")
        if api_base_url:
            print(f"LLM API Base URL: {api_base_url}")

        # 确保 schema 和行就绪（面向整个 binary_id，而不仅仅是某个 view）
        ensure_analysis_schema(conn)
        ensure_analysis_rows_for_binary(conn, binary_id)

        # 构建跨视图统一依赖图
        unified_graph = build_unified_graph(conn, binary_id)
        print(f"统一图中共有 {len(unified_graph.nodes)} 个物理函数节点。")

        # ===== 第一阶段：底向上知识传播（带断点续工 + 进度条） =====
        # 预估本轮最多要处理的物理函数数量：
        # 仅统计“尚未 ANALYZED/LOCKED 的物理节点”数量，并与 --max-functions 取最小值。
        analysis_info = load_analysis_info(conn)
        scores = compute_unified_scores(unified_graph, analysis_info)
        update_unified_scores_in_db(conn, unified_graph, scores)

        pending_nodes_initial: List[UnifiedFunctionNode] = []
        for _, node in unified_graph.nodes.items():
            any_analyzed = False
            for fid in node.function_ids:
                info = analysis_info.get(fid)
                if info and info.get("analysis_state") in ("ANALYZED", "LOCKED"):
                    any_analyzed = True
                    break
            if not any_analyzed:
                pending_nodes_initial.append(node)

        total_pending = len(pending_nodes_initial)
        if total_pending == 0:
            print("当前 binary 下已无 PENDING 物理函数，跳过第一阶段。")
            processed = 0
        else:
            target_count = args.max_functions
            if target_count <= 0 or target_count > total_pending:
                target_count = total_pending

            print(
                f"[Phase 1] 计划分析 {target_count} 个物理函数 "
                f"(当前剩余 PENDING 物理函数总数: {total_pending})"
            )

            pbar = tqdm(
                total=target_count,
                desc="Phase 1: Knowledge Propagation",
                unit="func",
            )

            processed = 0
            while processed < target_count:
                analysis_info = load_analysis_info(conn)
                scores = compute_unified_scores(unified_graph, analysis_info)
                update_unified_scores_in_db(conn, unified_graph, scores)

                # 找出当前 binary 中所有“尚未分析”的物理函数节点：
                # 该节点下所有 function_id 都是 PENDING/NULL 才算 PENDING。
                pending_nodes: List[UnifiedFunctionNode] = []
                for entry_va, node in unified_graph.nodes.items():
                    any_analyzed = False
                    for fid in node.function_ids:
                        info = analysis_info.get(fid)
                        if info and info.get("analysis_state") in ("ANALYZED", "LOCKED"):
                            any_analyzed = True
                            break
                    if not any_analyzed:
                        pending_nodes.append(node)

                if not pending_nodes:
                    pbar.write("当前 binary 下已无 PENDING 物理函数，分析提前结束。")
                    break

                # 选择评分最高的一个作为本轮目标
                pending_nodes.sort(
                    key=lambda n: scores.get(n.entry_va, 0),
                    reverse=True,
                )
                target_node = pending_nodes[0]
                desc = (
                    f"Phase 1: 0x{target_node.entry_va:08X} "
                    f"(score={scores.get(target_node.entry_va, 0)})"
                )
                pbar.set_description(desc)

                print(
                    "\n[SELECT] 选择评分最高的待分析物理函数："
                    f"{'/'.join(sorted(target_node.names)) if target_node.names else '(unnamed)'} "
                    f"(entry_va=0x{target_node.entry_va:08X}, "
                    f"score={scores.get(target_node.entry_va, 0)}, "
                    f"function_ids={sorted(target_node.function_ids)})"
                )

                # 执行 LLM 分析（或 dry-run）
                analyze_one_unified_function(
                    conn=conn,
                    graph=unified_graph,
                    entry_va=target_node.entry_va,
                    analysis_info=analysis_info,
                    llm_settings=llm_settings,
                    dry_run=args.dry_run,
                    ida_sync=args.ida_sync,
                    ida_url=args.ida_url,
                )

                processed += 1
                pbar.update(1)

            pbar.close()
            print(f"\n[Phase 1] 完成，本次运行共处理物理函数数量：{processed}")

    finally:
        conn.close()

    # 第二阶段：调用链 Top-down 校验（可选，默认 5 秒倒计时后执行）
    if not args.skip_validation:
        if _prompt_run_validation_with_timeout(timeout_sec=5):
            conn2 = sqlite3.connect(str(db_path))
            try:
                run_validation_phase(
                    conn=conn2,
                    graph=unified_graph,
                    llm_settings=llm_settings,
                    max_functions=args.max_functions,
                    ida_sync=args.ida_sync,
                    ida_url=args.ida_url,
                    dry_run=args.dry_run,
                )
            finally:
                conn2.close()

    # 第三阶段：全局变量重命名与类型推断
    if not args.skip_global:
        conn3 = sqlite3.connect(str(db_path))
        try:
            run_global_var_phase(
                conn=conn3,
                graph=unified_graph,
                llm_settings=llm_settings,
                max_globals=args.max_globals if args.max_globals and args.max_globals > 0 else None,
                ida_sync=args.ida_sync,
                ida_url=args.ida_url,
                dry_run=args.dry_run,
            )
        finally:
            conn3.close()

    # 若启用了 IDA 同步，在所有分析结束后请求 idat 端保存并退出
    if args.ida_sync and requests is not None:
        try:
            print(f"[IDA-Sync] 请求 IDA 保存数据库并有序退出: {args.ida_url}")
            resp = requests.post(
                args.ida_url,
                json={"action": "save_and_exit"},
                timeout=20.0,
            )
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except Exception:
                    data = {}
                print(f"[IDA-Sync] save_and_exit 响应: {data or resp.text[:200]}")
            else:
                print(f"[IDA-Sync] save_and_exit HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            print(f"[IDA-Sync] save_and_exit 调用失败: {exc}")


if __name__ == "__main__":
    main()
