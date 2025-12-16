#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
knowledge_propagation.py

基于 alignment_loader.py 生成的 SQLite 数据库，实现一个简化版的
“LLM + 依赖图知识传播（Knowledge Propagation on Dependency Graph）” 流程。

核心能力：
1. 从对齐 SQLite 数据库（例如 sample_name.db）中按 view_id 构建函数级依赖图（调用关系 + 字符串引用）。
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
import math
import os
import sqlite3
import sys
import threading
import time
import builtins
import inspect
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

import heapq
import re
import unicodedata

import yaml
from tqdm import tqdm

# 共享的“动态 Prompt + 动态 Batch”生成器
from dynamic_batching import DynamicBatchResult, yield_dynamic_batch

# Phase modules (extracted implementations). Use aliases to avoid being shadowed by
# legacy in-file implementations that still exist below in this file.
from phases.phase1_kp import (
    analyze_one_unified_function as phase1_analyze_one_unified_function,
)
from phases.phase1_kp import analyze_unified_batch as phase1_analyze_unified_batch
from phases.phase2_validation import run_validation_phase as phase2_run_validation_phase
from phases.phase3_globals import run_global_var_phase as phase3_run_global_var_phase
from phases.phase4_lvar import run_local_var_phase as phase4_run_local_var_phase
from phases.phase5_annotation import run_annotation_phase as phase5_run_annotation_phase

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - 可选依赖
    requests = None


logger = logging.getLogger(__name__)
ACTIVE_INPUT_DB: str = ""


# 超时：连续收到空响应时持续重试的最长等待时间（秒）
EMPTY_RESPONSE_RETRY_TIMEOUT = 90.0

# 单个函数在第四阶段局部变量重命名中，最多尝试的分析轮数
MAX_LVAR_PASSES = 1


def _install_print_with_location() -> None:
    """Prefix every print with absolute file path and line number."""
    if getattr(builtins, "_original_print", None):
        return

    builtins._original_print = builtins.print  # type: ignore[attr-defined]

    def _print_with_location(*args, **kwargs):
        frame = inspect.currentframe()
        if frame and frame.f_back:
            caller = frame.f_back
            path = Path(caller.f_code.co_filename).resolve()
            lineno = caller.f_lineno
            prefix = f"{path}:{lineno} "
        else:
            prefix = ""
        message = " ".join(str(a) for a in args)
        builtins._original_print(f"{prefix}{message}", **kwargs)

    builtins.print = _print_with_location  # type: ignore[assignment]


_install_print_with_location()


# =========================
# 数据结构定义
# =========================


def setup_logging(log_path: Path, input_db: Optional[Path] = None) -> None:
    """
    初始化日志系统：
    - 文件：DEBUG 及以上写入 log_path；
    - 控制台：INFO 及以上，简洁输出。
    多次调用时只在第一次生效，避免重复添加 handler。
    """
    root = logging.getLogger()
    if root.handlers:
        return

    global ACTIVE_INPUT_DB
    if input_db is not None:
        try:
            ACTIVE_INPUT_DB = str(Path(input_db).resolve())
        except Exception:
            ACTIVE_INPUT_DB = str(input_db)

    class _DBPathFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            record.db_path = ACTIVE_INPUT_DB or "N/A"
            return True

    log_path.parent.mkdir(parents=True, exist_ok=True)

    root.setLevel(logging.DEBUG)

    # 文件日志：详细记录
    fh = logging.FileHandler(str(log_path), encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s %(pathname)s:%(lineno)d - [db=%(db_path)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    # 控制台日志：简要输出
    ch = logging.StreamHandler(stream=sys.stderr)
    ch.setLevel(logging.INFO)
    ch.setFormatter(
        logging.Formatter("%(name)s %(pathname)s:%(lineno)d [db=%(db_path)s] %(message)s")
    )

    db_filter = _DBPathFilter()
    fh.addFilter(db_filter)
    ch.addFilter(db_filter)

    root.addHandler(fh)
    root.addHandler(ch)


def install_stdout_tee(target_logger: logging.Logger) -> None:
    """将 stdout 同步写入日志文件，便于回溯命令行输出。"""

    class _StdoutTee:
        def __init__(self, original, logger_obj: logging.Logger) -> None:
            self._original = original
            self._logger = logger_obj
            self._buffer = ""

        def write(self, s: str) -> int:
            self._original.write(s)
            if not s:
                return 0
            self._buffer += s
            while "\n" in self._buffer:
                line, self._buffer = self._buffer.split("\n", 1)
                if line.strip():
                    self._logger.debug(line)
            return len(s)

        def flush(self) -> None:
            self._original.flush()

    # 避免重复安装
    if isinstance(sys.stdout, _StdoutTee):
        return

    sys.stdout = _StdoutTee(sys.stdout, target_logger)  # type: ignore[assignment]


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
    # 为第四阶段局部变量优化增加断点续工标记列（若已存在则忽略错误）
    try:
        conn.execute(
            "ALTER TABLE analysis_status "
            "ADD COLUMN lvar_optimized INTEGER DEFAULT 0;"
        )
    except sqlite3.OperationalError:
        # 列已存在或其他模式下不支持 ALTER，忽略
        pass
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
    # IDA 数字编码（在对齐数据库中看到的典型值）
    "17",
    "19",
    "21",
}

# 第四阶段：用于检测仍然存在的“默认局部变量名”（a1/v1/var_10 等）
GENERIC_LVAR_PATTERN = re.compile(
    r"\b(?:a\d+|arg\d+|arg_\d+|v\d+|var_[0-9A-Fa-f]+)\b"
)

# 用于检测函数名是否仍然是默认的 sub_xxxx 形式
SUBFUNC_NAME_PATTERN = re.compile(r"\bsub_[0-9A-Fa-f]+\b")

# 用于检测明显“默认地址命名”的函数名，例如 sub_401000 / fun_0010E210 / loc_80483F0 等
DEFAULT_FUNC_NAME_PATTERN = re.compile(r"^(?:sub_|fun_|loc_)[0-9A-Fa-f]+$")


def _count_effective_pseudocode_lines(code: str) -> int:
    """统计“有效伪代码行数”。

    过滤空行与仅包含大括号的行，避免把导入/桩函数的极短伪代码也计入。
    """
    if not code:
        return 0
    lines = []
    for raw in code.splitlines():
        s = raw.strip()
        if not s:
            continue
        if s in ("{", "}"):
            continue
        lines.append(s)
    return len(lines)


def _find_generic_lvar_names(code: str) -> Set[str]:
    """在伪代码文本中查找疑似默认局部变量名集合。"""
    if not code:
        return set()
    return {m.group(0) for m in GENERIC_LVAR_PATTERN.finditer(code)}


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


def _load_ida_subfunc_entries(
    conn: sqlite3.Connection, binary_id: int, ida_url: Optional[str] = None
) -> Dict[int, str]:
    """
    加载该 binary 下仍为 sub_ 前缀的函数名映射。
    优先使用数据库中的 IDA 视图记录，同时在可用时合并来自实时 IDB 的 sub_ 函数列表。
    """
    cur = conn.cursor()

    # 1) 记录本地 DB 中该 binary 的所有函数入口地址，用于检测“IDB 有但 DB 无”的情况
    cur.execute(
        """
        SELECT DISTINCT f.entry_va
        FROM functions AS f
        JOIN binary_views AS bv ON f.view_id = bv.id
        WHERE bv.binary_id = ?;
        """,
        (binary_id,),
    )
    db_known_vas: Set[int] = {int(row[0]) for row in cur.fetchall()}

    # 2) 从 DB 中读取 IDA 视图里仍为 sub_ 前缀的函数
    cur.execute(
        """
        SELECT f.entry_va, f.name
        FROM functions AS f
        JOIN binary_views AS bv ON f.view_id = bv.id
        JOIN tools AS t ON bv.tool_id = t.id
        WHERE bv.binary_id = ? AND LOWER(t.name) = 'ida';
        """,
        (binary_id,),
    )

    result: Dict[int, str] = {}
    for entry_va, name in cur.fetchall():
        nm = (name or "").strip()
        if not nm:
            continue
        if SUBFUNC_NAME_PATTERN.fullmatch(nm):
            result[int(entry_va)] = nm

    # 3) 如提供 ida_url，则尝试从实时 IDB 中获取 sub_ 函数并与 DB 数据合并
    if ida_url:
        live_subs = _fetch_live_ida_subfuncs(ida_url)
        if live_subs:
            # 检测 IDA 中存在但 DB 缺失的 sub_ 函数
            missing: List[Tuple[int, str]] = []
            for ea, nm in live_subs.items():
                if ea not in db_known_vas:
                    missing.append((ea, nm))
            if missing:
                print("\n" + "!" * 60)
                print(
                    f"[IDA-Sync] 发现 {len(missing)} 个函数在 IDB 中仍为 sub_ 前缀，"
                    "但本地 SQLite DB 中没有对应记录。"
                )
                sample = ", ".join(
                    f"0x{ea:08X}({name})" for ea, name in missing[:5]
                )
                print(f"示例: {sample}")
                print("可能原因：")
                print("  1) 这些函数是在 alignment_loader 运行之后由 IDA 自动分析新增的；")
                print("  2) alignment_loader 导出时被过滤或发生错误。")
                print("处理建议：")
                print("  - 当前脚本无法为这些“DB 不存在”的函数构建依赖图，将跳过它们；")
                print("  - 若需分析，请在 IDA 中保存数据库后重新运行 alignment_loader.py 更新 .db 文件。")
                print("!" * 60 + "\n")

            # 合并实时 IDA sub_ 列表到结果中（以 IDB 名称为准）
            for ea, nm in live_subs.items():
                result[int(ea)] = nm

    return result


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
    构建全局变量 -> 读写函数 的引用图。
    改进版策略：
    1. 只要有指令引用该地址 (dst_va)，且该地址不是函数入口，就视为候选。
    2. 特别包含 off_*, dword_*, unk_*, byte_* 等默认命名。
    3. 排除段名 (.text, .data) 和纯代码标签。
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

    # 1) 获取所有被引用的目标地址 (dst_va)
    #    排除掉显然是函数调用的引用类型 (CALL)
    #    仅保留 DATA 读写相关的引用
    cur.execute(
            f"""
            SELECT DISTINCT dst_va, dst_name
            FROM xrefs
            WHERE view_id IN ({placeholders}) 
                AND dst_va IS NOT NULL
                AND ref_type_raw NOT IN ('UNCONDITIONAL_CALL', 'COMPUTED_CALL', '17', '19', '21');
            """,
            view_ids,
    )

    candidate_globals: Dict[int, Set[str]] = {}
    text_based_readers: Dict[int, Set[int]] = {}

    # 获取已知的所有函数入口，用于过滤
    code_entry_addrs: Set[int] = set(graph.nodes.keys())

    # 典型的段名/无关符号黑名单
    blacklist_names: Set[str] = {
        ".text",
        ".data",
        ".rdata",
        ".idata",
        ".edata",
        ".bss",
        ".tls",
        ".crt",
        ".ctors",
        ".dtors",
        "header",
        "debug",
    }

    # 典型的默认命名模式 (Regex)
    # 匹配: off_XXXX, dword_XXXX, byte_XXXX, unk_XXXX, qword_XXXX, word_XXXX, xmmword_XXXX
    default_name_pattern = re.compile(
        r"^(off|dword|byte|qword|unk|word|xmmword|float|double)_[0-9A-Fa-f]+$",
        re.IGNORECASE,
    )

    for dst_va, dst_name in cur.fetchall():
        addr = int(dst_va)

        # A. 绝对排除：如果这个地址是函数入口，跳过
        if addr in code_entry_addrs:
            continue

        name_str = (dst_name or "").strip()
        lower_name = name_str.lower()

        # B. 绝对排除：黑名单段名
        if lower_name in blacklist_names:
            continue

        # C. 纳入标准：
        #    1. 名字匹配默认变量名模式 (off_*, dword_*) -> 必须包含
        #    2. 或者名字为空 (依靠地址) -> 必须包含
        #    3. 或者原本 symbols 表里标记为 global/data (后续补充检查)

        is_default_pattern = bool(default_name_pattern.match(name_str))

        # 如果不是默认模式，且名字看起来很有意义（比如 "g_Config"），我们也要纳入分析吗？
        # 是的，因为可能名字不够好，需要 LLM 优化。

        if addr not in candidate_globals:
            candidate_globals[addr] = set()

        if name_str:
            candidate_globals[addr].add(name_str)

    # 2) 补充 symbols 表中的信息 (针对那些可能没有 xrefs 但明确是 global data 的情况，虽然 LLM 分析主要依赖 xrefs)
    #    同时利用 symbols 表里的全名来丰富 candidate_globals
    cur.execute(
        f"""
        SELECT address_va, name
        FROM symbols
        WHERE view_id IN ({placeholders}) 
          AND address_va IS NOT NULL
          AND (kind IN ('data', 'object', 'obj') OR is_global = 1);
        """,
        view_ids,
    )
    for addr_va, name in cur.fetchall():
        addr = int(addr_va)
        if addr in code_entry_addrs:
            continue
        if addr not in candidate_globals:
            # 如果 xrefs 没扫到，但 symbols 说是 data，也加进来
            candidate_globals[addr] = set()
        if name:
            candidate_globals[addr].add(str(name))

    # 3) 扫描伪代码文本，捕获 xrefs 漏掉的默认命名全局变量
    print("[Global] 正在从伪代码文本中挖掘潜在的全局变量引用...")
    cur.execute(
        f"""
        SELECT f.entry_va, pf.body
        FROM pseudo_functions AS pf
        JOIN functions AS f ON pf.function_id = f.id
        JOIN binary_views AS bv ON f.view_id = bv.id
        WHERE bv.binary_id = ? AND pf.body IS NOT NULL;
        """,
        (binary_id,),
    )

    scan_pattern = re.compile(
        r"\b((?:off|dword|byte|qword|unk|word|xmmword|float|double)_[0-9A-Fa-f]+)\b",
        re.IGNORECASE,
    )

    for entry_va, code_body in cur.fetchall():
        if entry_va is None or not code_body:
            continue

        matches = scan_pattern.findall(code_body)
        if not matches:
            continue

        for raw_name in matches:
            parts = raw_name.rsplit("_", 1)
            if len(parts) != 2:
                continue

            try:
                addr = int(parts[1], 16)
            except ValueError:
                continue

            if addr in code_entry_addrs:
                continue

            candidate_globals.setdefault(addr, set()).add(raw_name)
            text_based_readers.setdefault(addr, set()).add(int(entry_va))

    if not candidate_globals:
        return {}

    # 4) 构建 GlobalVarNode
    globals_by_addr: Dict[int, GlobalVarNode] = {}
    for addr, names in candidate_globals.items():
        node = GlobalVarNode(address_va=addr)
        node.names = names
        globals_by_addr[addr] = node

    # 5) 填充 readers / writers (这步逻辑不变，用于计算上下文)
    #    先构建快速查找表
    addr_to_func: Dict[Tuple[int, int], int] = {}
    cur.execute(
        f"""
        SELECT view_id, function_id, address_va
        FROM instructions
        WHERE view_id IN ({placeholders}) AND address_va IS NOT NULL;
        """,
        view_ids,
    )
    for view_id, fid, addr_va in cur.fetchall():
        addr_to_func[(int(view_id), int(addr_va))] = int(fid)

    func_to_entry: Dict[int, int] = {}
    cur.execute(
        f"SELECT id, entry_va FROM functions WHERE view_id IN ({placeholders});",
        view_ids,
    )
    for fid, entry_va in cur.fetchall():
        if entry_va is not None:
            func_to_entry[int(fid)] = int(entry_va)

    # 再次遍历 xrefs 填充读写关系
    cur.execute(
        f"""
        SELECT view_id, src_va, dst_va, ref_type_raw
        FROM xrefs
        WHERE view_id IN ({placeholders}) AND dst_va IS NOT NULL;
        """,
        view_ids,
    )
    for view_id, src_va, dst_va, ref_type_raw in cur.fetchall():
        addr = int(dst_va)
        node = globals_by_addr.get(addr)
        if node is None:
            continue

        func_id = addr_to_func.get((int(view_id), int(src_va)))
        if func_id is None:
            continue
        entry_va = func_to_entry.get(func_id)
        if entry_va is None:
            continue

        # 记录读写者
        access_kind = (ref_type_raw or "").strip().upper()
        # 简单的 heuristic: 包含 WRITE 视为写，否则视为读
        if "WRITE" in access_kind:
            node.writers.add(entry_va)
        else:
            node.readers.add(entry_va)

    # 6) 合并伪代码扫描得到的读者集合（避免漏掉未生成 xref 的引用）
    for addr, readers in text_based_readers.items():
        node = globals_by_addr.get(addr)
        if not node:
            continue
        node.readers.update(readers)

    return globals_by_addr


def build_validation_prompt(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entry_va: int,
) -> str:
    """第二阶段：单函数 Top-down Validation Prompt。"""

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


def build_validation_context(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entry_va: int,
) -> str:
    """构造 Phase2 校验的“上下文段”，便于单体/批量 Prompt 复用。"""

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

    display_name = (
        next(iter(sorted(node.names)), f"sub_{entry_va:08X}")
        if node.names
        else f"sub_{entry_va:08X}"
    )

    # 上游调用者视角
    caller_snippets: List[str] = []
    for caller_va in sorted(node.caller_vas):
        snippet = _get_call_site_snippet(conn, graph, caller_va, node.names)
        caller_name = (
            next(iter(sorted(graph.nodes[caller_va].names)), f"sub_{caller_va:08X}")
            if caller_va in graph.nodes
            else f"sub_{caller_va:08X}"
        )
        if snippet:
            caller_snippets.append(
                f"[Caller {caller_name} @ 0x{caller_va:08X}]\n{snippet}"
            )
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
        callee_name = (
            next(iter(sorted(callee.names)), f"sub_{callee_va:08X}")
            if callee.names
            else f"sub_{callee_va:08X}"
        )
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


def build_validation_batch_prompt(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entry_vas: List[int],
) -> str:
    """Phase2：批量校验 Prompt（返回 JSON 数组，顺序与输入一致）。"""
    lines: List[str] = []
    lines.append("你是一名进行‘第二阶段 Top-down 校验’的逆向工程专家。")
    lines.append(
        "请对以下多个函数的命名/签名进行校验。返回一个 JSON 数组，长度必须等于条目数量，顺序完全一致。"
    )
    lines.append(
        '数组中每个对象字段：{"entry_va":"0x...","action":"RENAME"|"CONFIRM","new_name":"...","confidence":0.0-1.0,"reasoning":"..."}。'
    )
    lines.append("仅当当前名称为默认风格(sub_/fun_/loc_)且你有更好建议时选择 RENAME。")

    for idx, va in enumerate(entry_vas, 1):
        ctx = build_validation_context(conn, graph, va)
        lines.append(f"\n[Item {idx}/{len(entry_vas)}] entry_va=0x{va:08X}\n{ctx}")

    return "\n".join(lines)


def _apply_validation_llm_result(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entry_va: int,
    result: Dict[str, Any],
    ida_sync: bool,
    ida_url: str,
) -> Optional[float]:
    """将 Phase2 单条结果落库/同步，并返回后验置信度。"""

    node = graph.nodes[entry_va]
    display_name = (
        next(iter(sorted(node.names)), f"sub_{entry_va:08X}")
        if node.names
        else f"sub_{entry_va:08X}"
    )

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
            cur.execute(
                "SELECT summary_signature FROM analysis_status WHERE function_id = ?;",
                (fid,),
            )
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
        cur.execute(
            """
            UPDATE analysis_status
            SET analysis_state = 'LOCKED'
            WHERE function_id = ?;
            """,
            (fid,),
        )
    conn.commit()

    return max(0.0, min(1.0, confidence))


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
    # 在启用 IDA 同步的情况下，每次校验前都确认 idat_server 在线
    if ida_sync and ida_url:
        wait_for_ida_server(ida_url)

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

    return _apply_validation_llm_result(
        conn=conn,
        graph=graph,
        entry_va=entry_va,
        result=result,
        ida_sync=ida_sync,
        ida_url=ida_url,
    )


def run_validation_phase(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    llm_settings: LLMSettings,
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
    batch_size: int = 10,
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
    batch_target = max(1, int(batch_size) if batch_size else 1)

    while queue:
        # 每一轮尽量取出 Top-N 个需要 LLM 校验的默认命名函数
        to_validate: List[int] = []

        while queue and len(to_validate) < batch_target:
            task = heapq.heappop(queue)
            entry_va = task.entry_va

            # 已经 LOCKED 的节点：跳过 LLM，仅用于向下传播
            if _is_locked(entry_va):
                node = graph.nodes.get(entry_va)
                if node:
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
                        if pbar is not None:
                            pbar.total += 1
                            pbar.refresh()
                if pbar is not None:
                    pbar.update(1)
                    pbar.set_description(f"Phase 2: Skip LOCKED 0x{entry_va:08X}")
                continue

            # 具名函数跳过 LLM 校验
            node = graph.nodes.get(entry_va)
            if not node:
                if pbar is not None:
                    pbar.update(1)
                continue

            current_name = (
                next(iter(sorted(node.names)), f"sub_{entry_va:08X}")
                if node.names
                else f"sub_{entry_va:08X}"
            )
            is_default_name = bool(DEFAULT_FUNC_NAME_PATTERN.fullmatch(current_name))

            if not is_default_name:
                posterior_conf = 1.0
                if pbar is not None:
                    pbar.set_description(f"Phase 2: Skip Named 0x{entry_va:08X}")
                    pbar.update(1)

                if posterior_conf > 0.6:
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
                        if pbar is not None:
                            pbar.total += 1
                            pbar.refresh()
                continue

            # 默认名函数进入批量校验
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
            if pbar is not None:
                top_va = batch.items[0]
                pbar.set_description(f"Phase 2: batch={len(batch.items)} top=0x{top_va:08X}")

            if dry_run:
                print("=" * 80)
                print(f"[Phase 2 DRY-RUN] batch size={len(batch.items)}")
                print(batch.prompt[:2000])
                # dry-run 不落库，仍以高置信度向下传播
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
                        heapq.heappush(
                            queue,
                            ValidationTask(
                                entry_va=callee_va,
                                priority=posterior_conf * 100.0,
                                path_confidence=posterior_conf,
                            ),
                        )
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

                posterior_conf = _apply_validation_llm_result(
                    conn=conn,
                    graph=graph,
                    entry_va=entry_va,
                    result=res,
                    ida_sync=ida_sync,
                    ida_url=ida_url,
                )
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
                    heapq.heappush(
                        queue,
                        ValidationTask(
                            entry_va=callee_va,
                            priority=posterior_conf * 100.0,
                            path_confidence=posterior_conf,
                        ),
                    )
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


def _build_global_var_context(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    var_node: GlobalVarNode,
    analysis_info: Dict[int, dict],
    max_users: int = 6,
) -> str:
    """构造 Phase3 单个全局变量的上下文段（供批量 Prompt 复用）。"""

    addr = var_node.address_va
    current_names = sorted(var_node.names) or [f"byte_{addr:08X}"]

    access_funcs: List[Tuple[float, int, str, str]] = []

    all_users = list(var_node.writers | var_node.readers)
    for entry_va in all_users:
        fn = graph.nodes.get(entry_va)
        if not fn:
            continue
        fn_name = (
            next(iter(sorted(fn.names)), f"sub_{entry_va:08X}")
            if fn.names
            else f"sub_{entry_va:08X}"
        )

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

        snippet = _get_global_use_snippet(conn, graph, entry_va, var_node)
        if not snippet:
            continue

        access_funcs.append((best_conf, entry_va, fn_name, snippet))

    if not access_funcs:
        usage_section = "(没有找到可靠的函数访问上下文，仅基于名称和地址做轻量推断。)"
    else:
        access_funcs.sort(key=lambda x: x[0], reverse=True)
        lines: List[str] = []
        for conf, entry_va, fn_name, snippet in access_funcs[:max_users]:
            lines.append(
                f"[Function {fn_name} @ 0x{entry_va:08X}, confidence={conf:.2f}]\n{snippet}"
            )
        usage_section = "\n\n".join(lines)

    return (
        f"当前全局变量：0x{addr:08X}\n"
        f"当前名称候选：{', '.join(current_names)}\n\n"
        f"[访问上下文（函数如何读写该变量）]\n{usage_section}"
    ).strip()


def build_global_var_batch_prompt(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    var_nodes: List[GlobalVarNode],
    analysis_info: Dict[int, dict],
) -> str:
    """Phase3：批量全局变量分析 Prompt（返回 JSON 数组，顺序与输入一致）。"""

    lines: List[str] = []
    lines.append("你是一名擅长从访问模式推断‘全局变量语义’的逆向工程专家。")
    lines.append(
        "请分析以下多个全局变量，返回一个 JSON 数组，长度必须等于条目数量，顺序完全一致。"
    )
    lines.append(
        '数组中每个对象字段：{"address_va":"0x...","name":"g_VarName","type":"...","confidence":0.0-1.0,"reason":"..."}。'
    )

    for idx, node in enumerate(var_nodes, 1):
        ctx = _build_global_var_context(conn, graph, node, analysis_info)
        lines.append(
            f"\n[Item {idx}/{len(var_nodes)}] address_va=0x{node.address_va:08X}\n{ctx}"
        )

    return "\n".join(lines)


def _apply_global_var_llm_result(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    var_node: GlobalVarNode,
    result: Dict[str, Any],
    ida_sync: bool,
    ida_url: str,
) -> float:
    """将 Phase3 单条全局变量结果落库/同步，并返回后验置信度。"""

    addr = var_node.address_va

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

    if not name or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name) or len(name) > 255:
        print("[GLOBAL] 提议的变量名不符合标识符规范，跳过改名。")
        final_name = (
            next(iter(sorted(var_node.names)), f"g_{addr:08X}")
            if var_node.names
            else f"g_{addr:08X}"
        )
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
    batch_size: int = 10,
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

    # 按优先级截取本次要处理的变量
    selected_addrs = pending_addrs[:target_count]
    selected_nodes = [globals_by_addr[a] for a in selected_addrs]
    batch_target = max(1, int(batch_size) if batch_size else 1)

    def _builder(nodes: List[GlobalVarNode]) -> str:
        return build_global_var_batch_prompt(conn, graph, nodes, analysis_info)

    for batch in yield_dynamic_batch(
        selected_nodes,
        prompt_builder=_builder,
        max_prompt_tokens=llm_settings.max_tokens,
        token_estimator=estimate_token_usage,
        initial_batch_size=batch_target,
        min_batch_size=1,
    ):
        if not batch.items:
            continue

        top_addr = batch.items[0].address_va
        pbar.set_description(f"Phase 3: batch={len(batch.items)} top=0x{top_addr:08X}")

        if dry_run:
            print("=" * 80)
            print(f"[Phase 3 DRY-RUN] batch size={len(batch.items)}")
            print(batch.prompt[:2000])
            processed += len(batch.items)
            pbar.update(len(batch.items))
            continue

        conversation, request_kwargs = build_chat_request(batch.prompt, llm_settings)
        result_list = call_llm_analyze_function(
            conversation=conversation,
            request_kwargs=request_kwargs,
            api_settings=llm_settings.api_settings,
            expect_array=True,
            expected_size=len(batch.items),
        )

        if not result_list or not isinstance(result_list, list):
            print("[GLOBAL] 批量 LLM 返回非法，跳过该批次。")
            processed += len(batch.items)
            pbar.update(len(batch.items))
            continue

        for var_node, res in zip(batch.items, result_list):
            addr = var_node.address_va
            score = scores.get(addr, 0)
            print(
                f"\n[GLOBAL] 选择全局变量 0x{addr:08X} (score={score}, names={sorted(var_node.names)})"
            )
            if isinstance(res, dict):
                _apply_global_var_llm_result(
                    conn=conn,
                    graph=graph,
                    var_node=var_node,
                    result=res,
                    ida_sync=ida_sync,
                    ida_url=ida_url,
                )
            else:
                print("[GLOBAL] 跳过：返回值不是 JSON 对象。")

        processed += len(batch.items)
        pbar.update(len(batch.items))

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


def _is_quota_exhausted_error(exc: Exception) -> bool:
    text = str(exc) if exc else ""
    lowered = text.lower()
    keywords = (
        "token quota is not enough",
        "pre_consume_token_quota_failed",
        "insufficient_quota",
        "insufficient quota",
    )
    return any(k in lowered for k in keywords)


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


def _repair_json_string(text: str) -> str:
    """
    [新增辅助函数] 尝试修复常见的 LLM JSON 格式错误。
    """
    text = re.sub(r",\s*\]", "]", text)
    text = re.sub(r",\s*\}", "}", text)
    clean_text = text.replace("\n", " ").replace("\r", "")
    return clean_text


def call_llm_analyze_function(
    conversation: List[Dict[str, str]],
    request_kwargs: Dict[str, Any],
    api_settings: Dict[str, Any],
    max_attempts: int = 3,
    return_raw_on_error: bool = False,
    expect_array: bool = False,
    expected_size: Optional[int] = None,
) -> Any:
    """
    调用 OpenAI ChatCompletion 做函数分析。

    默认期望返回单个 JSON 对象；若 expect_array=True，则要求返回 JSON 数组，
    并在 expected_size 给定时校验数组长度。
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
                if _is_quota_exhausted_error(exc):
                    exit_msg = (
                        "检测到 LLM API 余额不足，流程将安全退出；当前任务支持断点续工，"
                        "请充值后重新运行。"
                    )
                    print(exit_msg)
                    logger.error("%s", exit_msg)
                    sys.exit(1)

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

        # 解析顺序：
        #   - 批量模式直接尝试完整字符串（保留方括号），避免裁剪成对象导致失败；
        #   - 单对象模式保持原有大括号裁剪作为容错。
        candidates: List[str] = []
        if expect_array:
            candidates.append(text_str.strip())
        else:
            start = text_str.find("{")
            end = text_str.rfind("}")
            if start != -1 and end != -1 and end > start:
                candidates.append(text_str[start : end + 1])
            else:
                candidates.append(text_str)

        data = None
        parse_ok = False

        for candidate in candidates:
            try:
                data = json.loads(candidate)
                parse_ok = True
                break
            except json.JSONDecodeError:
                pass

            try:
                data = json.loads(candidate, strict=False)
                parse_ok = True
                break
            except json.JSONDecodeError:
                pass

            try:
                cleaned = _repair_json_string(candidate)
                data = json.loads(cleaned, strict=False)
                parse_ok = True
                break
            except json.JSONDecodeError:
                data = None

        if not parse_ok:
            last_error = (
                f"LLM 返回内容无法解析为 JSON({attempt}/{max_attempts})：{candidates[0]!r}"
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

        if expect_array:
            if not isinstance(data, list):
                last_error = (
                    f"LLM 返回的 JSON 不是数组({attempt}/{max_attempts})：{data!r}"
                )
                logger.warning("%s", last_error)
                continue

            if expected_size is not None and len(data) != expected_size:
                last_error = (
                    f"LLM 返回数组长度不符({attempt}/{max_attempts})："
                    f"expected={expected_size}, got={len(data)}"
                )
                logger.warning("%s", last_error)
                continue

            return data

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
    return [] if expect_array else {}


def build_chat_request(prompt: str, llm_settings: LLMSettings) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    """构造要发送给 ChatCompletion 的消息与请求参数。"""

    conversation: List[Dict[str, str]] = [
        {
            "role": "system",
            "content": (
                "You are an expert reverse engineer. "
                "You must respond with a single valid JSON value only."
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


def estimate_token_usage(text: str) -> int:
    """按经验比例估算 token 数，便于在批处理前做容量预检。

    规则：
      - 1 token ~= 0.75 个英文单词
      - 1 token ~= 0.5 个中文字符
      - 1 token ~= 3 个标点符号
      - 其他字符按 0.3 token/字符 近似，避免明显低估。
    """

    words = re.findall(r"[A-Za-z]+", text)
    word_tokens = len(words) / 0.75 if words else 0.0

    chinese_chars = re.findall(r"[\u4e00-\u9fff]", text)
    chinese_tokens = len(chinese_chars) / 0.5 if chinese_chars else 0.0

    punctuation_count = sum(
        1 for ch in text if unicodedata.category(ch).startswith("P")
    )
    punctuation_tokens = punctuation_count / 3.0 if punctuation_count else 0.0

    english_letter_count = sum(len(w) for w in words)
    residual_count = max(
        0, len(text) - english_letter_count - len(chinese_chars) - punctuation_count
    )
    residual_tokens = residual_count * 0.3

    estimated = word_tokens + chinese_tokens + punctuation_tokens + residual_tokens
    return int(math.ceil(estimated))


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


def _make_name_unique(conn: sqlite3.Connection, base_name: str, current_fid: int) -> str:
    """
    检查数据库中是否已存在 base_name。
    如果存在且不是当前函数，则自动追加 _1, _2 等后缀。

    若 base_name 为空或仍然是明显的默认地址命名（sub_XXXX / fun_XXXX / loc_XXXX），
    则原样返回，由上层逻辑决定是否改名或放弃同步。
    """
    base_name = (base_name or "").strip()
    if not base_name:
        return base_name

    # 典型 decompiler 默认名：不在这里做自动去重，由上层决定是否沿用或放弃
    if DEFAULT_FUNC_NAME_PATTERN.fullmatch(base_name):
        return base_name

    cur = conn.cursor()
    cur.execute(
        "SELECT id FROM functions WHERE name = ? AND id != ?;",
        (base_name, current_fid),
    )
    rows = cur.fetchall()
    if not rows:
        return base_name

    counter = 1
    while True:
        candidate = f"{base_name}_{counter}"
        cur.execute(
            "SELECT id FROM functions WHERE name = ? AND id != ?;",
            (candidate, current_fid),
        )
        if not cur.fetchone():
            return candidate
        counter += 1


def _sync_global_with_ida_and_update_db(
    conn: sqlite3.Connection,
    address_va: int,
    new_name: str,
    type_str: Optional[str],
    ida_url: str,
) -> None:
    """
    将全局变量改名/类型信息同步到 idat_server，并更新对齐数据库中的 symbols/global_vars。
    """
    if requests is None or not new_name:
        logger.info(
            "[IDA-Sync] requests 未安装或 new_name 为空，跳过全局变量同步。 addr=0x%08X",
            address_va,
        )
        return

    # 每次与 IDA 同步前，都先确认 idat_server 在线
    if ida_url:
        wait_for_ida_server(ida_url)

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
    # 确认 IDA 端是否成功处理
    if (data or {}).get("status") != "ok":
        logger.error(
            "[IDA-Sync] rename_global IDA 返回错误: %s",
            data or resp.text[:200],
        )
        return

    ida_new_name = data.get("new_name") or new_name
    if data.get("new_name") and data["new_name"] != new_name:
        logger.warning(
            "[IDA-Sync] rename_global 名字不一致：requested=%s, applied=%s (addr=0x%08X)",
            new_name,
            data["new_name"],
            address_va,
        )
    applied_type = data.get("applied_type")
    logger.info(
        "[IDA-Sync] rename_global 成功: addr=0x%08X, name=%s, applied_type=%s",
        address_va,
        ida_new_name,
        applied_type or type_str,
    )

    # 同步对齐数据库中 symbols 表的名字
    cur = conn.cursor()
    cur.execute(
        "UPDATE symbols SET name = ? WHERE address_va = ?;",
        (ida_new_name, address_va),
    )
    conn.commit()
    logger.debug(
        "[IDA-Sync] 已在数据库中将 symbols.address_va=0x%08X 更新为 name=%s",
        address_va,
        new_name,
    )


def _prompt_run_validation_with_timeout(timeout_sec: int = 5) -> bool:
    """
    带倒计时的简易交互 (非阻塞版)：
    - Windows: 使用 msvcrt.kbhit/getwch 检测按键，避免线程 + input 占用 stdin 锁；
    - *nix: 使用 select.select 监听 stdin；
    - 非交互环境直接默认继续。
    """
    if not sys.stdin or not sys.stdin.isatty():
        print("[Validation] 非交互环境，默认执行第二阶段调用链校验。")
        return True

    print(
        f"[Validation] 即将进入第二阶段校验。输入 N/n 跳过，其他键或等待 {timeout_sec} 秒后继续..."
    )

    start_time = time.time()
    user_input: Optional[str] = None

    if sys.platform == "win32":
        import msvcrt

        while True:
            remaining = timeout_sec - (time.time() - start_time)
            if remaining <= 0:
                print("\n[Validation] 自动继续。")
                break

            sys.stdout.write(
                f"\r[Validation] 倒计时: {remaining:.1f} 秒 (按 N 跳过)   "
            )
            sys.stdout.flush()

            if msvcrt.kbhit():
                char = msvcrt.getwch()
                print(f"\n[Validation] 检测到输入: {char}")
                user_input = char
                break

            time.sleep(0.1)

    else:
        import select

        print(f"[Validation] 请在 {timeout_sec} 秒内输入...")
        rlist, _, _ = select.select([sys.stdin], [], [], timeout_sec)
        if rlist:
            user_input = sys.stdin.readline().strip()
        else:
            print("\n[Validation] 自动继续。")

    if user_input and str(user_input).strip().lower() in ("n", "no"):
        print("[Validation] 用户选择跳过第二阶段调用链校验。")
        return False

    print("[Validation] 进入第二阶段调用链逻辑流校验。")
    return True


def _force_ida_save_database(ida_url: str, timeout: float = 15.0) -> bool:
    """请求 idat_server 立即保存数据库（不退出）。"""
    if requests is None:
        return False

    try:
        resp = requests.post(
            ida_url, json={"action": "save_database"}, timeout=timeout
        )
    except Exception as exc:
        logger.warning("[IDA-Sync] save_database 调用失败: %s", exc)
        return False

    if resp.status_code != 200:
        logger.warning(
            "[IDA-Sync] save_database HTTP %s: %s",
            resp.status_code,
            resp.text[:200],
        )
        return False

    try:
        data = resp.json()
    except Exception:
        return False

    return data.get("status") == "ok"


def _fetch_ida_pseudocode(entry_va: int, ida_url: str, timeout: float = 10.0) -> Optional[str]:
    """向 idat_server 请求指定函数的最新伪代码。"""
    if requests is None:
        return None

    payload = {"action": "get_pseudocode", "ea": entry_va}
    try:
        resp = requests.post(ida_url, json=payload, timeout=timeout)
    except Exception as exc:
        logger.warning(
            "[IDA-Sync] get_pseudocode 调用失败 0x%08X: %s", entry_va, exc
        )
        return None

    if resp.status_code != 200:
        logger.warning(
            "[IDA-Sync] get_pseudocode HTTP %s: %s",
            resp.status_code,
            resp.text[:200],
        )
        return None

    try:
        data = resp.json()
    except Exception as exc:
        logger.warning(
            "[IDA-Sync] 解析 get_pseudocode 响应失败 0x%08X: %s; body=%s",
            entry_va,
            exc,
            resp.text[:200],
        )
        return None

    if data.get("status") != "ok":
        logger.warning(
            "[IDA-Sync] get_pseudocode 返回错误 0x%08X: %s", entry_va, data
        )
        return None

    code = data.get("pseudocode")
    return code if isinstance(code, str) else None


def _fetch_live_ida_subfuncs(ida_url: str, timeout: float = 30.0) -> Dict[int, str]:
    """
    从正在运行的 idat_server 获取当前 IDB 中所有仍为 sub_ 前缀的函数。
    返回字典 { entry_va(int): name(str) }。
    """
    if requests is None:
        return {}

    payload = {"action": "get_sub_functions"}
    try:
        resp = requests.post(ida_url, json=payload, timeout=timeout)
    except Exception as exc:
        logger.warning("[IDA-Sync] get_sub_functions 调用失败: %s", exc)
        return {}

    if resp.status_code != 200:
        logger.warning(
            "[IDA-Sync] get_sub_functions HTTP %s: %s",
            resp.status_code,
            resp.text[:200],
        )
        return {}

    try:
        data = resp.json()
    except Exception as exc:
        logger.warning(
            "[IDA-Sync] 解析 get_sub_functions 响应失败: %s; body=%s",
            exc,
            resp.text[:200],
        )
        return {}

    if data.get("status") != "ok":
        logger.warning("[IDA-Sync] get_sub_functions 返回错误: %s", data)
        return {}

    raw = data.get("sub_functions") or {}
    if not isinstance(raw, dict):
        return {}

    result: Dict[int, str] = {}
    for k, v in raw.items():
        name = (v or "").strip()
        if not name:
            continue
        try:
            if isinstance(k, int):
                ea = int(k)
            elif isinstance(k, str):
                s = k.strip()
                if s.lower().startswith("0x"):
                    ea = int(s, 16)
                else:
                    ea = int(s)
            else:
                continue
        except Exception:
            continue
        result[ea] = name

    return result


def _save_and_refresh_pseudocode(
    entry_va: int, ida_url: str, wait_seconds: float = 1.0
) -> Optional[str]:
    """强制保存 IDA 数据库后，等待片刻并重新获取伪代码。"""
    _force_ida_save_database(ida_url)
    if wait_seconds > 0:
        time.sleep(wait_seconds)
    return _fetch_ida_pseudocode(entry_va, ida_url)


def _reconcile_ida_db_mismatch(
    conn: sqlite3.Connection,
    binary_id: int,
    ida_url: str,
    llm_settings: LLMSettings,
    ida_sync: bool,
    max_items: int = 50,
) -> None:
    """
    在进入第一阶段前，对比数据库（IDA 视图）与实际 .i64 的名称/伪代码差异，
    通过 LLM 决策采用哪一侧的名称/伪代码，并同步更新。
    """
    if requests is None:
        return

    # 仅当数据库中该 binary 的所有函数都处于 PENDING 状态时才执行对齐
    cur = conn.cursor()
    cur.execute(
        """
        SELECT COUNT(*) AS total_count,
               SUM(CASE WHEN a.analysis_state IS NULL OR a.analysis_state = 'PENDING' THEN 1 ELSE 0 END) AS pending_count
        FROM functions AS f
        JOIN binary_views AS bv ON f.view_id = bv.id
        LEFT JOIN analysis_status AS a ON a.function_id = f.id
        WHERE bv.binary_id = ?;
        """,
        (binary_id,),
    )
    total_count, pending_count = cur.fetchone() or (0, 0)
    all_pending = total_count > 0 and pending_count == total_count
    if not all_pending:
        logger.info(
            "[Align] 跳过 IDA/DB 不一致对齐：存在非 PENDING 函数 (pending=%s, total=%s)",
            pending_count,
            total_count,
        )
        return

    # 找出 IDA 视图 id
    cur.execute(
        """
        SELECT bv.id
        FROM binary_views AS bv
        JOIN tools AS t ON bv.tool_id = t.id
        WHERE bv.binary_id = ? AND LOWER(t.name) = 'ida'
        ORDER BY bv.id LIMIT 1;
        """,
        (binary_id,),
    )
    row = cur.fetchone()
    if not row:
        return
    ida_view_id = int(row[0])

    cur.execute(
        """
        SELECT f.id, f.entry_va, COALESCE(f.name, '') AS name, COALESCE(pf.body, '') AS body
        FROM functions AS f
        LEFT JOIN pseudo_functions AS pf ON pf.function_id = f.id
        WHERE f.view_id = ?;
        """,
        (ida_view_id,),
    )
    rows = cur.fetchall()

    mismatches: List[Tuple[int, int, str, str, dict]] = []
    removed_function_ids: set[int] = set()

    for function_id, entry_va, db_name, db_body in rows:
        info = _fetch_ida_function_info(entry_va, ida_url)
        if not info:
            _drop_function_record(conn, function_id, entry_va)
            removed_function_ids.add(function_id)
            continue
        ida_name = info.get("name", "") or ""
        ida_code = info.get("pseudocode", "") or ""

        name_diff = (db_name or "") != (ida_name or "")
        code_diff = (db_body or "").strip() != (ida_code or "").strip()

        # 仅在 IDA 名字仍为 sub_ 前缀时触发对齐（核心需求）
        ida_is_sub = bool(SUBFUNC_NAME_PATTERN.fullmatch(ida_name or ""))

        if not ida_is_sub:
            continue
        if not name_diff and not code_diff:
            continue

        mismatches.append((function_id, entry_va, db_name, db_body, info))
        if len(mismatches) >= max_items:
            break

    if not mismatches:
        return

    print(
        f"[Align] 检测到 {len(mismatches)} 个 IDA/DB 不一致的函数，"
        "将其重置为 PENDING，交由 Phase 1 知识传播重新分析。"
    )

    ids_to_reset: Set[int] = set()
    pbar = tqdm(mismatches, desc="Aligning DB vs IDA", unit="fn")

    for function_id, entry_va, db_name, db_body, info in pbar:
        pbar.set_postfix(address=f"0x{entry_va:08X}")

        ida_name = info.get("name", "") or ""
        ida_code = info.get("pseudocode", "") or ""

        # 刷新 IDA 视图对应的伪代码，避免后续使用过时内容
        if ida_code:
            cur.execute(
                "UPDATE pseudo_functions SET body = ? WHERE function_id = ?;",
                (ida_code, function_id),
            )

        # 将同一 entry_va 下的所有视图标记为 PENDING，便于 Phase 1 统一重跑
        cur.execute(
            """
            SELECT f.id
            FROM functions AS f
            JOIN binary_views AS bv ON f.view_id = bv.id
            WHERE bv.binary_id = ? AND f.entry_va = ?;
            """,
            (binary_id, entry_va),
        )
        related_ids = [row[0] for row in cur.fetchall()]
        for fid in related_ids:
            ids_to_reset.add(int(fid))

        logger.info(
            "[Align] 0x%08X: 发现 DB/IDA 差异，名称(db=%s, ida=%s)，已加入 PENDING 队列。",
            entry_va,
            db_name,
            ida_name,
        )

    if ids_to_reset:
        for fid in sorted(ids_to_reset):
            cur.execute(
                """
                UPDATE analysis_status
                SET analysis_state = 'PENDING',
                    confidence_score = 0,
                    summary_signature = NULL,
                    semantic_summary = NULL
                WHERE function_id = ?;
                """,
                (fid,),
            )
        conn.commit()

    print(
        f"[Align] 已处理 {len(mismatches)} 个不一致函数，"
        f"重置 {len(ids_to_reset)} 条 analysis_status 记录为 PENDING。"
    )


def _fetch_ida_function_info(entry_va: int, ida_url: str, timeout: float = 10.0) -> Optional[dict]:
    """获取 IDA 中的函数名称与伪代码。"""
    if requests is None:
        return None

    payload = {"action": "get_function_info", "ea": entry_va}
    try:
        resp = requests.post(ida_url, json=payload, timeout=timeout)
    except Exception as exc:
        logger.warning(
            "[IDA-Sync] get_function_info 调用失败 0x%08X: %s", entry_va, exc
        )
        return None

    if resp.status_code != 200:
        logger.warning(
            "[IDA-Sync] get_function_info HTTP %s: %s",
            resp.status_code,
            resp.text[:200],
        )
        return None

    try:
        data = resp.json()
    except Exception as exc:
        logger.warning(
            "[IDA-Sync] 解析 get_function_info 响应失败 0x%08X: %s; body=%s",
            entry_va,
            exc,
            resp.text[:200],
        )
        return None

    if data.get("status") != "ok":
        logger.warning(
            "[IDA-Sync] get_function_info 返回错误 0x%08X: %s", entry_va, data
        )
        return None

    return data


def _drop_function_record(conn: sqlite3.Connection, function_id: int, entry_va: int) -> None:
    """删除无法反编译/无效的函数记录及相关指令、伪代码。"""
    cur = conn.cursor()
    cur.execute("DELETE FROM instructions WHERE function_id = ?;", (function_id,))
    cur.execute("DELETE FROM pseudo_functions WHERE function_id = ?;", (function_id,))
    cur.execute("DELETE FROM functions WHERE id = ?;", (function_id,))
    conn.commit()
    print(f"[Align] 移除无法反编译的函数 0x{entry_va:08X} (function_id={function_id})")


def _collect_function_snippets(
    conn: sqlite3.Connection, function_id: int, max_asm_lines: int = 120
) -> dict:
    """提取指定函数的伪代码和汇编片段，用于重名冲突时的 LLM 判断。"""
    cur = conn.cursor()

    cur.execute(
        "SELECT entry_va, COALESCE(body, '') FROM pseudo_functions WHERE function_id = ?;",
        (function_id,),
    )
    row = cur.fetchone()
    entry_va = int(row[0]) if row else 0
    pseudocode = row[1] if row else ""

    cur.execute(
        """
        SELECT raw_line
        FROM instructions
        WHERE function_id = ?
        ORDER BY index_in_function
        LIMIT ?;
        """,
        (function_id, max_asm_lines),
    )
    asm_lines = [r[0] for r in cur.fetchall() if r and r[0]]
    asm_text = "\n".join(asm_lines)

    return {
        "entry_va": entry_va,
        "pseudocode": pseudocode,
        "asm": asm_text,
    }


def _resolve_name_collision_with_llm(
    base_name: str,
    current_ea: int,
    existing_ea: int,
    current_snippets: dict,
    existing_snippets: dict,
    llm_settings,
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


def _sync_with_ida_and_update_db(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    node: UnifiedFunctionNode,
    entry_va: int,
    signature: str,
    summary: str,
    ida_url: str,
    enforce_non_sub: bool = True,
) -> None:
    """
    调用在 idat 中运行的 HTTP 服务（idat_server.py），对物理函数进行重命名，
    并使用返回的最新伪代码刷新当前数据库中对应 IDA 视图的 pseudo_functions / functions。
    """
    if requests is None:
        logger.info(
            "[IDA-Sync] 未安装 requests，跳过函数同步。pip install requests 可启用。"
        )
        return

    # 每次与 IDA 同步前，都先确认 idat_server 在线（支持断链自动重试 + 人工立即重试）
    if ida_url:
        wait_for_ida_server(ida_url)

    # 选出 IDA 视图上的 function_id（如果存在），优先同步该视图的伪代码
    ida_function_id: Optional[int] = None
    for fid in node.function_ids:
        tool_name = graph.func_tool.get(fid, "")
        if tool_name.lower() == "ida":
            ida_function_id = fid
            break
    if ida_function_id is None:
        # 没有 IDA 视图，仅更新对齐数据库中的名字即可
        logger.info(
            "[IDA-Sync] 未找到 IDA 视图对应的 function_id，仅更新当前数据库。 entry_va=0x%08X",
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

    # 如果从 signature 中解析出来的名字仍然是明显的默认地址命名（sub_XXXX / fun_XXXX / loc_XXXX），
    # 则回退到当前数据库/IDA 中已有的名字，避免把 LLM 生成的默认形式强行写回。
    if DEFAULT_FUNC_NAME_PATTERN.fullmatch(final_name) and fallback_name:
        logger.info(
            "[IDA-Sync] 解析出的函数名 %s 看起来是默认地址命名，回退为现有名字 %s。 entry_va=0x%08X",
            final_name,
            fallback_name,
            entry_va,
        )
        final_name = fallback_name

    # 在真正同步到 IDA 之前，先在数据库范围内做一次去重，必要时自动追加 _1 / _2 等后缀
    ref_fid: Optional[int] = None
    if node.function_ids:
        ref_fid = next(iter(node.function_ids))
    elif ida_function_id is not None:
        ref_fid = ida_function_id

    if ref_fid is not None:
        unique_name = _make_name_unique(conn, final_name, ref_fid)
        if unique_name != final_name:
            logger.info(
                "[IDA-Sync] entry_va=0x%08X 函数名发生去重调整: %s -> %s",
                entry_va,
                final_name,
                unique_name,
            )
        final_name = unique_name

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

    max_retry = 3
    applied_name = final_name
    latest_code: str = ""

    def _post_rename_once() -> Tuple[Optional[dict], Optional[str]]:
        try:
            resp = requests.post(ida_url, json=payload, timeout=10.0)
        except Exception as exc:
            logger.error("[IDA-Sync] 连接 IDA 失败: %s", exc)
            return None, None

        if resp.status_code != 200:
            logger.error(
                "[IDA-Sync] HTTP %s: %s",
                resp.status_code,
                resp.text[:200],
            )
            return None, None

        try:
            data = resp.json()
        except Exception as exc:  # pragma: no cover - 解析失败仅日志
            logger.error(
                "[IDA-Sync] 解析 IDA 响应失败: %s; body=%s",
                exc,
                resp.text[:200],
            )
            return None, None

        if data.get("status") != "ok":
            logger.error("[IDA-Sync] IDA 返回错误: %s", data)
            return None, None

        return data, data.get("updated_pseudocode") or ""

    for attempt in range(1, max_retry + 1):
        data, updated_code = _post_rename_once()
        if data is None:
            return

        ida_new_name = data.get("new_name")
        if ida_new_name and ida_new_name != applied_name:
            logger.warning(
                "[IDA-Sync] IDA 实际应用的函数名与建议名不一致：requested=%s, applied=%s",
                applied_name,
                ida_new_name,
            )
            applied_name = ida_new_name

        if updated_code:
            latest_code = updated_code

        refreshed = _save_and_refresh_pseudocode(entry_va, ida_url)
        if refreshed:
            latest_code = refreshed

        if enforce_non_sub:
            if latest_code and not SUBFUNC_NAME_PATTERN.search(latest_code):
                break

            if attempt < max_retry:
                logger.warning(
                    "[IDA-Sync] 0x%08X 伪代码仍包含 sub_ 前缀，尝试重新同步 (%d/%d)",
                    entry_va,
                    attempt,
                    max_retry,
                )
            else:
                logger.warning(
                    "[IDA-Sync] 0x%08X 多次同步后仍检测到 sub_ 前缀，可能需要人工确认。",
                    entry_va,
                )
        else:
            # 不强制检查 sub_，第一次成功即退出循环
            break

    logger.info(
        "[IDA-Sync] 成功同步到 IDA，最新伪代码长度: %d 字符。",
        len(latest_code),
    )

    cur = conn.cursor()

    if latest_code:
        cur.execute(
            """
            UPDATE pseudo_functions
            SET body = ?, prototype = ?, name = ?
            WHERE function_id = ?;
            """,
            (latest_code, signature, applied_name, ida_function_id),
        )

    # 所有视图的 functions 记录统一使用新名字，便于后续分析
    for fid in node.function_ids:
        cur.execute("UPDATE functions SET name = ? WHERE id = ?;", (applied_name, fid))

    conn.commit()
    node.names.add(applied_name)
    logger.debug(
        "[IDA-Sync] 数据库已更新为最新名字与伪代码。entry_va=0x%08X, name=%s",
        entry_va,
        applied_name,
    )


def _build_unified_prompt_body(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    node: UnifiedFunctionNode,
    analysis_info: Dict[int, dict],
    max_disasm_lines: int = 200,
    max_pseudo_chars_per_tool: int = 4000,
    max_strings: int = 20,
) -> Tuple[str, List[str]]:
    """收集单个物理函数的上下文，用于单/多目标 Prompt 复用。"""

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

    # 2) 外部 API 调用信息（聚合后去重）
    ext_names = sorted(set(node.external_callee_names))

    # 3) 字符串引用（取若干条，做简单清洗）
    string_texts: List[str] = []
    for raw in list(sorted(node.string_refs))[:max_strings]:
        clean = " ".join((raw or "").split())
        if len(clean) > 120:
            clean = clean[:117] + "..."
        string_texts.append(clean)

    # 额外的命名提示：当 IDA 仍为 sub_ 前缀且数据库中存在其他命名时，
    # 将这些候选名作为辅助参考加入 Prompt。
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
        unique_hints = []
        seen_hint: Set[str] = set()
        for hint in name_hints:
            if hint in seen_hint:
                continue
            seen_hint.add(hint)
            unique_hints.append(hint)
            if len(unique_hints) >= 5:
                break
        string_texts.append(
            "[DB hint] " + ", ".join(unique_hints)
        )

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

    # 7) 组合主体内容（不含指令头）
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
        lines.append(
            "\n[调用的外部 API / 导入函数（聚合自多个工具）]\n" + ", ".join(ext_names)
        )

    if string_texts:
        lines.append(
            "\n[函数中引用的关键字符串示例（聚合自多个工具）]\n"
            + "\n".join(f"- {s}" for s in string_texts)
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
    """
    为跨视图统一节点构造 Prompt：
      - 聚合 Ghidra / IDA 的伪代码，多视图并列展示；
      - 使用统一的字符串 / 外部 API / 内部调用信息；
      - 使用“已知子函数”的签名和摘要作为知识传播的输入。
    """

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
    """为批量物理函数构造合并 Prompt，要求返回 JSON 数组。"""

    lines: List[str] = []
    lines.append(
        "你是一个精通逆向工程和 C/C++ 的安全分析专家，现在需要一次性分析多个物理函数。"
    )
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
    lines.append(
        "若判断为标准库/编译器运行时/纯导入包装，请设置 libfunction=1 并在 summary/notes 中说明依据；否则设为 0。"
    )
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

        lines.append(
            f"\n[函数 {idx}/{len(nodes)}] {display_name} @ 0x{node.entry_va:08X} "
            f"(function_ids={sorted(node.function_ids)})"
        )
        lines.extend(body_lines)

    return "\n".join(lines)


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


def build_local_var_batch_prompt(items: List[Dict[str, Any]]) -> str:
    """Phase4：批量局部变量重命名 Prompt（返回 JSON 数组，顺序与输入一致）。"""

    lines: List[str] = []
    lines.append("你是一个代码重构专家。当前任务是优化反编译代码的可读性。")
    lines.append("**核心原则：必须优先重命名函数形参（a1, a2...），其次尽力重命名内部变量（v1, v2...）。**")
    lines.append(
        "请对以下多个函数分别给出变量重命名建议。返回一个 JSON 数组，长度必须等于条目数量，顺序完全一致。"
    )
    lines.append(
        "数组中每个元素格式：{\"entry_va\":\"0x...\",\"renames\":{\"old\":\"new\",...}}。"
    )
    lines.append(
        "若无法推断任何变量含义，请返回 renames 为 {}（空对象）。不要输出除 JSON 数组之外的任何文字。"
    )

    for idx, item in enumerate(items, 1):
        node: UnifiedFunctionNode = item["node"]
        code = item.get("code", "") or ""
        signature = item.get("signature", "") or ""
        summary = item.get("summary", "") or ""
        display_name = "/".join(sorted(node.names)) if node.names else f"sub_{node.entry_va:08X}"

        lines.append(
            f"\n[Function {idx}/{len(items)}] {display_name} entry_va=0x{node.entry_va:08X}"
        )
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
    """为 Phase4 构造单个函数的 batch item（选择最佳 fid + 伪代码 + 摘要）。"""

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

        cur.execute(
            "SELECT body FROM pseudo_functions WHERE function_id = ? LIMIT 1;",
            (int(fid),),
        )
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
            ida_candidates.sort(key=lambda c: (int(c.get("score", 0) or 0), int(c.get("line_cnt", 0) or 0)), reverse=True)
            chosen = ida_candidates[0]

    if chosen is None:
        candidates.sort(key=lambda c: (int(c.get("score", 0) or 0), int(c.get("line_cnt", 0) or 0)), reverse=True)
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


def _apply_lvar_result_for_candidate(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    item: Dict[str, Any],
    rename_map: Dict[str, Any],
    ida_sync: bool,
    ida_url: str,
) -> bool:
    """对单个 Phase4 candidate 应用重命名（含可选 IDA 同步 + 持久化验证）。"""

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
        cur.execute(
            "UPDATE pseudo_functions SET body = ? WHERE function_id = ?;",
            (new_code, best_fid),
        )
        conn.commit()
        changed = True
        total_renamed = len(clean_map)

        if ida_sync and ida_url:
            updated = _sync_lvars_with_ida(node.entry_va, clean_map, ida_url)
            if updated:
                updated_code = updated
                cur.execute(
                    "UPDATE pseudo_functions SET body = ? WHERE function_id = ?;",
                    (updated, best_fid),
                )
                conn.commit()

    # 读取最终伪代码并检查残留默认名
    final_code: Optional[str]
    cur.execute(
        "SELECT body FROM pseudo_functions WHERE function_id = ? LIMIT 1;",
        (best_fid,),
    )
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
        )
        if verified_code:
            final_code = verified_code

    # 策略与旧逻辑保持一致：只要完成了一次尝试，就标记为已检查
    mark_optimized = True
    try:
        cur.execute(
            "UPDATE analysis_status SET lvar_optimized = ? WHERE function_id = ?;",
            (1 if mark_optimized else 0, best_fid),
        )
        conn.commit()
    except Exception as exc:
        logger.warning("更新 lvar_optimized 状态失败 function_id=%s: %s", best_fid, exc)

    if remaining_generics:
        generic_list = sorted(remaining_generics)
        generic_preview = ", ".join(generic_list[:8]) + (", ..." if len(generic_list) > 8 else "")
    else:
        generic_preview = ""

    if changed:
        print(
            f"[LVAR] 0x{node.entry_va:08X} 局部变量重命名完成，共修改 {total_renamed} 个标识符，已标记为已检查。"
        )
    else:
        if generic_preview:
            print(
                f"[LVAR] 0x{node.entry_va:08X} 未进行局部变量重命名，已标记为已检查。"
                f"仍检测到默认变量名：{generic_preview}"
            )
        else:
            print(
                f"[LVAR] 0x{node.entry_va:08X} 未进行局部变量重命名，已标记为已检查。"
            )

    return changed


def analyze_local_var_batch(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    items: List[Dict[str, Any]],
    llm_settings: LLMSettings,
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
    prompt: Optional[str] = None,
) -> int:
    """对一批候选函数执行一次 LLM 调用并分别应用结果，返回发生修改的函数数量。"""

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

    for item, res in zip(items, result_list):
        node: UnifiedFunctionNode = item["node"]
        entry_va = int(item.get("entry_va", node.entry_va))

        if not isinstance(res, dict):
            print(f"[LVAR] 0x{entry_va:08X} 跳过：返回值不是 JSON 对象。")
            continue

        # 兼容两种格式：
        # 1) {entry_va:..., renames:{...}}
        # 2) 直接返回 {old:new,...}
        renames_obj: Dict[str, Any]
        if "renames" in res and isinstance(res.get("renames"), dict):
            renames_obj = res.get("renames")  # type: ignore[assignment]
        else:
            # 尽量过滤掉 entry_va 等非映射字段
            renames_obj = {k: v for k, v in res.items() if isinstance(k, str) and k != "entry_va"}

        if ida_sync and ida_url:
            wait_for_ida_server(ida_url)

        changed = _apply_lvar_result_for_candidate(
            conn=conn,
            graph=graph,
            item=item,
            rename_map=renames_obj,
            ida_sync=ida_sync,
            ida_url=ida_url,
        )
        if changed:
            changed_count += 1

    return changed_count


def apply_local_var_renames(code: str, rename_map: Dict[str, str]) -> str:
    """
    使用正则将 rename_map 应用到伪代码文本中。
    使用 Word Boundary (\b) 防止部分匹配错误（如把 v10 中的 v1 替换了）。
    """
    if not rename_map:
        return code

    new_code = code
    # 按变量名长度降序，避免 v11 先被 v1 匹配
    sorted_keys = sorted(rename_map.keys(), key=len, reverse=True)

    for old_name in sorted_keys:
        new_name = rename_map[old_name]
        if old_name == new_name:
            continue

        pattern = r"\b" + re.escape(old_name) + r"\b"
        new_code = re.sub(pattern, new_name, new_code)

    return new_code


def _sync_lvars_with_ida(
    entry_va: int,
    rename_map: Dict[str, str],
    ida_url: str,
) -> Optional[str]:
    """
    将局部变量重命名同步到 IDA。需要 idat_server 支持 'rename_lvar' 动作。
    如 IDA 返回 updated_pseudocode，则将其以字符串形式返回，便于调用方覆盖本地伪代码。
    """
    if requests is None or not rename_map:
        return None

    payload = {
        "action": "rename_lvar",  # 服务端需要处理此 action
        "ea": entry_va,
        "renames": rename_map,  # { "v1": "name", ... }
    }

    try:
        resp = requests.post(ida_url, json=payload, timeout=10.0)
    except Exception as exc:
        logger.warning(f"[IDA-Sync-Lvar] 同步局部变量失败 0x{entry_va:08X}: {exc}")
        return None

    if resp.status_code != 200:
        logger.warning(
            "[IDA-Sync-Lvar] HTTP %s when syncing lvars for 0x%08X: %s",
            resp.status_code,
            entry_va,
            resp.text[:200],
        )
        return None

    try:
        data = resp.json()
    except Exception as exc:
        logger.warning(
            "[IDA-Sync-Lvar] 解析 IDA 返回的 JSON 失败 0x%08X: %s; body=%s",
            entry_va,
            exc,
            resp.text[:200],
        )
        return None

    if data.get("status") != "ok":
        logger.warning("[IDA-Sync-Lvar] IDA 返回错误 0x%08X: %s", entry_va, data)
        return None

    updated_code = data.get("updated_pseudocode")
    if isinstance(updated_code, str) and updated_code.strip():
        logger.info(
            "[IDA-Sync-Lvar] 0x%08X 返回更新伪代码，长度=%d",
            entry_va,
            len(updated_code),
        )
        return updated_code

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
    """
    在同步局部变量重命名后，强制保存 IDA 数据库并重新获取伪代码，
    以确认 a1/v1 等默认名确实被写入 .i64。
    返回最新伪代码和剩余的默认变量名集合。
    """
    latest_code = initial_code
    remaining = _find_generic_lvar_names(latest_code or "")

    if requests is None:
        return latest_code, remaining

    cur = conn.cursor()

    for attempt in range(1, max_retries + 1):
        refreshed = _save_and_refresh_pseudocode(entry_va, ida_url, wait_seconds)
        if refreshed:
            latest_code = refreshed
            cur.execute(
                "UPDATE pseudo_functions SET body = ? WHERE function_id = ?;",
                (refreshed, function_id),
            )
            conn.commit()

        remaining = _find_generic_lvar_names(latest_code or "")
        if not remaining:
            break

        if attempt < max_retries and rename_map:
            _sync_lvars_with_ida(entry_va, rename_map, ida_url)

    return latest_code, remaining


def analyze_one_function_vars(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    node: UnifiedFunctionNode,
    analysis_info: Dict[int, dict],
    llm_settings: LLMSettings,
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
) -> bool:
    """
    第四阶段核心逻辑：单函数局部变量分析与重命名。
    返回 True 表示进行了修改。
    """
    # 1. 获取当前最佳的伪代码和签名信息：
    #    - 只考虑 ANALYZED/LOCKED 的结果；
    #    - 若启用 IDA 同步，则优先选择 IDA 视图对应的 function_id；
    #    - 否则按置信度最高选择。
    best_fid: Optional[int] = None
    best_conf = -1
    signature = ""
    summary = ""

    preferred_tool = "ida" if ida_sync else None
    candidates: List[Dict[str, Any]] = []

    for fid in node.function_ids:
        info = analysis_info.get(fid)
        if not info:
            continue
        state = info.get("analysis_state", "")
        if state not in ("ANALYZED", "LOCKED"):
            continue

        score = int(info.get("confidence_score", 0) or 0)
        tool_name = graph.func_tool.get(fid, "").lower()
        candidates.append(
            {
                "fid": fid,
                "score": score,
                "tool": tool_name,
                "info": info,
            }
        )

    if not candidates:
        return False

    chosen: Optional[Dict[str, Any]] = None

    if preferred_tool:
        ida_candidates = [c for c in candidates if preferred_tool in c["tool"]]
        if ida_candidates:
            ida_candidates.sort(key=lambda c: c["score"], reverse=True)
            chosen = ida_candidates[0]

    if chosen is None:
        candidates.sort(key=lambda c: c["score"], reverse=True)
        chosen = candidates[0]
        if ida_sync and preferred_tool:
            print(
                f"[LVAR-WARN] 0x{node.entry_va:08X} 想要同步 IDA，但未找到 IDA 视图的已分析记录，"
                f"回退使用工具={chosen['tool'] or 'unknown'}，重命名可能无法在 IDA 中完全生效。"
            )

    best_fid = int(chosen["fid"])
    best_conf = int(chosen["score"])
    chosen_info = chosen["info"]
    signature = chosen_info.get("summary_signature", "") or ""
    summary = chosen_info.get("semantic_summary", "") or ""

    # 设定一个门槛，只处理相对可信的函数
    if best_fid is None or best_conf < 60:
        return False

    # 读取伪代码
    cur = conn.cursor()
    cur.execute(
        "SELECT body FROM pseudo_functions WHERE function_id = ? LIMIT 1;",
        (best_fid,),
    )
    row = cur.fetchone()
    if not row or not row[0]:
        return False

    original_code = row[0]

    # 2. 构造 Prompt
    prompt = build_local_var_prompt(node, original_code, signature, summary)
    conversation, request_kwargs = build_chat_request(prompt, llm_settings)

    print(
        f"[LVAR] Analyzing 0x{node.entry_va:08X} "
        f"(tool={chosen.get('tool') or 'unknown'}, score={best_conf})..."
    )

    if dry_run:
        print(f"[LVAR-DRY] Prompt preview:\n{prompt[:500]}...")
        return False

    # 3. 调用 LLM
    result = call_llm_analyze_function(
        conversation=conversation,
        request_kwargs=request_kwargs,
        api_settings=llm_settings.api_settings,
        return_raw_on_error=True,
    )

    # 可能返回包含原始错误信息的字典，便于调试
    if isinstance(result, dict) and "_raw_text" in result:
        raw_text = result.get("_raw_text", "")
        raw_err = result.get("_raw_error", "")
        print(
            f"[LVAR] JSON 解析失败，保持该函数为待优化状态以便后续重试。\n"
            f"[LVAR-ERROR] {raw_err}\n"
            f"[LVAR-RAW]\n{'-' * 40}\n{raw_text}\n{'-' * 40}"
        )
        return False

    if not result:
        # 网络错误或多次尝试完全失败，不标记为已完成，方便后续重试
        return False

    # result 本身就是 map，因为 Prompt 要求返回 {old: new}
    # 但为了稳健，如果 LLM 包裹了一层 key，兼容一下
    rename_map: Dict[str, str] = result  # type: ignore[assignment]
    if "renames" in result and isinstance(result["renames"], dict):
        rename_map = result["renames"]

    # 过滤掉非法的 Key/Value
    clean_map: Dict[str, str] = {}
    for k, v in rename_map.items():
        if isinstance(k, str) and isinstance(v, str) and k != v:
            # 简单的安全检查：新名字必须是合法标识符
            if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", v):
                clean_map[k] = v

    changed = False
    total_renamed = 0
    updated_code: Optional[str] = None

    if not clean_map:
        print("[LVAR] LLM 未提供有效的重命名建议。")
        # 若有原始 JSON，可用于调试
        if result:
            try:
                print(
                    f"[LVAR-DEBUG] LLM 原始 JSON: "
                    f"{json.dumps(result, ensure_ascii=False)}"
                )
            except Exception:
                print(f"[LVAR-DEBUG] LLM 原始 JSON（无法编码）: {result!r}")
    else:
        print(f"[LVAR] 应用重命名: {json.dumps(clean_map, ensure_ascii=False)}")

        # 4. 更新本地数据库 (伪代码文本替换)
        new_code = apply_local_var_renames(original_code, clean_map)

        # 这里选择只更新 best_fid，避免破坏其他工具的原始结构太严重
        cur.execute(
            "UPDATE pseudo_functions SET body = ? WHERE function_id = ?;",
            (new_code, best_fid),
        )
        conn.commit()
        changed = True
        total_renamed = len(clean_map)

        # 5. 同步到 IDA (如果启用)，并尽量使用 IDA 端返回的最新伪代码覆盖本地版本
        if ida_sync and ida_url:
            updated = _sync_lvars_with_ida(node.entry_va, clean_map, ida_url)
            if updated:
                updated_code = updated
                cur.execute(
                    "UPDATE pseudo_functions SET body = ? WHERE function_id = ?;",
                    (updated, best_fid),
                )
                conn.commit()

    # 重新从数据库读取最终伪代码，并检查是否仍存在默认变量名（a1/v1/var_10 等）
    final_code: Optional[str]
    cur.execute(
        "SELECT body FROM pseudo_functions WHERE function_id = ? LIMIT 1;",
        (best_fid,),
    )
    row2 = cur.fetchone()
    if row2 and row2[0]:
        final_code = row2[0]
    else:
        # 回退：优先使用 IDA 返回的版本，其次是本地替换版，最后是原始版本
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
        )
        if verified_code:
            final_code = verified_code
    # 当前策略：只要本轮已成功完成一次 LVAR 尝试（无论是否仍有默认名残留），
    # 就将该函数标记为“已检查”，避免在后续运行中反复进入第四阶段。
    mark_optimized = True

    # 更新 lvar_optimized 标记
    try:
        cur.execute(
            "UPDATE analysis_status SET lvar_optimized = ? WHERE function_id = ?;",
            (1 if mark_optimized else 0, best_fid),
        )
        conn.commit()
    except Exception as exc:
        logger.warning(
            "更新 lvar_optimized 状态失败 function_id=%s: %s", best_fid, exc
        )

    # 清晰的结论性输出，便于在进度条中看出本函数是否真正发生了改名
    if remaining_generics:
        generic_list = sorted(remaining_generics)
        if len(generic_list) > 8:
            generic_preview = ", ".join(generic_list[:8]) + ", ..."
        else:
            generic_preview = ", ".join(generic_list)
    else:
        generic_preview = ""

    if changed:
        if mark_optimized:
            print(
                f"[LVAR] 0x{node.entry_va:08X} 局部变量重命名完成，共修改 {total_renamed} 个标识符，"
                "已标记为已检查。"
            )
        else:
            print(
                f"[LVAR] 0x{node.entry_va:08X} 已重命名 {total_renamed} 个标识符，"
                f"但仍检测到 {len(remaining_generics)} 个默认变量名：{generic_preview}"
            )
    else:
        if mark_optimized:
            print(
                f"[LVAR] 0x{node.entry_va:08X} 未进行局部变量重命名，"
                "已标记为已检查。"
            )
        else:
            print(
                f"[LVAR] 0x{node.entry_va:08X} LLM 未提供有效重命名建议，且仍存在 "
                f"{len(remaining_generics)} 个默认变量名：{generic_preview}"
            )

    return changed


def run_local_var_phase(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    llm_settings: LLMSettings,
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
    batch_size: int = 3,
    only_sub: bool = False,
    ida_only: bool = True,
    min_pseudo_lines: int = 6,
    exclude_import_export: bool = True,
) -> None:
    """
    第四阶段入口：遍历高置信度函数，优化局部变量名。
    """
    if ida_sync and ida_url:
        wait_for_ida_server(ida_url)

    # 确保 analysis_status 表以及 lvar_optimized 字段存在
    ensure_analysis_schema(conn)
    # Phase4 可能会处理未经过 Phase1 的函数，因此需要确保全 binary 行已补齐
    ensure_analysis_rows_for_binary(conn, graph.binary_id)
    analysis_info = load_analysis_info(conn)

    # 预加载已完成局部变量优化的函数，支持断点续工
    cur = conn.cursor()
    cur.execute("SELECT function_id FROM analysis_status WHERE lvar_optimized = 1;")
    optimized_fids: Set[int] = {int(row[0]) for row in cur.fetchall()}

    def _ida_name_is_sub(entry_va: int) -> bool:
        """判断该物理函数在 IDA 视图里的名字是否仍为 sub_XXXX。"""
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

        # fallback：没有 IDA 记录时，退回用统一节点名字集合做粗判
        if node.names:
            any_sub = any(SUBFUNC_NAME_PATTERN.fullmatch((n or "").strip()) for n in node.names)
            any_semantic = any(
                n and not DEFAULT_FUNC_NAME_PATTERN.fullmatch((n or "").strip())
                for n in node.names
            )
            return bool(any_sub and not any_semantic)

        return False

    def _load_ida_phase4_eligible_fids() -> Dict[int, Set[int]]:
        """返回 entry_va -> {ida_function_id,...}，满足：
        - 来自 IDA 视图
        - 非 import/external（可选也排除 export source）
        - 伪代码有效行数 >= min_pseudo_lines
        """

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
                # IDA symbols.csv 的 Source 字段在不同导出器下可能是 Export/EXPORT/Exported
                if "export" in (sym_source or "").strip().lower():
                    continue

            if min_pseudo_lines and _count_effective_pseudocode_lines(code) < int(min_pseudo_lines):
                continue

            if entry_va_i not in eligible:
                eligible[entry_va_i] = set()
            eligible[entry_va_i].add(fid_i)
        return eligible

    ida_eligible_fids_by_entry: Optional[Dict[int, Set[int]]] = None
    if ida_only:
        ida_eligible_fids_by_entry = _load_ida_phase4_eligible_fids()
        print(
            f"[Phase 4] IDA 过滤：eligible_entry={len(ida_eligible_fids_by_entry)} "
            f"(min_lines={min_pseudo_lines}, exclude_import_export={exclude_import_export})"
        )

    # 筛选候选函数：尚未做过局部变量优化
    # - ida_only=True 时：以 IDA 视图中“有效伪代码行数达标”的函数为准，不再强制要求 Phase1 已 ANALYZED
    # - ida_only=False 时：保持旧行为（仍依赖 analysis_state）
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
            # IDA-only 模式：不强制要求 has_analyzed
            candidates.append((int(entry_va), int(max_score)))
        else:
            if has_analyzed:
                candidates.append((int(entry_va), int(max_score)))

    # 按分数从高到低排序
    candidates.sort(key=lambda x: x[1], reverse=True)

    print(f"[Phase 4] Local Variable Renaming: 目标函数数量 {len(candidates)}")

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
            ida_sync=ida_sync,
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

        # 动态 batch：可能会进一步拆成更小的 micro-batch
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
                ida_sync=ida_sync,
                ida_url=ida_url,
                dry_run=dry_run,
                prompt=batch.prompt,
            )
            processed_count += changed_in_batch
            pbar.update(len(batch.items))

        prepared = []

    # 收尾：处理最后不足 batch_target 的尾巴
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
                ida_sync=ida_sync,
                ida_url=ida_url,
                dry_run=dry_run,
                prompt=batch.prompt,
            )
            processed_count += changed_in_batch
            pbar.update(len(batch.items))

    pbar.close()
    print(f"[Phase 4] 完成，共优化了 {processed_count} 个函数的局部变量。")


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

    # 尝试对单视图结果的函数名也做一次去重处理，避免与其他函数同名
    if signature:
        raw_name = _extract_name_from_signature(signature, fallback="") or ""
        if raw_name and not DEFAULT_FUNC_NAME_PATTERN.fullmatch(raw_name):
            unique_name = _make_name_unique(conn, raw_name, function_id)
            if unique_name != raw_name:
                logger.info(
                    "[Phase1-Single] entry_va=0x%08X 函数名发生去重调整: %s -> %s",
                    node.entry_va,
                    raw_name,
                    unique_name,
                )
            signature = signature.replace(raw_name, unique_name)

    confidence = result.get("confidence")
    try:
        confidence_score = int(float(confidence) * 100) if confidence is not None else 0
    except (TypeError, ValueError):
        confidence_score = 0

    libfunction = _coerce_libfunction_flag(result.get("libfunction"))
    if libfunction:
        confidence_score = 0
        print("[LLM] 模型判断为库函数/运行时，跳过进一步视图查找与重试。")
        logger.info(
            "[Phase1-Single] entry_va=0x%08X 被标记为库函数，设置为 LOCKED 并停止后续尝试。",
            node.entry_va,
        )

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
    cur.execute(
        """
        UPDATE analysis_status
        SET analysis_state = ?,
            confidence_score = ?,
            summary_signature = ?,
            semantic_summary = ?
        WHERE function_id = ?;
        """,
        (analysis_state, confidence_score, signature, summary, function_id),
    )
    conn.commit()


def _apply_unified_llm_result(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    node: UnifiedFunctionNode,
    result: Dict[str, Any],
    ida_sync: bool = False,
    ida_url: Optional[str] = None,
) -> None:
    """将 LLM 返回结果写回数据库，并可选同步到 IDA。"""

    signature = str(result.get("signature", "")).strip() or None
    summary = str(result.get("summary", "")).strip() or None
    confidence = result.get("confidence")
    try:
        confidence_score = int(float(confidence) * 100) if confidence is not None else 0
    except (TypeError, ValueError):
        confidence_score = 0

    # 1) 从 signature 中提取 LLM 建议的名字，并在写入数据库前做一次去重处理
    if signature and node.function_ids:
        raw_name = _extract_name_from_signature(signature, fallback="") or ""
        if raw_name:
            if DEFAULT_FUNC_NAME_PATTERN.fullmatch(raw_name):
                # 仍然是明显的默认地址命名（sub_XXXX / fun_XXXX / loc_XXXX），保留原始名字，由上层决定是否改名
                logger.info(
                    "[Phase1] entry_va=0x%08X LLM 返回默认风格函数名 %s，保留现有命名。",
                    node.entry_va,
                    raw_name,
                )
            else:
                ref_fid = next(iter(node.function_ids))
                unique_name = _make_name_unique(conn, raw_name, ref_fid)
                if unique_name != raw_name:
                    logger.info(
                        "[Phase1] entry_va=0x%08X 函数名发生去重调整: %s -> %s",
                        node.entry_va,
                        raw_name,
                        unique_name,
                    )
                # 用去重后的名字替换 signature 中出现的原始名字
                signature = signature.replace(raw_name, unique_name)

    libfunction = _coerce_libfunction_flag(result.get("libfunction"))
    if libfunction:
        confidence_score = 0
        print("[LLM] 模型判断为库函数/运行时，跳过后续视图查找与同步。")
        logger.info(
            "[Phase1] entry_va=0x%08X 被标记为库函数，设置为 LOCKED 并停止后续尝试。",
            node.entry_va,
        )

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

    logger.info(
        "[Phase1] RESULT entry_va=0x%08X, signature=%r, confidence_score=%d, libfunction=%s",
        node.entry_va,
        signature,
        confidence_score,
        libfunction,
    )

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
            (analysis_state, confidence_score, signature, summary, fid),
        )
    conn.commit()

    # 可选：将结果同步到正在运行的 IDA(idat_server)，并用返回的最新伪代码刷新数据库
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
        except Exception as exc:  # 同步失败不应影响主流程
            print(f"[IDA-Sync] 同步到 IDA 失败: {exc}")


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

    _apply_unified_llm_result(
        conn=conn,
        graph=graph,
        node=node,
        result=result,
        ida_sync=ida_sync,
        ida_url=ida_url,
    )


def analyze_unified_batch(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    nodes: List[UnifiedFunctionNode],
    analysis_info: Dict[int, dict],
    llm_settings: LLMSettings,
    prompt: Optional[str] = None,
    estimated_tokens: Optional[int] = None,
    dry_run: bool = False,
    ida_sync: bool = False,
    ida_url: Optional[str] = None,
) -> None:
    """批量分析多个物理函数，共用一次 LLM 调用。"""

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

    logger.info(
        "[Phase1-Batch] TARGET size=%d, entry_vas=%s",
        len(nodes),
        target_list,
    )

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

    if len(result_list) != len(nodes):
        logger.warning(
            "[Phase1-Batch] 返回数组长度与请求不一致：expected=%d, got=%d",
            len(nodes),
            len(result_list),
        )

    for node, result in zip(nodes, result_list):
        if not isinstance(result, dict):
            logger.warning(
                "[Phase1-Batch] 跳过 entry_va=0x%08X，原因：返回值不是对象：%r",
                node.entry_va,
                result,
            )
            continue

        _apply_unified_llm_result(
            conn=conn,
            graph=graph,
            node=node,
            result=result,
            ida_sync=ida_sync,
            ida_url=ida_url,
        )


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
        help="输入的 SQLite 数据库路径，例如 tmp/Malware_sample.exe.db",
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
        "--batch",
        type=int,
        default=25,
        help="Phase 1 批处理大小（默认 50，最小 1），一次性并行分析多个物理函数。",
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
        "--skip-lvar",
        action="store_true",
        help="跳过第四阶段局部变量（v1, a2...）的易读性整理。",
    )
    parser.add_argument(
        "--lvar-only-sub",
        action="store_true",
        help="第四阶段仅对 IDA 侧仍为 sub_XXXX 的函数执行局部变量重命名（默认：对所有符合条件函数执行）。",
    )
    parser.add_argument(
        "--lvar-min-lines",
        type=int,
        default=6,
        help="第四阶段仅处理有效伪代码行数 >= N 的函数（默认 6，即要求 >5 行）。",
    )
    parser.add_argument(
        "--lvar-ida-only",
        action="store_true",
        help="第四阶段仅基于 IDA 视图的函数列表进行候选筛选（推荐）。",
    )
    parser.add_argument(
        "--lvar-include-non-ida",
        action="store_true",
        help="允许第四阶段候选包含非 IDA 视图函数（与 --lvar-ida-only 互斥；默认只做 IDA）。",
    )
    parser.add_argument(
        "--lvar-include-import-export",
        action="store_true",
        help="第四阶段不排除导入/外部/导出来源符号（默认会排除）。",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="仅构建依赖图并计算评分，不实际调用 LLM。",
    )
    parser.add_argument(
        "--ida-sync",
        action="store_true",
        help="在每个物理函数分析完成后，尝试通过 HTTP 同步到正在运行的 idat_server，并用返回的伪代码刷新数据库。",
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

    # 初始化日志系统（按数据库路径派生日志文件名，便于多数据集区分）
    log_path = db_path.with_suffix(db_path.suffix + ".knowledge.log")
    setup_logging(log_path, input_db=db_path)
    install_stdout_tee(logger)
    logger.info("知识传播管线启动，数据库: %s", db_path)

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

        # [Config] 按需求跳过 IDA/DB 不一致对齐（避免全量扫描与额外 LLM/token 开销）
        # 原逻辑会在 all_pending 时调用 _reconcile_ida_db_mismatch(...)。
        if args.ida_sync:
            print("[Config] 已跳过 IDA/DB 不一致性检查 (Alignment Check)。")
            logger.info("[Config] 已跳过 IDA/DB 不一致性检查 (Alignment Check)。")

        # 构建跨视图统一依赖图（在可能的删除/同步之后）
        unified_graph = build_unified_graph(conn, binary_id)
        print(f"统一图中共有 {len(unified_graph.nodes)} 个物理函数节点。")

        # [Config] 仅分析 IDA 侧仍为 sub_ 前缀的函数（避免对已命名函数的全量分析）
        print("[Config] 正在获取 IDA 侧仍为 sub_ 前缀的函数列表...")
        target_sub_map = _load_ida_subfunc_entries(
            conn,
            binary_id,
            ida_url=args.ida_url if args.ida_sync else None,
        )
        target_sub_vas: Set[int] = set(target_sub_map.keys())
        print(
            f"[Config] 锁定目标: 仅分析 {len(target_sub_vas)} 个 sub_ 开头的未命名函数。"
        )

        # 强制重跑：即使某些 sub_ 已被标成 ANALYZED/LOCKED，也一律重置为 PENDING。
        # 目标是“直到 IDA 侧名称不再是 sub_”为止。
        if target_sub_vas:
            cur = conn.cursor()
            ids_to_reset: Set[int] = set()
            missing_nodes: List[Tuple[int, str]] = []

            for entry_va, ida_name in target_sub_map.items():
                node = unified_graph.nodes.get(entry_va)
                if not node:
                    missing_nodes.append((entry_va, ida_name))
                    continue
                for fid in node.function_ids:
                    ids_to_reset.add(fid)

            if missing_nodes:
                print(
                    f"[Phase 1] 警告: {len(missing_nodes)} 个 sub_ 函数在统一依赖图中未找到 (可能是新生成的)，已跳过重置。"
                )

            if ids_to_reset:
                placeholders = ",".join("?" for _ in ids_to_reset)
                cur.execute(
                    f"""
                    UPDATE analysis_status
                    SET analysis_state = 'PENDING',
                        confidence_score = 0,
                        summary_signature = NULL,
                        semantic_summary = NULL
                    WHERE function_id IN ({placeholders});
                    """,
                    tuple(ids_to_reset),
                )
                conn.commit()
                print(
                    f"[Phase 1] 已强制重置 {len(ids_to_reset)} 条记录为 PENDING（含原 ANALYZED/LOCKED）。"
                )

        # ===== 第一阶段：底向上知识传播（带断点续工 + 进度条） =====
        # 预估本轮要处理的物理函数数量：
        # 仅统计“尚未 ANALYZED/LOCKED 的物理节点”数量。
        analysis_info = load_analysis_info(conn)
        scores = compute_unified_scores(unified_graph, analysis_info)
        update_unified_scores_in_db(conn, unified_graph, scores)

        pending_nodes_initial: List[UnifiedFunctionNode] = []
        for entry_va, node in unified_graph.nodes.items():
            if entry_va not in target_sub_vas:
                continue
            any_analyzed = False
            for fid in node.function_ids:
                info = analysis_info.get(fid)
                if info and info.get("analysis_state") in ("ANALYZED", "LOCKED"):
                    any_analyzed = True
                    break
            if not any_analyzed:
                pending_nodes_initial.append(node)

        initial_pending_count = len(pending_nodes_initial)
        processed = 0

        if initial_pending_count > 0:
            print(
                f"[Phase 1] 计划分析 {initial_pending_count} 个物理函数 (已过滤掉非 sub_ 函数)"
            )

            pbar = tqdm(
                total=initial_pending_count,
                desc="Phase 1: Knowledge Propagation",
                unit="func",
            )

            batch_target = max(1, args.batch or 1)

            while True:
                analysis_info = load_analysis_info(conn)
                scores = compute_unified_scores(unified_graph, analysis_info)
                update_unified_scores_in_db(conn, unified_graph, scores)

                # 找出当前 binary 中所有“尚未分析”的物理函数节点：
                # 该节点下所有 function_id 都是 PENDING/NULL 才算 PENDING。
                pending_nodes: List[UnifiedFunctionNode] = []
                for entry_va, node in unified_graph.nodes.items():
                    if entry_va not in target_sub_vas:
                        continue
                    any_analyzed = False
                    for fid in node.function_ids:
                        info = analysis_info.get(fid)
                        if info and info.get("analysis_state") in ("ANALYZED", "LOCKED"):
                            any_analyzed = True
                            break
                    if not any_analyzed:
                        pending_nodes.append(node)

                if not pending_nodes:
                    pbar.write("所有目标 sub_ 函数均已分析完毕。")
                    break

                # 按得分排序，优先处理高分节点
                pending_nodes.sort(
                    key=lambda n: scores.get(n.entry_va, 0),
                    reverse=True,
                )

                requested_nodes = pending_nodes[: min(batch_target, len(pending_nodes))]

                def _phase1_builder(nodes: List[UnifiedFunctionNode]) -> str:
                    if len(nodes) == 1:
                        return build_unified_prompt(
                            conn,
                            unified_graph,
                            nodes[0],
                            analysis_info,
                        )
                    return build_unified_batch_prompt(
                        conn,
                        unified_graph,
                        nodes,
                        analysis_info,
                    )

                # 动态 batch：使用共享生成器，从“Top-N”中挑出能塞进 token 预算的最大前缀
                prompt: Optional[str] = None
                estimated_tokens: Optional[int] = None
                selected_nodes: List[UnifiedFunctionNode] = []

                try:
                    first_batch = next(
                        yield_dynamic_batch(
                            requested_nodes,
                            prompt_builder=_phase1_builder,
                            max_prompt_tokens=llm_settings.max_tokens,
                            token_estimator=estimate_token_usage,
                            initial_batch_size=len(requested_nodes),
                            min_batch_size=1,
                        )
                    )
                    selected_nodes = first_batch.items  # type: ignore[assignment]
                    prompt = first_batch.prompt
                    estimated_tokens = first_batch.estimated_tokens
                except StopIteration:
                    selected_nodes = []

                batch_size = len(selected_nodes)

                if batch_size == 0:
                    pbar.write("[Phase 1] 未能构造有效批次，终止本轮。")
                    break

                if batch_size < len(requested_nodes) and estimated_tokens is not None:
                    logger.info(
                        "[Phase1-Batch] 因 token 预估调整批量大小：requested=%d, applied=%d, estimated_tokens=%d, max_tokens=%d",
                        len(requested_nodes),
                        batch_size,
                        estimated_tokens,
                        llm_settings.max_tokens,
                    )

                top_node = selected_nodes[0]
                desc = (
                    f"Phase 1: batch={batch_size} top=0x{top_node.entry_va:08X} "
                    f"(score={scores.get(top_node.entry_va, 0)})"
                )
                pbar.set_description(desc)

                if batch_size > 1:
                    print("\n[SELECT] 本轮批量分析候选：")
                    for node in selected_nodes:
                        print(
                            f"  - 0x{node.entry_va:08X} score={scores.get(node.entry_va, 0)} "
                            f"names={','.join(sorted(node.names)) if node.names else '(unnamed)'} "
                            f"function_ids={sorted(node.function_ids)}"
                        )

                    phase1_analyze_unified_batch(
                        conn=conn,
                        graph=unified_graph,
                        nodes=selected_nodes,
                        analysis_info=analysis_info,
                        llm_settings=llm_settings,
                        prompt=prompt,
                        estimated_tokens=estimated_tokens,
                        dry_run=args.dry_run,
                        ida_sync=args.ida_sync,
                        ida_url=args.ida_url,
                    )

                    processed += batch_size
                    pbar.update(batch_size)
                else:
                    target_node = selected_nodes[0]
                    print(
                        "\n[SELECT] 选择评分最高的待分析物理函数："
                        f"{'/'.join(sorted(target_node.names)) if target_node.names else '(unnamed)'} "
                        f"(entry_va=0x{target_node.entry_va:08X}, "
                        f"score={scores.get(target_node.entry_va, 0)}, "
                        f"function_ids={sorted(target_node.function_ids)})"
                    )

                    if estimated_tokens and estimated_tokens > llm_settings.max_tokens:
                        logger.warning(
                            "[Phase1] 单函数 Prompt 预估已超过 max_tokens: estimated=%d, max=%d",
                            estimated_tokens,
                            llm_settings.max_tokens,
                        )

                    phase1_analyze_one_unified_function(
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
        else:
            print("[Phase 1] 无需处理的任务，跳过。")

    finally:
        conn.close()

    # 第二阶段：调用链 Top-down 校验（可选，默认 5 秒倒计时后执行）
    if not args.skip_validation:
        if _prompt_run_validation_with_timeout(timeout_sec=5):
            conn2 = sqlite3.connect(str(db_path))
            try:
                phase2_run_validation_phase(
                    conn=conn2,
                    graph=unified_graph,
                    llm_settings=llm_settings,
                    ida_sync=args.ida_sync,
                    ida_url=args.ida_url,
                    dry_run=args.dry_run,
                    batch_size=max(1, int(args.batch or 1)),
                )
            finally:
                conn2.close()

    # 第三阶段：全局变量重命名与类型推断
    if not args.skip_global:
        conn3 = sqlite3.connect(str(db_path))
        try:
            phase3_run_global_var_phase(
                conn=conn3,
                graph=unified_graph,
                llm_settings=llm_settings,
                max_globals=args.max_globals if args.max_globals and args.max_globals > 0 else None,
                ida_sync=args.ida_sync,
                ida_url=args.ida_url,
                dry_run=args.dry_run,
                batch_size=max(1, int(args.batch or 1)),
            )
        finally:
            conn3.close()

    # 第四阶段：局部变量易读性整理
    if not args.skip_lvar:
        conn4 = sqlite3.connect(str(db_path))
        try:
            phase4_run_local_var_phase(
                conn=conn4,
                graph=unified_graph,
                llm_settings=llm_settings,
                ida_sync=args.ida_sync,
                ida_url=args.ida_url,
                dry_run=args.dry_run,
                batch_size=max(1, min(3, int(args.batch or 1))),
                only_sub=bool(args.lvar_only_sub),
                ida_only=bool(args.lvar_ida_only or not args.lvar_include_non_ida),
                min_pseudo_lines=max(0, int(args.lvar_min_lines or 0)),
                exclude_import_export=not bool(args.lvar_include_import_export),
            )
        finally:
            conn4.close()

    # 若启用了 IDA 同步，在所有分析结束后请求 idat 端保存并退出
    if args.ida_sync and requests is not None:
        try:
            print(f"[IDA-Sync] 请求 IDA 保存数据库并有序退出: {args.ida_url}")
            requests.post(
                args.ida_url,
                json={"action": "save_and_exit"},
                timeout=2.0,
            )
            print("[IDA-Sync] 指令已发送。")
        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
            print("[IDA-Sync] IDA 已响应并正在关闭（连接中断是预期的）。")
        except Exception as exc:
            print(f"[IDA-Sync] save_and_exit 调用异常 (可忽略): {exc}")


if __name__ == "__main__":
    main()
