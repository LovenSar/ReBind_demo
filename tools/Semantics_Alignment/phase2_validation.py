#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phase2_validation.py

Phase 2: Top-down Validation Functions
基于调用链的 Top-down 校验模块，从 knowledge_propagation.py 提取。

核心功能：
1. 从入口点（main / 高置信度函数）出发，沿调用链向下传播校验任务
2. 对单个物理函数执行第二阶段 Top-down 校验
3. 构建校验 Prompt，包含调用者上下文和被调用者信息
4. 支持 IDA 同步和交互式确认
"""

from __future__ import annotations

import heapq
import json
import logging
import re
import sqlite3
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from tqdm import tqdm

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - 可选依赖
    requests = None


logger = logging.getLogger(__name__)


# =========================
# Constants and Data Classes (imported from knowledge_propagation.py)
# =========================

# 匹配 sub_XXXXXXXX 格式的函数名模式
SUBFUNC_NAME_PATTERN = re.compile(r"\bsub_[0-9A-Fa-f]+\b")


# =========================
# Helper Functions
# =========================

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


def _get_any_function_id_for_va(graph: Any, entry_va: int) -> Optional[int]:
    """从统一图节点中任选一个 function_id，优先选择 IDA 视图。"""
    node = graph.nodes.get(entry_va)
    if not node:
        return None
    ida_fids = [fid for fid in node.function_ids if graph.func_tool.get(fid, "").lower() == "ida"]
    if ida_fids:
        return ida_fids[0]
    return next(iter(node.function_ids)) if node.function_ids else None


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

    return True


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
        if data.get("status") != "ok":
            return None
        return data.get("pseudocode", "")
    except Exception as exc:
        logger.warning(
            "[IDA-Sync] 解析伪代码响应失败 0x%08X: %s", entry_va, exc
        )
        return None


def _save_and_refresh_pseudocode(
    entry_va: int, ida_url: str, wait_seconds: float = 1.0
) -> Optional[str]:
    """强制保存 IDA 数据库后，等待片刻并重新获取伪代码。"""
    _force_ida_save_database(ida_url)
    if wait_seconds > 0:
        time.sleep(wait_seconds)
    return _fetch_ida_pseudocode(entry_va, ida_url)


def _sync_with_ida_and_update_db(
    conn: sqlite3.Connection,
    graph: Any,
    node: Any,
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

    # 更新数据库中的 functions 和 pseudo_functions
    cur = conn.cursor()
    cur.execute(
        "UPDATE functions SET name = ? WHERE id = ?;",
        (applied_name, ida_function_id),
    )

    if latest_code:
        # 假设伪代码格式为 "原型\n函数体"
        lines = latest_code.splitlines()
        prototype = lines[0] if lines else ""
        body = "\n".join(lines[1:]) if len(lines) > 1 else ""

        cur.execute(
            """
            UPDATE pseudo_functions
            SET prototype = ?, body = ?
            WHERE function_id = ?;
            """,
            (prototype, body, ida_function_id),
        )

    conn.commit()


# =========================
# Phase 2 Core Functions
# =========================

def _get_entry_points_for_validation(
    conn: sqlite3.Connection,
    graph: Any,
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


def _get_call_site_snippet(
    conn: sqlite3.Connection,
    graph: Any,
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


def build_validation_prompt(
    conn: sqlite3.Connection,
    graph: Any,
    entry_va: int,
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


def validate_one_function(
    conn: sqlite3.Connection,
    graph: Any,
    entry_va: int,
    llm_settings: Any,
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
    max_attempts: int = 3,
) -> Optional[float]:
    """
    对单个物理函数执行第二阶段 Top-down 校验。
    返回该节点的"后验置信度"（用于向下传播）。

    注意：此函数需要从 knowledge_propagation.py 导入以下函数：
    - build_chat_request
    - call_llm_analyze_function
    """
    # Import here to avoid circular dependency
    from tools.Semantics_Alignment.knowledge_propagation_2 import build_chat_request, call_llm_analyze_function

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
        # 利用现有的 IDA 同步 + 数据库更新逻辑
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
    graph: Any,
    llm_settings: Any,
    max_functions: Optional[int],
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
) -> None:
    """
    第二阶段：基于调用链的 Top-down 校验。
    从入口点（main / 高置信度函数）出发，沿调用链向下传播校验任务。

    注意：此函数需要 ValidationTask 数据类，应从 knowledge_propagation.py 导入
    """
    # Import ValidationTask here to avoid circular dependency
    from tools.Semantics_Alignment.knowledge_propagation_2 import ValidationTask

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

    # 进度条采用"Expanding Horizon"模式：
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
            # 这个节点本身在本轮视为"已处理"（来自断点续工），应更新进度条
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
                "是否执行第二阶段\"调用链逻辑流校验\"？\n"
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
