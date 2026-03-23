"""kp_sync.py

Shared helpers for name extraction / uniqueness and syncing unified analysis
results back to IDA via idat_server.

Extracted from knowledge_propagation.py to be reused by Phase1 & Phase2.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import Optional, Tuple

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None

from .kp_ida import wait_for_ida_server
from .kp_ida_utils import save_and_refresh_pseudocode
from .kp_types import DEFAULT_FUNC_NAME_PATTERN, SUBFUNC_NAME_PATTERN, UnifiedFunctionNode, UnifiedGraph


logger = logging.getLogger(__name__)


def _extract_name_from_signature(signature: str, fallback: str) -> Optional[str]:
    """Extract function name from C-like signature (heuristic).

    Args:
        signature: C-like 函数签名，例如 ``void *func_name(int a, int b)``
        fallback: 无法解析时的回退名称

    Returns:
        解析出的函数名，或 fallback（均为 None 时返回 None）
    """
    sig = (signature or "").strip()
    if not sig:
        return (fallback or None)
    try:
        before_paren = sig.split("(", 1)[0].strip()
        if not before_paren:
            return fallback or None
        tokens = before_paren.split()
        name = tokens[-1]
        name = name.strip("*&")
        if not name:
            return fallback or None
        return name
    except Exception:
        return fallback or None


def extract_func_name(signature: str) -> str:
    """从 C-like 函数签名中提取函数名，解析失败时返回空字符串。

    这是 ``_extract_name_from_signature`` 的简化封装，专供不需要 fallback 的调用方使用
    （原本在 phase2_validation.py 和 depth/engine.py 中各有一份相同逻辑的本地副本）。
    """
    return _extract_name_from_signature(signature, fallback="") or ""


def _make_name_unique(conn: sqlite3.Connection, base_name: str, current_fid: int) -> str:
    """Ensure base_name unique in functions table; append _1/_2 if needed."""
    base_name = (base_name or "").strip()
    if not base_name:
        return base_name

    if DEFAULT_FUNC_NAME_PATTERN.fullmatch(base_name):
        return base_name

    cur = conn.cursor()
    cur.execute("SELECT id FROM functions WHERE name = ? AND id != ?;", (base_name, current_fid))
    if not cur.fetchall():
        return base_name

    counter = 1
    while True:
        candidate = f"{base_name}_{counter}"
        cur.execute("SELECT id FROM functions WHERE name = ? AND id != ?;", (candidate, current_fid))
        if not cur.fetchone():
            return candidate
        counter += 1


def _sync_with_ida_and_update_db(
    *,
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    node: UnifiedFunctionNode,
    entry_va: int,
    signature: str,
    summary: str,
    ida_url: str,
    enforce_non_sub: bool = True,
) -> None:
    """Rename physical function in IDA and refresh DB with latest pseudocode."""
    if requests is None:
        logger.info("[IDA-Sync] 未安装 requests，跳过函数同步。pip install requests 可启用。")
        return

    ida_reachable = True
    if ida_url:
        ida_reachable = wait_for_ida_server(ida_url, max_wait_seconds=30.0)
        if not ida_reachable:
            logger.warning(
                "[IDA-Sync] IDA 不可达，跳过实时同步（仅更新 DB）。 entry_va=0x%08X",
                entry_va,
            )

    ida_function_id: Optional[int] = None
    for fid in node.function_ids:
        tool_name = graph.func_tool.get(fid, "")
        if tool_name.lower() == "ida":
            ida_function_id = fid
            break
    if ida_function_id is None:
        logger.info("[IDA-Sync] 未找到 IDA 视图对应的 function_id，仅更新当前数据库。 entry_va=0x%08X", entry_va)
        return

    fallback_name = (
        next(iter(sorted(node.names)), f"sub_{entry_va:08X}") if node.names else f"sub_{entry_va:08X}"
    )
    final_name = _extract_name_from_signature(signature, fallback=fallback_name)
    if not final_name:
        logger.warning("[IDA-Sync] 无法从 signature 中提取函数名，跳过同步。 entry_va=0x%08X, signature=%r", entry_va, signature)
        return

    if DEFAULT_FUNC_NAME_PATTERN.fullmatch(final_name) and fallback_name:
        logger.info(
            "[IDA-Sync] 解析出的函数名 %s 看起来是默认地址命名，回退为现有名字 %s。 entry_va=0x%08X",
            final_name,
            fallback_name,
            entry_va,
        )
        final_name = fallback_name

    ref_fid: Optional[int] = None
    if node.function_ids:
        ref_fid = next(iter(node.function_ids))
    elif ida_function_id is not None:
        ref_fid = ida_function_id

    if ref_fid is not None:
        unique_name = _make_name_unique(conn, final_name, ref_fid)
        if unique_name != final_name:
            logger.info("[IDA-Sync] entry_va=0x%08X 函数名发生去重调整: %s -> %s", entry_va, final_name, unique_name)
        final_name = unique_name

    applied_name = final_name
    latest_code: str = ""

    if not ida_reachable:
        # IDA 不可达：跳过 HTTP 同步，仅更新 DB 中的函数名
        logger.info("[IDA-Sync] IDA 离线，仅更新 DB 函数名: ea=0x%08X, name=%s", entry_va, applied_name)
    else:
        full_comment = f"[Unified-LLM]\nName: {final_name}\nSignature: {signature}\nSummary: {summary}"
        payload = {"action": "rename_and_sync", "ea": int(entry_va), "name": final_name, "comment": full_comment}

        logger.info("[IDA-Sync] 尝试同步函数到 IDA: ea=0x%08X, name=%s (%s)", entry_va, final_name, ida_url)

        max_retry = 3

        def _post_rename_once() -> Tuple[Optional[dict], Optional[str]]:
            try:
                resp = requests.post(ida_url, json=payload, timeout=10.0)
            except Exception as exc:
                logger.error("[IDA-Sync] 连接 IDA 失败: %s", exc)
                return None, None

            if resp.status_code != 200:
                logger.error("[IDA-Sync] HTTP %s: %s", resp.status_code, resp.text[:200])
                return None, None

            try:
                data = resp.json()
            except Exception as exc:
                logger.error("[IDA-Sync] 解析 IDA 响应失败: %s; body=%s", exc, resp.text[:200])
                return None, None

            if data.get("status") != "ok":
                logger.error("[IDA-Sync] IDA 返回错误: %s", data)
                return None, None

            return data, data.get("updated_pseudocode") or ""

        for attempt in range(1, max_retry + 1):
            data, updated_code = _post_rename_once()
            if data is None:
                logger.warning("[IDA-Sync] IDA 同步请求失败，仅更新 DB。 ea=0x%08X", entry_va)
                break

            ida_new_name = data.get("new_name")
            if ida_new_name and ida_new_name != applied_name:
                logger.warning("[IDA-Sync] IDA 实际应用的函数名与建议名不一致：requested=%s, applied=%s", applied_name, ida_new_name)
                applied_name = ida_new_name

            if updated_code:
                latest_code = updated_code

            refreshed = save_and_refresh_pseudocode(entry_va, ida_url)
            if refreshed:
                latest_code = refreshed

            if enforce_non_sub:
                if latest_code and not SUBFUNC_NAME_PATTERN.search(latest_code):
                    break
                if attempt < max_retry:
                    logger.warning("[IDA-Sync] 0x%08X 伪代码仍包含 sub_ 前缀，尝试重新同步 (%d/%d)", entry_va, attempt, max_retry)
                else:
                    logger.warning("[IDA-Sync] 0x%08X 多次同步后仍检测到 sub_ 前缀，可能需要人工确认。", entry_va)
            else:
                break

    cur = conn.cursor()

    if latest_code:
        cur.execute(
            """
            UPDATE pseudo_functions
            SET body = ?, prototype = ?, name = ?
            WHERE function_id = ?;
            """,
            (latest_code, signature, applied_name, int(ida_function_id)),
        )

    for fid in node.function_ids:
        cur.execute("UPDATE functions SET name = ? WHERE id = ?;", (applied_name, int(fid)))

    conn.commit()
    node.names.add(applied_name)
    logger.info("[IDA-Sync] 成功同步: entry_va=0x%08X name=%s (%s)", entry_va, applied_name, ida_url)
