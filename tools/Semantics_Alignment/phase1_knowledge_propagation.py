#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phase1_knowledge_propagation.py

第一阶段：底向上知识传播 - 函数级基础分析
从 knowledge_propagation.py 中提取的 Phase 1 相关函数和功能。

核心功能：
1. 按优先级评分选择待分析函数
2. 调用 LLM 对函数进行语义分析
3. 将分析结果写回数据库
4. 支持断点续工和进度跟踪
"""

from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any, Dict, List, Optional

from tqdm import tqdm

logger = logging.getLogger(__name__)

# 导入需要从主文件中访问的类型和函数
# 这些将在实际使用时从 knowledge_propagation.py 导入
try:
    from tools.Semantics_Alignment.knowledge_propagation_2 import (
        UnifiedGraph,
        UnifiedFunctionNode,
        LLMSettings,
        load_analysis_info,
        wait_for_ida_server,
        build_unified_prompt,
        build_chat_request,
        call_llm_analyze_function,
        compute_unified_scores,
        update_unified_scores_in_db,
        _load_ida_subfunc_entries,
        _sync_with_ida_and_update_db,
        requests,
    )
except ImportError:
    # 如果作为独立模块使用，这些类型需要单独定义或从其他模块导入
    pass


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
    对一个"物理函数"（按 entry_va 聚合的 UnifiedFunctionNode）执行一次 LLM 分析，
    并将结果写回所有关联的 functions.id 上的 analysis_status 记录。

    参数：
        conn: SQLite 数据库连接
        graph: 跨视图统一依赖图
        entry_va: 目标函数的入口虚拟地址
        analysis_info: 当前所有函数的分析状态信息
        llm_settings: LLM 配置参数
        dry_run: 是否为演练模式（不实际调用 LLM）
        ida_sync: 是否同步结果到 IDA
        ida_url: IDA 服务器的 URL
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
                entry_va=entry_va,
                signature=signature,
                summary=summary or "",
                ida_url=ida_url or "http://127.0.0.1:12345",
                enforce_non_sub=False,
            )
        except Exception as exc:  # 同步失败不应影响主流程
            print(f"[IDA-Sync] 同步到 IDA 失败: {exc}")


def run_phase1(
    conn: sqlite3.Connection,
    unified_graph: UnifiedGraph,
    binary_id: int,
    llm_settings: LLMSettings,
    max_functions: int,
    ida_sync: bool = False,
    ida_url: Optional[str] = None,
    dry_run: bool = False,
) -> int:
    """
    执行第一阶段：底向上知识传播（带断点续工 + 进度条）

    流程：
    1. 预估待处理的物理函数数量
    2. 计算每个函数的优先级评分
    3. 按评分从高到低逐个分析函数
    4. 每分析完一个函数后，重新计算评分（知识传播）
    5. 支持断点续工：已分析的函数会跳过

    参数：
        conn: SQLite 数据库连接
        unified_graph: 跨视图统一依赖图
        binary_id: 二进制文件 ID
        llm_settings: LLM 配置参数
        max_functions: 本次运行最多分析的函数数量
        ida_sync: 是否同步结果到 IDA
        ida_url: IDA 服务器的 URL
        dry_run: 是否为演练模式

    返回：
        本次实际处理的函数数量
    """
    # 预估本轮最多要处理的物理函数数量：
    # 仅统计"尚未 ANALYZED/LOCKED 的物理节点"数量，并与 --max-functions 取最小值。
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
        print("当前 binary 下已无 PENDING 物理函数，跳过第一阶段基础队列。")
        processed = 0
        # 额外检查 IDA 视图是否仍存在 sub_ 前缀的函数名，若有则直接走第一阶段 LLM 分析/重命名流程
        ida_subs = _load_ida_subfunc_entries(conn, binary_id)
        if ida_subs:
            print(
                f"[Phase 1] 发现 {len(ida_subs)} 个 IDA 函数仍为 sub_ 前缀，触发第一阶段 LLM 重跑。"
            )
            analysis_info = load_analysis_info(conn)
            scores = compute_unified_scores(unified_graph, analysis_info)
            update_unified_scores_in_db(conn, unified_graph, scores)

            for entry_va, ida_name in ida_subs.items():
                node = unified_graph.nodes.get(entry_va)
                if not node:
                    continue
                try:
                    analyze_one_unified_function(
                        conn=conn,
                        graph=unified_graph,
                        entry_va=entry_va,
                        analysis_info=analysis_info,
                        llm_settings=llm_settings,
                        dry_run=dry_run,
                        ida_sync=ida_sync,
                        ida_url=ida_url,
                    )
                    processed += 1
                except Exception as exc:
                    logger.warning(
                        "[Phase1] sub_ LLM 重跑失败 entry_va=0x%08X: %s",
                        entry_va,
                        exc,
                    )
        else:
            print("[Phase 1] 未发现 sub_ 前缀残留，直接跳过第一阶段。")
    else:
        target_count = max_functions
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

            # 找出当前 binary 中所有"尚未分析"的物理函数节点：
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
                dry_run=dry_run,
                ida_sync=ida_sync,
                ida_url=ida_url,
            )

            processed += 1
            pbar.update(1)

        pbar.close()
        print(f"\n[Phase 1] 完成，本次运行共处理物理函数数量：{processed}")

    return processed


# 为了方便作为独立模块调用，提供一个简化的接口函数
def run_phase1_analysis(
    db_path: str,
    binary_id: int,
    llm_settings: LLMSettings,
    max_functions: int = 10,
    ida_sync: bool = False,
    ida_url: Optional[str] = None,
    dry_run: bool = False,
) -> int:
    """
    Phase 1 分析的简化入口函数

    参数：
        db_path: SQLite 数据库路径
        binary_id: 二进制文件 ID
        llm_settings: LLM 配置参数
        max_functions: 最多分析的函数数量
        ida_sync: 是否同步到 IDA
        ida_url: IDA 服务器 URL
        dry_run: 是否为演练模式

    返回：
        实际处理的函数数量
    """
    from tools.Semantics_Alignment.knowledge_propagation_2 import (
        build_unified_graph,
        ensure_analysis_schema,
        ensure_analysis_rows_for_binary,
    )

    conn = sqlite3.connect(db_path)
    try:
        # 确保数据库 schema 完整
        ensure_analysis_schema(conn)
        ensure_analysis_rows_for_binary(conn, binary_id)

        # 构建统一依赖图
        unified_graph = build_unified_graph(conn, binary_id)

        # 执行 Phase 1 分析
        processed = run_phase1(
            conn=conn,
            unified_graph=unified_graph,
            binary_id=binary_id,
            llm_settings=llm_settings,
            max_functions=max_functions,
            ida_sync=ida_sync,
            ida_url=ida_url,
            dry_run=dry_run,
        )

        return processed
    finally:
        conn.close()


if __name__ == "__main__":
    """
    示例：作为独立模块运行
    """
    import argparse
    from pathlib import Path
    from tools.Semantics_Alignment.knowledge_propagation_2 import (
        LLMSettings,
        load_semantics_config,
        setup_logging,
    )

    parser = argparse.ArgumentParser(
        description="Phase 1: Bottom-up knowledge propagation for function analysis"
    )
    parser.add_argument(
        "db_path",
        type=Path,
        help="Path to the alignment SQLite database",
    )
    parser.add_argument(
        "--binary-id",
        type=int,
        default=1,
        help="Binary ID to analyze (default: 1)",
    )
    parser.add_argument(
        "--max-functions",
        type=int,
        default=10,
        help="Maximum number of functions to analyze in this run (default: 10)",
    )
    parser.add_argument(
        "--ida-sync",
        action="store_true",
        help="Enable IDA synchronization",
    )
    parser.add_argument(
        "--ida-url",
        type=str,
        default="http://127.0.0.1:12345",
        help="IDA server URL (default: http://127.0.0.1:12345)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Dry run mode: show prompts without calling LLM",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        help="Log file path (default: phase1_knowledge_propagation.log)",
    )

    args = parser.parse_args()

    # 设置日志
    log_file = args.log_file or Path("phase1_knowledge_propagation.log")
    setup_logging(log_file, args.db_path)

    # 加载 LLM 配置
    config = load_semantics_config()
    llm_settings = LLMSettings(
        model=config.get("model", "gpt-4.1-mini"),
        temperature=config.get("temperature", 0.1),
        max_tokens=config.get("max_tokens", 512),
        api_settings=config.get("api_settings", {}),
        chat_completion_kwargs=config.get("chat_completion_kwargs", {}),
    )

    # 运行 Phase 1 分析
    processed = run_phase1_analysis(
        db_path=str(args.db_path),
        binary_id=args.binary_id,
        llm_settings=llm_settings,
        max_functions=args.max_functions,
        ida_sync=args.ida_sync,
        ida_url=args.ida_url if args.ida_sync else None,
        dry_run=args.dry_run,
    )

    print(f"\n[完成] Phase 1 分析完成，共处理 {processed} 个函数。")
