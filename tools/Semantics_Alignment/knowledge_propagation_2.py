#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
knowledge_propagation.py

主入口脚本：基于 SQLite 对齐数据库，执行"LLM + 依赖图知识传播"函数级分析。

本脚本已模块化重构，核心功能分布在以下模块中：
- common_utils.py: 共享工具和数据结构
- graph_builder.py: 依赖图构建和评分
- llm_interface.py: LLM交互接口
- ida_synchronizer.py: IDA同步功能
- phase1_knowledge_propagation.py: 第一阶段底向上知识传播
- phase2_validation.py: 第二阶段调用链校验
- phase3_global_vars.py: 第三阶段全局变量重命名
- phase4_local_vars.py: 第四阶段局部变量整理
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Iterable, Optional

# 导入共享工具
from common_utils import (
    DOTENV_PATH,
    SEMANTICS_CONFIG_FILE,
    load_semantics_config,
    load_dotenv,
    build_llm_settings,
    setup_logging,
    install_stdout_tee,
    ensure_analysis_schema,
    ensure_analysis_rows_for_binary,
    load_analysis_info,
    logger,
)

# 导入图构建
from graph_builder import (
    build_unified_graph,
    resolve_view_id,
)

# 导入IDA同步
from ida_synchronizer import (
    _reconcile_ida_db_mismatch,
    _load_ida_subfunc_entries,
)

# 导入各阶段入口
from phase1_knowledge_propagation import analyze_one_unified_function
from phase2_validation import run_validation_phase, _prompt_run_validation_with_timeout
from phase3_global_vars import run_global_var_phase
from phase4_local_vars import run_local_var_phase

try:
    import requests  # type: ignore
except Exception:
    requests = None


def main(argv: Optional[Iterable[str]] = None) -> None:
    """主入口函数：解析参数并调度四个阶段的执行。"""

    parser = argparse.ArgumentParser(
        description=(
            "基于 SQLite 对齐数据库，执行\"LLM + 依赖图知识传播\"函数级分析。"
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
        "--skip-lvar",
        action="store_true",
        help="跳过第四阶段局部变量（v1, a2...）的易读性整理。",
    )
    parser.add_argument(
        "--max-lvar-funcs",
        type=int,
        default=20,
        help="第四阶段最多处理多少个函数（默认20，0表示不限制）。",
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

    # 加载配置
    config_arg = args.config
    semantics_config = load_semantics_config(config_arg)
    dotenv_values = load_dotenv(DOTENV_PATH)
    if dotenv_values:
        for env_key, env_value in dotenv_values.items():
            # 若系统环境变量缺失或为空，则用 .env 的值填充，避免空 Bearer 头。
            if not os.environ.get(env_key):
                os.environ[env_key] = env_value
        print(f"加载 .env 环境变量文件: {DOTENV_PATH}")

    llm_settings = build_llm_settings(
        semantics_config,
        args.model,
        args.temperature,
        args.max_tokens,
    )
    key_env_var = (
        (semantics_config.get("llm") or {}).get("api", {}) if isinstance(semantics_config, dict) else {}
    )
    key_env_var = key_env_var.get("key_env_var", "OPENAI_API_KEY")
    api_key_dbg = os.environ.get(key_env_var)
    if not api_key_dbg:
        raise SystemExit(
            f"环境变量 {key_env_var} 为空或未设置，无法调用 LLM；请在 .env 或系统环境中提供有效密钥。"
        )
    else:
        print(f"检测到 LLM Key 环境变量 {key_env_var}，长度={len(api_key_dbg)}")
    config_source = Path(config_arg) if config_arg else SEMANTICS_CONFIG_FILE

    # 初始化数据库
    db_path = Path(args.db).resolve()
    if not db_path.exists():
        raise SystemExit(f"数据库文件不存在：{db_path}")

    # 初始化日志系统
    log_path = db_path.with_suffix(db_path.suffix + ".knowledge.log")
    setup_logging(log_path, input_db=db_path)
    install_stdout_tee(logger)
    logger.info("知识传播管线启动，数据库: %s", db_path)

    # 打开数据库并解析视图
    conn = sqlite3.connect(str(db_path))
    try:
        # 选择锚点视图
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

        # 确保 schema 和行就绪
        ensure_analysis_schema(conn)
        ensure_analysis_rows_for_binary(conn, binary_id)

        # IDA/DB 差异对齐（如果启用IDA同步且非全部PENDING）
        if args.ida_sync:
            analysis_info_probe = load_analysis_info(conn)
            total = 0
            pending = 0
            for info in analysis_info_probe.values():
                total += 1
                state = (info or {}).get("analysis_state")
                if state is None or state == "PENDING":
                    pending += 1

            all_pending = total > 0 and pending == total

            if all_pending or total == 0:
                print("[Align] 所有函数均为 PENDING，跳过 IDA/DB 不一致对齐，先走基础重命名流程。")
            else:
                _reconcile_ida_db_mismatch(
                    conn=conn,
                    binary_id=binary_id,
                    ida_url=args.ida_url,
                    llm_settings=llm_settings,
                    ida_sync=args.ida_sync,
                )

        # 构建跨视图统一依赖图
        unified_graph = build_unified_graph(conn, binary_id)
        print(f"统一图中共有 {len(unified_graph.nodes)} 个物理函数节点。")

        # ===== 第一阶段：底向上知识传播 =====
        from phase1_knowledge_propagation import run_phase1

        processed = run_phase1(
            conn=conn,
            binary_id=binary_id,
            unified_graph=unified_graph,
            llm_settings=llm_settings,
            max_functions=args.max_functions,
            ida_sync=args.ida_sync,
            ida_url=args.ida_url,
            dry_run=args.dry_run,
        )
        print(f"\n[Phase 1] 完成，本次运行共处理物理函数数量：{processed}")

    finally:
        conn.close()

    # ===== 第二阶段：调用链 Top-down 校验 =====
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

    # ===== 第三阶段：全局变量重命名与类型推断 =====
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

    # ===== 第四阶段：局部变量易读性整理 =====
    if not args.skip_lvar:
        conn4 = sqlite3.connect(str(db_path))
        try:
            run_local_var_phase(
                conn=conn4,
                graph=unified_graph,
                llm_settings=llm_settings,
                ida_sync=args.ida_sync,
                ida_url=args.ida_url,
                dry_run=args.dry_run,
                max_funcs=args.max_lvar_funcs,
            )
        finally:
            conn4.close()

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
