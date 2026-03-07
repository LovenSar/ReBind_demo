#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""deep_path_dfs.py

Deep-path DFS command entrypoint.

This file is intentionally kept thin:
- kp.kp_deep_path: graph/path/core extraction logic
- phases.phase2_deep_path: deepest-path step-by-step LLM polling
- pmt.prompts: deep-path LLM prompt template
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Optional

from kp.kp_deep_path import (
    estimate_global_deepest_depth,
    pick_binary_id,
    resolve_db_path,
    resolve_entry_points,
    run_deep_path_analysis,
)
from kp.kp_graph import build_unified_graph
from kp.kp_settings import build_llm_settings, load_semantics_config
from phases.phase2_deep_path import run_llm_poll_on_deepest_path


def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="入口点驱动的深度优先路径分析（DFS）")
    ap.add_argument(
        "input_path",
        nargs="?",
        default=None,
        help="输入路径（推荐只传一个）：可为样本 exe/dll/sys/bin、IDA .idb/.i64、或 .db",
    )
    ap.add_argument("--db", default=None, help="可选：显式指定 SQLite 数据库路径（优先级最高）")
    ap.add_argument("--binary-id", type=int, default=None, help="可选：指定 binary_id（多 binary 时必须）")
    ap.add_argument(
        "--entry",
        action="append",
        default=[],
        help="入口点（可重复）：支持地址(0x401000)或名称关键字(main/xxx)",
    )
    ap.add_argument("--auto-entry-limit", type=int, default=5, help="未指定 --entry 时自动选择的入口点数量上限（默认 5）")
    ap.add_argument(
        "--max-depth",
        type=int,
        default=0,
        help="DFS 最大深度（默认 0=自动取全局最深；传正数可手动限制）",
    )
    ap.add_argument("--max-paths", type=int, default=300, help="最多保留多少条叶子路径（默认 300）")
    ap.add_argument("--max-branch", type=int, default=6, help="每层最多展开多少个子调用（默认 6）")
    ap.add_argument("--max-call-sites", type=int, default=3, help="每条边最多分析多少个调用点（默认 3）")
    ap.add_argument("--cond-window", type=int, default=10, help="向上回溯多少行提取守卫条件（默认 10）")
    ap.add_argument("--max-guards-per-site", type=int, default=3, help="每个调用点最多采集多少条守卫条件（默认 3）")
    ap.add_argument("--top", type=int, default=20, help="终端最多打印前 N 条最深路径（默认 20）")
    ap.add_argument("--output", default=None, help="输出 JSON 路径（默认: <db>_deep_dfs_paths.json）")

    ap.add_argument(
        "--llm-poll-deepest",
        dest="llm_poll_deepest",
        action="store_true",
        default=True,
        help="对“最深/最长路径”逐层调用 LLM 推断输入与条件链（默认开启）",
    )
    ap.add_argument(
        "--no-llm-poll-deepest",
        dest="llm_poll_deepest",
        action="store_false",
        help="关闭最深路径 LLM 轮询",
    )
    ap.add_argument(
        "--llm-mode",
        choices=("auto", "on", "off"),
        default="auto",
        help="LLM 执行模式：auto=失败自动降级；on=失败即报错；off=不调用（默认 auto）",
    )
    ap.add_argument("--llm-config", default=None, help="可选：LLM 配置路径（默认使用 tools/Semantics_Alignment/config.yaml）")
    ap.add_argument("--llm-model", default=None, help="可选：覆盖模型名")
    ap.add_argument("--llm-temperature", type=float, default=None, help="可选：覆盖 temperature")
    ap.add_argument("--llm-max-tokens", type=int, default=None, help="可选：覆盖 max_tokens")
    ap.add_argument("--llm-max-attempts", type=int, default=3, help="每层 LLM 调用最大重试次数（默认 3）")
    ap.add_argument("--llm-max-steps", type=int, default=0, help="限制最多轮询多少层（0 表示不限制）")
    ap.add_argument("--llm-code-chars", type=int, default=1200, help="每层给 LLM 的 caller/callee 伪代码截断长度（默认 1200）")
    ap.add_argument("--llm-dry-run", action="store_true", default=False, help="仅生成逐层 prompt 预览，不实际调用 LLM")
    ap.add_argument("--llm-verbose", action="store_true", default=False, help="打印逐层轮询细节（发送 prompt、原始回复预览、解析结果）")
    ap.add_argument("--llm-prompt-preview-chars", type=int, default=1800, help="llm-verbose 时每步 prompt 预览最大字符数（默认 1800）")
    ap.add_argument("--llm-raw-preview-chars", type=int, default=2000, help="llm-verbose 时每步原始回复预览最大字符数（默认 2000）")
    ap.add_argument("--llm-log-file", default=None, help="可选：逐层 LLM 轮询 JSONL 日志输出路径（默认不写）")
    return ap.parse_args()


def main() -> int:
    args = _parse_args()

    db_path = resolve_db_path(args.input_path, args.db)
    out_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else db_path.with_name(f"{db_path.stem}_deep_dfs_paths.json")
    )

    binary_id = 0
    result: Dict[str, Any] = {}
    llm_poll_result: Optional[Dict[str, Any]] = None
    resolved_max_depth = 0

    conn = sqlite3.connect(str(db_path))
    try:
        binary_id = pick_binary_id(conn, args.binary_id)
        graph = build_unified_graph(
            conn=conn,
            binary_id=int(binary_id),
            include_call_xrefs=True,
            include_string_xrefs=False,
        )

        entries = resolve_entry_points(
            graph=graph,
            entries=list(args.entry or []),
            auto_entry_limit=max(1, int(args.auto_entry_limit or 1)),
        )
        if not entries:
            raise SystemExit("未找到可用入口点；请显式传入 --entry。")

        requested_max_depth = int(args.max_depth or 0)
        if requested_max_depth <= 0:
            resolved_max_depth = max(1, int(estimate_global_deepest_depth(graph)))
            print(f"[DeepDFS] 自动深度: 全局最深={resolved_max_depth}")
        else:
            resolved_max_depth = requested_max_depth

        result = run_deep_path_analysis(
            conn=conn,
            graph=graph,
            entries=entries,
            max_depth=int(resolved_max_depth),
            max_paths=max(1, int(args.max_paths or 1)),
            max_branch=max(1, int(args.max_branch or 1)),
            max_call_sites=max(1, int(args.max_call_sites or 1)),
            cond_window=max(1, int(args.cond_window or 1)),
            max_guards_per_site=max(1, int(args.max_guards_per_site or 1)),
        )

        if args.llm_mode == "off":
            llm_poll_result = {"status": "skipped", "reason": "llm_mode_off"}
        elif args.llm_poll_deepest:
            try:
                llm_cfg = load_semantics_config(args.llm_config)
                llm_settings = build_llm_settings(
                    llm_cfg,
                    model=args.llm_model,
                    temperature=args.llm_temperature,
                    max_tokens=args.llm_max_tokens,
                )
                llm_poll_result = run_llm_poll_on_deepest_path(
                    conn=conn,
                    graph=graph,
                    paths=list(result.get("paths", []) or []),
                    llm_settings=llm_settings,
                    max_attempts=max(1, int(args.llm_max_attempts or 1)),
                    code_chars=max(200, int(args.llm_code_chars or 1200)),
                    max_steps=max(0, int(args.llm_max_steps or 0)),
                    dry_run=bool(args.llm_dry_run),
                    verbose=bool(args.llm_verbose),
                    prompt_preview_chars=max(200, int(args.llm_prompt_preview_chars or 1800)),
                    raw_response_chars=max(200, int(args.llm_raw_preview_chars or 2000)),
                    log_file=str(args.llm_log_file) if args.llm_log_file else None,
                )
            except Exception as exc:
                if str(args.llm_mode or "auto").lower() == "on":
                    raise
                llm_poll_result = {
                    "status": "skipped",
                    "reason": "llm_auto_failed",
                    "error": str(exc),
                }
    finally:
        conn.close()

    report = {
        "config": {
            "input_path": str(Path(args.input_path).expanduser().resolve()) if args.input_path else "",
            "db_path": str(db_path),
            "binary_id": int(binary_id),
            "max_depth_requested": int(args.max_depth),
            "max_depth_effective": int(resolved_max_depth),
            "max_paths": int(args.max_paths),
            "max_branch": int(args.max_branch),
            "max_call_sites": int(args.max_call_sites),
            "cond_window": int(args.cond_window),
            "max_guards_per_site": int(args.max_guards_per_site),
            "llm_poll_deepest": bool(args.llm_poll_deepest),
            "llm_mode": str(args.llm_mode),
            "llm_dry_run": bool(args.llm_dry_run),
            "llm_max_steps": int(args.llm_max_steps),
            "llm_verbose": bool(args.llm_verbose),
            "llm_log_file": str(Path(args.llm_log_file).expanduser().resolve()) if args.llm_log_file else "",
        },
        "entries": result.get("entries", []),
        "stats": result.get("stats", {}),
        "paths": result.get("paths", []),
    }
    if llm_poll_result is not None:
        report["llm_deepest_poll"] = llm_poll_result

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    print(f"[DeepDFS] db={db_path}")
    print(f"[DeepDFS] binary_id={binary_id}")
    print(f"[DeepDFS] entry_count={len(report['entries'])} path_count={report['stats'].get('total_paths', 0)}")
    print(f"[DeepDFS] output={out_path}")
    if llm_poll_result is not None:
        print(
            "[DeepDFS][LLM] "
            f"status={llm_poll_result.get('status', 'unknown')} "
            f"avg_step_conf={llm_poll_result.get('avg_step_confidence', 0.0)} "
            f"initial_input={llm_poll_result.get('most_likely_initial_input', '')}"
        )

    top_n = max(1, int(args.top or 1))
    paths = list(report.get("paths", []))[:top_n]
    for idx, item in enumerate(paths, 1):
        chain = " -> ".join(
            f"{name}({va})"
            for name, va in zip(item.get("path_names", []), item.get("path_vas", []))
        )
        envs = ", ".join(item.get("aggregated_env_signals", [])) or "-"
        reason = item.get("leaf_reason", "")
        print(
            f"[DeepDFS][{idx:02d}] depth={item.get('depth', 0)} "
            f"gate={item.get('path_gating_strength', 0)} reason={reason} env=[{envs}]"
        )
        print(f"  path: {chain}")
        guards = item.get("sample_guards", []) or []
        for g in guards[:3]:
            print(f"  guard: {g}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
