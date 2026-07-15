#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase7 任务 JSON 预处理：分析对齐 DB，匹配档位（exploratory/balanced/conservative），生成推荐任务配置。

用法示例：

  python scripts/phase7_preprocess.py --db /path/to/sample.db --input /path/to/sample.exe \\
      --out /tmp/phase7_task.suggested.json

  python -m depth.engine --task-config /tmp/phase7_task.suggested.json --db ... sample.exe
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_SA = _REPO / "tools" / "Semantics_Alignment"
if str(_SA) not in sys.path:
    sys.path.insert(0, str(_SA))
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from depth.phase7_preprocess import (  # noqa: E402
    build_suggested_task_config,
    report_to_jsonable,
    write_json,
)
from kp.kp_deep_path import resolve_db_path  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Phase7 预处理：根据 DB 规模匹配预设并写出推荐任务 JSON + 报告。",
    )
    ap.add_argument("--db", default=None, help="对齐 SQLite（与引擎 --db 一致）")
    ap.add_argument(
        "--input",
        "-i",
        default=None,
        help="样本路径（exe 等），用于推断 IDA 导出目录；可省略。",
    )
    ap.add_argument(
        "input_path",
        nargs="?",
        default=None,
        help="同 --input（位置参数）；二者填其一即可。",
    )
    ap.add_argument("--binary-id", type=int, default=None, help="多 binary 时指定 binary_id")
    ap.add_argument(
        "--out",
        "-o",
        default=None,
        help="输出任务 JSON 路径；默认 <db 父目录>/phase7_task.suggested.json",
    )
    ap.add_argument(
        "--report-out",
        default=None,
        help="分析报告 JSON；默认与 --out 同目录、同名加 .preprocess_report.json",
    )
    ap.add_argument("--quiet", action="store_true", help="不打印摘要到 stdout")
    args = ap.parse_args()

    input_path = args.input or args.input_path
    db_path = resolve_db_path(input_path, args.db)
    repo_root = _REPO
    merged, report = build_suggested_task_config(
        repo_root=repo_root,
        db_path=db_path,
        input_path=input_path,
        binary_id=args.binary_id,
    )

    out = Path(args.out).expanduser().resolve() if args.out else db_path.parent / "phase7_task.suggested.json"
    write_json(out, merged)

    if args.report_out:
        report_path = Path(args.report_out).expanduser().resolve()
    else:
        report_path = out.parent / f"{out.stem}.preprocess_report.json"
    write_json(report_path, report_to_jsonable(report))

    if not args.quiet:
        print("[Phase7 预处理] 完成", flush=True)
        print(f"  档位 tier: {report.tier}", flush=True)
        print(f"  匹配预设: {report.matched_preset_file or '(无文件，仅用 defaults + 夹紧)'}", flush=True)
        print(f"  函数数( IDA 视图): {report.stats.function_count}", flush=True)
        print(f"  xref 数: {report.stats.xref_count}", flush=True)
        print(f"  建议 phase7_5_ida_dir: {report.ida_dir_suggested or '(未能自动唯一确定)'}", flush=True)
        if report.ida_dir_note:
            note = report.ida_dir_note.strip()
            if len(note) > 240:
                note = note[:240] + "…"
            print(f"  IDA 目录说明: {note}", flush=True)
        if report.warnings:
            for w in report.warnings:
                print(f"  警告: {w}", flush=True)
        print(f"  任务 JSON: {out}", flush=True)
        print(f"  报告 JSON: {report_path}", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
