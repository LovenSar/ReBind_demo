#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dump_phase4_candidates.py

导出 Phase 4（Local Vars）实际会选中的函数列表，并解释为何会从 1w+ 函数降到 8k+。

该脚本复用 Phase4 的核心过滤逻辑：
- 仅 IDA 视图（tools.name='ida'）
- 必须存在伪代码 (pseudo_functions.body 非空)
- 可选：排除 import / external / export
- 可选：伪代码有效行数 >= min_lines（忽略空行与单独的 '{' / '}'）
- 排除已完成 lvar_optimized 的函数（analysis_status.lvar_optimized=1）

用法示例：
  python tools/Semantics_Alignment/dump_phase4_candidates.py --db tmp/CSAgent.sys.db --out tmp/phase4_candidates.csv
"""

from __future__ import annotations

import argparse
import csv
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from kp.kp_types import SUBFUNC_NAME_PATTERN, _count_effective_pseudocode_lines


def _pick_single_binary_id(conn: sqlite3.Connection, user_binary_id: Optional[int]) -> int:
    if user_binary_id is not None:
        return int(user_binary_id)

    cur = conn.cursor()
    cur.execute("SELECT id FROM binaries ORDER BY id;")
    rows = [int(r[0]) for r in cur.fetchall()]
    if not rows:
        raise SystemExit("数据库中未找到 binaries 记录，无法确定 binary_id。")
    if len(rows) == 1:
        return int(rows[0])

    raise SystemExit(
        "数据库包含多个 binary_id，请用 --binary-id 指定。可用列表: "
        + ", ".join(str(x) for x in rows)
    )


def _iter_ida_functions(conn: sqlite3.Connection, binary_id: int) -> Iterable[Tuple[int, int, str, str, str, str, int]]:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT
            f.entry_va,
            f.id AS function_id,
            COALESCE(f.name, '') AS func_name,
            COALESCE(pf.body, '') AS pseudo_body,
            COALESCE(s.kind, '') AS sym_kind,
            COALESCE(s.source, '') AS sym_source,
            COALESCE(s.is_external, 0) AS sym_is_external
        FROM functions AS f
        JOIN binary_views AS bv ON f.view_id = bv.id
        JOIN tools AS t ON bv.tool_id = t.id
        LEFT JOIN symbols AS s ON f.source_symbol_id = s.id
        LEFT JOIN pseudo_functions AS pf ON pf.function_id = f.id
        WHERE bv.binary_id = ? AND LOWER(t.name) = 'ida'
        ORDER BY f.entry_va;
        """,
        (int(binary_id),),
    )
    for row in cur.fetchall():
        entry_va, fid, func_name, pseudo_body, sym_kind, sym_source, sym_is_external = row
        yield int(entry_va), int(fid), str(func_name or ""), str(pseudo_body or ""), str(sym_kind or ""), str(sym_source or ""), int(sym_is_external or 0)


def _load_optimized_fids(conn: sqlite3.Connection) -> set[int]:
    cur = conn.cursor()
    try:
        cur.execute("SELECT function_id FROM analysis_status WHERE lvar_optimized = 1;")
    except sqlite3.OperationalError:
        return set()
    return {int(r[0]) for r in cur.fetchall()}


def main() -> int:
    ap = argparse.ArgumentParser(description="导出 Phase 4 实际候选函数列表（IDA 视图）")
    ap.add_argument("--db", required=True, help="SQLite 数据库路径（alignment_loader 输出的 .db）")
    ap.add_argument("--binary-id", type=int, default=None, help="可选：指定 binary_id（数据库含多个 binary 时需要）")
    ap.add_argument("--out", default=None, help="输出 CSV 路径（默认: <db>_phase4_candidates.csv）")
    ap.add_argument("--min-lines", type=int, default=6, help="最少有效伪代码行数（默认 6）")
    ap.add_argument(
        "--exclude-import-export",
        action="store_true",
        default=True,
        help="排除 import/external/export 符号（默认启用）",
    )
    ap.add_argument(
        "--include-optimized",
        action="store_true",
        default=False,
        help="包含已标记 lvar_optimized=1 的函数（默认排除）",
    )
    ap.add_argument(
        "--only-sub",
        action="store_true",
        default=False,
        help="仅保留 sub_xxxx 样式函数名（与 Phase4 only_sub 对齐）",
    )
    args = ap.parse_args()

    db_path = Path(args.db).expanduser().resolve()
    if not db_path.exists():
        raise SystemExit(f"数据库不存在: {db_path}")

    out_path = Path(args.out).expanduser().resolve() if args.out else db_path.with_name(f"{db_path.stem}_phase4_candidates.csv")
    min_lines = max(0, int(args.min_lines or 0))
    exclude_import_export = bool(args.exclude_import_export)
    include_optimized = bool(args.include_optimized)
    only_sub = bool(args.only_sub)

    conn = sqlite3.connect(str(db_path))
    try:
        binary_id = _pick_single_binary_id(conn, args.binary_id)
        optimized_fids = _load_optimized_fids(conn)

        # 统计（按 Phase4 的过滤顺序做“逐步剔除”计数，便于解释为何数量变少）
        total = 0
        no_pseudo = 0
        excluded_import = 0
        excluded_external = 0
        excluded_export = 0
        excluded_short = 0
        excluded_optimized = 0
        excluded_not_sub = 0

        candidates: List[Dict[str, Any]] = []

        for entry_va, fid, func_name, pseudo_body, sym_kind, sym_source, sym_is_external in _iter_ida_functions(conn, binary_id):
            total += 1

            if not pseudo_body:
                no_pseudo += 1
                continue

            if exclude_import_export:
                if (sym_kind or "").strip().lower() == "import":
                    excluded_import += 1
                    continue
                if int(sym_is_external or 0) != 0:
                    excluded_external += 1
                    continue
                if "export" in (sym_source or "").strip().lower():
                    excluded_export += 1
                    continue

            eff_lines = _count_effective_pseudocode_lines(pseudo_body)
            if min_lines and eff_lines < min_lines:
                excluded_short += 1
                continue

            if (not include_optimized) and (fid in optimized_fids):
                excluded_optimized += 1
                continue

            if only_sub and not SUBFUNC_NAME_PATTERN.fullmatch((func_name or "").strip()):
                excluded_not_sub += 1
                continue

            candidates.append(
                {
                    "entry_va": entry_va,
                    "function_id": fid,
                    "name": func_name,
                    "effective_lines": eff_lines,
                    "sym_kind": sym_kind,
                    "sym_source": sym_source,
                    "sym_is_external": int(sym_is_external or 0),
                }
            )

        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(
                [
                    "entry_va",
                    "function_id",
                    "name",
                    "effective_lines",
                    "sym_kind",
                    "sym_source",
                    "sym_is_external",
                ]
            )
            for it in candidates:
                w.writerow(
                    [
                        f"0x{int(it['entry_va']):X}",
                        int(it["function_id"]),
                        it["name"],
                        int(it["effective_lines"]),
                        it["sym_kind"],
                        it["sym_source"],
                        int(it["sym_is_external"]),
                    ]
                )

        # 提示：Phase4 的日志里用的是“entry_va 去重后的 entry 数”，这里导出是“function 行”。
        # 大多数情况下两者接近（IDA view 下 entry_va 通常唯一）。
        unique_entries = len({int(it["entry_va"]) for it in candidates})

        print(f"[Phase4Dump] db={db_path}")
        print(f"[Phase4Dump] binary_id={binary_id}")
        print(f"[Phase4Dump] filters: min_lines={min_lines}, exclude_import_export={exclude_import_export}, include_optimized={include_optimized}, only_sub={only_sub}")
        print(f"[Phase4Dump] total_ida_functions={total}")
        print(
            "[Phase4Dump] excluded:"
            f" no_pseudo={no_pseudo}, import={excluded_import}, external={excluded_external}, export={excluded_export},"
            f" too_short={excluded_short}, optimized={excluded_optimized}, not_sub={excluded_not_sub}"
        )
        print(f"[Phase4Dump] candidates_rows={len(candidates)}, candidates_unique_entry_va={unique_entries}")
        print(f"[Phase4Dump] wrote: {out_path}")
    finally:
        conn.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

