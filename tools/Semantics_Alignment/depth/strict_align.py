#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phase7_5_strict_align.py

Phase7.5: 严格对齐组件（IDA 导出 -> DB）。

目标：
1) 在 Phase7 主干搜索前，先把 DB 与当前 IDA 导出结果严格对齐；
2) 对关键语义表做哈希级校验（函数/指令/xrefs/字符串/符号/伪代码 + FCG/CFG 边）；
3) 若发现漂移，使用重建库原子替换工作 DB，并保留备份与对账报告。
"""

from __future__ import annotations

import hashlib
import itertools
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


ALIGNMENT_LOADER_SCRIPT = Path(__file__).resolve().parents[1] / "breadth" / "alignment_loader.py"

_LINE2_MAX = 180

# 哈希对账各子步骤说明（行内展示，宜简短）
_PHASE75_METRIC_HINT: Dict[str, str] = {
    "symbols_all": "IDA符号全表",
    "import_symbols": "导入符号",
    "export_symbols": "导出符号",
    "strings": "字符串表",
    "functions": "函数元数据",
    "instructions": "反汇编指令流",
    "xrefs": "交叉引用",
    "pseudo_functions": "伪代码函数体",
    "fcg_call_edges": "FCG: call类xref→跨函数调用边(重JOIN)",
    "cfg_intra_edges": "CFG: 函数内非call控制流边(重JOIN)",
}


def _phase75_metric_data_line(metric_name: str, db_path: Path) -> str:
    """单行补充：数据来自哪个 DB、在做什么（避免误以为在读伪代码目录）。"""
    dn = db_path.name
    lines: Dict[str, str] = {
        "symbols_all": f"库[{dn}] 表 symbols 顺序读行→哈希",
        "import_symbols": f"库[{dn}] 表 symbols 筛 import 相关行",
        "export_symbols": f"库[{dn}] 表 symbols 筛 export 相关行",
        "strings": f"库[{dn}] 表 strings",
        "functions": f"库[{dn}] 表 functions",
        "instructions": f"库[{dn}] 表 instructions+functions 联表",
        "xrefs": f"库[{dn}] 表 xrefs",
        "pseudo_functions": f"库[{dn}] 表 pseudo_functions(伪代码正文已在此表中)",
        "fcg_call_edges": (
            f"库[{dn}] JOIN:xrefs+instr@src+instr@dst+funcs→CALL边;不读.c文件"
        ),
        "cfg_intra_edges": (
            f"库[{dn}] JOIN:同函数内xrefs+双instr;非读磁盘导出文件"
        ),
        "pseudo_variable_names": f"库[{dn}] 逐函数解析伪代码中的变量名",
    }
    return lines.get(metric_name, f"库[{dn}] 表扫描")


def _phase75_print_heavy_join_banner(
    metric_name: str,
    db_path: Path,
    step_one_based: int,
    total_steps: int,
) -> None:
    """对最耗时的 JOIN 步，在开始前多打几行说明，避免误以为卡死或读文件。"""
    if not sys.stdout.isatty():
        return
    dn = db_path.name
    abs_db = str(db_path.resolve())
    if metric_name == "fcg_call_edges":
        print(
            f"\n[Phase7][Phase7.5] ══ 第{step_one_based}/{total_steps}步 fcg_call_edges ══\n"
            f"  · 不是在读 *_pseudocode/*.c：那些已在导入 alignment 时写入 SQLite。\n"
            f"  · 当前只读打开 SQLite: {abs_db}\n"
            f"  · 正在执行库内 SQL：xrefs JOIN instructions(源地址) JOIN instructions(目的地址)\n"
            f"    JOIN functions(两侧)，筛 ref_type ∈ CALL 集合，得到 FCG「调用边」行集合并算 SHA256。\n"
            f"  · 若下方长时间停在「首行未返回」：SQLite 正在做查询计划/全表/索引扫描，属正常。\n",
            flush=True,
        )
    elif metric_name == "cfg_intra_edges":
        print(
            f"\n[Phase7][Phase7.5] ══ 第{step_one_based}/{total_steps}步 cfg_intra_edges ══\n"
            f"  · 同样只访问 SQLite「{dn}」，不逐个打开伪代码文件。\n"
            f"  · 当前 SQL：同函数内的 xrefs，经双 instruction JOIN，筛非 CALL 的 xref 作 CFG 内边。\n"
            f"  · 库路径: {abs_db}\n",
            flush=True,
        )


def _phase75_format_elapsed(seconds: float) -> str:
    """人类可读耗时；60s 内保留一位小数，避免全程显示 0s。"""
    s = max(0.0, float(seconds))
    if s >= 3600:
        si = int(s)
        return f"{si // 3600}h{(si % 3600) // 60}m"
    if s >= 60:
        si = int(s)
        return f"{si // 60}m{si % 60}s"
    return f"{s:.1f}s"


def _phase75_format_timers(
    step_start_mono: float,
    phase75_start_mono: float,
    goal_run_start_mono: Optional[float],
) -> str:
    """行首：本步耗时 | Phase7.5 累计 |（可选）引擎进程累计。"""
    now = time.monotonic()
    parts = [
        f"本步{_phase75_format_elapsed(now - step_start_mono)}",
        f"P7.5计{_phase75_format_elapsed(now - phase75_start_mono)}",
    ]
    if goal_run_start_mono is not None:
        parts.append(f"引擎计{_phase75_format_elapsed(now - goal_run_start_mono)}")
    return "[" + " ".join(parts) + "]"


def _phase75_line2_tty_ok(console_progress: bool) -> bool:
    return bool(console_progress) and sys.stdout.isatty()


def _phase75_progress_bar(cur: int, total: int, width: int = 14) -> str:
    if total <= 0:
        return "[?]"
    filled = int(width * cur / total)
    filled = min(width, max(0, filled))
    return "[" + "\u2588" * filled + "\u2591" * (width - filled) + "]"


def _phase75_line2_render(msg: str) -> None:
    """单行刷新（不换行）：前置 \\r 并用空格擦尾，避免残字。"""
    if not sys.stdout.isatty():
        return
    try:
        cols = max(48, min(_LINE2_MAX, shutil.get_terminal_size((100, 24)).columns))
    except Exception:
        cols = _LINE2_MAX
    prefix = "[Phase7][Phase7.5] "
    body = prefix + msg
    if len(body) > cols - 1:
        body = body[: cols - 4] + "..."
    pad = body + " " * max(0, cols - len(body))
    print("\r" + pad, end="", flush=True, file=sys.stdout)


def _phase75_line2_done() -> None:
    if sys.stdout.isatty():
        print(file=sys.stdout)
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ASSIGN_LHS_RE = re.compile(r"(?<![=!<>])\b([A-Za-z_][A-Za-z0-9_]*)\s*=")
PROTO_ARG_BLOCK_RE = re.compile(r"\((.*)\)", re.DOTALL)
C_KEYWORDS: set[str] = {
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "int",
    "long",
    "register",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
    "bool",
    "true",
    "false",
    "__int8",
    "__int16",
    "__int32",
    "__int64",
}


class Phase75StrictAlignError(RuntimeError):
    """Raised when strict alignment cannot be completed safely."""


def _filter_variable_token(token: str) -> bool:
    t = str(token or "").strip()
    if not t:
        return False
    tl = t.lower()
    if tl in C_KEYWORDS:
        return False
    if tl.startswith("sub_") or tl.startswith("loc_"):
        return False
    if t.startswith("__"):
        return False
    return True


def _extract_proto_arg_names(proto: str) -> List[str]:
    raw = str(proto or "")
    m = PROTO_ARG_BLOCK_RE.search(raw)
    if not m:
        return []
    arg_text = m.group(1).strip()
    if not arg_text or arg_text.lower() == "void":
        return []
    out: List[str] = []
    for part in arg_text.split(","):
        tokens = IDENT_RE.findall(part)
        if not tokens:
            continue
        cand = tokens[-1]
        if _filter_variable_token(cand):
            out.append(cand)
    return out


def _extract_variable_names_from_pseudo(prototype: str, body: str) -> List[str]:
    names: set[str] = set()
    for name in _extract_proto_arg_names(prototype):
        names.add(name)
    for m in ASSIGN_LHS_RE.finditer(str(body or "")):
        cand = str(m.group(1) or "")
        if _filter_variable_token(cand):
            names.add(cand)
    return sorted(names)


def _collect_pseudo_variable_metric(
    conn: sqlite3.Connection,
    *,
    on_fn_progress: Optional[Callable[[int], None]] = None,
    progress_fn_interval: int = 200,
    progress_min_interval_sec: float = 0.12,
) -> Dict[str, Any]:
    sql = """
    SELECT p.entry_va, COALESCE(p.name, ''), COALESCE(p.prototype, ''), COALESCE(p.body, '')
    FROM pseudo_functions AS p
    JOIN binary_views AS bv ON p.view_id = bv.id
    JOIN tools AS t ON bv.tool_id = t.id
    WHERE LOWER(t.name) = 'ida'
    ORDER BY p.entry_va, COALESCE(p.name, ''), p.id;
    """
    cur = conn.execute(sql)
    h = hashlib.sha256()
    fn_count = 0
    token_total = 0
    last_pb = 0.0
    for row in cur:
        entry_va = int(row[0] or 0)
        name = str(row[1] or "")
        prototype = str(row[2] or "")
        body = str(row[3] or "")
        var_names = _extract_variable_names_from_pseudo(prototype, body)
        payload = [entry_va, name, var_names]
        blob = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)
        h.update(blob.encode("utf-8"))
        h.update(b"\n")
        fn_count += 1
        token_total += len(var_names)
        if on_fn_progress is not None:
            now = time.monotonic()
            tick_rows = progress_fn_interval > 0 and fn_count % progress_fn_interval == 0
            tick_time = progress_min_interval_sec > 0 and (now - last_pb) >= progress_min_interval_sec
            if fn_count == 1 or tick_rows or tick_time:
                on_fn_progress(fn_count)
                last_pb = now
    return {"count": int(fn_count), "sha256": h.hexdigest(), "token_total": int(token_total)}


def _focus_metric_entry(
    metric_key: str,
    current_profile: Dict[str, Dict[str, Any]],
    rebuilt_profile: Dict[str, Dict[str, Any]],
    active_profile: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    cur = current_profile.get(metric_key) or {}
    reb = rebuilt_profile.get(metric_key) or {}
    act = active_profile.get(metric_key) or {}
    return {
        "metric": metric_key,
        "current": {
            "count": int(cur.get("count", 0) or 0),
            "sha256": str(cur.get("sha256", "")),
        },
        "rebuilt": {
            "count": int(reb.get("count", 0) or 0),
            "sha256": str(reb.get("sha256", "")),
        },
        "active": {
            "count": int(act.get("count", 0) or 0),
            "sha256": str(act.get("sha256", "")),
        },
        "aligned_after_phase7_5": str(act.get("sha256", "")) == str(reb.get("sha256", "")),
    }


def _build_focus_metrics_summary(
    *,
    current_profile: Dict[str, Dict[str, Any]],
    rebuilt_profile: Dict[str, Dict[str, Any]],
    active_profile: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    return {
        "imports": _focus_metric_entry("import_symbols", current_profile, rebuilt_profile, active_profile),
        "exports": _focus_metric_entry("export_symbols", current_profile, rebuilt_profile, active_profile),
        "variable_names": _focus_metric_entry("pseudo_variable_names", current_profile, rebuilt_profile, active_profile),
    }


def _safe_name(text: str) -> str:
    raw = str(text or "").strip()
    if not raw:
        return "sample"
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in raw).strip("._-") or "sample"


def _default_ida_dir_name_from_input(input_path: Optional[str], db_path: Path) -> str:
    if input_path:
        name = Path(input_path).name
        if name:
            return f"{name.replace('.', '_')}_idademo"
    stem = db_path.stem or "sample"
    return f"{stem.replace('.', '_')}_idademo"


def _ida_export_dir_from_db(db_path: Path) -> Optional[Path]:
    """从对齐库 ``binary_views.output_dir`` 读取 IDA 视图目录（若存在且仍为有效目录）。"""
    if not db_path.is_file():
        return None
    try:
        conn = sqlite3.connect(str(db_path))
    except Exception:
        return None
    try:
        cur = conn.execute(
            """
            SELECT bv.output_dir
            FROM binary_views AS bv
            JOIN tools AS t ON bv.tool_id = t.id
            WHERE LOWER(COALESCE(t.name, '')) = 'ida'
            ORDER BY bv.id
            LIMIT 1;
            """
        )
        row = cur.fetchone()
    except Exception:
        return None
    finally:
        conn.close()
    if not row or not row[0]:
        return None
    p = Path(str(row[0])).expanduser().resolve()
    if p.is_dir():
        return p
    return None


def _scan_rebind_nested_idademo(db_parent: Path) -> List[Path]:
    """扫描 ``*_rebind_demo/*_idademo`` 嵌套布局（IDA adapter 常见输出位置）。"""
    found: List[Path] = []
    for pattern in ("*_rebind_demo/*_idademo", "*_rebind_demo/*/*_idademo"):
        for p in db_parent.glob(pattern):
            if p.is_dir():
                found.append(p.resolve())
    return sorted(set(found))


def _pick_ida_export_dir(
    *,
    db_path: Path,
    input_path: Optional[str],
    ida_dir_override: Optional[str],
) -> Path:
    if ida_dir_override:
        p = Path(ida_dir_override).expanduser().resolve()
        if not p.exists() or not p.is_dir():
            raise Phase75StrictAlignError(f"指定的 --phase7-5-ida-dir 不存在或不是目录: {p}")
        return p

    resolved_from_db = _ida_export_dir_from_db(db_path)

    candidates: List[Path] = []
    seen: set[str] = set()

    def _add(p: Path) -> None:
        rp = str(p.resolve())
        if rp not in seen:
            seen.add(rp)
            candidates.append(p.resolve())

    db_parent = db_path.parent.resolve()

    if resolved_from_db is not None:
        _add(resolved_from_db)

    _add(db_parent / _default_ida_dir_name_from_input(input_path, db_path))
    _add(db_parent / f"{db_path.stem.replace('.', '_')}_idademo")

    if input_path:
        inp = Path(input_path).expanduser().resolve()
        _add(inp.parent / f"{inp.name.replace('.', '_')}_idademo")
        if inp.stem:
            _add(inp.parent / f"{inp.stem.replace('.', '_')}_idademo")

    for p in sorted(db_parent.glob("*_idademo")):
        if p.is_dir():
            _add(p)

    for p in _scan_rebind_nested_idademo(db_parent):
        _add(p)

    existing = [p for p in candidates if p.exists() and p.is_dir()]
    if not existing:
        hint = "\n".join(f"  - {p}" for p in candidates[:8])
        raise Phase75StrictAlignError(
            "未找到可用的 IDA 导出目录(*_idademo)。\n"
            f"db={db_path}\n"
            "尝试过：\n"
            f"{hint if hint else '  (no candidates)'}"
        )

    if resolved_from_db is not None:
        dbr = resolved_from_db.resolve()
        for p in existing:
            if p.resolve() == dbr:
                return dbr

    preferred = db_parent / f"{db_path.stem.replace('.', '_')}_idademo"
    if preferred.exists() and preferred.is_dir():
        return preferred.resolve()

    if len(existing) == 1:
        return existing[0]

    hint = "\n".join(f"  - {p}" for p in existing)
    raise Phase75StrictAlignError(
        "检测到多个 *_idademo 目录，无法自动唯一确定。\n"
        f"请使用 --phase7-5-ida-dir 指定：\n{hint}"
    )


def _metric_digest(
    conn: sqlite3.Connection,
    sql: str,
    params: Sequence[Any] = (),
    *,
    on_row_progress: Optional[Callable[[int], None]] = None,
    progress_row_interval: int = 25000,
    progress_min_interval_sec: float = 0.12,
    heartbeat_while_waiting_first_row_sec: float = 0.25,
) -> Tuple[int, str]:
    """对查询结果逐行哈希；大 JOIN 可能在返回首行前阻塞很久，故用心跳线程刷进度。"""
    cur = conn.execute(sql, tuple(params))
    h = hashlib.sha256()
    cnt = 0
    last_pb = 0.0
    first_row_done = threading.Event()
    stop_heartbeat = threading.Event()

    def _heartbeat_loop() -> None:
        while not stop_heartbeat.is_set():
            if first_row_done.is_set():
                return
            if stop_heartbeat.wait(heartbeat_while_waiting_first_row_sec):
                return
            if first_row_done.is_set():
                return
            if on_row_progress is not None:
                try:
                    on_row_progress(0)
                except Exception:
                    pass

    hb_thread: Optional[threading.Thread] = None
    if on_row_progress is not None and heartbeat_while_waiting_first_row_sec > 0:
        hb_thread = threading.Thread(target=_heartbeat_loop, name="phase75_sqlite_hb", daemon=True)
        hb_thread.start()

    try:
        for row in cur:
            if not first_row_done.is_set():
                first_row_done.set()
                stop_heartbeat.set()
            normalized: List[Any] = []
            for cell in row:
                if isinstance(cell, bytes):
                    normalized.append({"__bytes_hex__": cell.hex()})
                else:
                    normalized.append(cell)
            blob = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), default=str)
            h.update(blob.encode("utf-8"))
            h.update(b"\n")
            cnt += 1
            if on_row_progress is not None:
                now = time.monotonic()
                tick_rows = progress_row_interval > 0 and cnt % progress_row_interval == 0
                tick_time = progress_min_interval_sec > 0 and (now - last_pb) >= progress_min_interval_sec
                if cnt == 1 or tick_rows or tick_time:
                    on_row_progress(cnt)
                    last_pb = now
    finally:
        first_row_done.set()
        stop_heartbeat.set()
        if hb_thread is not None:
            hb_thread.join(timeout=2.0)

    return cnt, h.hexdigest()


def _progress_row_interval_for(metric_name: str) -> int:
    """JOIN 重的步骤缩短行数间隔，配合时间节流更易看到刷新。"""
    if metric_name in ("fcg_call_edges", "cfg_intra_edges"):
        return 400
    if metric_name == "instructions":
        return 4000
    if metric_name in ("xrefs", "pseudo_functions"):
        return 2000
    return 25000


def _collect_ida_profile(
    db_path: Path,
    call_ref_types: Sequence[str],
    *,
    console_progress: bool = False,
    profile_label: str = "对账",
    phase75_start_mono: Optional[float] = None,
    goal_run_start_mono: Optional[float] = None,
) -> Dict[str, Dict[str, Any]]:
    if not db_path.exists():
        raise Phase75StrictAlignError(f"数据库不存在: {db_path}")

    if phase75_start_mono is None:
        phase75_start_mono = time.monotonic()

    # WAL 数据库在缺少 -shm 时，``mode=ro`` 无法创建协调文件而打不开刚被
    # Phase7.5 原子替换的库。以 rw 打开后立即设为 query_only，允许 SQLite 建立
    # sidecar，但保证本函数不会修改业务数据。
    conn = sqlite3.connect(f"file:{db_path}?mode=rw", uri=True)
    try:
        conn.execute("PRAGMA query_only=ON;")
        metrics: Dict[str, Dict[str, Any]] = {}
        call_types = [str(x) for x in call_ref_types if str(x or "").strip()]
        if not call_types:
            call_types = ["CALL"]
        call_ph = ",".join("?" for _ in call_types)

        queries: List[Tuple[str, str, Sequence[Any]]] = [
            (
                "symbols_all",
                """
                SELECT COALESCE(s.address_va, -1), COALESCE(s.raw_address, ''), COALESCE(s.name, ''),
                       COALESCE(s.kind, ''), COALESCE(s.raw_type, ''), COALESCE(s.source, ''),
                       COALESCE(s.is_global, -1), COALESCE(s.is_primary, -1),
                       COALESCE(s.is_external, -1), COALESCE(s.namespace, '')
                FROM symbols AS s
                JOIN binary_views AS bv ON s.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                ORDER BY COALESCE(s.address_va, -1), COALESCE(s.name, ''), s.id;
                """,
                (),
            ),
            (
                "import_symbols",
                """
                SELECT COALESCE(s.address_va, -1), COALESCE(s.name, ''), COALESCE(s.raw_type, ''),
                       COALESCE(s.source, ''), COALESCE(s.raw_address, ''), COALESCE(s.is_external, -1)
                FROM symbols AS s
                JOIN binary_views AS bv ON s.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                  AND (
                    LOWER(COALESCE(s.kind, '')) = 'import'
                    OR COALESCE(s.is_external, 0) = 1
                    OR UPPER(COALESCE(s.source, '')) LIKE '%IMPORT%'
                    OR UPPER(COALESCE(s.raw_type, '')) LIKE '%IMPORT%'
                  )
                ORDER BY COALESCE(s.address_va, -1), COALESCE(s.name, ''), s.id;
                """,
                (),
            ),
            (
                "export_symbols",
                """
                SELECT COALESCE(s.address_va, -1), COALESCE(s.name, ''), COALESCE(s.raw_type, ''),
                       COALESCE(s.source, ''), COALESCE(s.raw_address, ''), COALESCE(s.is_external, -1)
                FROM symbols AS s
                JOIN binary_views AS bv ON s.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                  AND (
                    LOWER(COALESCE(s.kind, '')) = 'export'
                    OR UPPER(COALESCE(s.source, '')) LIKE '%EXPORT%'
                    OR UPPER(COALESCE(s.raw_type, '')) LIKE '%EXPORT%'
                  )
                ORDER BY COALESCE(s.address_va, -1), COALESCE(s.name, ''), s.id;
                """,
                (),
            ),
            (
                "strings",
                """
                SELECT s.address_va, COALESCE(s.value, ''), COALESCE(s.length, -1)
                FROM strings AS s
                JOIN binary_views AS bv ON s.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                ORDER BY s.address_va, COALESCE(s.value, ''), s.id;
                """,
                (),
            ),
            (
                "functions",
                """
                SELECT f.entry_va, COALESCE(f.name, ''), COALESCE(f.size_bytes, -1), COALESCE(f.raw_file, '')
                FROM functions AS f
                JOIN binary_views AS bv ON f.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                ORDER BY f.entry_va, COALESCE(f.name, ''), f.id;
                """,
                (),
            ),
            (
                "instructions",
                """
                SELECT f.entry_va, i.index_in_function, i.address_va, COALESCE(i.bytes, ''),
                       COALESCE(i.mnemonic, ''), COALESCE(i.op_str, ''), COALESCE(i.raw_line, '')
                FROM instructions AS i
                JOIN functions AS f ON i.function_id = f.id
                JOIN binary_views AS bv ON i.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                ORDER BY f.entry_va, i.index_in_function, i.address_va, i.id;
                """,
                (),
            ),
            (
                "xrefs",
                """
                SELECT x.src_va, COALESCE(x.dst_va, -1), COALESCE(x.dst_name, ''),
                       COALESCE(x.ref_type_raw, ''), COALESCE(x.containing_function, ''),
                       COALESCE(x.is_primary, -1)
                FROM xrefs AS x
                JOIN binary_views AS bv ON x.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                ORDER BY x.src_va, COALESCE(x.dst_va, -1), COALESCE(x.ref_type_raw, ''), x.id;
                """,
                (),
            ),
            (
                "pseudo_functions",
                """
                SELECT p.entry_va, COALESCE(p.name, ''), COALESCE(p.prototype, ''),
                       COALESCE(p.body, ''), COALESCE(p.raw_file, '')
                FROM pseudo_functions AS p
                JOIN binary_views AS bv ON p.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                WHERE LOWER(t.name) = 'ida'
                ORDER BY p.entry_va, COALESCE(p.name, ''), p.id;
                """,
                (),
            ),
            (
                "fcg_call_edges",
                f"""
                SELECT sf.entry_va, df.entry_va, COALESCE(x.ref_type_raw, '')
                FROM xrefs AS x
                JOIN binary_views AS bv ON x.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                CROSS JOIN instructions AS si
                  ON si.view_id = x.view_id AND si.address_va = x.src_va
                CROSS JOIN instructions AS di
                  ON di.view_id = x.view_id AND di.address_va = x.dst_va
                JOIN functions AS sf ON sf.id = si.function_id
                JOIN functions AS df ON df.id = di.function_id
                WHERE LOWER(t.name) = 'ida'
                  AND COALESCE(x.ref_type_raw, '') IN ({call_ph})
                ORDER BY sf.entry_va, df.entry_va, COALESCE(x.ref_type_raw, ''), x.id;
                """,
                call_types,
            ),
            (
                "cfg_intra_edges",
                f"""
                SELECT sf.entry_va, x.src_va, x.dst_va, COALESCE(x.ref_type_raw, '')
                FROM xrefs AS x
                JOIN binary_views AS bv ON x.view_id = bv.id
                JOIN tools AS t ON bv.tool_id = t.id
                CROSS JOIN instructions AS si
                  ON si.view_id = x.view_id AND si.address_va = x.src_va
                CROSS JOIN instructions AS di
                  ON di.view_id = x.view_id AND di.address_va = x.dst_va
                JOIN functions AS sf ON sf.id = si.function_id
                WHERE LOWER(t.name) = 'ida'
                  AND si.function_id = di.function_id
                  AND COALESCE(x.ref_type_raw, '') NOT IN ({call_ph})
                ORDER BY sf.entry_va, x.src_va, x.dst_va, COALESCE(x.ref_type_raw, ''), x.id;
                """,
                call_types,
            ),
        ]

        tty = _phase75_line2_tty_ok(console_progress)
        total_steps = len(queries) + 1

        for step_idx, (name, sql, params) in enumerate(queries):
            step_start = time.monotonic()
            hint = _PHASE75_METRIC_HINT.get(name, name)
            row_interval = _progress_row_interval_for(name)
            if tty and name in ("fcg_call_edges", "cfg_intra_edges"):
                _phase75_print_heavy_join_banner(name, db_path, step_idx + 1, total_steps)
            row_cb: Optional[Callable[[int], None]] = None
            if tty:

                def _make_row_cb(
                    mn: str,
                    si: int,
                    ss: float,
                    hn: str,
                    dbp: Path,
                ) -> Callable[[int], None]:
                    dline = _phase75_metric_data_line(mn, dbp)

                    def _cb(rows: int) -> None:
                        timers = _phase75_format_timers(ss, phase75_start_mono, goal_run_start_mono)
                        if rows == 0:
                            _phase75_line2_render(
                                f"{timers}  {profile_label}  {si + 1}/{total_steps} {mn}  {hn}  | {dline}  "
                                f"SQLite首行等待…  {_phase75_progress_bar(si + 1, total_steps)}"
                            )
                        else:
                            _phase75_line2_render(
                                f"{timers}  {profile_label}  {si + 1}/{total_steps} {mn}  {hn}  | {dline}  "
                                f"已扫描 {rows} 行  {_phase75_progress_bar(si + 1, total_steps)}"
                            )

                    return _cb

                row_cb = _make_row_cb(name, step_idx, step_start, hint, db_path)
            cnt, digest = _metric_digest(
                conn,
                sql,
                params,
                on_row_progress=row_cb,
                progress_row_interval=row_interval,
                progress_min_interval_sec=0.12,
            )
            metrics[name] = {"count": int(cnt), "sha256": str(digest)}
            if tty:
                timers_done = _phase75_format_timers(step_start, phase75_start_mono, goal_run_start_mono)
                ddone = _phase75_metric_data_line(name, db_path)
                _phase75_line2_render(
                    f"{timers_done}  {profile_label}  {step_idx + 1}/{total_steps} {name}  {hint}  | {ddone}  "
                    f"完成 {cnt} 行  {_phase75_progress_bar(step_idx + 1, total_steps)}"
                )

        if tty:
            pv_step_start = time.monotonic()
            pv_hint = "伪代码内变量名聚合"
            pv_dline = _phase75_metric_data_line("pseudo_variable_names", db_path)

            def _pv_fn(fn: int) -> None:
                timers = _phase75_format_timers(pv_step_start, phase75_start_mono, goal_run_start_mono)
                _phase75_line2_render(
                    f"{timers}  {profile_label}  {total_steps}/{total_steps} pseudo_variable_names  {pv_hint}  "
                    f"| {pv_dline}  已处理 {fn} 个函数  {_phase75_progress_bar(total_steps, total_steps)}"
                )

            metrics["pseudo_variable_names"] = _collect_pseudo_variable_metric(
                conn,
                on_fn_progress=_pv_fn,
                progress_fn_interval=80,
                progress_min_interval_sec=0.12,
            )
        else:
            metrics["pseudo_variable_names"] = _collect_pseudo_variable_metric(conn)
        return metrics
    finally:
        conn.close()


def _diff_profiles(
    current: Dict[str, Dict[str, Any]],
    rebuilt: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    keys = sorted(set(current.keys()) | set(rebuilt.keys()))
    diffs: List[Dict[str, Any]] = []
    for k in keys:
        a = current.get(k) or {"count": -1, "sha256": ""}
        b = rebuilt.get(k) or {"count": -1, "sha256": ""}
        if int(a.get("count", -1)) != int(b.get("count", -1)) or str(a.get("sha256", "")) != str(b.get("sha256", "")):
            diffs.append(
                {
                    "metric": k,
                    "current_count": int(a.get("count", -1)),
                    "rebuilt_count": int(b.get("count", -1)),
                    "current_sha256": str(a.get("sha256", "")),
                    "rebuilt_sha256": str(b.get("sha256", "")),
                }
            )
    return diffs


def _copy_sidecar_if_exists(src_db: Path, dst_db: Path) -> None:
    for suffix in ("-wal", "-shm"):
        src = src_db.with_name(src_db.name + suffix)
        if src.exists():
            dst = dst_db.with_name(dst_db.name + suffix)
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def _remove_sidecars(db_path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        p = db_path.with_name(db_path.name + suffix)
        if p.exists():
            p.unlink()


def _replace_db_atomically(
    *,
    target_db: Path,
    rebuilt_db: Path,
    backup_db: Path,
) -> None:
    backup_db.parent.mkdir(parents=True, exist_ok=True)
    if target_db.exists():
        shutil.copy2(target_db, backup_db)
        _copy_sidecar_if_exists(target_db, backup_db)

    _remove_sidecars(target_db)
    staged = target_db.with_suffix(target_db.suffix + ".phase7_5_tmp")
    if staged.exists():
        staged.unlink()
    shutil.copy2(rebuilt_db, staged)
    staged.replace(target_db)
    _remove_sidecars(target_db)


def _run_alignment_loader_ida_only(
    *,
    rebuilt_db: Path,
    ida_dir: Path,
    console_progress: bool = False,
    phase75_start_mono: Optional[float] = None,
    goal_run_start_mono: Optional[float] = None,
) -> None:
    rebuilt_db.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        str(ALIGNMENT_LOADER_SCRIPT),
        "--db",
        str(rebuilt_db),
        "--ida-dir",
        str(ida_dir),
        "--delete-db",
    ]
    cwd = str(ALIGNMENT_LOADER_SCRIPT.parent)
    if not _phase75_line2_tty_ok(console_progress):
        result = subprocess.run(cmd, cwd=cwd)
        if result.returncode != 0:
            raise Phase75StrictAlignError(
                f"alignment_loader.py(IDA-only) 失败，退出码={result.returncode}"
            )
        if not rebuilt_db.exists():
            raise Phase75StrictAlignError(f"重建 DB 未生成: {rebuilt_db}")
        return

    loader_log = rebuilt_db.parent / "alignment_loader.log"
    with loader_log.open("wb") as log_fp:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            stdout=log_fp,
            stderr=subprocess.STDOUT,
        )
        spinner = itertools.cycle("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")
        loader_step_start = time.monotonic()
        p75 = phase75_start_mono if phase75_start_mono is not None else loader_step_start
        while proc.poll() is None:
            ch = next(spinner)
            timers = _phase75_format_timers(loader_step_start, p75, goal_run_start_mono)
            _phase75_line2_render(
                f"{timers}  重建 IDA 库  {ch}  alignment_loader 导入 IDA 导出→SQLite…"
            )
            time.sleep(0.12)
    if proc.returncode != 0:
        try:
            err_text = loader_log.read_text(encoding="utf-8", errors="replace")[-4000:]
        except Exception:
            err_text = ""
        raise Phase75StrictAlignError(
            f"alignment_loader.py(IDA-only) 失败，退出码={proc.returncode}\n{err_text}"
        )
    if not rebuilt_db.exists():
        raise Phase75StrictAlignError(f"重建 DB 未生成: {rebuilt_db}")


def run_phase7_5_strict_align(
    *,
    db_path: Path,
    input_path: Optional[str],
    artifacts_dir: Path,
    call_ref_types: Sequence[str],
    ida_dir: Optional[str] = None,
    keep_rebuilt_db: bool = False,
    console_progress: bool = False,
    goal_run_start_mono: Optional[float] = None,
) -> Dict[str, Any]:
    """Run strict alignment and return a structured report."""

    report: Dict[str, Any] = {
        "enabled": True,
        "mode": "strict",
        "status": "running",
        "db_path": str(db_path),
        "input_path": str(input_path or ""),
        "ida_dir": "",
        "rebuilt_db": "",
        "backup_db": "",
        "profile_diff_count": 0,
        "profile_diffs": [],
        "current_profile": {},
        "rebuilt_profile": {},
        "post_replace_profile": {},
        "focus_metrics_summary": {},
        "notes": [],
    }

    if not db_path.exists():
        raise Phase75StrictAlignError(f"目标 DB 不存在: {db_path}")

    tty_line2 = _phase75_line2_tty_ok(console_progress)
    phase75_start_mono = time.monotonic()
    try:
        ida_export_dir = _pick_ida_export_dir(
            db_path=db_path,
            input_path=input_path,
            ida_dir_override=ida_dir,
        )

        phase75_dir = artifacts_dir / "phase7_5"
        phase75_dir.mkdir(parents=True, exist_ok=True)
        rebuilt_db = phase75_dir / f"{_safe_name(db_path.stem)}.rebuilt_from_ida.db"
        backup_db = phase75_dir / f"{_safe_name(db_path.name)}.before_replace.db"

        report["ida_dir"] = str(ida_export_dir)
        report["rebuilt_db"] = str(rebuilt_db)
        report["backup_db"] = str(backup_db)

        _run_alignment_loader_ida_only(
            rebuilt_db=rebuilt_db,
            ida_dir=ida_export_dir,
            console_progress=console_progress,
            phase75_start_mono=phase75_start_mono,
            goal_run_start_mono=goal_run_start_mono,
        )

        current_profile = _collect_ida_profile(
            db_path,
            call_ref_types,
            console_progress=console_progress,
            profile_label="工作库",
            phase75_start_mono=phase75_start_mono,
            goal_run_start_mono=goal_run_start_mono,
        )
        rebuilt_profile = _collect_ida_profile(
            rebuilt_db,
            call_ref_types,
            console_progress=console_progress,
            profile_label="重建库",
            phase75_start_mono=phase75_start_mono,
            goal_run_start_mono=goal_run_start_mono,
        )
        profile_diffs = _diff_profiles(current_profile, rebuilt_profile)

        report["current_profile"] = current_profile
        report["rebuilt_profile"] = rebuilt_profile
        report["profile_diffs"] = profile_diffs
        report["profile_diff_count"] = len(profile_diffs)

        if profile_diffs:
            _replace_db_atomically(
                target_db=db_path,
                rebuilt_db=rebuilt_db,
                backup_db=backup_db,
            )
            try:
                post_profile = _collect_ida_profile(
                    db_path,
                    call_ref_types,
                    console_progress=console_progress,
                    profile_label="替换后",
                    phase75_start_mono=phase75_start_mono,
                    goal_run_start_mono=goal_run_start_mono,
                )
            finally:
                # 该 sidecar 由替换后的只读画像临时创建；函数返回前收敛产物。
                _remove_sidecars(db_path)
            post_diff = _diff_profiles(post_profile, rebuilt_profile)
            report["post_replace_profile"] = post_profile
            report["post_replace_diff_count"] = len(post_diff)
            report["post_replace_diffs"] = post_diff
            report["focus_metrics_summary"] = _build_focus_metrics_summary(
                current_profile=current_profile,
                rebuilt_profile=rebuilt_profile,
                active_profile=post_profile,
            )
            if post_diff:
                report["status"] = "failed"
                raise Phase75StrictAlignError(
                    "Phase7.5 替换 DB 后仍与重建结果不一致，已中止。"
                )
            report["status"] = "replaced"
            report["notes"] = [
                "drift detected; active DB replaced by rebuilt IDA-only DB"
            ]
        else:
            report["status"] = "aligned"
            report["notes"] = [
                "active DB already matches rebuilt IDA-only profile"
            ]
            report["focus_metrics_summary"] = _build_focus_metrics_summary(
                current_profile=current_profile,
                rebuilt_profile=rebuilt_profile,
                active_profile=current_profile,
            )

        if not keep_rebuilt_db:
            if rebuilt_db.exists():
                rebuilt_db.unlink()
            _remove_sidecars(rebuilt_db)
            report["rebuilt_db_removed"] = True
        else:
            report["rebuilt_db_removed"] = False

        return report
    finally:
        if tty_line2:
            _phase75_line2_done()
