"""kp_deep_path.py

Deep path DFS helpers extracted from deep_path_dfs.py.

This module keeps non-LLM, reusable graph traversal / edge extraction logic.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from .kp_types import UnifiedGraph


CONTROL_LINE_RE = re.compile(r"\b(?:if|else\s+if|switch|case|while|for)\b", re.IGNORECASE)
COMPARE_RE = re.compile(r"(==|!=|<=|>=|<|>|&&|\|\||\?)")
ENTRY_NAME_HINT_RE = re.compile(r"(?:^|_)(?:main|entry|start|w?main)(?:$|_)", re.IGNORECASE)
IDA_DB_EXTS = {".idb", ".i64"}

ENV_KEYWORDS: Dict[str, Tuple[str, ...]] = {
    "command_line": ("argv", "argc", "getcommandline", "commandlinetoargv", "lpcommandline"),
    "environment_var": ("getenv", "getenvironmentvariable", "setenvironmentvariable"),
    "anti_debug": (
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ntqueryinformationprocess",
        "beingdebugged",
        "debugport",
        "outputdebugstring",
    ),
    "vm_sandbox": ("vmware", "virtualbox", "vbox", "qemu", "sandbox", "hyper-v", "parallels"),
    "file_system": ("createfile", "readfile", "writefile", "getfileattributes", "fopen(", "open(", "stat(", "access("),
    "registry": ("regopenkey", "regqueryvalue", "hkey_"),
    "network": ("socket(", "connect(", "send(", "recv(", "internetopen", "httpsendrequest", "winhttp", "wsastartup"),
    "timing": ("sleep(", "gettickcount", "queryperformancecounter", "timegettime", "rdtsc"),
    "privilege_process": ("openprocess", "createprocess", "createtoolhelp32snapshot", "gettokeninformation", "adjusttokenprivileges"),
}


def parse_va(text: str) -> int:
    s = str(text or "").strip()
    if not s:
        raise ValueError("empty address")
    return int(s, 0)


def fmt_va(va: int) -> str:
    return f"0x{int(va):08X}"


def pick_binary_id(conn: sqlite3.Connection, user_binary_id: Optional[int]) -> int:
    if user_binary_id is not None:
        return int(user_binary_id)

    cur = conn.cursor()
    cur.execute("SELECT id FROM binaries ORDER BY id;")
    rows = [int(r[0]) for r in cur.fetchall()]
    if not rows:
        raise SystemExit("数据库中不存在 binaries 记录，无法确定 binary_id。")
    if len(rows) == 1:
        return int(rows[0])
    raise SystemExit(
        "数据库包含多个 binary_id，请通过 --binary-id 指定。可用值: "
        + ", ".join(str(x) for x in rows)
    )


def _derive_db_from_sample_file(sample_path: Path) -> Path:
    return sample_path.parent / f"{sample_path.name}.db"


def _derive_db_from_ida_db_file(ida_db_path: Path) -> Path:
    sample_name = ida_db_path.stem
    m = re.match(r"^(.+?\.(?:exe|dll|sys|bin))(?:[-_].*)?$", sample_name, flags=re.IGNORECASE)
    if m:
        sample_name = m.group(1)
    return ida_db_path.parent / f"{sample_name}.db"


def resolve_db_path(input_path: Optional[str], explicit_db: Optional[str]) -> Path:
    if explicit_db:
        db = Path(explicit_db).expanduser().resolve()
        if not db.exists():
            raise SystemExit(f"数据库不存在: {db}")
        return db

    if not input_path:
        raise SystemExit("请提供输入路径（exe/idb/i64/db），或使用 --db 指定数据库路径。")

    target = Path(input_path).expanduser().resolve()
    if not target.exists():
        raise SystemExit(f"输入路径不存在: {target}")

    if target.is_dir():
        db_files = sorted(target.glob("*.db"))
        if len(db_files) == 1:
            return db_files[0].resolve()
        if len(db_files) > 1:
            hint = "\n".join(f"  - {p}" for p in db_files[:10])
            raise SystemExit("目录下存在多个 .db，无法自动确定，请改用 --db 指定：\n" f"{hint}")
        raise SystemExit(f"目录下未找到 .db 文件: {target}")

    suffix = target.suffix.lower()
    if suffix == ".db":
        return target

    if suffix in IDA_DB_EXTS:
        candidate = _derive_db_from_ida_db_file(target)
        if candidate.exists():
            return candidate.resolve()
        raise SystemExit(
            "已识别为 IDA 数据库文件，但未找到对应的对齐 DB：\n"
            f"  input: {target}\n"
            f"  expected_db: {candidate}\n"
            "请先运行语义对齐流水线生成 .db，或用 --db 显式指定。"
        )

    candidate = _derive_db_from_sample_file(target)
    if candidate.exists():
        return candidate.resolve()

    raise SystemExit(
        "未找到可用的对齐 DB：\n"
        f"  input: {target}\n"
        f"  expected_db: {candidate}\n"
        "支持输入 exe/dll/sys/bin/idb/i64/db；也可以直接传 --db。"
    )


def display_name(graph: UnifiedGraph, entry_va: int) -> str:
    node = graph.nodes.get(int(entry_va))
    if not node:
        return f"sub_{int(entry_va):08X}"
    if node.names:
        return next(iter(sorted(node.names)))
    return f"sub_{int(entry_va):08X}"


def get_any_function_id_for_va(graph: UnifiedGraph, entry_va: int) -> Optional[int]:
    node = graph.nodes.get(int(entry_va))
    if not node or not node.function_ids:
        return None

    ida_fids = [fid for fid in node.function_ids if graph.func_tool.get(int(fid), "").lower() == "ida"]
    if ida_fids:
        return int(ida_fids[0])
    return int(next(iter(node.function_ids)))


def resolve_entry_points(graph: UnifiedGraph, entries: Sequence[str], auto_entry_limit: int) -> List[int]:
    resolved: Set[int] = set()

    for raw in entries:
        token = str(raw or "").strip()
        if not token:
            continue

        matched = False
        try:
            va = parse_va(token)
            if va in graph.nodes:
                resolved.add(int(va))
                matched = True
        except Exception:
            matched = False

        if matched:
            continue

        low = token.lower()
        exact_hits: List[int] = []
        fuzzy_hits: List[int] = []
        for va, node in graph.nodes.items():
            if not node.names:
                continue
            names_low = [str(name).lower() for name in node.names]
            if any(n == low for n in names_low):
                exact_hits.append(int(va))
                continue
            if any(low in n for n in names_low):
                fuzzy_hits.append(int(va))

        if exact_hits:
            for va in exact_hits:
                resolved.add(int(va))
            matched = True
        elif fuzzy_hits:
            for va in fuzzy_hits:
                resolved.add(int(va))
            matched = True
            if len(fuzzy_hits) > 10:
                print(
                    f"[DeepDFS] 提示: entry={token!r} 触发了 {len(fuzzy_hits)} 个模糊匹配，"
                    "如果想更精准建议传入函数地址（如 0x401000）。"
                )

        if not matched:
            print(f"[DeepDFS] 警告: entry={token!r} 未匹配到函数，已忽略。")

    if resolved:
        return sorted(resolved)
    if entries:
        return []

    by_name_hint: List[int] = []
    for va, node in graph.nodes.items():
        if node.names and any(ENTRY_NAME_HINT_RE.search(str(n or "")) for n in node.names):
            by_name_hint.append(int(va))
    if by_name_hint:
        by_name_hint.sort(
            key=lambda va: (len(graph.nodes[int(va)].internal_callee_vas), -int(va)),
            reverse=True,
        )
        return by_name_hint[: max(1, int(auto_entry_limit or 1))]

    roots: List[int] = [int(va) for va, node in graph.nodes.items() if not node.caller_vas and node.internal_callee_vas]
    if not roots:
        roots = [int(va) for va, node in graph.nodes.items() if node.internal_callee_vas]
    roots.sort(
        key=lambda va: (len(graph.nodes[int(va)].internal_callee_vas), -int(va)),
        reverse=True,
    )
    return roots[: max(1, int(auto_entry_limit or 1))]


def _load_pseudocode_for_fid(conn: sqlite3.Connection, fid: int) -> str:
    cur = conn.cursor()
    cur.execute(
        """
        SELECT COALESCE(prototype, ''), COALESCE(body, '')
        FROM pseudo_functions
        WHERE function_id = ?
        ORDER BY LENGTH(COALESCE(body, '')) DESC, id ASC
        LIMIT 1;
        """,
        (int(fid),),
    )
    row = cur.fetchone()
    if not row:
        return ""
    return ((row[0] or "") + "\n" + (row[1] or "")).strip()


def get_pseudocode_by_va(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entry_va: int,
    cache: Dict[int, str],
) -> str:
    va = int(entry_va)
    if va in cache:
        return str(cache[va] or "")

    fid = get_any_function_id_for_va(graph, va)
    if fid is None:
        cache[va] = ""
        return ""

    code = _load_pseudocode_for_fid(conn, fid)
    cache[va] = code
    return code


def _normalize_text_line(line: str) -> str:
    return re.sub(r"\s+", " ", str(line or "").strip())


def _keyword_categories(text: str) -> List[str]:
    low = str(text or "").lower()
    hits: List[str] = []
    for category, kws in ENV_KEYWORDS.items():
        if any(k in low for k in kws):
            hits.append(str(category))
    return sorted(set(hits))


def _find_call_sites(lines: Sequence[str], callee_names: Sequence[str], callee_va: int, max_call_sites: int) -> List[int]:
    indices: List[int] = []

    patterns: List[re.Pattern[str]] = []
    for name in callee_names:
        n = str(name or "").strip()
        if not n:
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", n):
            patterns.append(re.compile(rf"\b{re.escape(n)}\b"))
        else:
            patterns.append(re.compile(re.escape(n)))

    va_hex = f"{int(callee_va):X}".lower()
    fallback_patterns = (f"0x{va_hex}", f"sub_{va_hex}", f"loc_{va_hex}", f"fun_{va_hex}")

    for idx, raw in enumerate(lines):
        line = str(raw or "")
        matched = any(p.search(line) for p in patterns) if patterns else False
        if not matched:
            low = line.lower()
            matched = any(fp in low for fp in fallback_patterns)
        if matched:
            indices.append(int(idx))
            if len(indices) >= int(max_call_sites):
                break
    return indices


def _extract_guard_lines(lines: Sequence[str], call_idx: int, cond_window: int, max_guards: int) -> List[str]:
    guards: List[str] = []
    seen: Set[str] = set()
    start = max(0, int(call_idx) - max(1, int(cond_window)))
    for idx in range(int(call_idx) - 1, start - 1, -1):
        line = _normalize_text_line(lines[idx])
        if not line or line.startswith("//"):
            continue
        if CONTROL_LINE_RE.search(line) or COMPARE_RE.search(line):
            if line not in seen:
                seen.add(line)
                guards.append(line)
        if len(guards) >= int(max_guards):
            break
    return guards


def _analyze_edge_condition(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    caller_va: int,
    callee_va: int,
    pseudo_cache: Dict[int, str],
    max_call_sites: int,
    cond_window: int,
    max_guards_per_site: int,
) -> Dict[str, Any]:
    caller = int(caller_va)
    callee = int(callee_va)
    code = get_pseudocode_by_va(conn, graph, caller, pseudo_cache)
    if not code:
        return {
            "caller_va": fmt_va(caller),
            "caller_name": display_name(graph, caller),
            "callee_va": fmt_va(callee),
            "callee_name": display_name(graph, callee),
            "status": "no_pseudocode",
            "call_sites": [],
            "aggregated_env_signals": [],
            "gating_strength": 0,
        }

    lines = code.splitlines()
    callee_node = graph.nodes.get(callee)
    callee_names: List[str] = list(sorted(callee_node.names)) if callee_node and callee_node.names else []
    if not callee_names:
        callee_names = [f"sub_{callee:08X}"]

    call_indices = _find_call_sites(
        lines=lines,
        callee_names=callee_names,
        callee_va=callee,
        max_call_sites=max_call_sites,
    )
    if not call_indices:
        return {
            "caller_va": fmt_va(caller),
            "caller_name": display_name(graph, caller),
            "callee_va": fmt_va(callee),
            "callee_name": display_name(graph, callee),
            "status": "callsite_not_found",
            "call_sites": [],
            "aggregated_env_signals": [],
            "gating_strength": 0,
        }

    site_items: List[Dict[str, Any]] = []
    all_env_signals: Set[str] = set()
    total_guards = 0
    for idx in call_indices:
        call_line = _normalize_text_line(lines[idx])
        g_lines = _extract_guard_lines(lines=lines, call_idx=idx, cond_window=cond_window, max_guards=max_guards_per_site)

        scan_s = max(0, idx - max(1, int(cond_window)))
        scan_e = min(len(lines), idx + 2)
        env_hits = _keyword_categories("\n".join(lines[scan_s:scan_e]))
        all_env_signals.update(env_hits)
        total_guards += len(g_lines)
        site_items.append(
            {
                "line_number": int(idx) + 1,
                "call_line": call_line,
                "guards": g_lines,
                "env_signals": env_hits,
            }
        )

    return {
        "caller_va": fmt_va(caller),
        "caller_name": display_name(graph, caller),
        "callee_va": fmt_va(callee),
        "callee_name": display_name(graph, callee),
        "status": "ok",
        "call_sites": site_items,
        "aggregated_env_signals": sorted(all_env_signals),
        "gating_strength": int(total_guards + len(all_env_signals)),
    }


def _estimate_downstream_depth(graph: UnifiedGraph, start_va: int, memo: Dict[int, int]) -> int:
    start = int(start_va)
    if start in memo:
        return int(memo[start])

    visiting: Set[int] = set()
    stack: List[Tuple[int, int]] = [(start, 0)]
    while stack:
        va, state = stack.pop()
        va = int(va)
        if state == 1:
            node = graph.nodes.get(va)
            if not node:
                memo[va] = 0
            else:
                best = 0
                for callee in node.internal_callee_vas:
                    c = int(callee)
                    if c not in graph.nodes:
                        continue
                    child_depth = int(memo.get(c, 0))
                    if child_depth + 1 > best:
                        best = child_depth + 1
                memo[va] = int(best)
            visiting.discard(va)
            continue

        if va in memo:
            continue
        if va in visiting:
            memo[va] = 0
            continue

        visiting.add(va)
        stack.append((va, 1))
        node = graph.nodes.get(va)
        if not node:
            memo[va] = 0
            visiting.discard(va)
            continue
        for callee in node.internal_callee_vas:
            c = int(callee)
            if c not in graph.nodes or c in visiting:
                continue
            if c not in memo:
                stack.append((c, 0))
    return int(memo.get(start, 0))


def estimate_global_deepest_depth(
    graph: UnifiedGraph,
    *,
    only_entry_vas: Optional[Sequence[int]] = None,
) -> int:
    """Estimate deepest reachable call depth in the graph.

    Depth definition:
    - node with no callee has depth 0
    - one hop path A->B has depth 1

    If `only_entry_vas` is provided, compute max depth among those starts;
    otherwise compute max depth across all nodes (global).
    """

    memo: Dict[int, int] = {}
    deepest = 0

    if only_entry_vas:
        starts = [int(va) for va in only_entry_vas if int(va) in graph.nodes]
    else:
        starts = [int(va) for va in graph.nodes.keys()]

    for va in starts:
        d = int(_estimate_downstream_depth(graph, int(va), memo))
        if d > deepest:
            deepest = d

    return int(deepest)


def _ordered_callees(graph: UnifiedGraph, entry_va: int, depth_memo: Dict[int, int], max_branch: int) -> List[int]:
    node = graph.nodes.get(int(entry_va))
    if not node:
        return []

    callees = [int(c) for c in node.internal_callee_vas if int(c) in graph.nodes]
    for c in callees:
        if c not in depth_memo:
            _estimate_downstream_depth(graph, c, depth_memo)

    callees.sort(
        key=lambda c: (
            int(depth_memo.get(c, 0)),
            len(graph.nodes.get(c).internal_callee_vas) if graph.nodes.get(c) else 0,
            -int(c),
        ),
        reverse=True,
    )
    if int(max_branch) > 0:
        return callees[: int(max_branch)]
    return callees


def _path_summary(edges: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    env_signals: Set[str] = set()
    guard_lines: List[str] = []
    total_strength = 0

    for edge in edges:
        total_strength += int(edge.get("gating_strength", 0) or 0)
        for cat in edge.get("aggregated_env_signals", []) or []:
            env_signals.add(str(cat))
        for site in edge.get("call_sites", []) or []:
            for g in site.get("guards", []) or []:
                g_text = str(g or "").strip()
                if g_text:
                    guard_lines.append(g_text)
                if len(guard_lines) >= 12:
                    break
            if len(guard_lines) >= 12:
                break
        if len(guard_lines) >= 12:
            break

    return {
        "aggregated_env_signals": sorted(env_signals),
        "sample_guards": guard_lines,
        "path_gating_strength": int(total_strength),
    }


def run_deep_path_analysis(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entries: Sequence[int],
    max_depth: int,
    max_paths: int,
    max_branch: int,
    max_call_sites: int,
    cond_window: int,
    max_guards_per_site: int,
) -> Dict[str, Any]:
    pseudo_cache: Dict[int, str] = {}
    edge_cache: Dict[Tuple[int, int], Dict[str, Any]] = {}
    depth_memo: Dict[int, int] = {}

    all_paths: List[Dict[str, Any]] = []
    total_cycle_cuts = 0

    for entry in entries:
        if len(all_paths) >= int(max_paths):
            break
        entry_va = int(entry)
        if entry_va not in graph.nodes:
            continue

        stack: List[Tuple[int, List[int], Set[int], List[Dict[str, Any]]]] = [(entry_va, [entry_va], {entry_va}, [])]
        while stack and len(all_paths) < int(max_paths):
            current_va, path_vas, path_set, edge_conditions = stack.pop()
            depth = len(path_vas) - 1
            node = graph.nodes.get(int(current_va))
            if not node:
                continue

            raw_callees = [int(c) for c in node.internal_callee_vas if int(c) in graph.nodes]
            ordered = _ordered_callees(graph=graph, entry_va=int(current_va), depth_memo=depth_memo, max_branch=max_branch)
            candidate = [c for c in ordered if c not in path_set]

            leaf_reason = ""
            if depth >= int(max_depth):
                leaf_reason = "max_depth"
            elif not raw_callees:
                leaf_reason = "no_callee"
            elif not candidate:
                leaf_reason = "cycle_cut"
                total_cycle_cuts += 1

            if leaf_reason:
                summary = _path_summary(edge_conditions)
                all_paths.append(
                    {
                        "entry_va": fmt_va(entry_va),
                        "entry_name": display_name(graph, entry_va),
                        "depth": int(depth),
                        "leaf_reason": leaf_reason,
                        "path_vas": [fmt_va(va) for va in path_vas],
                        "path_names": [display_name(graph, va) for va in path_vas],
                        "edge_conditions": edge_conditions,
                        "aggregated_env_signals": summary["aggregated_env_signals"],
                        "sample_guards": summary["sample_guards"],
                        "path_gating_strength": int(summary["path_gating_strength"]),
                    }
                )
                continue

            for callee in reversed(candidate):
                key = (int(current_va), int(callee))
                edge_detail = edge_cache.get(key)
                if edge_detail is None:
                    edge_detail = _analyze_edge_condition(
                        conn=conn,
                        graph=graph,
                        caller_va=int(current_va),
                        callee_va=int(callee),
                        pseudo_cache=pseudo_cache,
                        max_call_sites=max_call_sites,
                        cond_window=cond_window,
                        max_guards_per_site=max_guards_per_site,
                    )
                    edge_cache[key] = edge_detail

                stack.append((int(callee), [*path_vas, int(callee)], {*path_set, int(callee)}, [*edge_conditions, edge_detail]))

    all_paths.sort(key=lambda p: (int(p.get("depth", 0)), int(p.get("path_gating_strength", 0))), reverse=True)
    return {
        "entries": [{"entry_va": fmt_va(e), "entry_name": display_name(graph, e)} for e in entries if int(e) in graph.nodes],
        "stats": {
            "total_paths": len(all_paths),
            "total_cycle_cuts": int(total_cycle_cuts),
            "edge_condition_cache_size": len(edge_cache),
        },
        "paths": all_paths,
    }
