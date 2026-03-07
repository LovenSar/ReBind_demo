"""Phase 3: Global variable renaming and type inference.

Extracted from knowledge_propagation.py.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

from tqdm import tqdm

from dynamic_batching import yield_dynamic_batch
from kp.kp_ida import wait_for_ida_server
from kp.kp_llm import build_chat_request, call_llm_analyze_function, estimate_token_usage
from kp.kp_schema import load_analysis_info
from kp.kp_types import GlobalVarNode, UnifiedGraph
from kp.kp_ida_utils import force_ida_save_database

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None


logger = logging.getLogger(__name__)
_IDA_SAVE_TIMEOUT_S = 15.0


def ensure_global_vars_schema(conn: sqlite3.Connection) -> None:
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


def _get_any_function_id_for_va(graph: UnifiedGraph, entry_va: int) -> Optional[int]:
    node = graph.nodes.get(entry_va)
    if not node:
        return None
    ida_fids = [fid for fid in node.function_ids if graph.func_tool.get(fid, "").lower() == "ida"]
    if ida_fids:
        return ida_fids[0]
    return next(iter(node.function_ids)) if node.function_ids else None


def build_global_var_graph(conn: sqlite3.Connection, binary_id: int, graph: UnifiedGraph) -> Dict[int, GlobalVarNode]:
    cur = conn.cursor()

    cur.execute("SELECT id FROM binary_views WHERE binary_id = ?;", (binary_id,))
    view_rows = cur.fetchall()
    if not view_rows:
        return {}
    view_ids = [row[0] for row in view_rows]
    placeholders = ",".join("?" for _ in view_ids)

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

    code_entry_addrs: Set[int] = set(graph.nodes.keys())

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

    default_name_pattern = re.compile(
        r"^(off|dword|byte|qword|unk|word|xmmword|float|double)_[0-9A-Fa-f]+$",
        re.IGNORECASE,
    )

    for dst_va, dst_name in cur.fetchall():
        addr = int(dst_va)
        if addr in code_entry_addrs:
            continue

        name_str = (dst_name or "").strip()
        lower_name = name_str.lower()

        if lower_name in blacklist_names:
            continue

        _ = bool(default_name_pattern.match(name_str))

        candidate_globals.setdefault(addr, set())
        if name_str:
            candidate_globals[addr].add(name_str)

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
        candidate_globals.setdefault(addr, set())
        if name:
            candidate_globals[addr].add(str(name))

    print("[Global] 正在从伪代码文本中挖掘潜在的全局变量引用...")
    cur.execute(
        """
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

    globals_by_addr: Dict[int, GlobalVarNode] = {}
    for addr, names in candidate_globals.items():
        node = GlobalVarNode(address_va=addr)
        node.names = names
        globals_by_addr[addr] = node

    cur.execute(
        f"""
        SELECT x.dst_va, x.ref_type_raw, f.entry_va
        FROM xrefs AS x
        JOIN instructions AS i
          ON i.view_id = x.view_id
         AND i.address_va = x.src_va
        JOIN functions AS f
          ON f.id = i.function_id
        WHERE x.view_id IN ({placeholders})
          AND x.dst_va IS NOT NULL
          AND f.entry_va IS NOT NULL;
        """,
        view_ids,
    )
    for dst_va, ref_type_raw, entry_va_raw in cur.fetchall():
        addr = int(dst_va)
        node = globals_by_addr.get(addr)
        if node is None:
            continue
        entry_va = int(entry_va_raw)

        access_kind = (ref_type_raw or "").strip().upper()
        if "WRITE" in access_kind:
            node.writers.add(entry_va)
        else:
            node.readers.add(entry_va)

    for addr, readers in text_based_readers.items():
        node = globals_by_addr.get(addr)
        if not node:
            continue
        node.readers.update(readers)

    return globals_by_addr


def compute_global_var_scores(graph: UnifiedGraph, globals_by_addr: Dict[int, GlobalVarNode], analysis_info: Dict[int, dict]) -> Dict[int, int]:
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

        total_score += 0.1 * len(users)
        if total_score > 0.0:
            scores[addr] = int(total_score * 100)

    return scores


def _get_global_use_snippet(conn: sqlite3.Connection, graph: UnifiedGraph, entry_va: int, var_node: GlobalVarNode, max_snippets: int = 2) -> str:
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
    for nm in var_node.names:
        if nm:
            patterns.append(re.escape(nm))
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


def _build_global_var_context(conn: sqlite3.Connection, graph: UnifiedGraph, var_node: GlobalVarNode, analysis_info: Dict[int, dict], max_users: int = 6) -> str:
    addr = var_node.address_va
    current_names = sorted(var_node.names) or [f"byte_{addr:08X}"]

    access_funcs: List[Tuple[float, int, str, str]] = []

    all_users = list(var_node.writers | var_node.readers)
    for entry_va in all_users:
        fn = graph.nodes.get(entry_va)
        if not fn:
            continue
        fn_name = next(iter(sorted(fn.names)), f"sub_{entry_va:08X}") if fn.names else f"sub_{entry_va:08X}"

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
            lines.append(f"[Function {fn_name} @ 0x{entry_va:08X}, confidence={conf:.2f}]\n{snippet}")
        usage_section = "\n\n".join(lines)

    return (
        f"当前全局变量：0x{addr:08X}\n"
        f"当前名称候选：{', '.join(current_names)}\n\n"
        f"[访问上下文（函数如何读写该变量）]\n{usage_section}"
    ).strip()


def build_global_var_prompt(conn: sqlite3.Connection, graph: UnifiedGraph, var_node: GlobalVarNode, analysis_info: Dict[int, dict]) -> str:
    addr = var_node.address_va
    current_names = sorted(var_node.names) or [f"byte_{addr:08X}"]

    usage_section = _build_global_var_context(conn, graph, var_node, analysis_info)

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


def build_global_var_batch_prompt(conn: sqlite3.Connection, graph: UnifiedGraph, var_nodes: List[GlobalVarNode], analysis_info: Dict[int, dict]) -> str:
    lines: List[str] = []
    lines.append("你是一名擅长从访问模式推断‘全局变量语义’的逆向工程专家。")
    lines.append("请分析以下多个全局变量，返回一个 JSON 数组，长度必须等于条目数量，顺序完全一致。")
    lines.append('数组中每个对象字段：{"address_va":"0x...","name":"g_VarName","type":"...","confidence":0.0-1.0,"reason":"..."}。')

    for idx, node in enumerate(var_nodes, 1):
        ctx = _build_global_var_context(conn, graph, node, analysis_info)
        lines.append(f"\n[Item {idx}/{len(var_nodes)}] address_va=0x{node.address_va:08X}\n{ctx}")

    return "\n".join(lines)


def _sync_global_with_ida_and_update_db(conn: sqlite3.Connection, address_va: int, new_name: str, type_str: Optional[str], ida_url: str) -> None:
    if requests is None or not new_name:
        logger.info("[IDA-Sync] requests 未安装或 new_name 为空，跳过全局变量同步。 addr=0x%08X", address_va)
        return

    if ida_url:
        wait_for_ida_server(ida_url)

    payload = {"action": "rename_global", "ea": address_va, "name": new_name, "type": type_str or ""}

    try:
        resp = requests.post(ida_url, json=payload, timeout=10.0)
    except Exception as exc:
        logger.error("[IDA-Sync] 全局变量同步失败: %s", exc)
        return

    if resp.status_code != 200:
        logger.error("[IDA-Sync] rename_global HTTP %s: %s", resp.status_code, resp.text[:200])
        return

    try:
        data = resp.json()
    except Exception:
        data = {}

    if (data or {}).get("status") != "ok":
        logger.error("[IDA-Sync] rename_global IDA 返回错误: %s", data or resp.text[:200])
        return

    ida_new_name = data.get("new_name") or new_name

    cur = conn.cursor()
    cur.execute("UPDATE symbols SET name = ? WHERE address_va = ?;", (ida_new_name, address_va))
    conn.commit()


def _apply_global_var_llm_result(conn: sqlite3.Connection, graph: UnifiedGraph, var_node: GlobalVarNode, result: Dict[str, Any], ida_sync: bool, ida_url: str) -> float:
    addr = var_node.address_va

    name = str(result.get("name", "")).strip()
    type_str = str(result.get("type", "")).strip() or None
    reason = str(result.get("reason", "")).strip()
    conf_val = result.get("confidence")
    try:
        confidence = float(conf_val) if conf_val is not None else 0.8
    except (TypeError, ValueError):
        confidence = 0.8

    if not name or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name) or len(name) > 255:
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

    cur.execute("UPDATE symbols SET name = ? WHERE address_va = ?;", (final_name, addr))
    conn.commit()

    if apply_rename and ida_sync:
        _sync_global_with_ida_and_update_db(conn=conn, address_va=addr, new_name=final_name, type_str=type_str, ida_url=ida_url)

    return max(0.0, min(1.0, confidence))


def run_global_var_phase(
    *,
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    llm_settings: Any,
    max_globals: Optional[int],
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
    batch_size: int = 10,
) -> None:
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

    ordered_addrs = sorted(scores.keys(), key=lambda a: scores[a], reverse=True)

    ensure_global_vars_schema(conn)
    cur = conn.cursor()
    cur.execute("SELECT address_va FROM global_vars WHERE analysis_state = 'ANALYZED';")
    analyzed_addrs = {row[0] for row in cur.fetchall()}

    pending_addrs = [addr for addr in ordered_addrs if addr not in analyzed_addrs]
    if not pending_addrs:
        print("[GLOBAL] 所有高优先级全局变量均已 ANALYZED，跳过第三阶段。")
        return

    target_count = len(pending_addrs)
    if max_globals is not None and max_globals > 0:
        target_count = min(target_count, max_globals)

    print(f"[GLOBAL] 总计发现 {len(ordered_addrs)} 个高优先级全局变量，其中 {len(pending_addrs)} 个尚未分析，本次计划处理 {target_count} 个。")

    pbar = tqdm(total=target_count, desc="Phase 3: Globals", unit="var")

    selected_addrs = pending_addrs[:target_count]
    selected_nodes = [globals_by_addr[a] for a in selected_addrs]
    batch_target = max(1, int(batch_size) if batch_size else 1)

    def _builder(nodes: List[GlobalVarNode]) -> str:
        return build_global_var_batch_prompt(conn, graph, nodes, analysis_info)

    processed = 0

    pending_ida_save: Optional[threading.Thread] = None
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
        if pending_ida_save and not pending_ida_save.is_alive():
            pending_ida_save = None

        top_addr = batch.items[0].address_va
        pbar.set_description(f"Phase 3: batch={len(batch.items)} top=0x{top_addr:08X}")

        if dry_run:
            print("=" * 80)
            print(f"[Phase 3 DRY-RUN] batch size={len(batch.items)}")
            print(batch.prompt[:2000])
            processed += len(batch.items)
            pbar.update(len(batch.items))
            continue

        if ida_sync and ida_url and (pending_ida_save is None or not pending_ida_save.is_alive()):
            logger.debug("[GLOBAL] 启动后台保存 IDA 数据库（并行 LLM 请求）")
            pending = threading.Thread(
                target=force_ida_save_database,
                args=(ida_url,),
                kwargs={"timeout": _IDA_SAVE_TIMEOUT_S},
                daemon=True,
            )
            pending.start()
            pending_ida_save = pending

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
            print(f"\n[GLOBAL] 选择全局变量 0x{addr:08X} (score={score}, names={sorted(var_node.names)})")
            if isinstance(res, dict):
                _apply_global_var_llm_result(conn=conn, graph=graph, var_node=var_node, result=res, ida_sync=ida_sync, ida_url=ida_url)
            else:
                print("[GLOBAL] 跳过：返回值不是 JSON 对象。")

        processed += len(batch.items)
        pbar.update(len(batch.items))

    pbar.close()
    if pending_ida_save and pending_ida_save.is_alive():
        pending_ida_save.join(timeout=5.0)
    print(f"[GLOBAL] 第三阶段共处理全局变量数量：{processed}")
