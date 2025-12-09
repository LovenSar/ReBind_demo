#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phase3_global_vars.py

Phase 3: Global Variable Analysis Module
Extracted from knowledge_propagation.py

This module handles the third phase of semantic alignment:
- Building global variable reference graphs
- Computing priority scores for global variables
- Analyzing and renaming global variables using LLM
- Synchronizing changes with IDA Pro
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from tqdm import tqdm

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    requests = None


logger = logging.getLogger(__name__)


# Constants
DEFAULT_API_KEY_ENV = "OPENAI_API_KEY"
EMPTY_RESPONSE_RETRY_TIMEOUT = 90.0


# =========================
# Data Structures
# =========================


class GlobalVarNode:
    """Phase 3: Global variable node (aggregates multi-view symbols and references by address_va)."""

    def __init__(self, address_va: int):
        self.address_va = address_va
        self.names: Set[str] = set()
        self.readers: Set[int] = set()  # entry_va set
        self.writers: Set[int] = set()  # entry_va set


class UnifiedGraph:
    """Cross-view unified dependency graph (aggregates all views by binary_id)."""

    def __init__(
        self,
        binary_id: int,
        nodes: Dict[int, Any],
        tool_map: Dict[int, str],
        func_tool: Dict[int, str],
    ):
        self.binary_id = binary_id
        self.nodes = nodes  # entry_va -> UnifiedFunctionNode
        self.tool_map = tool_map  # tool_id -> tool_name
        self.func_tool = func_tool  # function_id -> tool_name


class LLMSettings:
    """LLM parameters and OpenAI API settings."""

    def __init__(
        self,
        model: str,
        temperature: float,
        max_tokens: int,
        api_settings: Dict[str, Any],
        chat_completion_kwargs: Dict[str, Any],
    ):
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.api_settings = api_settings
        self.chat_completion_kwargs = chat_completion_kwargs


# =========================
# Database Schema
# =========================


def ensure_global_vars_schema(conn: sqlite3.Connection) -> None:
    """Ensure the global_vars table exists for recording global variable analysis results."""
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


# =========================
# Helper Functions
# =========================


def load_analysis_info(conn: sqlite3.Connection) -> Dict[int, dict]:
    """
    Read all function analysis_status, return dict[function_id] -> {state, score, signature, summary}.
    """
    cur = conn.cursor()
    cur.execute(
        """
        SELECT function_id, analysis_state, confidence_score,
               summary_signature, semantic_summary
        FROM analysis_status;
        """
    )
    info: Dict[int, dict] = {}
    for fid, state, score, sig, summary in cur.fetchall():
        info[fid] = {
            "analysis_state": state or "PENDING",
            "confidence_score": int(score or 0),
            "summary_signature": sig,
            "semantic_summary": summary,
        }
    return info


def _get_any_function_id_for_va(graph: UnifiedGraph, entry_va: int) -> Optional[int]:
    """Select any function_id from the unified graph node, preferring IDA view."""
    node = graph.nodes.get(entry_va)
    if not node:
        return None
    ida_fids = [fid for fid in node.function_ids if graph.func_tool.get(fid, "").lower() == "ida"]
    if ida_fids:
        return ida_fids[0]
    return next(iter(node.function_ids)) if node.function_ids else None


def wait_for_ida_server(ida_url: str) -> None:
    """
    Check connection with idat_server.
    - If available: return immediately;
    - If disconnected: enter loop, automatically retry every 30 seconds;
      During waiting, if user presses Enter, immediately trigger a retry.
    """
    import sys
    import threading

    if requests is None:
        # Cannot actively probe when requests is not installed, return directly
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
                f"[IDA-Sync] Cannot connect to IDA server {ida_url}: {exc}."
                " Will auto-retry in 30 seconds, press Enter to retry immediately, Ctrl+C to abort."
            )
            print(msg)
            logger.warning("%s", msg)

            # Wait 30 seconds or until user presses Enter
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
            # After exiting wait, return to top of while loop to try ping again


# =========================
# Global Variable Graph Construction
# =========================


def build_global_var_graph(
    conn: sqlite3.Connection,
    binary_id: int,
    graph: UnifiedGraph,
) -> Dict[int, GlobalVarNode]:
    """
    Build global variable -> read/write function reference graph,
    considering only views associated with the specified binary_id.
    """
    cur = conn.cursor()

    cur.execute(
        "SELECT id FROM binary_views WHERE binary_id = ?;",
        (binary_id,),
    )
    view_rows = cur.fetchall()
    if not view_rows:
        return {}
    view_ids = [row[0] for row in view_rows]
    placeholders = ",".join("?" for _ in view_ids)

    # 1) Aggregate all global data symbols across views by address_va
    #    Add multiple layers of filtering to avoid treating code entry / segment start /
    #    import functions as "global variables":
    #      - If address is in unified function graph's entry_va set, treat as code entry, skip;
    #      - If symbol name is a typical segment name (.text/.data/.ctors etc.), skip;
    #      - If kind is explicitly marked as function / import / thunk, skip.
    globals_by_addr: Dict[int, GlobalVarNode] = {}
    code_entry_addrs: Set[int] = set(graph.nodes.keys())
    segment_name_blacklist: Set[str] = {
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
    }
    cur.execute(
        f"""
        SELECT view_id, address_va, name, kind, COALESCE(is_global, 0)
        FROM symbols
        WHERE view_id IN ({placeholders}) AND address_va IS NOT NULL;
        """,
        view_ids,
    )
    for view_id, addr_va, name, kind, is_global in cur.fetchall():
        if addr_va is None:
            continue
        addr = int(addr_va)
        # A. If this address is already an entry address of a unified function, treat as code entry, skip
        if addr in code_entry_addrs:
            continue

        # B. Filter typical segment name symbols (segment start labels, not actual variables)
        name_str = (name or "").strip()
        if name_str and name_str.strip().lower() in segment_name_blacklist:
            continue

        k = (kind or "").strip().lower()
        # C. Exclude explicit function / import / thunk symbols
        if any(key in k for key in ("func", "code", "import", "thunk")):
            continue

        # D. Only care about global data objects
        if int(is_global or 0) != 1 and k not in ("data", "object", "obj"):
            continue
        node = globals_by_addr.get(addr)
        if node is None:
            node = GlobalVarNode(address_va=addr)
            globals_by_addr[addr] = node
        if name:
            node.names.add(str(name))

    if not globals_by_addr:
        return {}

    # 2) Function mapping: view_id,address_va -> function_id; function_id -> entry_va
    addr_to_func: Dict[Tuple[int, int], int] = {}
    cur.execute(
        f"""
        SELECT view_id, function_id, address_va
        FROM instructions
        WHERE view_id IN ({placeholders});
        """,
        view_ids,
    )
    for view_id, fid, addr_va in cur.fetchall():
        if addr_va is None:
            continue
        addr_to_func[(int(view_id), int(addr_va))] = int(fid)

    func_to_entry: Dict[int, int] = {}
    cur.execute(
        f"""
        SELECT id, entry_va
        FROM functions
        WHERE view_id IN ({placeholders});
        """,
        view_ids,
    )
    for fid, entry_va in cur.fetchall():
        func_to_entry[int(fid)] = int(entry_va)

    # 3) Traverse xrefs, find read/write references pointing to global variable addresses
    cur.execute(
        f"""
        SELECT view_id, src_va, dst_va, ref_type_raw
        FROM xrefs
        WHERE view_id IN ({placeholders}) AND dst_va IS NOT NULL;
        """,
        view_ids,
    )
    for view_id, src_va, dst_va, ref_type_raw in cur.fetchall():
        if dst_va is None:
            continue
        addr = int(dst_va)
        node = globals_by_addr.get(addr)
        if node is None:
            continue

        func_id = addr_to_func.get((int(view_id), int(src_va)))
        if func_id is None:
            continue
        entry_va = func_to_entry.get(func_id)
        if entry_va is None or entry_va not in graph.nodes:
            continue

        access_kind = (ref_type_raw or "").strip().upper()
        if access_kind in ("WRITE", "READ_WRITE"):
            node.writers.add(entry_va)
        else:
            node.readers.add(entry_va)

    return globals_by_addr


# =========================
# Score Computation
# =========================


def compute_global_var_scores(
    graph: UnifiedGraph,
    globals_by_addr: Dict[int, GlobalVarNode],
    analysis_info: Dict[int, dict],
) -> Dict[int, int]:
    """
    Compute priority score for each global variable:
      - The more high-confidence functions accessing it, the higher the score;
      - Write access has higher weight than read access.
    """
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
            # Select the "most reliable" function_id for this physical function as representative
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

        # Slightly increase the impact of number of referencing functions
        total_score += 0.1 * len(users)
        if total_score > 0.0:
            scores[addr] = int(total_score * 100)

    return scores


# =========================
# Code Snippet Extraction
# =========================


def _get_global_use_snippet(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entry_va: int,
    var_node: GlobalVarNode,
    max_snippets: int = 2,
) -> str:
    """Extract code snippets from function pseudocode that access the specified global variable."""
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
    # Variable's existing names
    for nm in var_node.names:
        if nm:
            patterns.append(re.escape(nm))
    # Address form
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


# =========================
# Prompt Construction
# =========================


def build_global_var_prompt(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    var_node: GlobalVarNode,
    analysis_info: Dict[int, dict],
) -> str:
    """
    Construct Phase 3 global variable renaming / type inference Prompt.
    Context: several high-confidence accessor functions + access code snippets.
    """
    addr = var_node.address_va
    current_names = sorted(var_node.names) or [f"byte_{addr:08X}"]
    display_name = current_names[0]

    # Select representative accessors: prioritize locked / high-confidence functions
    access_funcs: List[Tuple[float, int, str, str]] = []  # (score, entry_va, name, snippet)

    all_users = list(var_node.writers | var_node.readers)
    for entry_va in all_users:
        fn = graph.nodes.get(entry_va)
        if not fn:
            continue
        # Function name
        fn_name = next(iter(sorted(fn.names)), f"sub_{entry_va:08X}") if fn.names else f"sub_{entry_va:08X}"

        # Get representative function_id's analysis info
        best_info = None
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
                best_info = info

        if best_conf <= 0.0:
            continue

        snippet = _get_global_use_snippet(conn, graph, entry_va, var_node)
        if not snippet:
            continue

        access_funcs.append((best_conf, entry_va, fn_name, snippet))

    if not access_funcs:
        # No reliable context, only lightweight prompting
        usage_section = "(No reliable function access context found, only lightweight inference based on name and address.)"
    else:
        # Sort by confidence descending, truncate to first few entries
        access_funcs.sort(key=lambda x: x[0], reverse=True)
        lines: List[str] = []
        for conf, entry_va, fn_name, snippet in access_funcs[:6]:
            lines.append(
                f"[Function {fn_name} @ 0x{entry_va:08X}, confidence={conf:.2f}]\n{snippet}"
            )
        usage_section = "\n\n".join(lines)

    prompt = f"""
You are a reverse engineering expert skilled at inferring "global variable semantics" from access patterns.

Current global variable: 0x{addr:08X}
Current name candidates: {", ".join(current_names)}

[Access Context (how functions read/write this variable)]
{usage_section}

[Task]
1. Based on the above access patterns, infer the "semantic name" of this global variable (e.g., g_LoginRetryCount, g_AppConfig).
2. Infer a reasonable C type (e.g., int, bool, HANDLE, struct APP_CONFIG *, etc.).
3. Provide your confidence level and brief reasoning.

Please return strictly in JSON format:
{{
  "name": "g_VarName",
  "type": "int or struct APP_CONFIG *",
  "confidence": 0.0 ~ 1.0,
  "reason": "Brief explanation"
}}
"""
    return prompt.strip()


# =========================
# LLM Communication
# =========================


def require_openai(api_settings: Dict[str, Any]) -> Any:
    """
    Lazy import openai and return a client compatible with openai>=1.0.0;
    If old version SDK detected, fallback to module-level API.
    """
    try:
        import openai  # type: ignore
    except ImportError as exc:  # pragma: no cover - environment dependency
        raise RuntimeError(
            "openai library not installed, please run: pip install openai"
        ) from exc

    api_key_env = api_settings.get("key_env_var") or DEFAULT_API_KEY_ENV
    api_key = os.environ.get(api_key_env)
    if not api_key:
        raise RuntimeError(
            f"Environment variable {api_key_env} not set, cannot call OpenAI LLM."
        )

    # New openai (>=1.0.0): use OpenAI client
    if hasattr(openai, "OpenAI"):
        client_kwargs: Dict[str, Any] = {"api_key": api_key}
        base_url = api_settings.get("base_url")
        if base_url:
            client_kwargs["base_url"] = base_url
        organization = api_settings.get("organization")
        if organization:
            client_kwargs["organization"] = organization
        # Other fields (like proxy) handled by upstream requests, not forced mapping here
        return openai.OpenAI(**client_kwargs)  # type: ignore[attr-defined]

    # Old openai (<1.0.0): maintain backward compatibility
    openai.api_key = api_key  # type: ignore[attr-defined]

    attr_map: Dict[str, str] = {
        "base_url": "api_base",
        "type": "api_type",
        "version": "api_version",
        "organization": "organization",
        "proxy": "proxy",
    }
    for config_key, attr_name in attr_map.items():
        value = api_settings.get(config_key)
        if value:
            setattr(openai, attr_name, value)  # type: ignore[attr-defined]

    return openai


def build_chat_request(prompt: str, llm_settings: LLMSettings) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    """Construct messages and request parameters to send to ChatCompletion."""

    conversation: List[Dict[str, str]] = [
        {
            "role": "system",
            "content": (
                "You are an expert reverse engineer. "
                "You must respond with a single valid JSON object only."
            ),
        },
        {"role": "user", "content": prompt},
    ]

    request_kwargs: Dict[str, Any] = dict(llm_settings.chat_completion_kwargs)
    request_kwargs.update(
        {
            "model": llm_settings.model,
            "temperature": llm_settings.temperature,
            "max_tokens": llm_settings.max_tokens,
            "messages": conversation,
        }
    )

    return conversation, request_kwargs


def call_llm_analyze_function(
    conversation: List[Dict[str, str]],
    request_kwargs: Dict[str, Any],
    api_settings: Dict[str, Any],
    max_attempts: int = 3,
    return_raw_on_error: bool = False,
) -> dict:
    """
    Call OpenAI ChatCompletion to have the model analyze a single function.
    Expects to return a JSON object with fields:
      - signature: C-style function declaration / prototype
      - summary: One-sentence or short semantic description
      - confidence: confidence level from 0.0 ~ 1.0
      - tags: several keywords
      - notes: optional supplementary notes
    """
    client = require_openai(api_settings)

    last_error: Optional[str] = None

    try:
        logger.debug(
            "LLM request payload: %s",
            json.dumps(request_kwargs, ensure_ascii=False, indent=2),
        )
    except Exception:
        logger.debug("LLM request payload (repr): %r", request_kwargs)

    for attempt in range(1, max_attempts + 1):
        text_str = ""
        attempt_start = time.time()
        while True:
            try:
                # Compatible with both old and new openai calling methods
                if hasattr(client, "chat") and hasattr(client.chat, "completions"):
                    # openai>=1.0.0: use client.chat.completions.create
                    logger.debug(
                        "LLM request (attempt %d/%d, new API): model=%s, temp=%s, max_tokens=%s, prompt_chars=%d",
                        attempt,
                        max_attempts,
                        request_kwargs.get("model"),
                        request_kwargs.get("temperature"),
                        request_kwargs.get("max_tokens"),
                        len(
                            "".join(
                                str(m.get("content", ""))
                                for m in request_kwargs.get("messages", [])
                            )
                        ),
                    )
                    resp = client.chat.completions.create(**request_kwargs)  # type: ignore[attr-defined]
                    text = resp.choices[0].message.content or ""  # type: ignore[union-attr]
                elif hasattr(client, "ChatCompletion"):
                    # Old openai: module-level ChatCompletion.create
                    logger.debug(
                        "LLM request (attempt %d/%d, old API): model=%s, temp=%s, max_tokens=%s, prompt_chars=%d",
                        attempt,
                        max_attempts,
                        request_kwargs.get("model"),
                        request_kwargs.get("temperature"),
                        request_kwargs.get("max_tokens"),
                        len(
                            "".join(
                                str(m.get("content", ""))
                                for m in request_kwargs.get("messages", [])
                            )
                        ),
                    )
                    resp = client.ChatCompletion.create(**request_kwargs)  # type: ignore[attr-defined]
                    text = resp["choices"][0]["message"]["content"]  # type: ignore[index]
                else:  # pragma: no cover - extreme case
                    last_error = "Current openai client does not support ChatCompletion interface"
                    break
            except Exception as exc:  # Network / API failure
                last_error = f"LLM call failed({attempt}/{max_attempts}): {exc}"
                logger.warning("%s", last_error)
                break

            text_str = (text or "").strip()
            # If model returns JSON wrapped in Markdown code block, try to strip ``` wrapping
            if text_str.startswith("```"):
                lines = text_str.splitlines()
                if lines and lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].strip() == "```":
                    lines = lines[:-1]
                text_str = "\n".join(lines).strip()

            if text_str:
                break

            if time.time() - attempt_start >= EMPTY_RESPONSE_RETRY_TIMEOUT:
                last_error = (
                    f"LLM returned empty string multiple times, retried for {EMPTY_RESPONSE_RETRY_TIMEOUT:.0f} seconds without success."
                )
                logger.warning("%s", last_error)
                break

            logger.info(
                "LLM has no response content yet, fast retrying (timeout %.0f seconds)...",
                EMPTY_RESPONSE_RETRY_TIMEOUT,
            )
            continue

        if not text_str:
            continue

        logger.debug(
            "LLM raw response (attempt %d/%d): %s",
            attempt,
            max_attempts,
            text_str,
        )

        start = text_str.find("{")
        end = text_str.rfind("}")
        if start != -1 and end != -1 and end > start:
            text_str_json = text_str[start : end + 1]
        else:
            text_str_json = text_str

        try:
            data = json.loads(text_str_json)
        except json.JSONDecodeError:
            last_error = (
                f"LLM returned content cannot be parsed as JSON({attempt}/{max_attempts}): {text_str_json!r}"
            )
            # Return raw text to caller for debugging if needed
            if return_raw_on_error and attempt == max_attempts:
                logger.warning(
                    "%s\nFull LLM response: %s",
                    last_error,
                    text_str,
                )
                return {"_raw_error": last_error, "_raw_text": text_str}
            logger.warning(
                "%s\nFull LLM response: %s",
                last_error,
                text_str,
            )
            continue

        if not isinstance(data, dict):
            last_error = (
                f"LLM returned JSON is not an object({attempt}/{max_attempts}): {data!r}"
            )
            logger.warning("%s", last_error)
            continue

        return data

    # After multiple attempts still failed, return empty dict, let upper layer decide how to handle
    if last_error:
        logger.error(
            "After %d attempts still did not get valid JSON: %s", max_attempts, last_error
        )
    return {}


# =========================
# IDA Synchronization
# =========================


def _sync_global_with_ida_and_update_db(
    conn: sqlite3.Connection,
    address_va: int,
    new_name: str,
    type_str: Optional[str],
    ida_url: str,
) -> None:
    """
    Synchronize global variable rename/type info to idat_server and update symbols/global_vars in alignment database.
    """
    if requests is None or not new_name:
        logger.info(
            "[IDA-Sync] requests not installed or new_name is empty, skip global variable sync. addr=0x%08X",
            address_va,
        )
        return

    # Before each IDA sync, confirm idat_server is online
    if ida_url:
        wait_for_ida_server(ida_url)

    payload = {
        "action": "rename_global",
        "ea": address_va,
        "name": new_name,
        "type": type_str or "",
    }

    logger.info(
        "[IDA-Sync] Attempting to sync global variable 0x%08X -> %s to IDA (%s)",
        address_va,
        new_name,
        ida_url,
    )
    logger.debug("[IDA-Sync] rename_global payload: %s", payload)

    try:
        resp = requests.post(ida_url, json=payload, timeout=10.0)
    except Exception as exc:
        logger.error("[IDA-Sync] Global variable sync failed: %s", exc)
        return

    if resp.status_code != 200:
        logger.error(
            "[IDA-Sync] rename_global HTTP %s: %s",
            resp.status_code,
            resp.text[:200],
        )
        return

    try:
        data = resp.json()
    except Exception:
        data = {}
    # Confirm if IDA side successfully processed
    if (data or {}).get("status") != "ok":
        logger.error(
            "[IDA-Sync] rename_global IDA returned error: %s",
            data or resp.text[:200],
        )
        return

    ida_new_name = data.get("new_name") or new_name
    if data.get("new_name") and data["new_name"] != new_name:
        logger.warning(
            "[IDA-Sync] rename_global name mismatch: requested=%s, applied=%s (addr=0x%08X)",
            new_name,
            data["new_name"],
            address_va,
        )
    applied_type = data.get("applied_type")
    logger.info(
        "[IDA-Sync] rename_global success: addr=0x%08X, name=%s, applied_type=%s",
        address_va,
        ida_new_name,
        applied_type or type_str,
    )

    # Synchronize name in symbols table of alignment database
    cur = conn.cursor()
    cur.execute(
        "UPDATE symbols SET name = ? WHERE address_va = ?;",
        (ida_new_name, address_va),
    )
    conn.commit()


# =========================
# Global Variable Analysis
# =========================


def analyze_one_global_var(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    var_node: GlobalVarNode,
    analysis_info: Dict[int, dict],
    llm_settings: LLMSettings,
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
) -> float:
    """
    Execute Phase 3 analysis for a single global variable, return posterior confidence.
    """
    addr = var_node.address_va

    if ida_sync and ida_url:
        wait_for_ida_server(ida_url or "http://127.0.0.1:12345")
    prompt = build_global_var_prompt(conn, graph, var_node, analysis_info)
    conversation, request_kwargs = build_chat_request(prompt, llm_settings)

    print("=" * 80)
    print(f"[GLOBAL] address=0x{addr:08X}, names={sorted(var_node.names)}")

    if dry_run:
        print("\n[GLOBAL DRY-RUN] Request parameters:")
        print(json.dumps(request_kwargs, ensure_ascii=False, indent=2))
        print("\n[GLOBAL DRY-RUN] Prompt preview:")
        print(prompt[:2000])
        return 1.0

    result = call_llm_analyze_function(
        conversation=conversation,
        request_kwargs=request_kwargs,
        api_settings=llm_settings.api_settings,
    )

    if not result:
        print(
            "[GLOBAL] This global variable LLM returned illegal content or failed after multiple attempts, keeping PENDING state for later retry."
        )
        return 0.0

    name = str(result.get("name", "")).strip()
    type_str = str(result.get("type", "")).strip() or None
    reason = str(result.get("reason", "")).strip()
    conf_val = result.get("confidence")
    try:
        confidence = float(conf_val) if conf_val is not None else 0.8
    except (TypeError, ValueError):
        confidence = 0.8

    print("\n[GLOBAL RESULT]")
    print("name      :", name)
    print("type      :", type_str)
    print("confidence:", confidence)
    if reason:
        print("reason    :", reason)

    # Validity check
    if not name or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name) or len(name) > 255:
        print("[GLOBAL] Proposed variable name does not conform to identifier specification, skip renaming.")
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

    # Synchronize symbols table name
    cur.execute(
        "UPDATE symbols SET name = ? WHERE address_va = ?;",
        (final_name, addr),
    )
    conn.commit()

    if apply_rename and ida_sync:
        _sync_global_with_ida_and_update_db(
            conn=conn,
            address_va=addr,
            new_name=final_name,
            type_str=type_str,
            ida_url=ida_url,
        )

    return max(0.0, min(1.0, confidence))


# =========================
# Phase 3 Main Entry
# =========================


def run_global_var_phase(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    llm_settings: LLMSettings,
    max_globals: Optional[int],
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
) -> None:
    """
    Phase 3: Global variable renaming and type inference.
    """
    if ida_sync and ida_url:
        wait_for_ida_server(ida_url)
    globals_by_addr = build_global_var_graph(conn, graph.binary_id, graph)
    if not globals_by_addr:
        print("[GLOBAL] No analyzable global variables found, skip Phase 3.")
        return

    analysis_info = load_analysis_info(conn)
    scores = compute_global_var_scores(graph, globals_by_addr, analysis_info)
    if not scores:
        print("[GLOBAL] No high-priority global variables, skip Phase 3.")
        return

    # Select by score descending
    ordered_addrs = sorted(scores.keys(), key=lambda a: scores[a], reverse=True)

    # Resume from checkpoint: filter out already ANALYZED global variables
    ensure_global_vars_schema(conn)
    cur = conn.cursor()
    cur.execute(
        "SELECT address_va FROM global_vars WHERE analysis_state = 'ANALYZED';"
    )
    analyzed_addrs = {row[0] for row in cur.fetchall()}

    pending_addrs = [addr for addr in ordered_addrs if addr not in analyzed_addrs]
    if not pending_addrs:
        print("[GLOBAL] All high-priority global variables already ANALYZED, skip Phase 3.")
        return

    target_count = len(pending_addrs)
    if max_globals is not None and max_globals > 0:
        target_count = min(target_count, max_globals)

    print(
        f"[GLOBAL] Total found {len(ordered_addrs)} high-priority global variables, "
        f"of which {len(pending_addrs)} not yet analyzed, planning to process {target_count} this time."
    )

    pbar = tqdm(total=target_count, desc="Phase 3: Globals", unit="var")
    processed = 0

    for addr in pending_addrs:
        if processed >= target_count:
            break
        node = globals_by_addr[addr]
        score = scores.get(addr, 0)
        pbar.set_description(
            f"Phase 3: 0x{addr:08X} (score={score})"
        )
        print(
            f"\n[GLOBAL] Selecting global variable 0x{addr:08X} (score={score}, names={sorted(node.names)})"
        )
        analyze_one_global_var(
            conn=conn,
            graph=graph,
            var_node=node,
            analysis_info=analysis_info,
            llm_settings=llm_settings,
            ida_sync=ida_sync,
            ida_url=ida_url,
            dry_run=dry_run,
        )
        processed += 1
        pbar.update(1)

    pbar.close()
    print(f"[GLOBAL] Phase 3 processed total global variables: {processed}")
