#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
phase4_local_vars.py

Phase 4: Local Variable Renaming Module

This module extracts the Phase 4 local variable renaming functionality from
knowledge_propagation.py. It includes functions for analyzing and renaming
local variables in decompiled code using LLM assistance.

Core Functions:
- run_local_var_phase: Entry point for Phase 4, iterates through high-confidence functions
- analyze_one_function_vars: Analyzes a single function and applies variable renaming
- apply_local_var_renames: Applies rename mappings to pseudocode text
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
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
MAX_LVAR_PASSES = 1

# Regex pattern for detecting generic local variable names (a1/v1/var_10 etc.)
GENERIC_LVAR_PATTERN = re.compile(
    r"\b(?:a\d+|arg\d+|arg_\d+|v\d+|var_[0-9A-Fa-f]+)\b"
)


# =========================
# Data Structures
# =========================


@dataclass
class UnifiedFunctionNode:
    """
    Cross-view unified node: represents the same physical function in binary.
    Aggregates information from multiple views (Ghidra / IDA etc.).
    """

    entry_va: int
    binary_id: int
    function_ids: Set[int]
    names: Set[str]
    instr_count: int = 0
    primary_function_id: Optional[int] = None
    pseudocodes: Dict[str, str] = None
    internal_callee_vas: Set[int] = None
    external_callee_names: Set[str] = None
    string_refs: Set[str] = None
    caller_vas: Set[int] = None

    def __post_init__(self) -> None:
        if self.pseudocodes is None:
            self.pseudocodes = {}
        if self.internal_callee_vas is None:
            self.internal_callee_vas = set()
        if self.external_callee_names is None:
            self.external_callee_names = set()
        if self.string_refs is None:
            self.string_refs = set()
        if self.caller_vas is None:
            self.caller_vas = set()


@dataclass
class UnifiedGraph:
    """Cross-view unified dependency graph (aggregated by binary_id)."""

    binary_id: int
    nodes: Dict[int, UnifiedFunctionNode]
    tool_map: Dict[int, str]
    func_tool: Dict[int, str]


@dataclass
class LLMSettings:
    """LLM parameters and OpenAI API settings."""

    model: str
    temperature: float
    max_tokens: int
    api_settings: Dict[str, Any]
    chat_completion_kwargs: Dict[str, Any]


# =========================
# Helper Functions
# =========================


def wait_for_ida_server(ida_url: str) -> None:
    """
    Check connection to idat_server.
    - If available: return immediately
    - If disconnected: retry every 30 seconds; user can press Enter to retry immediately
    """
    if requests is None:
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
                " Will retry in 30 seconds, press Enter to retry immediately, Ctrl+C to abort."
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
            import sys

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


def ensure_analysis_schema(conn: sqlite3.Connection) -> None:
    """
    Ensure analysis_status table exists for recording LLM analysis results.

    Table schema:
      - analysis_state: 'PENDING' / 'ANALYZED' / 'LOCKED'
      - confidence_score: current heuristic score (can be updated multiple times)
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analysis_status (
            function_id       INTEGER PRIMARY KEY,
            analysis_state    TEXT,
            confidence_score  INTEGER,
            summary_signature TEXT,
            semantic_summary  TEXT,
            FOREIGN KEY(function_id) REFERENCES functions(id)
        );
        """
    )
    # Add lvar_optimized column for Phase 4 checkpoint resume
    try:
        conn.execute(
            "ALTER TABLE analysis_status "
            "ADD COLUMN lvar_optimized INTEGER DEFAULT 0;"
        )
    except sqlite3.OperationalError:
        # Column already exists or schema doesn't support ALTER
        pass
    conn.commit()


def load_analysis_info(conn: sqlite3.Connection) -> Dict[int, dict]:
    """
    Load all function analysis_status, return dict[function_id] -> {state, score, signature, summary}.
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


def _find_generic_lvar_names(code: str) -> Set[str]:
    """Find suspected default local variable names in pseudocode text."""
    if not code:
        return set()
    return {m.group(0) for m in GENERIC_LVAR_PATTERN.finditer(code)}


def require_openai(api_settings: Dict[str, Any]) -> Any:
    """
    Lazy import openai and return a client compatible with openai>=1.0.0;
    fallback to module-level API if old SDK is detected.
    """
    try:
        import openai  # type: ignore
    except ImportError as exc:  # pragma: no cover
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


def call_llm_analyze_function(
    conversation: List[Dict[str, str]],
    request_kwargs: Dict[str, Any],
    api_settings: Dict[str, Any],
    max_attempts: int = 3,
    return_raw_on_error: bool = False,
) -> dict:
    """
    Call OpenAI ChatCompletion to analyze a single function.
    Expected JSON response fields:
      - signature: C-style function declaration/prototype
      - summary: one-sentence or short semantic description
      - confidence: 0.0 ~ 1.0 confidence score
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
                # Support both new and old openai SDK
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
                else:  # pragma: no cover
                    last_error = "Current openai client doesn't support ChatCompletion interface"
                    break
            except Exception as exc:  # Network / API failure
                last_error = f"LLM call failed({attempt}/{max_attempts}): {exc}"
                logger.warning("%s", last_error)
                break

            text_str = (text or "").strip()
            # If model returns JSON wrapped in Markdown code block, strip ```
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
                "LLM has no response content, quickly retrying (timeout %.0f seconds)...",
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
                f"LLM response cannot be parsed as JSON({attempt}/{max_attempts}): {text_str_json!r}"
            )
            # Return raw text for debugging if requested
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

    # After multiple attempts still failed, return empty dict
    if last_error:
        logger.error(
            "Failed to obtain valid JSON after %d attempts: %s", max_attempts, last_error
        )
    return {}


def build_chat_request(
    prompt: str, llm_settings: LLMSettings
) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    """Build messages and request parameters to send to ChatCompletion."""

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


def build_local_var_prompt(
    node: UnifiedFunctionNode,
    code: str,
    signature: str,
    summary: str,
) -> str:
    """
    Build Phase 4 prompt: request LLM to identify and rename local variables.
    """
    display_name = (
        "/".join(sorted(node.names)) if node.names else f"sub_{node.entry_va:08X}"
    )

    prompt = f"""
You are a code refactoring expert. Current task is to optimize decompiled code readability, focusing on **renaming local variables and function parameters**.

Function: {display_name}
Signature: {signature}
Summary: {summary}

[Pseudocode]
{code}

[Task]
1. Analyze the pseudocode logic and identify meaningless default naming:
   - Focus on parameters: a1, a2, a3, arg1, arg2...
   - Focus on local variables: v1, v2, v3, var_C, var_10...
2. Infer their actual meaning from context and assign meaningful variable names (e.g., index, user_id, connection_handle).
3. Please be moderately aggressive:
   - If a1 is clearly a source buffer, rename it to src_buf;
   - If v5 is clearly a loop variable, rename it to i or idx;
   - If v8 receives a function return value and is used for judgment, rename it to ret_val or status.
4. If a variable name already has clear semantics (e.g., file_name, buffer_ptr), do not modify it.
5. If you cannot infer any variable meaning, return an empty JSON.

Return strictly a JSON object in the format of "old_name": "new_name" mappings:
{{
  "a1": "socket_fd",
  "a2": "buffer_ptr",
  "v5": "loop_idx",
  "v12": "bytes_received"
}}
"""
    return prompt.strip()


def apply_local_var_renames(code: str, rename_map: Dict[str, str]) -> str:
    """
    Apply rename_map to pseudocode text using regex.
    Use Word Boundary (\\b) to prevent partial match errors (e.g., v1 in v10).
    """
    if not rename_map:
        return code

    new_code = code
    # Sort by variable name length descending to avoid v11 being matched by v1 first
    sorted_keys = sorted(rename_map.keys(), key=len, reverse=True)

    for old_name in sorted_keys:
        new_name = rename_map[old_name]
        if old_name == new_name:
            continue

        pattern = r"\b" + re.escape(old_name) + r"\b"
        new_code = re.sub(pattern, new_name, new_code)

    return new_code


def _force_ida_save_database(ida_url: str, timeout: float = 15.0) -> bool:
    """Request idat_server to immediately save database (without exiting)."""
    if requests is None:
        return False

    try:
        resp = requests.post(
            ida_url, json={"action": "save_database"}, timeout=timeout
        )
    except Exception as exc:
        logger.warning("[IDA-Sync] save_database call failed: %s", exc)
        return False

    if resp.status_code != 200:
        logger.warning(
            "[IDA-Sync] save_database HTTP %s: %s",
            resp.status_code,
            resp.text[:200],
        )
        return False

    try:
        data = resp.json()
    except Exception:
        return False

    return data.get("status") == "ok"


def _fetch_ida_pseudocode(
    entry_va: int, ida_url: str, timeout: float = 10.0
) -> Optional[str]:
    """Request idat_server for the latest pseudocode of specified function."""
    if requests is None:
        return None

    payload = {"action": "get_pseudocode", "ea": entry_va}
    try:
        resp = requests.post(ida_url, json=payload, timeout=timeout)
    except Exception as exc:
        logger.warning(
            "[IDA-Sync] get_pseudocode call failed 0x%08X: %s", entry_va, exc
        )
        return None

    if resp.status_code != 200:
        logger.warning(
            "[IDA-Sync] get_pseudocode HTTP %s: %s",
            resp.status_code,
            resp.text[:200],
        )
        return None

    try:
        data = resp.json()
    except Exception as exc:
        logger.warning(
            "[IDA-Sync] Failed to parse get_pseudocode response 0x%08X: %s; body=%s",
            entry_va,
            exc,
            resp.text[:200],
        )
        return None

    if data.get("status") != "ok":
        logger.warning(
            "[IDA-Sync] get_pseudocode returned error 0x%08X: %s", entry_va, data
        )
        return None

    code = data.get("pseudocode")
    return code if isinstance(code, str) else None


def _save_and_refresh_pseudocode(
    entry_va: int, ida_url: str, wait_seconds: float = 1.0
) -> Optional[str]:
    """Force save IDA database, wait a moment and re-fetch pseudocode."""
    _force_ida_save_database(ida_url)
    if wait_seconds > 0:
        time.sleep(wait_seconds)
    return _fetch_ida_pseudocode(entry_va, ida_url)


def _sync_lvars_with_ida(
    entry_va: int,
    rename_map: Dict[str, str],
    ida_url: str,
) -> Optional[str]:
    """
    Sync local variable renaming to IDA. Requires idat_server to support 'rename_lvar' action.
    If IDA returns updated_pseudocode, return it as string for caller to overwrite local pseudocode.
    """
    if requests is None or not rename_map:
        return None

    payload = {
        "action": "rename_lvar",  # Server needs to handle this action
        "ea": entry_va,
        "renames": rename_map,  # { "v1": "name", ... }
    }

    try:
        resp = requests.post(ida_url, json=payload, timeout=10.0)
    except Exception as exc:
        logger.warning(f"[IDA-Sync-Lvar] Failed to sync local variables 0x{entry_va:08X}: {exc}")
        return None

    if resp.status_code != 200:
        logger.warning(
            "[IDA-Sync-Lvar] HTTP %s when syncing lvars for 0x%08X: %s",
            resp.status_code,
            entry_va,
            resp.text[:200],
        )
        return None

    try:
        data = resp.json()
    except Exception as exc:
        logger.warning(
            "[IDA-Sync-Lvar] Failed to parse IDA JSON response 0x%08X: %s; body=%s",
            entry_va,
            exc,
            resp.text[:200],
        )
        return None

    if data.get("status") != "ok":
        logger.warning("[IDA-Sync-Lvar] IDA returned error 0x%08X: %s", entry_va, data)
        return None

    updated_code = data.get("updated_pseudocode")
    if isinstance(updated_code, str) and updated_code.strip():
        logger.info(
            "[IDA-Sync-Lvar] 0x%08X returned updated pseudocode, length=%d",
            entry_va,
            len(updated_code),
        )
        return updated_code

    return None


def _verify_lvar_persistence(
    conn: sqlite3.Connection,
    function_id: int,
    entry_va: int,
    ida_url: str,
    rename_map: Dict[str, str],
    initial_code: Optional[str],
    max_retries: int = 3,
    wait_seconds: float = 1.0,
) -> Tuple[Optional[str], Set[str]]:
    """
    After syncing local variable renaming, force save IDA database and re-fetch pseudocode,
    to confirm that default names like a1/v1 are indeed written to .i64.
    Returns latest pseudocode and remaining default variable name set.
    """
    latest_code = initial_code
    remaining = _find_generic_lvar_names(latest_code or "")

    if requests is None:
        return latest_code, remaining

    cur = conn.cursor()

    for attempt in range(1, max_retries + 1):
        refreshed = _save_and_refresh_pseudocode(entry_va, ida_url, wait_seconds)
        if refreshed:
            latest_code = refreshed
            cur.execute(
                "UPDATE pseudo_functions SET body = ? WHERE function_id = ?;",
                (refreshed, function_id),
            )
            conn.commit()

        remaining = _find_generic_lvar_names(latest_code or "")
        if not remaining:
            break

        if attempt < max_retries and rename_map:
            _sync_lvars_with_ida(entry_va, rename_map, ida_url)

    return latest_code, remaining


# =========================
# Phase 4 Core Functions
# =========================


def analyze_one_function_vars(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    node: UnifiedFunctionNode,
    analysis_info: Dict[int, dict],
    llm_settings: LLMSettings,
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
) -> bool:
    """
    Phase 4 core logic: single function local variable analysis and renaming.
    Returns True if modifications were made.
    """
    # 1. Get current best pseudocode and signature information:
    #    - Only consider ANALYZED/LOCKED results
    #    - If IDA sync enabled, prefer function_id from IDA view
    #    - Otherwise select by highest confidence
    best_fid: Optional[int] = None
    best_conf = -1
    signature = ""
    summary = ""

    preferred_tool = "ida" if ida_sync else None
    candidates: List[Dict[str, Any]] = []

    for fid in node.function_ids:
        info = analysis_info.get(fid)
        if not info:
            continue
        state = info.get("analysis_state", "")
        if state not in ("ANALYZED", "LOCKED"):
            continue

        score = int(info.get("confidence_score", 0) or 0)
        tool_name = graph.func_tool.get(fid, "").lower()
        candidates.append(
            {
                "fid": fid,
                "score": score,
                "tool": tool_name,
                "info": info,
            }
        )

    if not candidates:
        return False

    chosen: Optional[Dict[str, Any]] = None

    if preferred_tool:
        ida_candidates = [c for c in candidates if preferred_tool in c["tool"]]
        if ida_candidates:
            ida_candidates.sort(key=lambda c: c["score"], reverse=True)
            chosen = ida_candidates[0]

    if chosen is None:
        candidates.sort(key=lambda c: c["score"], reverse=True)
        chosen = candidates[0]
        if ida_sync and preferred_tool:
            print(
                f"[LVAR-WARN] 0x{node.entry_va:08X} wants to sync IDA, but no analyzed IDA view record found, "
                f"falling back to tool={chosen['tool'] or 'unknown'}, renaming may not fully take effect in IDA."
            )

    best_fid = int(chosen["fid"])
    best_conf = int(chosen["score"])
    chosen_info = chosen["info"]
    signature = chosen_info.get("summary_signature", "") or ""
    summary = chosen_info.get("semantic_summary", "") or ""

    # Set a threshold to only process relatively trustworthy functions
    if best_fid is None or best_conf < 60:
        return False

    # Read pseudocode
    cur = conn.cursor()
    cur.execute(
        "SELECT body FROM pseudo_functions WHERE function_id = ? LIMIT 1;",
        (best_fid,),
    )
    row = cur.fetchone()
    if not row or not row[0]:
        return False

    original_code = row[0]

    # 2. Build Prompt
    prompt = build_local_var_prompt(node, original_code, signature, summary)
    conversation, request_kwargs = build_chat_request(prompt, llm_settings)

    print(
        f"[LVAR] Analyzing 0x{node.entry_va:08X} "
        f"(tool={chosen.get('tool') or 'unknown'}, score={best_conf})..."
    )

    if dry_run:
        print(f"[LVAR-DRY] Prompt preview:\n{prompt[:500]}...")
        return False

    # 3. Call LLM
    result = call_llm_analyze_function(
        conversation=conversation,
        request_kwargs=request_kwargs,
        api_settings=llm_settings.api_settings,
        return_raw_on_error=True,
    )

    # May return dict containing raw error info for debugging
    if isinstance(result, dict) and "_raw_text" in result:
        raw_text = result.get("_raw_text", "")
        raw_err = result.get("_raw_error", "")
        print(
            f"[LVAR] JSON parsing failed, keeping this function in pending state for retry later.\n"
            f"[LVAR-ERROR] {raw_err}\n"
            f"[LVAR-RAW]\n{'-' * 40}\n{raw_text}\n{'-' * 40}"
        )
        return False

    if not result:
        # Network error or multiple attempts completely failed, don't mark as completed for later retry
        return False

    # result itself is a map, because Prompt requires returning {old: new}
    # But for robustness, handle if LLM wraps it with a key
    rename_map: Dict[str, str] = result  # type: ignore[assignment]
    if "renames" in result and isinstance(result["renames"], dict):
        rename_map = result["renames"]

    # Filter out invalid Key/Value
    clean_map: Dict[str, str] = {}
    for k, v in rename_map.items():
        if isinstance(k, str) and isinstance(v, str) and k != v:
            # Simple safety check: new name must be valid identifier
            if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", v):
                clean_map[k] = v

    changed = False
    total_renamed = 0
    updated_code: Optional[str] = None

    if not clean_map:
        print("[LVAR] LLM provided no valid renaming suggestions.")
        # If there's original JSON, use for debugging
        if result:
            try:
                print(
                    f"[LVAR-DEBUG] LLM original JSON: "
                    f"{json.dumps(result, ensure_ascii=False)}"
                )
            except Exception:
                print(f"[LVAR-DEBUG] LLM original JSON (cannot encode): {result!r}")
    else:
        print(f"[LVAR] Applying renames: {json.dumps(clean_map, ensure_ascii=False)}")

        # 4. Update local database (pseudocode text replacement)
        new_code = apply_local_var_renames(original_code, clean_map)

        # Here we choose to only update best_fid to avoid damaging other tools' original structure too severely
        cur.execute(
            "UPDATE pseudo_functions SET body = ? WHERE function_id = ?;",
            (new_code, best_fid),
        )
        conn.commit()
        changed = True
        total_renamed = len(clean_map)

        # 5. Sync to IDA (if enabled), and try to use IDA-returned latest pseudocode to overwrite local version
        if ida_sync and ida_url:
            updated = _sync_lvars_with_ida(node.entry_va, clean_map, ida_url)
            if updated:
                updated_code = updated
                cur.execute(
                    "UPDATE pseudo_functions SET body = ? WHERE function_id = ?;",
                    (updated, best_fid),
                )
                conn.commit()

    # Re-read final pseudocode from database and check if default variable names still exist (a1/v1/var_10 etc.)
    final_code: Optional[str]
    cur.execute(
        "SELECT body FROM pseudo_functions WHERE function_id = ? LIMIT 1;",
        (best_fid,),
    )
    row2 = cur.fetchone()
    if row2 and row2[0]:
        final_code = row2[0]
    else:
        # Fallback: prefer IDA-returned version, then local replaced version, finally original version
        if updated_code is not None:
            final_code = updated_code
        elif changed:
            final_code = new_code
        else:
            final_code = original_code

    remaining_generics = _find_generic_lvar_names(final_code or "")

    if changed and ida_sync and clean_map:
        verified_code, remaining_generics = _verify_lvar_persistence(
            conn=conn,
            function_id=best_fid,
            entry_va=node.entry_va,
            ida_url=ida_url,
            rename_map=clean_map,
            initial_code=final_code,
        )
        if verified_code:
            final_code = verified_code

    # Current strategy: as long as this round successfully completed one LVAR attempt (regardless of remaining defaults),
    # mark this function as "checked" to avoid repeatedly entering Phase 4 in subsequent runs.
    mark_optimized = True

    # Update lvar_optimized flag
    try:
        cur.execute(
            "UPDATE analysis_status SET lvar_optimized = ? WHERE function_id = ?;",
            (1 if mark_optimized else 0, best_fid),
        )
        conn.commit()
    except Exception as exc:
        logger.warning(
            "Failed to update lvar_optimized status function_id=%s: %s", best_fid, exc
        )

    # Clear conclusive output to see in progress bar if this function really had renaming
    if remaining_generics:
        generic_list = sorted(remaining_generics)
        if len(generic_list) > 8:
            generic_preview = ", ".join(generic_list[:8]) + ", ..."
        else:
            generic_preview = ", ".join(generic_list)
    else:
        generic_preview = ""

    if changed:
        if mark_optimized:
            print(
                f"[LVAR] 0x{node.entry_va:08X} local variable renaming completed, modified {total_renamed} identifiers, "
                "marked as checked."
            )
        else:
            print(
                f"[LVAR] 0x{node.entry_va:08X} renamed {total_renamed} identifiers, "
                f"but still detected {len(remaining_generics)} default variable names: {generic_preview}"
            )
    else:
        if mark_optimized:
            print(
                f"[LVAR] 0x{node.entry_va:08X} no local variable renaming performed, "
                "marked as checked."
            )
        else:
            print(
                f"[LVAR] 0x{node.entry_va:08X} LLM provided no valid renaming suggestions, and still has "
                f"{len(remaining_generics)} default variable names: {generic_preview}"
            )

    return changed


def run_local_var_phase(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    llm_settings: LLMSettings,
    ida_sync: bool,
    ida_url: str,
    dry_run: bool = False,
    max_funcs: int = 0,
) -> None:
    """
    Phase 4 entry point: iterate through high-confidence functions and optimize local variable names.
    """
    if ida_sync and ida_url:
        wait_for_ida_server(ida_url)

    # Ensure analysis_status table and lvar_optimized field exist
    ensure_analysis_schema(conn)
    analysis_info = load_analysis_info(conn)

    # Pre-load functions that have completed local variable optimization, support checkpoint resume
    cur = conn.cursor()
    cur.execute("SELECT function_id FROM analysis_status WHERE lvar_optimized = 1;")
    optimized_fids: Set[int] = {int(row[0]) for row in cur.fetchall()}

    # Filter candidate functions: analyzed with high score and not yet optimized for local variables
    candidates: List[Tuple[int, int]] = []
    for entry_va, node in graph.nodes.items():
        max_score = 0
        already_optimized = False
        for fid in node.function_ids:
            if fid in optimized_fids:
                already_optimized = True
            info = analysis_info.get(fid)
            if info:
                max_score = max(max_score, info.get("confidence_score", 0))

        if not already_optimized and max_score >= 70:
            candidates.append((entry_va, max_score))

    # Sort by score descending
    candidates.sort(key=lambda x: x[1], reverse=True)

    if max_funcs > 0:
        candidates = candidates[:max_funcs]

    print(f"[Phase 4] Local Variable Renaming: target function count {len(candidates)}")

    pbar = tqdm(total=len(candidates), desc="Phase 4: Local Vars", unit="func")

    processed_count = 0
    for entry_va, score in candidates:
        node = graph.nodes[entry_va]
        pbar.set_description(f"Phase 4: 0x{entry_va:08X} (score={score})")

        changed = analyze_one_function_vars(
            conn=conn,
            graph=graph,
            node=node,
            analysis_info=analysis_info,
            llm_settings=llm_settings,
            ida_sync=ida_sync,
            ida_url=ida_url,
            dry_run=dry_run,
        )
        if changed:
            processed_count += 1
        pbar.update(1)

    pbar.close()
    print(f"[Phase 4] Completed, optimized local variables for {processed_count} functions.")
