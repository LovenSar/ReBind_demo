#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ida_synchronizer.py

IDA Pro与数据库的同步功能。
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import requests  # type: ignore
except Exception:
    requests = None

try:
    from tqdm import tqdm  # type: ignore
except Exception:
    tqdm = None

logger = logging.getLogger(__name__)


# =========================
# 常量与正则表达式
# =========================

GENERIC_LVAR_PATTERN = re.compile(
    r"\b(?:a\d+|arg\d+|arg_\d+|v\d+|var_[0-9A-Fa-f]+)\b"
)

SUBFUNC_NAME_PATTERN = re.compile(r"\bsub_[0-9A-Fa-f]+\b")

# 超时：连续收到空响应时持续重试的最长等待时间（秒）
EMPTY_RESPONSE_RETRY_TIMEOUT = 90.0


# =========================
# 数据结构定义
# =========================

@dataclass
class LLMSettings:
    """LLM 参数与 OpenAI API 设置。"""

    model: str
    temperature: float
    max_tokens: int
    api_settings: Dict[str, Any]
    chat_completion_kwargs: Dict[str, Any]


# =========================
# 工具函数
# =========================

def _find_generic_lvar_names(code: str) -> Set[str]:
    """在伪代码文本中查找疑似默认局部变量名集合。"""
    if not code:
        return set()
    return {m.group(0) for m in GENERIC_LVAR_PATTERN.finditer(code)}


def _extract_name_from_signature(signature: str, fallback: str) -> Optional[str]:
    """
    从 LLM 提供的 C 风格 signature 中提取函数名。
    简单启发式：取 '(' 之前最后一个 token。
    """
    sig = signature.strip()
    if not sig:
        return fallback or None
    try:
        before_paren = sig.split("(", 1)[0].strip()
        if not before_paren:
            return fallback or None
        tokens = before_paren.split()
        name = tokens[-1]
        # 去掉星号等修饰符
        name = name.strip("*&")
        if not name:
            return fallback or None
        return name
    except Exception:
        return fallback or None


def _build_name_alignment_prompt(
    entry_va: int,
    db_name: str,
    ida_name: str,
    db_code: str,
    ida_code: str,
) -> str:
    """构造提示，要求 LLM 在 DB 与 IDA 命名/伪代码差异时选择更可信的名字来源。"""
    db_preview = (db_code or "").strip()
    ida_preview = (ida_code or "").strip()
    if len(db_preview) > 1200:
        db_preview = db_preview[:1200] + "..."
    if len(ida_preview) > 1200:
        ida_preview = ida_preview[:1200] + "..."

    prompt = f"""
你是一名逆向工程专家，现在需要对同一个函数在对齐数据库与 IDA .i64 中的差异进行裁决，并给出最终的函数名来源。

函数地址: 0x{entry_va:08X}

[数据库视图]
name: {db_name}
code:
{db_preview}

[IDA 视图]
name: {ida_name}
code:
{ida_preview}

任务：
1) 在两个候选名字中选择更可信的最终名字（通常更有语义的名字更好；如果其中一个是 sub_ 前缀，优先另一个；如两者都为 sub_，可保留更稳定的形式）。
2) 判断伪代码应以哪个来源为准（db 或 ida），考虑可读性与完整性。

请只返回一个 JSON 对象：
{{
  "final_name": "...",
  "source": "db" 或 "ida"  // 表示伪代码以哪个来源为准
}}
不要输出其他文字。
"""
    return prompt.strip()


def build_chat_request(prompt: str, llm_settings: LLMSettings) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    """构造要发送给 ChatCompletion 的消息与请求参数。"""

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


def require_openai(api_settings: Dict[str, Any]) -> Any:
    """动态导入并初始化 OpenAI 客户端（兼容新旧 API）。"""
    try:
        import openai  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "未安装 openai 库。请运行: pip install openai"
        ) from exc

    api_key = api_settings.get("api_key") or ""
    base_url = api_settings.get("base_url") or None

    if hasattr(openai, "OpenAI"):
        # openai>=1.0.0
        if base_url:
            client = openai.OpenAI(api_key=api_key, base_url=base_url)  # type: ignore[attr-defined]
        else:
            client = openai.OpenAI(api_key=api_key)  # type: ignore[attr-defined]
        return client
    else:
        # 旧版 openai
        openai.api_key = api_key  # type: ignore[attr-defined]
        if base_url:
            openai.api_base = base_url  # type: ignore[attr-defined]
        return openai


def call_llm_analyze_function(
    conversation: List[Dict[str, str]],
    request_kwargs: Dict[str, Any],
    api_settings: Dict[str, Any],
    max_attempts: int = 3,
    return_raw_on_error: bool = False,
) -> dict:
    """
    调用 OpenAI ChatCompletion，让模型对单个函数进行分析。
    期望返回一个 JSON 对象。
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
                # 兼容 openai 新旧两种调用方式
                if hasattr(client, "chat") and hasattr(client.chat, "completions"):
                    # openai>=1.0.0: 使用 client.chat.completions.create
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
                    # 旧版 openai: 模块级 ChatCompletion.create
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
                else:  # pragma: no cover - 极端情况
                    last_error = "当前 openai 客户端不支持 ChatCompletion 接口"
                    break
            except Exception as exc:  # 网络 / API 失败
                last_error = f"LLM 调用失败({attempt}/{max_attempts}): {exc}"
                logger.warning("%s", last_error)
                break

            text_str = (text or "").strip()
            # 若模型返回 Markdown 代码块包裹的 JSON，先尝试剥离 ``` 包围
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
                    f"LLM 多次返回空字符串，已重试 {EMPTY_RESPONSE_RETRY_TIMEOUT:.0f} 秒仍未成功。"
                )
                logger.warning("%s", last_error)
                break

            logger.info(
                "LLM 暂无回复内容，正在快速重试（超时 %.0f 秒）...",
                EMPTY_RESPONSE_RETRY_TIMEOUT,
            )
            time.sleep(0.5)

        if not text_str:
            logger.warning("Attempt %d/%d failed: no text", attempt, max_attempts)
            continue

        logger.debug("LLM response (attempt %d/%d): %s", attempt, max_attempts, text_str[:500])

        # 尝试解析 JSON
        try:
            parsed = json.loads(text_str)
            if not isinstance(parsed, dict):
                last_error = f"LLM 返回非字典类型: {type(parsed)}"
                logger.warning("%s", last_error)
                continue
            return parsed
        except json.JSONDecodeError as exc:
            last_error = f"JSON 解析失败: {exc}"
            logger.warning("%s (raw text: %s)", last_error, text_str[:200])

    # 所有尝试都失败
    if return_raw_on_error:
        return {"_raw_text": text_str or ""}

    logger.error("LLM 分析失败，已尝试 %d 次: %s", max_attempts, last_error)
    return {}


def wait_for_ida_server(ida_url: str) -> None:
    """
    等待 IDA server 可用。如果不可用，会提示用户启动并允许重试。
    这个函数需要从 common_utils 导入，这里提供一个占位实现。
    """
    # 这个函数实际上应该从 common_utils 导入
    # 这里提供一个简化版本
    if requests is None:
        return

    max_retries = 3
    for attempt in range(max_retries):
        try:
            resp = requests.post(ida_url, json={"action": "ping"}, timeout=5.0)
            if resp.status_code == 200:
                return
        except Exception:
            pass

        if attempt < max_retries - 1:
            logger.warning(
                "IDA server 未响应 (attempt %d/%d)，请确保 idat_server.py 正在运行。",
                attempt + 1,
                max_retries,
            )
            time.sleep(2)

    logger.error("无法连接到 IDA server: %s", ida_url)


# =========================
# IDA 同步核心函数
# =========================

def _load_ida_subfunc_entries(conn: sqlite3.Connection, binary_id: int) -> Dict[int, str]:
    """加载该 binary 下 IDA 视图仍为 sub_ 前缀的函数名映射。"""
    cur = conn.cursor()
    cur.execute(
        """
        SELECT f.entry_va, f.name
        FROM functions AS f
        JOIN binary_views AS bv ON f.view_id = bv.id
        JOIN tools AS t ON bv.tool_id = t.id
        WHERE bv.binary_id = ? AND LOWER(t.name) = 'ida';
        """,
        (binary_id,),
    )

    result: Dict[int, str] = {}
    for entry_va, name in cur.fetchall():
        nm = (name or "").strip()
        if not nm:
            continue
        if SUBFUNC_NAME_PATTERN.fullmatch(nm):
            result[int(entry_va)] = nm
    return result


def _sync_global_with_ida_and_update_db(
    conn: sqlite3.Connection,
    address_va: int,
    new_name: str,
    type_str: Optional[str],
    ida_url: str,
) -> None:
    """
    将全局变量改名/类型信息同步到 idat_server，并更新对齐数据库中的 symbols/global_vars。
    """
    if requests is None or not new_name:
        logger.info(
            "[IDA-Sync] requests 未安装或 new_name 为空，跳过全局变量同步。 addr=0x%08X",
            address_va,
        )
        return

    # 每次与 IDA 同步前，都先确认 idat_server 在线
    if ida_url:
        wait_for_ida_server(ida_url)

    payload = {
        "action": "rename_global",
        "ea": address_va,
        "name": new_name,
        "type": type_str or "",
    }

    logger.info(
        "[IDA-Sync] 尝试同步全局变量 0x%08X -> %s 到 IDA (%s)",
        address_va,
        new_name,
        ida_url,
    )
    logger.debug("[IDA-Sync] rename_global payload: %s", payload)

    try:
        resp = requests.post(ida_url, json=payload, timeout=10.0)
    except Exception as exc:
        logger.error("[IDA-Sync] 全局变量同步失败: %s", exc)
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
    # 确认 IDA 端是否成功处理
    if (data or {}).get("status") != "ok":
        logger.error(
            "[IDA-Sync] rename_global IDA 返回错误: %s",
            data or resp.text[:200],
        )
        return

    ida_new_name = data.get("new_name") or new_name
    if data.get("new_name") and data["new_name"] != new_name:
        logger.warning(
            "[IDA-Sync] rename_global 名字不一致：requested=%s, applied=%s (addr=0x%08X)",
            new_name,
            data["new_name"],
            address_va,
        )
    applied_type = data.get("applied_type")
    logger.info(
        "[IDA-Sync] rename_global 成功: addr=0x%08X, name=%s, applied_type=%s",
        address_va,
        ida_new_name,
        applied_type or type_str,
    )

    # 同步对齐数据库中 symbols 表的名字
    cur = conn.cursor()
    cur.execute(
        "UPDATE symbols SET name = ? WHERE address_va = ?;",
        (ida_new_name, address_va),
    )
    conn.commit()
    logger.debug(
        "[IDA-Sync] 已在数据库中将 symbols.address_va=0x%08X 更新为 name=%s",
        address_va,
        new_name,
    )


def _force_ida_save_database(ida_url: str, timeout: float = 15.0) -> bool:
    """请求 idat_server 立即保存数据库（不退出）。"""
    if requests is None:
        return False

    try:
        resp = requests.post(
            ida_url, json={"action": "save_database"}, timeout=timeout
        )
    except Exception as exc:
        logger.warning("[IDA-Sync] save_database 调用失败: %s", exc)
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


def _fetch_ida_pseudocode(entry_va: int, ida_url: str, timeout: float = 10.0) -> Optional[str]:
    """向 idat_server 请求指定函数的最新伪代码。"""
    if requests is None:
        return None

    payload = {"action": "get_pseudocode", "ea": entry_va}
    try:
        resp = requests.post(ida_url, json=payload, timeout=timeout)
    except Exception as exc:
        logger.warning(
            "[IDA-Sync] get_pseudocode 调用失败 0x%08X: %s", entry_va, exc
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
            "[IDA-Sync] 解析 get_pseudocode 响应失败 0x%08X: %s; body=%s",
            entry_va,
            exc,
            resp.text[:200],
        )
        return None

    if data.get("status") != "ok":
        logger.warning(
            "[IDA-Sync] get_pseudocode 返回错误 0x%08X: %s", entry_va, data
        )
        return None

    code = data.get("pseudocode")
    return code if isinstance(code, str) else None


def _save_and_refresh_pseudocode(
    entry_va: int, ida_url: str, wait_seconds: float = 1.0
) -> Optional[str]:
    """强制保存 IDA 数据库后，等待片刻并重新获取伪代码。"""
    _force_ida_save_database(ida_url)
    if wait_seconds > 0:
        time.sleep(wait_seconds)
    return _fetch_ida_pseudocode(entry_va, ida_url)


def _reconcile_ida_db_mismatch(
    conn: sqlite3.Connection,
    binary_id: int,
    ida_url: str,
    llm_settings: LLMSettings,
    ida_sync: bool,
    max_items: int = 50,
) -> None:
    """
    在进入第一阶段前，对比数据库（IDA 视图）与实际 .i64 的名称/伪代码差异，
    通过 LLM 决策采用哪一侧的名称/伪代码，并同步更新。
    """
    if requests is None:
        return

    # 找出 IDA 视图 id
    cur = conn.cursor()
    cur.execute(
        """
        SELECT bv.id
        FROM binary_views AS bv
        JOIN tools AS t ON bv.tool_id = t.id
        WHERE bv.binary_id = ? AND LOWER(t.name) = 'ida'
        ORDER BY bv.id LIMIT 1;
        """,
        (binary_id,),
    )
    row = cur.fetchone()
    if not row:
        return
    ida_view_id = int(row[0])

    cur.execute(
        """
        SELECT f.id, f.entry_va, COALESCE(f.name, '') AS name, COALESCE(pf.body, '') AS body
        FROM functions AS f
        LEFT JOIN pseudo_functions AS pf ON pf.function_id = f.id
        WHERE f.view_id = ?;
        """,
        (ida_view_id,),
    )
    rows = cur.fetchall()

    mismatches: List[Tuple[int, int, str, str, dict]] = []
    removed_function_ids: set[int] = set()

    for function_id, entry_va, db_name, db_body in rows:
        info = _fetch_ida_function_info(entry_va, ida_url)
        if not info:
            _drop_function_record(conn, function_id, entry_va)
            removed_function_ids.add(function_id)
            continue
        ida_name = info.get("name", "") or ""
        ida_code = info.get("pseudocode", "") or ""

        name_diff = (db_name or "") != (ida_name or "")
        code_diff = (db_body or "").strip() != (ida_code or "").strip()

        # 仅在 IDA 名字仍为 sub_ 前缀时触发对齐（核心需求）
        ida_is_sub = bool(SUBFUNC_NAME_PATTERN.fullmatch(ida_name or ""))

        if not ida_is_sub:
            continue
        if not name_diff and not code_diff:
            continue

        mismatches.append((function_id, entry_va, db_name, db_body, info))
        if len(mismatches) >= max_items:
            break

    if not mismatches:
        return

    print(f"[Align] 检测到 {len(mismatches)} 个 IDA/DB 不一致的函数，提交 LLM 评估。")

    # 使用 tqdm 进度条（如果可用）
    if tqdm is not None:
        pbar = tqdm(mismatches, desc="Aligning DB vs IDA", unit="fn")
    else:
        pbar = mismatches

    # 记录已经被占用的最终名字，避免重名（包含初始 DB 名称）
    used_names: dict[str, tuple[int, int]] = {}
    for function_id, entry_va, db_name, _db_body in rows:
        if function_id in removed_function_ids:
            continue
        if db_name:
            used_names[str(db_name)] = (int(function_id), int(entry_va))

    for function_id, entry_va, db_name, db_body, info in pbar:
        if tqdm is not None:
            pbar.set_postfix(address=f"0x{entry_va:08X}")
        ida_name = info.get("name", "") or ""
        ida_code = info.get("pseudocode", "") or ""

        prompt = _build_name_alignment_prompt(
            entry_va=entry_va,
            db_name=db_name,
            ida_name=ida_name,
            db_code=db_body,
            ida_code=ida_code,
        )
        conversation, request_kwargs = build_chat_request(prompt, llm_settings)

        try:
            result = call_llm_analyze_function(
                conversation=conversation,
                request_kwargs=request_kwargs,
                api_settings=llm_settings.api_settings,
                return_raw_on_error=True,
            )
        except Exception as exc:
            logger.warning(
                "[Align] LLM 决策失败 0x%08X: %s", entry_va, exc
            )
            continue

        if isinstance(result, dict) and "_raw_text" in result:
            continue
        if not isinstance(result, dict):
            continue

        final_name = str(result.get("final_name", db_name) or db_name)
        source = str(result.get("source", "db") or "db").lower()
        if source not in ("db", "ida"):
            source = "db"

        chosen_code = db_body if source == "db" else ida_code

        # 如果与已有名称冲突，尝试让 LLM 再判一次；失败则追加 _0/_1 后缀
        if final_name in used_names and used_names[final_name][0] != function_id:
            existing_fn_id, existing_ea = used_names[final_name]
            try:
                current_snippets = _collect_function_snippets(conn, function_id)
                existing_snippets = _collect_function_snippets(conn, existing_fn_id)
                resolved = _resolve_name_collision_with_llm(
                    base_name=final_name,
                    current_ea=entry_va,
                    existing_ea=existing_ea,
                    current_snippets=current_snippets,
                    existing_snippets=existing_snippets,
                    llm_settings=llm_settings,
                )
            except Exception:
                resolved = None

            if not resolved:
                suffix = 0
                candidate = f"{final_name}_{suffix}"
                while candidate in used_names:
                    suffix += 1
                    candidate = f"{final_name}_{suffix}"
                resolved = candidate

            final_name = resolved
            print(
                f"[Align] 0x{entry_va:08X}: 重名处理 -> {final_name}"
            )

        used_names[final_name] = (function_id, entry_va)

        print(
            f"[Align] 0x{entry_va:08X}: LLM 选定 final_name={final_name}, source={source}"
        )
        logger.info(
            "[Align] 0x%08X decision: final_name=%s, source=%s",
            entry_va,
            final_name,
            source,
        )

        # 更新数据库伪代码
        cur.execute(
            "UPDATE pseudo_functions SET body = ? WHERE function_id = ?;",
            (chosen_code, function_id),
        )

        # 更新名字（仅当前 function 记录）
        cur.execute(
            "UPDATE functions SET name = ? WHERE id = ?;",
            (final_name, function_id),
        )

        conn.commit()

        # 尝试同步到 IDA（保持 .i64 一致）
        if ida_sync and requests is not None:
            try:
                payload = {
                    "action": "rename_and_sync",
                    "ea": entry_va,
                    "name": final_name,
                    "comment": "[Align-Reconcile]",  # 简短标记
                }
                resp = requests.post(ida_url, json=payload, timeout=10.0)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        updated_code = data.get("updated_pseudocode") or ""
                        if updated_code:
                            cur.execute(
                                "UPDATE pseudo_functions SET body = ? WHERE function_id = ?;",
                                (updated_code, function_id),
                            )
                            conn.commit()
                    except Exception:
                        pass
            except Exception as exc:
                logger.warning(
                    "[Align] 同步到 IDA 失败 entry_va=0x%08X: %s", entry_va, exc
                )


def _fetch_ida_function_info(entry_va: int, ida_url: str, timeout: float = 10.0) -> Optional[dict]:
    """获取 IDA 中的函数名称与伪代码。"""
    if requests is None:
        return None

    payload = {"action": "get_function_info", "ea": entry_va}
    try:
        resp = requests.post(ida_url, json=payload, timeout=timeout)
    except Exception as exc:
        logger.warning(
            "[IDA-Sync] get_function_info 调用失败 0x%08X: %s", entry_va, exc
        )
        return None

    if resp.status_code != 200:
        logger.warning(
            "[IDA-Sync] get_function_info HTTP %s: %s",
            resp.status_code,
            resp.text[:200],
        )
        return None

    try:
        data = resp.json()
    except Exception as exc:
        logger.warning(
            "[IDA-Sync] 解析 get_function_info 响应失败 0x%08X: %s; body=%s",
            entry_va,
            exc,
            resp.text[:200],
        )
        return None

    if data.get("status") != "ok":
        logger.warning(
            "[IDA-Sync] get_function_info 返回错误 0x%08X: %s", entry_va, data
        )
        return None

    return data


def _drop_function_record(conn: sqlite3.Connection, function_id: int, entry_va: int) -> None:
    """删除无法反编译/无效的函数记录及相关指令、伪代码。"""
    cur = conn.cursor()
    cur.execute("DELETE FROM instructions WHERE function_id = ?;", (function_id,))
    cur.execute("DELETE FROM pseudo_functions WHERE function_id = ?;", (function_id,))
    cur.execute("DELETE FROM functions WHERE id = ?;", (function_id,))
    conn.commit()
    print(f"[Align] 移除无法反编译的函数 0x{entry_va:08X} (function_id={function_id})")


def _collect_function_snippets(
    conn: sqlite3.Connection, function_id: int, max_asm_lines: int = 120
) -> dict:
    """提取指定函数的伪代码和汇编片段，用于重名冲突时的 LLM 判断。"""
    cur = conn.cursor()

    cur.execute(
        "SELECT entry_va, COALESCE(body, '') FROM pseudo_functions WHERE function_id = ?;",
        (function_id,),
    )
    row = cur.fetchone()
    entry_va = int(row[0]) if row else 0
    pseudocode = row[1] if row else ""

    cur.execute(
        """
        SELECT raw_line
        FROM instructions
        WHERE function_id = ?
        ORDER BY index_in_function
        LIMIT ?;
        """,
        (function_id, max_asm_lines),
    )
    asm_lines = [r[0] for r in cur.fetchall() if r and r[0]]
    asm_text = "\n".join(asm_lines)

    return {
        "entry_va": entry_va,
        "pseudocode": pseudocode,
        "asm": asm_text,
    }


def _sync_with_ida_and_update_db(
    conn: sqlite3.Connection,
    graph: Any,  # UnifiedGraph
    node: Any,  # UnifiedFunctionNode
    entry_va: int,
    signature: str,
    summary: str,
    ida_url: str,
    enforce_non_sub: bool = True,
) -> None:
    """
    调用在 idat 中运行的 HTTP 服务（idat_server.py），对物理函数进行重命名，
    并使用返回的最新伪代码刷新当前数据库中对应 IDA 视图的 pseudo_functions / functions。
    """
    if requests is None:
        logger.info(
            "[IDA-Sync] 未安装 requests，跳过函数同步。pip install requests 可启用。"
        )
        return

    # 每次与 IDA 同步前，都先确认 idat_server 在线（支持断链自动重试 + 人工立即重试）
    if ida_url:
        wait_for_ida_server(ida_url)

    # 选出 IDA 视图上的 function_id（如果存在），优先同步该视图的伪代码
    ida_function_id: Optional[int] = None
    for fid in node.function_ids:
        tool_name = graph.func_tool.get(fid, "")
        if tool_name.lower() == "ida":
            ida_function_id = fid
            break
    if ida_function_id is None:
        # 没有 IDA 视图，仅更新对齐数据库中的名字即可
        logger.info(
            "[IDA-Sync] 未找到 IDA 视图对应的 function_id，仅更新当前数据库。 entry_va=0x%08X",
            entry_va,
        )
        return

    # 提取一个尽量合理的函数名
    fallback_name = (
        next(iter(sorted(node.names)), f"sub_{entry_va:08X}")
        if node.names
        else f"sub_{entry_va:08X}"
    )
    final_name = _extract_name_from_signature(signature, fallback=fallback_name)
    if not final_name:
        logger.warning(
            "[IDA-Sync] 无法从 signature 中提取函数名，跳过同步。 entry_va=0x%08X, signature=%r",
            entry_va,
            signature,
        )
        return

    full_comment = (
        f"[Unified-LLM]\nName: {final_name}\nSignature: {signature}\nSummary: {summary}"
    )
    payload = {
        "action": "rename_and_sync",
        "ea": entry_va,
        "name": final_name,
        "comment": full_comment,
    }

    logger.info(
        "[IDA-Sync] 尝试同步函数到 IDA: ea=0x%08X, name=%s (%s)",
        entry_va,
        final_name,
        ida_url,
    )
    logger.debug("[IDA-Sync] rename_and_sync payload: %s", payload)

    max_retry = 3
    applied_name = final_name
    latest_code: str = ""

    def _post_rename_once() -> Tuple[Optional[dict], Optional[str]]:
        try:
            resp = requests.post(ida_url, json=payload, timeout=10.0)
        except Exception as exc:
            logger.error("[IDA-Sync] 连接 IDA 失败: %s", exc)
            return None, None

        if resp.status_code != 200:
            logger.error(
                "[IDA-Sync] HTTP %s: %s",
                resp.status_code,
                resp.text[:200],
            )
            return None, None

        try:
            data = resp.json()
        except Exception as exc:  # pragma: no cover - 解析失败仅日志
            logger.error(
                "[IDA-Sync] 解析 IDA 响应失败: %s; body=%s",
                exc,
                resp.text[:200],
            )
            return None, None

        if data.get("status") != "ok":
            logger.error("[IDA-Sync] IDA 返回错误: %s", data)
            return None, None

        return data, data.get("updated_pseudocode") or ""

    for attempt in range(1, max_retry + 1):
        data, updated_code = _post_rename_once()
        if data is None:
            return

        ida_new_name = data.get("new_name")
        if ida_new_name and ida_new_name != applied_name:
            logger.warning(
                "[IDA-Sync] IDA 实际应用的函数名与建议名不一致：requested=%s, applied=%s",
                applied_name,
                ida_new_name,
            )
            applied_name = ida_new_name

        if updated_code:
            latest_code = updated_code

        refreshed = _save_and_refresh_pseudocode(entry_va, ida_url)
        if refreshed:
            latest_code = refreshed

        if enforce_non_sub:
            if latest_code and not SUBFUNC_NAME_PATTERN.search(latest_code):
                break

            if attempt < max_retry:
                logger.warning(
                    "[IDA-Sync] 0x%08X 伪代码仍包含 sub_ 前缀，尝试重新同步 (%d/%d)",
                    entry_va,
                    attempt,
                    max_retry,
                )
            else:
                logger.warning(
                    "[IDA-Sync] 0x%08X 多次同步后仍检测到 sub_ 前缀，可能需要人工确认。",
                    entry_va,
                )
        else:
            # 不强制检查 sub_，第一次成功即退出循环
            break

    logger.info(
        "[IDA-Sync] 成功同步到 IDA，最新伪代码长度: %d 字符。",
        len(latest_code),
    )

    cur = conn.cursor()

    if latest_code:
        cur.execute(
            """
            UPDATE pseudo_functions
            SET body = ?, prototype = ?, name = ?
            WHERE function_id = ?;
            """,
            (latest_code, signature, applied_name, ida_function_id),
        )

    # 所有视图的 functions 记录统一使用新名字，便于后续分析
    for fid in node.function_ids:
        cur.execute("UPDATE functions SET name = ? WHERE id = ?;", (applied_name, fid))

    conn.commit()
    node.names.add(applied_name)
    logger.debug(
        "[IDA-Sync] 数据库已更新为最新名字与伪代码。entry_va=0x%08X, name=%s",
        entry_va,
        applied_name,
    )


def _resolve_name_collision_with_llm(
    base_name: str,
    current_ea: int,
    existing_ea: int,
    current_snippets: dict,
    existing_snippets: dict,
    llm_settings: LLMSettings,
) -> Optional[str]:
    """
    在命名冲突时，附带双方的伪代码/汇编交给 LLM 决定：
    - 如果能判断出更合适的名字，返回该名字；
    - 如果建议使用基础名加后缀，返回 None（外层会追加 _0/_1）。
    期望 LLM 返回 JSON：{"resolved_name": "...", "use_suffix": true/false, "reason": "..."}
    """
    prompt = f"""
你是逆向辅助命名助手。现在有两个函数命名冲突，基础名为 {base_name}。
请比较两个函数的伪代码和汇编，给出一个更合适的最终名称，或明确要求使用基础名加数字后缀。
输出必须是 JSON，格式：{{"resolved_name": "<字符串或留空>", "use_suffix": <true/false>, "reason": "<简短理由>"}}
如果无法区分，设置 use_suffix 为 true。

函数A (current): entry_va=0x{current_ea:08X}
伪代码:
{current_snippets.get('pseudocode','')}

汇编:
{current_snippets.get('asm','')}

函数B (existing): entry_va=0x{existing_ea:08X}
伪代码:
{existing_snippets.get('pseudocode','')}

汇编:
{existing_snippets.get('asm','')}
"""

    conversation, request_kwargs = build_chat_request(prompt, llm_settings)

    try:
        result = call_llm_analyze_function(
            conversation=conversation,
            request_kwargs=request_kwargs,
            api_settings=llm_settings.api_settings,
            return_raw_on_error=True,
        )
    except Exception:
        return None

    if isinstance(result, dict) and "_raw_text" in result:
        return None
    if not isinstance(result, dict):
        return None

    resolved = result.get("resolved_name")
    if resolved:
        return str(resolved)

    use_suffix = result.get("use_suffix")
    if isinstance(use_suffix, bool) and use_suffix:
        return None

    return None


def _sync_lvars_with_ida(
    entry_va: int,
    rename_map: Dict[str, str],
    ida_url: str,
) -> Optional[str]:
    """
    将局部变量重命名同步到 IDA。需要 idat_server 支持 'rename_lvar' 动作。
    如 IDA 返回 updated_pseudocode，则将其以字符串形式返回，便于调用方覆盖本地伪代码。
    """
    if requests is None or not rename_map:
        return None

    payload = {
        "action": "rename_lvar",  # 服务端需要处理此 action
        "ea": entry_va,
        "renames": rename_map,  # { "v1": "name", ... }
    }

    try:
        resp = requests.post(ida_url, json=payload, timeout=10.0)
    except Exception as exc:
        logger.warning(f"[IDA-Sync-Lvar] 同步局部变量失败 0x{entry_va:08X}: {exc}")
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
            "[IDA-Sync-Lvar] 解析 IDA 返回的 JSON 失败 0x%08X: %s; body=%s",
            entry_va,
            exc,
            resp.text[:200],
        )
        return None

    if data.get("status") != "ok":
        logger.warning("[IDA-Sync-Lvar] IDA 返回错误 0x%08X: %s", entry_va, data)
        return None

    updated_code = data.get("updated_pseudocode")
    if isinstance(updated_code, str) and updated_code.strip():
        logger.info(
            "[IDA-Sync-Lvar] 0x%08X 返回更新伪代码，长度=%d",
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
    在同步局部变量重命名后，强制保存 IDA 数据库并重新获取伪代码，
    以确认 a1/v1 等默认名确实被写入 .i64。
    返回最新伪代码和剩余的默认变量名集合。
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
