"""depth/goal_collector.py

目标函数选择：GoalItem 数据类、语义丰富度评分、手工指定目标与自动目标候选。

从 engine.py 拆分而来，职责单一，不依赖 LLM 或图路径搜索。
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Set

from kp.kp_schema import load_analysis_info
from kp.kp_types import UnifiedFunctionNode, UnifiedGraph


STRUCT_HINT_RE = re.compile(r"\b(?:struct|field_|_ctx|_cfg|_info|_node|_state)\b|->", re.IGNORECASE)
TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")

GOAL_SIGNAL_KEYWORDS: Dict[str, int] = {
    "socket": 12, "send": 8, "recv": 8, "connect": 10, "bind": 8,
    "listen": 8, "accept": 8, "server": 10, "client": 8,
    "encrypt": 12, "decrypt": 12, "crypt": 10, "cipher": 10,
    "aes": 10, "rsa": 10, "sha": 8, "hash": 8, "hmac": 8,
    "file": 6, "open": 4, "read": 4, "write": 4, "close": 4,
    "transfer": 8, "download": 8, "upload": 8,
    "password": 10, "passwd": 10, "auth": 10, "login": 10, "token": 8,
    "key": 6, "cert": 8, "tls": 10, "ssl": 10,
    "exec": 8, "spawn": 8, "system": 6, "shell": 8, "command": 6,
    "inject": 10, "hook": 8, "patch": 6,
    "alloc": 4, "malloc": 4, "free": 4, "heap": 6,
    "mutex": 6, "thread": 6, "process": 6,
    "registry": 8, "config": 6, "setting": 4,
    "network": 8, "http": 8, "dns": 8, "url": 6, "packet": 8,
    "buffer": 6, "overflow": 10, "exploit": 12,
    "syslog": 6, "log": 4, "debug": 4,
}


# ──────────────────────────────────────────────────────────────────────────────
# 数据结构
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class GoalItem:
    """单个分析目标函数的描述项。"""
    entry_va: int
    source: str
    xref_count: int
    richness: int
    manual_score: int


# ──────────────────────────────────────────────────────────────────────────────
# Goal <-> dict 序列化
# ──────────────────────────────────────────────────────────────────────────────

def _goal_to_dict(goal: GoalItem) -> Dict[str, Any]:
    return {
        "entry_va": int(goal.entry_va),
        "source": str(goal.source),
        "xref_count": int(goal.xref_count),
        "richness": int(goal.richness),
        "manual_score": int(goal.manual_score),
    }


def _goal_from_dict(item: Dict[str, Any]) -> GoalItem:
    return GoalItem(
        entry_va=int(item.get("entry_va", 0) or 0),
        source=str(item.get("source") or ""),
        xref_count=int(item.get("xref_count", 0) or 0),
        richness=int(item.get("richness", 0) or 0),
        manual_score=int(item.get("manual_score", 0) or 0),
    )


# ──────────────────────────────────────────────────────────────────────────────
# 分析信息加载
# ──────────────────────────────────────────────────────────────────────────────

def _load_analysis_info_safe(conn: sqlite3.Connection) -> Dict[int, dict]:
    """尝试加载分析状态，出错时返回空字典。"""
    try:
        return load_analysis_info(conn)
    except Exception:
        return {}


# ──────────────────────────────────────────────────────────────────────────────
# 语义文本 / 丰富度评分
# ──────────────────────────────────────────────────────────────────────────────

def _node_text_blob(node: UnifiedFunctionNode) -> str:
    """将节点的所有文本字段合并为单个字符串，用于关键词匹配。"""
    parts: List[str] = []
    if node.names:
        parts.append(" ".join(sorted(node.names)))
    for code in node.pseudocodes.values():
        if code:
            parts.append(code)
    for s in node.string_refs:
        parts.append(s)
    for api in node.external_callee_names:
        parts.append(api)
    return "\n".join(parts)


def _semantic_richness(node: UnifiedFunctionNode, struct_tokens: Sequence[str]) -> int:
    """计算节点的语义丰富度分数（用于目标函数优先级排序）。

    评分维度：
    - 外部 API 调用数、字符串引用数、内部被调用数、调用者数
    - 结构体关键词命中、手动结构体线索命中
    - 指令数量（复杂度桶）
    - **字符串语义信号**：网络/加密/文件/鉴权等高价值关键词加权
    """
    text = _node_text_blob(node).lower()
    struct_hits = len(STRUCT_HINT_RE.findall(text))
    manual_struct_hits = 0
    for t in struct_tokens:
        tok = str(t or "").strip().lower()
        if tok and tok in text:
            manual_struct_hits += 1

    ext_api = len(node.external_callee_names)
    strings = len(node.string_refs)
    internal = len(node.internal_callee_vas)
    callers = len(node.caller_vas)
    instr_bucket = 2 if int(node.instr_count or 0) >= 120 else (1 if int(node.instr_count or 0) >= 30 else 0)

    signal_score = 0
    signal_seen: set = set()
    for s in node.string_refs:
        sl = str(s or "").lower()
        for kw, weight in GOAL_SIGNAL_KEYWORDS.items():
            if kw in sl and kw not in signal_seen:
                signal_score += weight
                signal_seen.add(kw)
    for n in node.names:
        nl = str(n or "").lower()
        for kw, weight in GOAL_SIGNAL_KEYWORDS.items():
            if kw in nl and kw not in signal_seen:
                signal_score += weight
                signal_seen.add(kw)

    score = 4 * min(ext_api, 15)
    score += 3 * min(strings, 20)
    score += 2 * min(internal, 20)
    score += 2 * min(callers, 20)
    score += 5 * min(struct_hits, 10)
    score += 8 * min(manual_struct_hits, 6)
    score += instr_bucket
    score += min(signal_score, 80)
    return int(score)


def _extract_tokens(text: str) -> Set[str]:
    toks = {m.group(0).lower() for m in TOKEN_RE.finditer(str(text or ""))}
    return {t for t in toks if len(t) >= 3}


def _node_name_tokens(node: UnifiedFunctionNode) -> Set[str]:
    tokens: Set[str] = set()
    for n in node.names:
        tokens.update(_extract_tokens(n))
    return tokens


# ──────────────────────────────────────────────────────────────────────────────
# 目标函数选择
# ──────────────────────────────────────────────────────────────────────────────

def _pick_manual_goals(
    graph: UnifiedGraph,
    adjacency: Dict[int, Dict[int, Set[str]]],
    *,
    goal_vas: Sequence[str],
    goal_keywords: Sequence[str],
    goal_structs: Sequence[str],
    goal_limit: int,
    parse_va_fn: Any,
) -> List[GoalItem]:
    """从用户提供的地址、关键词和结构体线索中筛选目标函数。"""
    selected: Dict[int, GoalItem] = {}

    for raw in goal_vas:
        token = str(raw or "").strip()
        if not token:
            continue
        try:
            va = int(parse_va_fn(token))
        except Exception:
            continue
        if va not in graph.nodes:
            continue
        node = graph.nodes[va]
        item = GoalItem(
            entry_va=int(va),
            source="manual_va",
            xref_count=len(adjacency.get(int(va), {})),
            richness=_semantic_richness(node, goal_structs),
            manual_score=100,
        )
        selected[int(va)] = item

    tokens = [str(x or "").strip().lower() for x in [*goal_keywords, *goal_structs] if str(x or "").strip()]
    if tokens:
        for va, node in graph.nodes.items():
            blob = _node_text_blob(node).lower()
            score = 0
            hit = False
            for t in tokens:
                if t and t in blob:
                    hit = True
                    score += 10 if t in [s.lower() for s in goal_structs] else 6
            if not hit:
                continue
            old = selected.get(int(va))
            xref_count = len(adjacency.get(int(va), {}))
            richness = _semantic_richness(node, goal_structs)
            item = GoalItem(
                entry_va=int(va),
                source="manual_text",
                xref_count=int(xref_count),
                richness=int(richness),
                manual_score=int(score),
            )
            if old is None:
                selected[int(va)] = item
            elif (item.manual_score, item.xref_count, item.richness) > (old.manual_score, old.xref_count, old.richness):
                selected[int(va)] = item

    out = sorted(
        selected.values(),
        key=lambda x: (int(x.manual_score), int(x.xref_count), int(x.richness), -int(x.entry_va)),
        reverse=True,
    )
    return out[: max(1, int(goal_limit))]


def _pick_auto_goals(
    graph: UnifiedGraph,
    adjacency: Dict[int, Dict[int, Set[str]]],
    *,
    goal_structs: Sequence[str],
    auto_limit: int,
    goal_limit: int,
) -> List[GoalItem]:
    """根据 xref_count 和语义丰富度自动选择候选目标函数。"""
    items: List[GoalItem] = []
    for va, node in graph.nodes.items():
        xref_count = len(adjacency.get(int(va), {}))
        richness = _semantic_richness(node, goal_structs)
        items.append(
            GoalItem(
                entry_va=int(va),
                source="auto",
                xref_count=int(xref_count),
                richness=int(richness),
                manual_score=0,
            )
        )

    candidates = sorted(items, key=lambda x: (int(x.xref_count), int(x.richness), -int(x.entry_va)), reverse=True)
    candidates = candidates[: max(1, int(auto_limit))]
    return candidates[: max(1, int(goal_limit))]
