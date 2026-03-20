"""depth/blackboard.py

语义黑板（Semantic Blackboard）：跨子树的共享语义层。

职责：
- 子树分析完成后写入语义条目（函数名、签名、结构体成员、变量语义、摘要）
- 新子树启动前按地址/关键词/向量查询已有语义
- 多子树结论冲突时按置信度+来源权重仲裁
- 持久化到 JSON 文件，支持增量更新与断点续跑

协议格式：
    每条条目（BlackboardEntry）包含：
    - entry_va: 函数入口地址
    - kind: 条目类型 (func_name / signature / summary / struct_field / lvar / tag)
    - value: 语义值（字符串）
    - confidence: 置信度 0-100
    - source: 来源标签（gen1 / gen2 / manual / breadth）
    - generation: 代际编号
    - goal_index: 产生该条目的目标索引
    - ts: 写入时间戳

冲突仲裁规则（_resolve_conflict）：
    1. manual > gen1 > gen2 > breadth
    2. 同来源时取 confidence 更高者
    3. confidence 相同时保留更新的（后写入优先）
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


SOURCE_PRIORITY: Dict[str, int] = {
    "manual": 100,
    "gen1": 80,
    "gen2": 60,
    "breadth": 40,
    "auto": 20,
}

ENTRY_KINDS = frozenset({
    "func_name",
    "signature",
    "summary",
    "struct_field",
    "lvar",
    "tag",
    "note",
})


@dataclass
class BlackboardEntry:
    """单条语义黑板条目。"""
    entry_va: int
    kind: str
    value: str
    confidence: int = 0
    source: str = "auto"
    generation: int = 0
    goal_index: int = 0
    ts: str = ""

    def priority_key(self) -> Tuple[int, int, str]:
        return (
            SOURCE_PRIORITY.get(self.source, 0),
            self.confidence,
            self.ts,
        )


@dataclass
class ConflictRecord:
    """一次冲突仲裁记录。"""
    entry_va: int
    kind: str
    winner: BlackboardEntry
    loser: BlackboardEntry
    reason: str


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _entry_to_dict(e: BlackboardEntry) -> Dict[str, Any]:
    return {
        "entry_va": int(e.entry_va),
        "kind": str(e.kind),
        "value": str(e.value),
        "confidence": int(e.confidence),
        "source": str(e.source),
        "generation": int(e.generation),
        "goal_index": int(e.goal_index),
        "ts": str(e.ts or ""),
    }


def _entry_from_dict(d: Dict[str, Any]) -> BlackboardEntry:
    return BlackboardEntry(
        entry_va=int(d.get("entry_va", 0) or 0),
        kind=str(d.get("kind") or "note"),
        value=str(d.get("value") or ""),
        confidence=int(d.get("confidence", 0) or 0),
        source=str(d.get("source") or "auto"),
        generation=int(d.get("generation", 0) or 0),
        goal_index=int(d.get("goal_index", 0) or 0),
        ts=str(d.get("ts") or ""),
    )


def _resolve_conflict(
    existing: BlackboardEntry,
    incoming: BlackboardEntry,
) -> Tuple[BlackboardEntry, BlackboardEntry, str]:
    """仲裁两条冲突条目，返回 (winner, loser, reason)。"""
    e_prio = existing.priority_key()
    i_prio = incoming.priority_key()

    if i_prio > e_prio:
        return incoming, existing, "incoming_higher_priority"
    if e_prio > i_prio:
        return existing, incoming, "existing_higher_priority"
    return incoming, existing, "tie_prefer_newer"


class SemanticBlackboard:
    """跨子树语义共享层。

    内部结构：
        _store: Dict[int, Dict[str, BlackboardEntry]]
            外层 key = entry_va
            内层 key = kind
            每个 (entry_va, kind) 只保留仲裁胜出的一条
        _conflicts: List[ConflictRecord]
            所有冲突仲裁历史
        _keyword_index: Dict[str, Set[int]]
            value 中的关键词 -> entry_va 集合，用于查询
    """

    def __init__(self) -> None:
        self._store: Dict[int, Dict[str, BlackboardEntry]] = defaultdict(dict)
        self._conflicts: List[ConflictRecord] = []
        self._keyword_index: Dict[str, Set[int]] = defaultdict(set)
        self._dirty: bool = False

    @property
    def total_entries(self) -> int:
        return sum(len(v) for v in self._store.values())

    @property
    def conflict_count(self) -> int:
        return len(self._conflicts)

    # ── 写入 ──────────────────────────────────────────────────────────────

    def write(
        self,
        entry_va: int,
        kind: str,
        value: str,
        *,
        confidence: int = 50,
        source: str = "auto",
        generation: int = 0,
        goal_index: int = 0,
    ) -> BlackboardEntry:
        """写入一条语义条目。若已有同 (va, kind) 条目则自动仲裁。"""
        va = int(entry_va)
        k = str(kind).strip()
        incoming = BlackboardEntry(
            entry_va=va,
            kind=k,
            value=str(value).strip(),
            confidence=max(0, min(100, int(confidence))),
            source=str(source),
            generation=int(generation),
            goal_index=int(goal_index),
            ts=_now_iso(),
        )

        existing = self._store[va].get(k)
        if existing is not None and existing.value:
            winner, loser, reason = _resolve_conflict(existing, incoming)
            if loser.value:
                self._conflicts.append(ConflictRecord(
                    entry_va=va, kind=k,
                    winner=winner, loser=loser, reason=reason,
                ))
            self._store[va][k] = winner
        else:
            self._store[va][k] = incoming

        self._rebuild_keyword_index_for(va, k)
        self._dirty = True
        return self._store[va][k]

    def write_batch(
        self,
        items: Sequence[Dict[str, Any]],
        *,
        source: str = "auto",
        generation: int = 0,
        goal_index: int = 0,
    ) -> int:
        """批量写入，返回实际写入条数。"""
        count = 0
        for item in items:
            va = item.get("entry_va")
            kind = item.get("kind")
            value = item.get("value")
            if va is None or not kind or not value:
                continue
            self.write(
                entry_va=int(va),
                kind=str(kind),
                value=str(value),
                confidence=int(item.get("confidence", 50) or 50),
                source=str(item.get("source") or source),
                generation=int(item.get("generation") or generation),
                goal_index=int(item.get("goal_index") or goal_index),
            )
            count += 1
        return count

    # ── 读取 / 查询 ──────────────────────────────────────────────────────

    def read(self, entry_va: int, kind: Optional[str] = None) -> List[BlackboardEntry]:
        """按地址读取语义条目。kind 为 None 时返回该地址所有条目。"""
        va = int(entry_va)
        bucket = self._store.get(va)
        if not bucket:
            return []
        if kind is not None:
            e = bucket.get(str(kind).strip())
            return [e] if e else []
        return list(bucket.values())

    def read_multi(self, entry_vas: Sequence[int]) -> Dict[int, List[BlackboardEntry]]:
        """批量读取多个地址的语义条目。"""
        result: Dict[int, List[BlackboardEntry]] = {}
        for va in entry_vas:
            entries = self.read(int(va))
            if entries:
                result[int(va)] = entries
        return result

    def query_by_keyword(self, keyword: str) -> List[BlackboardEntry]:
        """按关键词查询相关条目（模糊匹配 value 中的 token）。"""
        kw = str(keyword or "").strip().lower()
        if not kw:
            return []
        vas = self._keyword_index.get(kw, set())
        results: List[BlackboardEntry] = []
        for va in vas:
            for entry in self._store.get(va, {}).values():
                if kw in entry.value.lower():
                    results.append(entry)
        results.sort(key=lambda e: e.priority_key(), reverse=True)
        return results

    def query_by_kinds(self, kinds: Sequence[str]) -> List[BlackboardEntry]:
        """按条目类型查询所有匹配条目。"""
        target_kinds = {str(k).strip() for k in kinds}
        results: List[BlackboardEntry] = []
        for bucket in self._store.values():
            for k, entry in bucket.items():
                if k in target_kinds:
                    results.append(entry)
        results.sort(key=lambda e: e.priority_key(), reverse=True)
        return results

    def all_entries(self) -> List[BlackboardEntry]:
        """返回所有条目，按 (entry_va, kind) 排序。"""
        out: List[BlackboardEntry] = []
        for va in sorted(self._store.keys()):
            for k in sorted(self._store[va].keys()):
                out.append(self._store[va][k])
        return out

    def summary_stats(self) -> Dict[str, Any]:
        """返回黑板统计摘要。"""
        kind_counts: Dict[str, int] = defaultdict(int)
        source_counts: Dict[str, int] = defaultdict(int)
        for bucket in self._store.values():
            for entry in bucket.values():
                kind_counts[entry.kind] += 1
                source_counts[entry.source] += 1
        return {
            "total_entries": self.total_entries,
            "total_addresses": len(self._store),
            "conflict_count": self.conflict_count,
            "by_kind": dict(kind_counts),
            "by_source": dict(source_counts),
        }

    # ── 上下文构建（给 LLM 的查询接口）───────────────────────────────────

    def build_context_for_node(
        self,
        entry_va: int,
        *,
        neighbor_vas: Optional[Sequence[int]] = None,
        max_neighbor_entries: int = 20,
    ) -> Dict[str, Any]:
        """为 LLM 分析某节点时构建语义上下文。

        返回该节点已有语义 + 邻居节点的相关语义摘要。
        """
        va = int(entry_va)
        self_entries = self.read(va)

        neighbor_entries: List[Dict[str, Any]] = []
        if neighbor_vas:
            count = 0
            for nva in neighbor_vas:
                if count >= max_neighbor_entries:
                    break
                for e in self.read(int(nva)):
                    if count >= max_neighbor_entries:
                        break
                    neighbor_entries.append({
                        "entry_va": f"0x{e.entry_va:08X}",
                        "kind": e.kind,
                        "value": e.value,
                        "confidence": e.confidence,
                        "source": e.source,
                    })
                    count += 1

        return {
            "target_va": f"0x{va:08X}",
            "known_semantics": [_entry_to_dict(e) for e in self_entries],
            "neighbor_semantics": neighbor_entries,
        }

    # ── 持久化 ────────────────────────────────────────────────────────────

    def save(self, path: Path) -> None:
        """将黑板状态持久化到 JSON 文件。"""
        payload = {
            "ts": _now_iso(),
            "stats": self.summary_stats(),
            "entries": [_entry_to_dict(e) for e in self.all_entries()],
            "conflicts": [
                {
                    "entry_va": int(c.entry_va),
                    "kind": str(c.kind),
                    "winner": _entry_to_dict(c.winner),
                    "loser": _entry_to_dict(c.loser),
                    "reason": str(c.reason),
                }
                for c in self._conflicts
            ],
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as fp:
            json.dump(payload, fp, ensure_ascii=False, indent=2)
        tmp.replace(path)
        self._dirty = False

    def load(self, path: Path) -> None:
        """从 JSON 文件恢复黑板状态（增量合并到当前内容）。"""
        if not path.exists():
            return
        with path.open("r", encoding="utf-8") as fp:
            data = json.load(fp)
        if not isinstance(data, dict):
            return

        for item in data.get("entries", []):
            if not isinstance(item, dict):
                continue
            entry = _entry_from_dict(item)
            if not entry.value:
                continue
            existing = self._store[entry.entry_va].get(entry.kind)
            if existing is not None:
                winner, loser, reason = _resolve_conflict(existing, entry)
                self._store[entry.entry_va][entry.kind] = winner
            else:
                self._store[entry.entry_va][entry.kind] = entry

        self._rebuild_all_keyword_index()
        self._dirty = False

    @property
    def dirty(self) -> bool:
        return self._dirty

    # ── 内部索引 ──────────────────────────────────────────────────────────

    def _rebuild_keyword_index_for(self, va: int, kind: str) -> None:
        entry = self._store.get(va, {}).get(kind)
        if not entry:
            return
        tokens = _extract_tokens(entry.value)
        for t in tokens:
            self._keyword_index[t].add(va)

    def _rebuild_all_keyword_index(self) -> None:
        self._keyword_index.clear()
        for va, bucket in self._store.items():
            for entry in bucket.values():
                for t in _extract_tokens(entry.value):
                    self._keyword_index[t].add(va)


def _extract_tokens(text: str) -> Set[str]:
    """从文本中提取用于索引的关键词 token。"""
    import re
    raw = str(text or "").lower()
    return {m for m in re.findall(r"[a-z][a-z0-9_]{2,}", raw)}


# ── 从 LLM 分析结果自动回填黑板的工具函数 ─────────────────────────────────

def populate_from_profile(
    board: SemanticBlackboard,
    entry_va: int,
    profile: Dict[str, Any],
    *,
    source: str = "gen1",
    generation: int = 1,
    goal_index: int = 0,
) -> int:
    """将一个 LLM 分析 profile 的语义结果写入黑板。返回写入条数。"""
    va = int(entry_va)
    count = 0
    confidence = int(profile.get("confidence_score", 50) or 50)

    name = str(profile.get("name") or "").strip()
    if name:
        board.write(va, "func_name", name,
                    confidence=confidence, source=source,
                    generation=generation, goal_index=goal_index)
        count += 1

    sig = str(profile.get("summary_signature") or "").strip()
    if sig:
        board.write(va, "signature", sig,
                    confidence=confidence, source=source,
                    generation=generation, goal_index=goal_index)
        count += 1

    summary = str(profile.get("semantic_summary") or "").strip()
    if summary:
        board.write(va, "summary", summary,
                    confidence=confidence, source=source,
                    generation=generation, goal_index=goal_index)
        count += 1

    structured = profile.get("structured_analysis")
    if isinstance(structured, str):
        try:
            structured = json.loads(structured)
        except Exception:
            structured = None
    if isinstance(structured, dict):
        tags = structured.get("tags") or []
        for tag in tags:
            tag_str = str(tag or "").strip()
            if tag_str:
                board.write(va, "tag", tag_str,
                            confidence=confidence, source=source,
                            generation=generation, goal_index=goal_index)
                count += 1

        notes = str(structured.get("notes") or "").strip()
        if notes:
            board.write(va, "note", notes,
                        confidence=confidence, source=source,
                        generation=generation, goal_index=goal_index)
            count += 1

    return count


def populate_from_step_result(
    board: SemanticBlackboard,
    step: Dict[str, Any],
    *,
    source: str = "gen1",
    generation: int = 1,
    goal_index: int = 0,
) -> int:
    """将 deep_path_step 的单步 LLM 结果写入黑板。"""
    count = 0
    confidence = int(float(step.get("confidence", 0.5) or 0.5) * 100)

    from_name = str(step.get("from") or "").strip()
    likely_input = str(step.get("likely_initial_input") or "").strip()
    gate = str(step.get("gate_condition") or "").strip()
    reasoning = str(step.get("reasoning") or "").strip()

    if likely_input and from_name:
        board.write(0, "note", f"[{from_name}] initial_input: {likely_input}",
                    confidence=confidence, source=source,
                    generation=generation, goal_index=goal_index)
        count += 1

    if gate and from_name:
        board.write(0, "note", f"[{from_name}] gate: {gate}",
                    confidence=confidence, source=source,
                    generation=generation, goal_index=goal_index)
        count += 1

    if reasoning:
        board.write(0, "note", f"reasoning: {reasoning}",
                    confidence=confidence, source=source,
                    generation=generation, goal_index=goal_index)
        count += 1

    return count
