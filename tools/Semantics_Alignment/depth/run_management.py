"""depth/run_management.py

运行生命周期管理：RunLayout 数据类、运行目录初始化、checkpoint 读写、
manifest / journal 日志写入，以及运行恢复签名。

从 engine.py 拆分而来，不包含 LLM 推理、图构建或目标选择逻辑。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


# ──────────────────────────────────────────────────────────────────────────────
# 数据结构
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class RunLayout:
    """单次运行的全套输出路径。"""
    sample_tag: str
    run_id: str
    run_dir: Path
    artifacts_dir: Path
    logs_dir: Path
    checkpoints_dir: Path
    reports_dir: Path
    out_file: Path
    backup_file: Path
    gen1_deepest_file: Path
    manifest_file: Path
    checkpoint_file: Path
    journal_file: Path
    llm_poll_log_file: Path
    llm_trace_file: Path


# ──────────────────────────────────────────────────────────────────────────────
# 文件 I/O 工具
# ──────────────────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _write_json_file(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)
    tmp.replace(path)


def _append_jsonl(path: Path, event: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(event, ensure_ascii=False) + "\n")


# ──────────────────────────────────────────────────────────────────────────────
# 运行路径构建
# ──────────────────────────────────────────────────────────────────────────────

def _safe_stem(text: str) -> str:
    s = str(text or "").strip()
    if not s:
        return "unknown"
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)


def _build_output_paths(
    db_path: Path,
    input_path: Optional[str],
    explicit_output: Optional[str],
) -> Tuple[Path, Path, Path]:
    if explicit_output:
        out_file = Path(explicit_output).expanduser().resolve()
        out_dir = out_file.parent
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = out_dir / f"backup_{ts}.json"
        return out_dir, out_file, backup_file

    input_name = Path(input_path).name if input_path else db_path.stem
    run_dir = db_path.parent / f"goal_engine_runs_{_safe_stem(input_name)}"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = run_dir / f"goal_run_{ts}.json"
    backup_file = run_dir / f"goal_backup_{ts}.json"
    return run_dir, out_file, backup_file


def _build_gen1_deepest_output_path(out_file: Path) -> Path:
    return out_file.with_name(f"{out_file.stem}.gen1_deepest.json")


def _pick_latest_run_id(sample_root: Path) -> Optional[str]:
    if not sample_root.exists() or not sample_root.is_dir():
        return None
    candidates = [p for p in sample_root.iterdir() if p.is_dir()]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0].name


def _build_run_layout(
    *,
    db_path: Path,
    input_path: Optional[str],
    explicit_output: Optional[str],
    runs_root: Optional[str],
    run_id: Optional[str],
    resume: bool,
) -> RunLayout:
    """初始化单次运行的所有输出路径。"""
    sample_name = Path(input_path).name if input_path else db_path.stem
    sample_tag = _safe_stem(sample_name)

    root = Path(runs_root).expanduser().resolve() if runs_root else (db_path.parent / "runs")
    sample_root = root / sample_tag

    rid = _safe_stem(str(run_id or "").strip())
    if not rid:
        if resume:
            latest = _pick_latest_run_id(sample_root)
            if not latest:
                raise SystemExit(f"未找到可恢复 run: {sample_root}")
            rid = latest
        else:
            rid = datetime.now().strftime("%Y%m%d_%H%M%S")

    run_dir = sample_root / rid
    artifacts_dir = run_dir / "artifacts"
    logs_dir = run_dir / "logs"
    checkpoints_dir = run_dir / "checkpoints"
    reports_dir = run_dir / "reports"

    if explicit_output:
        out_file = Path(explicit_output).expanduser().resolve()
        backup_file = out_file.with_name("goal_backup.json")
        gen1_file = out_file.with_name("goal_gen1_deepest.json")
    else:
        out_file = reports_dir / "goal_run.json"
        backup_file = reports_dir / "goal_backup.json"
        gen1_file = reports_dir / "goal_gen1_deepest.json"

    return RunLayout(
        sample_tag=sample_tag,
        run_id=rid,
        run_dir=run_dir,
        artifacts_dir=artifacts_dir,
        logs_dir=logs_dir,
        checkpoints_dir=checkpoints_dir,
        reports_dir=reports_dir,
        out_file=out_file,
        backup_file=backup_file,
        gen1_deepest_file=gen1_file,
        manifest_file=run_dir / "manifest.json",
        checkpoint_file=checkpoints_dir / "state.json",
        journal_file=logs_dir / "journal.jsonl",
        llm_poll_log_file=logs_dir / "llm_poll.jsonl",
        llm_trace_file=logs_dir / "llm_trace.jsonl",
    )


# ──────────────────────────────────────────────────────────────────────────────
# Checkpoint / Manifest / Journal
# ──────────────────────────────────────────────────────────────────────────────

def _load_checkpoint(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fp:
            data = json.load(fp)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_checkpoint(path: Path, state: Dict[str, Any]) -> None:
    payload = dict(state)
    payload["ts"] = _now_iso()
    _write_json_file(path, payload)


def _write_manifest(layout: RunLayout, payload: Dict[str, Any]) -> None:
    _write_json_file(layout.manifest_file, payload)


def _log_event(layout: RunLayout, event_type: str, **data: Any) -> None:
    event = {"ts": _now_iso(), "event": str(event_type)}
    event.update(data)
    _append_jsonl(layout.journal_file, event)


def _checkpoint_stage(layout: RunLayout, state: Dict[str, Any], stage: str) -> None:
    payload = dict(state)
    payload["stage"] = str(stage)
    _save_checkpoint(layout.checkpoint_file, payload)


# ──────────────────────────────────────────────────────────────────────────────
# 恢复签名
# ──────────────────────────────────────────────────────────────────────────────

def _build_resume_signature(args: argparse.Namespace, db_path: Path) -> str:
    """生成运行参数的 SHA256 摘要，用于检测断点续跑时参数是否变化。"""
    raw = vars(args)
    excluded = {"resume", "force_resume", "run_id", "runs_root", "output", "log_raw_llm"}
    payload: Dict[str, Any] = {k: raw[k] for k in sorted(raw.keys()) if k not in excluded}
    payload["db_path"] = str(db_path)
    enc = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(enc.encode("utf-8")).hexdigest()
