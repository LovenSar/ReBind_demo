"""depth/run_management.py

运行生命周期管理：RunLayout 数据类、运行目录初始化、checkpoint 读写、
manifest / journal 日志写入，以及运行恢复签名。

从 engine.py 拆分而来，不包含 LLM 推理、图构建或目标选择逻辑。
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import yaml


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

    raw_run_id = str(run_id or "").strip()
    rid = _safe_stem(raw_run_id) if raw_run_id else ""
    if not rid:
        if resume:
            latest = _pick_latest_run_id(sample_root)
            if not latest:
                raise SystemExit(f"未找到可恢复 run: {sample_root}")
            rid = latest
        else:
            rid = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

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

_RESUME_SIGNATURE_EXCLUDE = frozenset(
    {
        "resume",
        "force_resume",
        "run_id",
        "runs_root",
        "output",
        "log_raw_llm",
        "no_console_progress",
        "task_config",
        "phase7_task_loaded_from",
        "llm_config",
    }
)


def _llm_config_bytes_sha256(llm_config_path: Optional[str]) -> Optional[str]:
    """对 ``--llm-config`` 文件原始字节做 SHA256（仅用于与旧逻辑对照）。"""
    if not llm_config_path:
        return None
    p = Path(str(llm_config_path)).expanduser().resolve()
    if not p.is_file():
        return None
    h = hashlib.sha256()
    with p.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _llm_config_semantic_sha256(llm_config_path: Optional[str]) -> Optional[str]:
    """对 YAML 解析后的对象做规范化 JSON 再 SHA256。

    Phase7 未指定路径时固定使用仓库根 ``config.yaml``，因此配置变更会进入续跑签名。
    传入路径仅服务旧 manifest 的兼容判定。
    """
    p = (
        Path(str(llm_config_path)).expanduser().resolve()
        if llm_config_path
        else Path(__file__).resolve().parents[3] / "config.yaml"
    )
    if not p.is_file():
        return None
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except Exception:
        return None
    if data is None:
        data = {}
    try:
        enc = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except TypeError:
        enc = json.dumps(data, default=str, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(enc.encode("utf-8")).hexdigest()


def _build_resume_signature_payload(args: argparse.Namespace, db_path: Path) -> Dict[str, Any]:
    """构造可落盘、可审计的规范化续跑参数快照。"""
    raw = vars(args)
    payload: Dict[str, Any] = {
        k: raw[k] for k in sorted(raw.keys()) if k not in _RESUME_SIGNATURE_EXCLUDE
    }
    payload["db_path"] = str(db_path)
    payload["llm_config_semantic_sha256"] = _llm_config_semantic_sha256(raw.get("llm_config"))
    return payload


def _build_resume_signature(args: argparse.Namespace, db_path: Path) -> str:
    """生成运行参数的 SHA256 摘要，用于检测断点续跑时参数是否变化。"""
    payload = _build_resume_signature_payload(args, db_path)
    enc = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(enc.encode("utf-8")).hexdigest()


def _build_resume_signature_llm_path_only(args: argparse.Namespace, db_path: Path) -> str:
    """旧版签名：把 ``--llm-config`` 的完整路径纳入 hash（与临时 YAML 文件名耦合）。"""
    raw = vars(args)
    payload: Dict[str, Any] = {
        k: raw[k] for k in sorted(raw.keys()) if k not in (_RESUME_SIGNATURE_EXCLUDE - {"llm_config"})
    }
    payload["db_path"] = str(db_path)
    enc = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(enc.encode("utf-8")).hexdigest()


def _deep_equal_manifest_value(a: Any, b: Any) -> bool:
    """manifest 与当前 argparse 值的宽松相等（浮点、嵌套结构）。"""
    if isinstance(a, float) or isinstance(b, float):
        try:
            return math.isclose(float(a), float(b), rel_tol=0.0, abs_tol=1e-9)
        except (TypeError, ValueError):
            return False
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return False
        return all(_deep_equal_manifest_value(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        keys = set(a.keys()) | set(b.keys())
        for key in keys:
            left = a.get(key)
            right = b.get(key)
            # 新增的可选 CLI 参数在旧 manifest 中不存在时，默认 None 与缺省等价；
            # 非空值仍会被当成语义变化而拒绝恢复。
            if key not in a and right is None:
                continue
            if key not in b and left is None:
                continue
            if not _deep_equal_manifest_value(left, right):
                return False
        return True
    return a == b


def resume_signature_compatible_with_manifest_semantics(
    manifest_path: Path,
    args: argparse.Namespace,
    db_path: Path,
) -> bool:
    """仅当 manifest 中的规范化参数快照与当前完全一致时允许续跑。"""
    if not manifest_path.is_file():
        return False
    try:
        man = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return False
    previous = man.get("resume_signature_payload")
    if not isinstance(previous, dict):
        # 旧 manifest 没有保存 LLM 配置语义摘要，无法安全证明一致。
        return False
    current = _build_resume_signature_payload(args, db_path)
    return _deep_equal_manifest_value(previous, current)


def resume_signature_compatible_with_manifest(
    prev_sig: str,
    current_sig: str,
    args: argparse.Namespace,
    db_path: Path,
    manifest_path: Path,
) -> bool:
    """当前签名与 checkpoint 不一致时，判断是否因旧版 ``llm_config`` 路径策略导致。

    若 manifest 中仍保存历史上使用过的 ``--llm-config`` 路径，且与当前 YAML 语义一致，
    则视为可续跑（无需每次 ``--force-resume``）。
    """
    if prev_sig == current_sig:
        return True
    if not manifest_path.is_file():
        return False
    try:
        man = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return False
    old_args = man.get("args")
    if not isinstance(old_args, dict):
        return False
    old_llm = old_args.get("llm_config")
    if not old_llm:
        return False
    merged = copy.copy(args)
    merged.llm_config = old_llm
    legacy = _build_resume_signature_llm_path_only(merged, db_path)
    if prev_sig != legacy:
        return False
    old_sha = _llm_config_semantic_sha256(old_llm)
    cur_sha = _llm_config_semantic_sha256(getattr(args, "llm_config", None))
    if old_sha is None or cur_sha is None:
        return False
    return old_sha == cur_sha
