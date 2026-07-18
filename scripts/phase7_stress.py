#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase7 legacy/practical A/B stress benchmark.

The runner clones every SQLite database per run, disables DB write-back, executes
legacy and practical engines with the same sample configuration, then exports
JSONL/JSON/CSV/Markdown summaries. Optional expectations in the manifest turn
human-reviewed addresses, paths and semantic tokens into recall metrics.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import re
import shutil
import signal
import sqlite3
import statistics
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple

try:  # Optional. The benchmark still works without memory sampling.
    import psutil  # type: ignore
except Exception:  # pragma: no cover - environment dependent
    psutil = None


_REPO_ROOT = Path(__file__).resolve().parents[1]
_LEGACY_ENGINE = _REPO_ROOT / "tools" / "Semantics_Alignment" / "depth" / "engine.py"
_PRACTICAL_ENGINE = _REPO_ROOT / "tools" / "Semantics_Alignment" / "depth" / "practical_engine.py"

_PROFILES: Dict[str, Dict[str, Any]] = {
    "smoke": {"repeat": 1, "practical_budgets": [24]},
    "balanced": {"repeat": 2, "practical_budgets": [12, 24, 40]},
    "soak": {"repeat": 3, "practical_budgets": [12, 24, 40, 64]},
}

_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,}")
_SLUG_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_USAGE_KEYS = (
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "api_calls",
    "successful_api_calls",
    "failed_api_calls",
)


@dataclass(frozen=True)
class RunSpec:
    sample_name: str
    engine: str
    repeat_index: int
    practical_budget: Optional[int]
    input_path: Optional[Path]
    db_path: Path
    task_config: Optional[Path]
    ida_dir: Optional[Path]
    binary_id: Optional[int]
    goal_keywords: Tuple[str, ...]
    goal_vas: Tuple[str, ...]
    goal_structs: Tuple[str, ...]
    common_args: Tuple[str, ...]
    extra_args: Tuple[str, ...]
    expectations: Mapping[str, Any]

    @property
    def variant(self) -> str:
        if self.engine == "legacy":
            return "legacy"
        return f"practical-b{int(self.practical_budget or 0)}"

    @property
    def run_key(self) -> str:
        return f"{_slug(self.sample_name)}__{self.variant}__r{self.repeat_index:02d}"


@dataclass
class ProcessResult:
    return_code: int
    timed_out: bool
    interrupted: bool
    wall_time_sec: float
    peak_rss_mb: Optional[float]


def _slug(value: str) -> str:
    text = _SLUG_RE.sub("-", str(value).strip()).strip("-.")
    return text or "sample"


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def _resolve_path(value: Any, base_dir: Path, *, required: bool = False) -> Optional[Path]:
    if value is None or str(value).strip() == "":
        if required:
            raise ValueError("required path is missing")
        return None
    expanded = os.path.expandvars(os.path.expanduser(str(value)))
    path = Path(expanded)
    if not path.is_absolute():
        path = base_dir / path
    return path.resolve()


def _list_of_strings(value: Any, field_name: str) -> Tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a JSON array")
    return tuple(str(item) for item in value)


def _validate_expectations(value: Mapping[str, Any], field_name: str) -> None:
    goal_vas = value.get("goal_vas")
    if goal_vas is not None and not isinstance(goal_vas, list):
        raise ValueError(f"{field_name}.goal_vas must be a JSON array")

    paths = value.get("path_subsequences")
    if paths is not None:
        if not isinstance(paths, list) or any(
            not isinstance(path, list) or not path for path in paths
        ):
            raise ValueError(
                f"{field_name}.path_subsequences must be an array of non-empty arrays"
            )

    profile_tokens = value.get("profile_tokens")
    if profile_tokens is not None:
        if not isinstance(profile_tokens, dict):
            raise ValueError(f"{field_name}.profile_tokens must be a JSON object")
        for va, tokens in profile_tokens.items():
            if not isinstance(tokens, list) or not tokens:
                raise ValueError(
                    f"{field_name}.profile_tokens[{va!r}] must be a non-empty array"
                )


def load_manifest(path: Path) -> Dict[str, Any]:
    payload = _read_json(path)
    if not isinstance(payload, dict):
        raise ValueError("manifest root must be a JSON object")
    samples = payload.get("samples")
    if not isinstance(samples, list) or not samples:
        raise ValueError("manifest.samples must be a non-empty array")
    return payload


def _parse_budgets(raw: Optional[str]) -> Optional[List[int]]:
    if raw is None:
        return None
    values: List[int] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        value = int(item)
        if value < 1:
            raise ValueError("practical budgets must be positive integers")
        if value not in values:
            values.append(value)
    if not values:
        raise ValueError("at least one practical budget is required")
    return values


def build_run_matrix(
    manifest_path: Path,
    manifest: Mapping[str, Any],
    *,
    profile: str,
    repeat_override: Optional[int],
    budgets_override: Optional[Sequence[int]],
    engines_override: Optional[Sequence[str]],
) -> List[RunSpec]:
    base_dir = manifest_path.parent
    profile_cfg = dict(_PROFILES[profile])
    defaults = manifest.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise ValueError("manifest.defaults must be an object")

    repeat = int(
        repeat_override
        if repeat_override is not None
        else defaults.get("repeat", profile_cfg["repeat"])
    )
    if repeat < 1:
        raise ValueError("repeat must be >= 1")

    budgets_raw = (
        list(budgets_override)
        if budgets_override is not None
        else defaults.get("practical_budgets", profile_cfg["practical_budgets"])
    )
    if not isinstance(budgets_raw, list) or not budgets_raw:
        raise ValueError("practical_budgets must be a non-empty array")
    budgets = sorted({max(1, int(value)) for value in budgets_raw})

    engines_raw = list(engines_override) if engines_override else defaults.get("engines", ["legacy", "practical"])
    if not isinstance(engines_raw, list) or not engines_raw:
        raise ValueError("engines must be a non-empty array")
    engines = [str(value).strip().lower() for value in engines_raw]
    invalid = sorted(set(engines) - {"legacy", "practical"})
    if invalid:
        raise ValueError(f"unsupported engines: {invalid}")

    default_common_args = _list_of_strings(defaults.get("common_args", []), "defaults.common_args")
    default_expectations = defaults.get("expectations") or {}
    if not isinstance(default_expectations, dict):
        raise ValueError("defaults.expectations must be an object")
    _validate_expectations(default_expectations, "defaults.expectations")

    matrix: List[RunSpec] = []
    seen_names: set[str] = set()
    for index, raw_sample in enumerate(manifest["samples"], 1):
        if not isinstance(raw_sample, dict):
            raise ValueError(f"samples[{index}] must be an object")
        name = str(raw_sample.get("name") or f"sample-{index}").strip()
        if name in seen_names:
            raise ValueError(f"duplicate sample name: {name}")
        seen_names.add(name)

        db_path = _resolve_path(raw_sample.get("db"), base_dir, required=True)
        assert db_path is not None
        input_path = _resolve_path(raw_sample.get("input"), base_dir)
        task_config = _resolve_path(raw_sample.get("task_config"), base_dir)
        ida_dir = _resolve_path(raw_sample.get("ida_dir"), base_dir)
        binary_id_raw = raw_sample.get("binary_id")
        binary_id = int(binary_id_raw) if binary_id_raw is not None else None

        expectations: Dict[str, Any] = dict(default_expectations)
        sample_expectations = raw_sample.get("expectations") or {}
        if not isinstance(sample_expectations, dict):
            raise ValueError(f"samples[{index}].expectations must be an object")
        _validate_expectations(sample_expectations, f"samples[{index}].expectations")
        expectations.update(sample_expectations)

        sample_common = _list_of_strings(raw_sample.get("common_args", []), f"samples[{index}].common_args")
        extra_args = _list_of_strings(raw_sample.get("extra_args", []), f"samples[{index}].extra_args")

        shared = dict(
            sample_name=name,
            input_path=input_path,
            db_path=db_path,
            task_config=task_config,
            ida_dir=ida_dir,
            binary_id=binary_id,
            goal_keywords=_list_of_strings(raw_sample.get("goal_keywords", []), f"samples[{index}].goal_keywords"),
            goal_vas=_list_of_strings(raw_sample.get("goal_vas", []), f"samples[{index}].goal_vas"),
            goal_structs=_list_of_strings(raw_sample.get("goal_structs", []), f"samples[{index}].goal_structs"),
            common_args=tuple([*default_common_args, *sample_common]),
            extra_args=extra_args,
            expectations=expectations,
        )

        for repeat_index in range(1, repeat + 1):
            if "legacy" in engines:
                matrix.append(
                    RunSpec(engine="legacy", repeat_index=repeat_index, practical_budget=None, **shared)
                )
            if "practical" in engines:
                for budget in budgets:
                    matrix.append(
                        RunSpec(
                            engine="practical",
                            repeat_index=repeat_index,
                            practical_budget=int(budget),
                            **shared,
                        )
                    )
    run_keys: Dict[str, str] = {}
    for spec in matrix:
        previous = run_keys.get(spec.run_key)
        if previous is not None:
            raise ValueError(
                "sample names collide after normalization: "
                f"{previous!r} and {spec.sample_name!r} both produce {spec.run_key!r}"
            )
        run_keys[spec.run_key] = spec.sample_name
    return matrix


def clone_sqlite(source: Path, destination: Path) -> None:
    if not source.is_file():
        raise FileNotFoundError(f"SQLite DB not found: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        destination.unlink()
    source_uri = f"file:{source.as_posix()}?mode=ro"
    src = sqlite3.connect(source_uri, uri=True, timeout=60)
    dst = sqlite3.connect(str(destination), timeout=60)
    try:
        src.backup(dst)
        dst.execute("PRAGMA wal_checkpoint(FULL)")
        dst.commit()
    finally:
        dst.close()
        src.close()


def build_command(
    spec: RunSpec,
    *,
    work_db: Path,
    run_dir: Path,
    llm_mode: Optional[str],
    engine_dry_run: bool,
) -> List[str]:
    engine_path = _LEGACY_ENGINE if spec.engine == "legacy" else _PRACTICAL_ENGINE
    command: List[str] = [sys.executable, str(engine_path)]
    if spec.input_path is not None:
        command.append(str(spec.input_path))
    command.extend(["--db", str(work_db)])

    if spec.task_config is not None:
        command.extend(["--task-config", str(spec.task_config)])
    if spec.ida_dir is not None:
        command.extend(["--phase7-5-ida-dir", str(spec.ida_dir)])
    if spec.binary_id is not None:
        command.extend(["--binary-id", str(spec.binary_id)])
    for value in spec.goal_keywords:
        command.extend(["--goal-keyword", value])
    for value in spec.goal_vas:
        command.extend(["--goal-va", value])
    for value in spec.goal_structs:
        command.extend(["--goal-struct", value])

    command.extend(spec.common_args)
    command.extend(spec.extra_args)

    if spec.engine == "practical":
        command.extend(["--practical-node-budget", str(int(spec.practical_budget or 24))])

    if llm_mode:
        command.extend(["--llm-mode", llm_mode])
    if engine_dry_run:
        command.append("--dry-run")

    # Safety/fairness overrides are appended last so every benchmark remains
    # isolated, resumeless and unable to mutate the source database.
    command.extend(
        [
            "--runs-root",
            str(run_dir / "engine-runs"),
            "--run-id",
            "benchmark",
            "--output",
            str(run_dir / "report.json"),
            "--no-apply-db",
            "--no-log-raw-llm",
            "--no-resume",
            "--no-force-resume",
            "--no-console-progress",
        ]
    )
    return command


def _process_tree_rss_mb(process: subprocess.Popen[Any]) -> Optional[float]:
    if psutil is None:
        return None
    try:
        root = psutil.Process(process.pid)
        members = [root, *root.children(recursive=True)]
        total = 0
        for member in members:
            try:
                total += int(member.memory_info().rss)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return total / (1024.0 * 1024.0)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def _terminate_process_tree(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    if psutil is not None:
        try:
            root = psutil.Process(process.pid)
            children = root.children(recursive=True)
            for child in children:
                try:
                    child.terminate()
                except psutil.NoSuchProcess:
                    pass
            root.terminate()
            _, alive = psutil.wait_procs([*children, root], timeout=5)
            for member in alive:
                try:
                    member.kill()
                except psutil.NoSuchProcess:
                    pass
            return
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
            time.sleep(1.0)
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass


def run_process(command: Sequence[str], run_dir: Path, timeout_seconds: float) -> ProcessResult:
    run_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = run_dir / "stdout.log"
    stderr_path = run_dir / "stderr.log"
    (run_dir / "command.json").write_text(
        json.dumps(list(command), ensure_ascii=False, indent=2), encoding="utf-8"
    )

    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    popen_kwargs: Dict[str, Any] = {}
    if os.name == "posix":
        popen_kwargs["start_new_session"] = True

    started = time.perf_counter()
    peak_rss_mb: Optional[float] = None
    timed_out = False
    interrupted = False
    with stdout_path.open("w", encoding="utf-8", errors="replace") as stdout_file, stderr_path.open(
        "w", encoding="utf-8", errors="replace"
    ) as stderr_file:
        process = subprocess.Popen(
            list(command),
            cwd=str(_REPO_ROOT),
            stdout=stdout_file,
            stderr=stderr_file,
            env=env,
            **popen_kwargs,
        )
        try:
            while process.poll() is None:
                current_rss = _process_tree_rss_mb(process)
                if current_rss is not None:
                    peak_rss_mb = max(peak_rss_mb or 0.0, current_rss)
                if timeout_seconds > 0 and (time.perf_counter() - started) > timeout_seconds:
                    timed_out = True
                    _terminate_process_tree(process)
                    break
                time.sleep(0.25)
            try:
                return_code = int(process.wait(timeout=10))
            except subprocess.TimeoutExpired:
                _terminate_process_tree(process)
                return_code = 124
        except KeyboardInterrupt:
            interrupted = True
            _terminate_process_tree(process)
            return_code = 130
        finally:
            if process.poll() is None:
                _terminate_process_tree(process)

    if timed_out:
        return_code = 124
    return ProcessResult(
        return_code=return_code,
        timed_out=timed_out,
        interrupted=interrupted,
        wall_time_sec=round(time.perf_counter() - started, 4),
        peak_rss_mb=round(peak_rss_mb, 3) if peak_rss_mb is not None else None,
    )


def _as_number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _usage_from_dict(value: Any) -> Dict[str, float]:
    if not isinstance(value, dict):
        return {key: 0.0 for key in _USAGE_KEYS}
    result = {key: _as_number(value.get(key, 0)) for key in _USAGE_KEYS}
    if result["total_tokens"] <= 0:
        result["total_tokens"] = result["prompt_tokens"] + result["completion_tokens"]
    return result


def _add_usage(target: MutableMapping[str, float], value: Mapping[str, float]) -> None:
    for key in _USAGE_KEYS:
        target[key] = float(target.get(key, 0.0)) + float(value.get(key, 0.0))


def _sum_usage_nodes(value: Any) -> Dict[str, float]:
    """Sum usage blocks while avoiding aggregate/step double counting."""
    total: Dict[str, float] = {key: 0.0 for key in _USAGE_KEYS}

    def visit(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        if not isinstance(node, dict):
            return

        aggregate = node.get("token_usage")
        if isinstance(aggregate, dict):
            _add_usage(total, _usage_from_dict(aggregate))
            for key, child in node.items():
                if key in {"token_usage", "steps", "usage_records"}:
                    continue
                visit(child)
            return

        usage = node.get("usage")
        if isinstance(usage, dict) and any(key in usage for key in _USAGE_KEYS):
            _add_usage(total, _usage_from_dict(usage))
            for key, child in node.items():
                if key in {"usage", "usage_records"}:
                    continue
                visit(child)
            return

        for child in node.values():
            visit(child)

    visit(value)
    return total


def _normalize_va(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    try:
        return f"0x{int(text, 0):x}"
    except ValueError:
        return text


def _path_vas(path: Any) -> List[str]:
    if not isinstance(path, dict):
        return []
    raw = path.get("path_vas") or path.get("nodes") or path.get("path") or []
    if not isinstance(raw, list):
        return []
    return [_normalize_va(value) for value in raw if _normalize_va(value)]


def _is_subsequence(expected: Sequence[str], actual: Sequence[str]) -> bool:
    if not expected:
        return True
    cursor = 0
    for value in actual:
        if value == expected[cursor]:
            cursor += 1
            if cursor == len(expected):
                return True
    return False


def _tokens(value: Any) -> set[str]:
    result: set[str] = set()
    for match in _TOKEN_RE.finditer(str(value or "")):
        expanded = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", match.group(0))
        result.update(token for token in expanded.lower().split("_") if len(token) >= 2)
    return result


def _percentile(values: Sequence[float], fraction: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(float(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * fraction
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def extract_report_metrics(report_path: Path, expectations: Mapping[str, Any]) -> Dict[str, Any]:
    if not report_path.is_file():
        return {"report_status": "missing"}
    try:
        report = _read_json(report_path)
    except Exception as exc:
        return {"report_status": "invalid", "report_error": str(exc)}
    if not isinstance(report, dict):
        return {"report_status": "invalid", "report_error": "report root is not an object"}

    goals = report.get("selected_goals") or []
    generations = report.get("generations") or []
    function_compare = report.get("function_compare") or []
    selected_profiles = report.get("selected_profiles") or []

    selected_goal_vas = {
        _normalize_va(item.get("entry_va"))
        for item in goals
        if isinstance(item, dict) and _normalize_va(item.get("entry_va"))
    }
    all_paths: List[List[str]] = []
    seen_paths: set[Tuple[str, ...]] = set()
    coverage_nodes: set[str] = set()
    generation_count = 0
    llm_steps = 0
    successful_llm_steps = 0
    confidences: List[float] = []
    usage_total: Dict[str, float] = {key: 0.0 for key in _USAGE_KEYS}

    for goal in generations if isinstance(generations, list) else []:
        if not isinstance(goal, dict):
            continue
        goal_index = int(goal.get("goal_index", 0) or 0)
        generation_count += int(goal.get("actual_generations", 0) or 0)
        for generation in goal.get("generations", []) or []:
            if not isinstance(generation, dict):
                continue
            for key in ("lambda_nodes", "lambda_nodes_union"):
                raw_nodes = generation.get(key) or []
                if isinstance(raw_nodes, list):
                    coverage_nodes.update(_normalize_va(value) for value in raw_nodes if _normalize_va(value))
            result = generation.get("result") or {}
            if not isinstance(result, dict):
                continue
            for path in result.get("paths", []) or []:
                normalized = _path_vas(path)
                path_key = tuple(normalized)
                if normalized and path_key not in seen_paths:
                    seen_paths.add(path_key)
                    all_paths.append(normalized)
            llm = result.get("llm") or {}
            shared_source = generation.get("shared_source_goal_index")
            owns_llm_result = shared_source is None or int(shared_source or 0) == goal_index
            if isinstance(llm, dict) and owns_llm_result:
                _add_usage(usage_total, _usage_from_dict(llm.get("token_usage")))
                for step in llm.get("steps", []) or []:
                    if not isinstance(step, dict):
                        continue
                    llm_steps += 1
                    if step.get("status") == "ok":
                        successful_llm_steps += 1
                        confidences.append(_as_number(step.get("confidence")))

    for item in function_compare if isinstance(function_compare, list) else []:
        if not isinstance(item, dict):
            continue
        for key in ("new_profile", "llm_compare"):
            payload = item.get(key) or {}
            if isinstance(payload, dict):
                _add_usage(
                    usage_total,
                    _usage_from_dict(payload.get("usage") or payload.get("token_usage")),
                )

    selected_new = 0
    evidence_gate_passed = 0
    evidence_gate_seen = 0
    profile_analysis_attempts = 0
    profile_analysis_successes = 0
    profile_compare_attempts = 0
    profile_compare_successes = 0
    for item in function_compare if isinstance(function_compare, list) else []:
        if not isinstance(item, dict):
            continue
        selection = item.get("selection") or {}
        if not isinstance(selection, dict):
            continue
        new_profile = item.get("new_profile") or {}
        if isinstance(new_profile, dict) and str(new_profile.get("status") or "") not in {
            "",
            "dry_run",
            "skipped",
        }:
            profile_analysis_attempts += 1
            if str(new_profile.get("status") or "") == "ok":
                profile_analysis_successes += 1
        llm_compare = item.get("llm_compare") or {}
        if isinstance(llm_compare, dict) and str(llm_compare.get("status") or "") not in {
            "",
            "dry_run",
            "skipped",
        }:
            profile_compare_attempts += 1
            if str(llm_compare.get("status") or "") == "ok":
                profile_compare_successes += 1
        if str(selection.get("selected") or "").lower() == "new":
            selected_new += 1
        gate = selection.get("evidence_gate")
        if isinstance(gate, dict):
            evidence_gate_seen += 1
            if bool(gate.get("passed")):
                evidence_gate_passed += 1

    deepest_depth = max((max(0, len(path) - 1) for path in all_paths), default=0)
    avg_confidence = statistics.fmean(confidences) if confidences else None

    expected_goal_vas = {
        _normalize_va(value)
        for value in expectations.get("goal_vas", []) or []
        if _normalize_va(value)
    }
    goal_recall = None
    if expected_goal_vas:
        goal_recall = len(expected_goal_vas & selected_goal_vas) / len(expected_goal_vas)

    expected_paths_raw = expectations.get("path_subsequences", []) or []
    path_recall = None
    if isinstance(expected_paths_raw, list) and expected_paths_raw:
        expected_paths = [
            [_normalize_va(value) for value in path if _normalize_va(value)]
            for path in expected_paths_raw
            if isinstance(path, list)
        ]
        expected_paths = [path for path in expected_paths if path]
        if expected_paths:
            hits = sum(
                1
                for expected in expected_paths
                if any(_is_subsequence(expected, actual) for actual in all_paths)
            )
            path_recall = hits / len(expected_paths)

    profile_tokens_raw = expectations.get("profile_tokens") or {}
    profile_token_recall = None
    if isinstance(profile_tokens_raw, dict) and profile_tokens_raw:
        profile_by_va: Dict[str, set[str]] = {}
        for profile in selected_profiles if isinstance(selected_profiles, list) else []:
            if not isinstance(profile, dict):
                continue
            va = _normalize_va(profile.get("entry_va"))
            if not va:
                continue
            combined = " ".join(
                str(profile.get(key) or "")
                for key in ("name", "summary_signature", "semantic_summary", "structured_analysis")
            )
            profile_by_va[va] = _tokens(combined)
        expected_count = 0
        matched_count = 0
        for raw_va, raw_tokens in profile_tokens_raw.items():
            if not isinstance(raw_tokens, list):
                continue
            expected: set[str] = set()
            for value in raw_tokens:
                expected.update(_tokens(value))
            expected_count += len(expected)
            matched_count += len(expected & profile_by_va.get(_normalize_va(raw_va), set()))
        if expected_count:
            profile_token_recall = matched_count / expected_count

    db_apply = report.get("db_apply") or {}
    applied_count = int(db_apply.get("applied_count", 0) or 0) if isinstance(db_apply, dict) else 0
    planned_count = int(db_apply.get("planned_count", 0) or 0) if isinstance(db_apply, dict) else 0
    llm_interactions = llm_steps + profile_analysis_attempts + profile_compare_attempts
    successful_llm_interactions = (
        successful_llm_steps + profile_analysis_successes + profile_compare_successes
    )

    return {
        "report_status": "ok",
        "selected_goal_count": len(selected_goal_vas),
        "generation_count": generation_count,
        "coverage_node_count": len(coverage_nodes),
        "path_count": len(all_paths),
        "deepest_path_depth": deepest_depth,
        "llm_steps": llm_steps,
        "successful_llm_steps": successful_llm_steps,
        "llm_step_success_rate": successful_llm_steps / llm_steps if llm_steps else None,
        "profile_analysis_attempts": profile_analysis_attempts,
        "profile_analysis_successes": profile_analysis_successes,
        "profile_compare_attempts": profile_compare_attempts,
        "profile_compare_successes": profile_compare_successes,
        "llm_interactions": llm_interactions,
        "successful_llm_interactions": successful_llm_interactions,
        "llm_interaction_success_rate": (
            successful_llm_interactions / llm_interactions if llm_interactions else None
        ),
        "avg_step_confidence": avg_confidence,
        "prompt_tokens": int(usage_total["prompt_tokens"]),
        "completion_tokens": int(usage_total["completion_tokens"]),
        "total_tokens": int(usage_total["total_tokens"]),
        "api_calls": int(usage_total["api_calls"]),
        "successful_api_calls": int(usage_total["successful_api_calls"]),
        "failed_api_calls": int(usage_total["failed_api_calls"]),
        "compare_count": len(function_compare) if isinstance(function_compare, list) else 0,
        "selected_new_count": selected_new,
        "evidence_gate_seen": evidence_gate_seen,
        "evidence_gate_passed": evidence_gate_passed,
        "evidence_gate_pass_rate": evidence_gate_passed / evidence_gate_seen if evidence_gate_seen else None,
        "db_apply_planned": planned_count,
        "db_apply_applied": applied_count,
        "goal_recall": goal_recall,
        "path_recall": path_recall,
        "profile_token_recall": profile_token_recall,
    }


def execute_run(
    spec: RunSpec,
    *,
    output_root: Path,
    timeout_seconds: float,
    llm_mode: Optional[str],
    engine_dry_run: bool,
    keep_work_db: bool,
) -> Dict[str, Any]:
    run_dir = output_root / "runs" / spec.run_key
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    work_db = run_dir / "work.db"

    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    base: Dict[str, Any] = {
        "sample": spec.sample_name,
        "engine": spec.engine,
        "variant": spec.variant,
        "repeat": spec.repeat_index,
        "practical_budget": spec.practical_budget,
        "run_key": spec.run_key,
        "started_at": started_at,
        "source_db": str(spec.db_path),
        "input_path": str(spec.input_path) if spec.input_path else None,
        "run_dir": str(run_dir),
    }

    try:
        clone_started = time.perf_counter()
        clone_sqlite(spec.db_path, work_db)
        base["db_clone_sec"] = round(time.perf_counter() - clone_started, 4)
        command = build_command(
            spec,
            work_db=work_db,
            run_dir=run_dir,
            llm_mode=llm_mode,
            engine_dry_run=engine_dry_run,
        )
        process_result = run_process(command, run_dir, timeout_seconds)
        base.update(asdict(process_result))
        if process_result.interrupted:
            base["status"] = "interrupted"
        elif process_result.timed_out:
            base["status"] = "timeout"
        else:
            base["status"] = "ok" if process_result.return_code == 0 else "failed"
        metrics = extract_report_metrics(run_dir / "report.json", spec.expectations)
        base.update(metrics)
        if base["status"] == "ok" and metrics.get("report_status") != "ok":
            base["status"] = "failed"
            base["runner_error"] = "engine exited successfully but produced no valid report"
        if base["status"] == "ok" and int(metrics.get("db_apply_applied", 0) or 0) != 0:
            base["status"] = "failed"
            base["runner_error"] = "safety violation: benchmark applied database updates"
        if base["status"] == "ok" and llm_mode == "on":
            interactions = int(metrics.get("llm_interactions", 0) or 0)
            successes = int(metrics.get("successful_llm_interactions", 0) or 0)
            if interactions <= 0:
                base["status"] = "failed"
                base["runner_error"] = "llm_mode=on produced no measurable LLM interactions"
            elif successes != interactions:
                base["status"] = "failed"
                base["runner_error"] = (
                    "LLM interactions were incomplete: "
                    f"successful={successes} attempted={interactions}"
                )
    except Exception as exc:
        base.update(
            {
                "status": "runner_error",
                "return_code": -1,
                "timed_out": False,
                "interrupted": False,
                "wall_time_sec": 0.0,
                "peak_rss_mb": None,
                "report_status": "missing",
                "runner_error": f"{type(exc).__name__}: {exc}",
            }
        )
    finally:
        if work_db.exists() and not keep_work_db:
            try:
                work_db.unlink()
            except OSError:
                pass
    base["ended_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    _write_json(run_dir / "benchmark_result.json", base)
    return base


def _numeric_values(rows: Sequence[Mapping[str, Any]], key: str) -> List[float]:
    values: List[float] = []
    for row in rows:
        value = row.get(key)
        if isinstance(value, bool) or value is None:
            continue
        try:
            number = float(value)
        except (TypeError, ValueError):
            continue
        if math.isfinite(number):
            values.append(number)
    return values


def aggregate_results(results: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str], List[Mapping[str, Any]]] = {}
    for row in results:
        grouped.setdefault((str(row.get("sample")), str(row.get("variant"))), []).append(row)

    metrics = (
        "wall_time_sec",
        "peak_rss_mb",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "api_calls",
        "successful_api_calls",
        "failed_api_calls",
        "coverage_node_count",
        "path_count",
        "deepest_path_depth",
        "llm_step_success_rate",
        "llm_interaction_success_rate",
        "avg_step_confidence",
        "selected_new_count",
        "evidence_gate_pass_rate",
        "goal_recall",
        "path_recall",
        "profile_token_recall",
    )
    summary: List[Dict[str, Any]] = []
    for (sample, variant), rows in sorted(grouped.items()):
        successful_rows = [
            row
            for row in rows
            if row.get("status") == "ok" and row.get("report_status") == "ok"
        ]
        timeouts = sum(1 for row in rows if row.get("status") == "timeout")
        interruptions = sum(1 for row in rows if row.get("status") == "interrupted")
        runner_errors = sum(1 for row in rows if row.get("status") == "runner_error")
        failures = len(rows) - len(successful_rows) - timeouts - interruptions - runner_errors
        item: Dict[str, Any] = {
            "sample": sample,
            "variant": variant,
            "runs": len(rows),
            "successes": len(successful_rows),
            "timeouts": timeouts,
            "failures": failures,
            "runner_errors": runner_errors,
            "interruptions": interruptions,
        }
        item["success_rate"] = item["successes"] / item["runs"] if item["runs"] else 0.0
        item["timeout_rate"] = timeouts / item["runs"] if item["runs"] else 0.0
        item["failure_rate"] = (len(rows) - len(successful_rows)) / item["runs"] if item["runs"] else 0.0
        for metric in metrics:
            values = _numeric_values(successful_rows, metric)
            item[f"{metric}_mean"] = round(statistics.fmean(values), 6) if values else None
            item[f"{metric}_p50"] = round(_percentile(values, 0.50), 6) if values else None
            item[f"{metric}_p95"] = round(_percentile(values, 0.95), 6) if values else None
            item[f"{metric}_max"] = round(max(values), 6) if values else None
        summary.append(item)
    return summary


def build_comparisons(summary: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    by_sample: Dict[str, Dict[str, Mapping[str, Any]]] = {}
    for row in summary:
        by_sample.setdefault(str(row.get("sample")), {})[str(row.get("variant"))] = row

    comparisons: List[Dict[str, Any]] = []
    for sample, variants in sorted(by_sample.items()):
        legacy = variants.get("legacy")
        if legacy is None:
            continue
        for variant, practical in sorted(variants.items()):
            if not variant.startswith("practical-"):
                continue
            legacy_wall = _as_number(legacy.get("wall_time_sec_mean"))
            practical_wall = _as_number(practical.get("wall_time_sec_mean"))
            legacy_tokens = _as_number(legacy.get("total_tokens_mean"))
            practical_tokens = _as_number(practical.get("total_tokens_mean"))
            row: Dict[str, Any] = {
                "sample": sample,
                "variant": variant,
                "wall_speedup": round(legacy_wall / practical_wall, 6) if practical_wall > 0 else None,
                "token_reduction_pct": round((legacy_tokens - practical_tokens) / legacy_tokens * 100.0, 4)
                if legacy_tokens > 0
                else None,
                "coverage_delta": round(
                    _as_number(practical.get("coverage_node_count_mean"))
                    - _as_number(legacy.get("coverage_node_count_mean")),
                    4,
                ),
                "deepest_depth_delta": round(
                    _as_number(practical.get("deepest_path_depth_mean"))
                    - _as_number(legacy.get("deepest_path_depth_mean")),
                    4,
                ),
            }
            for metric in ("goal_recall", "path_recall", "profile_token_recall"):
                legacy_value = legacy.get(f"{metric}_mean")
                practical_value = practical.get(f"{metric}_mean")
                row[f"{metric}_delta"] = (
                    round(float(practical_value) - float(legacy_value), 6)
                    if legacy_value is not None and practical_value is not None
                    else None
                )
            comparisons.append(row)
    return comparisons


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    keys: List[str] = []
    for row in rows:
        for key in row.keys():
            if key not in keys:
                keys.append(key)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key) for key in keys})


def _fmt(value: Any, digits: int = 2) -> str:
    if value is None:
        return "-"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def write_markdown_summary(
    path: Path,
    summary: Sequence[Mapping[str, Any]],
    comparisons: Sequence[Mapping[str, Any]],
) -> None:
    lines = [
        "# Phase7 压力测试汇总",
        "",
        "## 运行聚合",
        "",
        "| 样本 | 变体 | 成功率 | 超时率 | 失败率 | LLM成功率 | 平均耗时(s) | P95耗时(s) | 峰值内存(MB) | 平均Token | 覆盖节点 | 最深路径 | Goal Recall | Path Recall | Profile Token Recall |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in summary:
        lines.append(
            "| {sample} | {variant} | {success_rate} | {timeout_rate} | {failure_rate} | {llm_success_rate} | {wall} | {wall_p95} | {rss} | {tokens} | {coverage} | {depth} | {goal} | {path_recall} | {profile} |".format(
                sample=row.get("sample"),
                variant=row.get("variant"),
                success_rate=_fmt(_as_number(row.get("success_rate")) * 100.0) + "%",
                timeout_rate=_fmt(_as_number(row.get("timeout_rate")) * 100.0) + "%",
                failure_rate=_fmt(_as_number(row.get("failure_rate")) * 100.0) + "%",
                llm_success_rate=(
                    "-"
                    if row.get("llm_interaction_success_rate_mean") is None
                    else _fmt(
                        _as_number(row.get("llm_interaction_success_rate_mean")) * 100.0
                    )
                    + "%"
                ),
                wall=_fmt(row.get("wall_time_sec_mean")),
                wall_p95=_fmt(row.get("wall_time_sec_p95")),
                rss=_fmt(row.get("peak_rss_mb_max")),
                tokens=_fmt(row.get("total_tokens_mean"), 0),
                coverage=_fmt(row.get("coverage_node_count_mean"), 1),
                depth=_fmt(row.get("deepest_path_depth_mean"), 1),
                goal=_fmt(row.get("goal_recall_mean")),
                path_recall=_fmt(row.get("path_recall_mean")),
                profile=_fmt(row.get("profile_token_recall_mean")),
            )
        )

    lines.extend(
        [
            "",
            "## Practical 相对 Legacy",
            "",
            "`wall_speedup > 1` 表示 practical 更快。`token_reduction_pct > 0` 表示 practical 使用更少 Token。",
            "",
            "| 样本 | Practical 变体 | 加速比 | Token减少 | 覆盖变化 | 深度变化 | Goal Recall变化 | Path Recall变化 | Profile Recall变化 |",
            "|---|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in comparisons:
        reduction = row.get("token_reduction_pct")
        lines.append(
            "| {sample} | {variant} | {speedup} | {reduction} | {coverage} | {depth} | {goal} | {path_recall} | {profile} |".format(
                sample=row.get("sample"),
                variant=row.get("variant"),
                speedup=_fmt(row.get("wall_speedup")),
                reduction=("-" if reduction is None else f"{float(reduction):.2f}%"),
                coverage=_fmt(row.get("coverage_delta")),
                depth=_fmt(row.get("deepest_depth_delta")),
                goal=_fmt(row.get("goal_recall_delta")),
                path_recall=_fmt(row.get("path_recall_delta")),
                profile=_fmt(row.get("profile_token_recall_delta")),
            )
        )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _print_plan(matrix: Sequence[RunSpec], timeout_seconds: float, profile: str) -> None:
    print(f"[Phase7 Stress] profile={profile} runs={len(matrix)} timeout={timeout_seconds:.0f}s")
    for spec in matrix:
        print(
            f"  {spec.run_key}: db={spec.db_path} "
            f"input={spec.input_path or '-'} goals={list(spec.goal_keywords)}"
        )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Phase7 legacy/practical A/B stress benchmark")
    parser.add_argument("--manifest", required=True, help="JSON sample manifest")
    parser.add_argument("--out-dir", default="tmp/phase7_stress", help="benchmark output directory")
    parser.add_argument("--profile", choices=tuple(_PROFILES), default="balanced")
    parser.add_argument("--repeat", type=int, default=None, help="override repeats per variant")
    parser.add_argument("--practical-budgets", default=None, help="comma-separated budgets, e.g. 12,24,40")
    parser.add_argument("--engines", default=None, help="legacy,practical or both as comma-separated values")
    parser.add_argument("--timeout-seconds", type=float, default=None)
    parser.add_argument("--llm-mode", choices=("auto", "on", "off"), default=None)
    parser.add_argument("--dry-run", action="store_true", help="pass --dry-run to Phase7; no LLM API calls")
    parser.add_argument("--plan-only", action="store_true", help="print matrix without executing")
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--keep-work-dbs", action="store_true")
    parser.add_argument("--max-runs", type=int, default=100, help="guard against accidental costly matrices")
    args = parser.parse_args(argv)

    manifest_path = Path(args.manifest).expanduser().resolve()
    manifest = load_manifest(manifest_path)
    defaults = manifest.get("defaults") or {}
    timeout_seconds = float(
        args.timeout_seconds
        if args.timeout_seconds is not None
        else defaults.get("timeout_seconds", 7200)
    )
    budgets_override = _parse_budgets(args.practical_budgets)
    engines_override = None
    if args.engines:
        raw = [item.strip().lower() for item in args.engines.split(",") if item.strip()]
        if raw == ["both"]:
            raw = ["legacy", "practical"]
        engines_override = raw

    matrix = build_run_matrix(
        manifest_path,
        manifest,
        profile=args.profile,
        repeat_override=args.repeat,
        budgets_override=budgets_override,
        engines_override=engines_override,
    )
    _print_plan(matrix, timeout_seconds, args.profile)
    if len(matrix) > int(args.max_runs):
        raise SystemExit(
            f"planned run count {len(matrix)} exceeds --max-runs={args.max_runs}; "
            "raise the guard explicitly after reviewing API cost"
        )
    if args.plan_only:
        return 0

    output_root = Path(args.out_dir).expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    _write_json(
        output_root / "benchmark_plan.json",
        {
            "manifest": str(manifest_path),
            "profile": args.profile,
            "timeout_seconds": timeout_seconds,
            "dry_run": bool(args.dry_run),
            "llm_mode": args.llm_mode,
            "psutil_available": psutil is not None,
            "runs": [
                {
                    "run_key": spec.run_key,
                    "sample": spec.sample_name,
                    "variant": spec.variant,
                    "repeat": spec.repeat_index,
                    "db": str(spec.db_path),
                    "input": str(spec.input_path) if spec.input_path else None,
                }
                for spec in matrix
            ],
        },
    )

    results: List[Dict[str, Any]] = []
    jsonl_path = output_root / "results.jsonl"
    if jsonl_path.exists():
        jsonl_path.unlink()

    for index, spec in enumerate(matrix, 1):
        print(f"[Phase7 Stress] [{index}/{len(matrix)}] {spec.run_key}", flush=True)
        result = execute_run(
            spec,
            output_root=output_root,
            timeout_seconds=timeout_seconds,
            llm_mode=args.llm_mode,
            engine_dry_run=bool(args.dry_run),
            keep_work_db=bool(args.keep_work_dbs),
        )
        results.append(result)
        with jsonl_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(result, ensure_ascii=False) + "\n")
        print(
            f"  status={result.get('status')} wall={result.get('wall_time_sec')}s "
            f"tokens={result.get('total_tokens', '-')} coverage={result.get('coverage_node_count', '-')}",
            flush=True,
        )
        if result.get("status") == "interrupted":
            print("[Phase7 Stress] interrupted; remaining runs were not started", flush=True)
            break
        if args.fail_fast and result.get("status") != "ok":
            break

    summary = aggregate_results(results)
    comparisons = build_comparisons(summary)
    _write_json(output_root / "results.json", results)
    _write_json(output_root / "summary.json", summary)
    _write_json(output_root / "comparisons.json", comparisons)
    _write_csv(output_root / "results.csv", results)
    _write_csv(output_root / "summary.csv", summary)
    _write_csv(output_root / "comparisons.csv", comparisons)
    write_markdown_summary(output_root / "summary.md", summary, comparisons)

    failed = sum(1 for result in results if result.get("status") != "ok")
    interrupted = any(result.get("status") == "interrupted" for result in results)
    print(f"[Phase7 Stress] completed={len(results)} failed={failed}")
    print(f"[Phase7 Stress] summary={output_root / 'summary.md'}")
    if interrupted:
        return 130
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
