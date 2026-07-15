"""Phase7 任务参数加载与合并到 argparse。

合并顺序：内置 argparse 默认值 → 根 ``config.yaml`` 的
``semantics.phase7.task_defaults`` → 显式任务 JSON → 命令行。

根配置是唯一隐式配置源；任务 JSON 只是单次运行的显式参数快照。以 ``_``
开头的 JSON 键视为说明字段，忽略。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import project_config  # noqa: E402


def peek_explicit_task_config_path(argv: Optional[List[str]] = None) -> Optional[str]:
    """从 argv 中解析 ``--task-config PATH`` 或 ``--task-config=PATH``。"""
    a = argv if argv is not None else sys.argv[1:]
    i = 0
    while i < len(a):
        arg = a[i]
        if arg == "--task-config" and i + 1 < len(a):
            return str(a[i + 1]).strip() or None
        if arg.startswith("--task-config="):
            return arg.split("=", 1)[1].strip() or None
        i += 1
    return None


def peek_explicit_platform_key(argv: Optional[List[str]] = None) -> Optional[str]:
    """从 argv 中读取可选的 ``--platform``，供加载根配置时选择平台覆盖。"""
    a = argv if argv is not None else sys.argv[1:]
    i = 0
    while i < len(a):
        arg = str(a[i])
        if arg == "--platform" and i + 1 < len(a):
            return str(a[i + 1]).strip() or None
        if arg.startswith("--platform="):
            return arg.split("=", 1)[1].strip() or None
        i += 1
    return None


def _strip_meta_keys(data: Dict[str, Any]) -> Dict[str, Any]:
    payload = {k: v for k, v in data.items() if k and not str(k).startswith("_")}
    legacy_key = "gen1_entry_auto_limit"
    canonical_key = "gen1_entry_top_k"
    if legacy_key in payload:
        if canonical_key in payload and payload[canonical_key] != payload[legacy_key]:
            raise SystemExit(
                f"任务配置同时给出 {legacy_key} 与 {canonical_key}，且值不一致。"
            )
        payload.setdefault(canonical_key, payload[legacy_key])
        payload.pop(legacy_key, None)
    return payload


def _fingerprint_payload(data: Dict[str, Any]) -> str:
    enc = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(enc.encode("utf-8")).hexdigest()


def load_phase7_config(
    config_path: Optional[Path] = None,
    *,
    platform_key: Optional[str] = None,
) -> Dict[str, Any]:
    """读取平台合并后的 ``semantics.phase7``。"""
    global_config = project_config.load_global_config(config_path)
    effective_platform = platform_key or project_config.detect_platform_key()
    try:
        return project_config.merge_phase7_config_dict(global_config, effective_platform)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc


def phase7_task_defaults(
    config_path: Optional[Path] = None,
    *,
    platform_key: Optional[str] = None,
) -> Dict[str, Any]:
    phase7 = load_phase7_config(config_path, platform_key=platform_key)
    defaults = phase7.get("task_defaults") or {}
    if not isinstance(defaults, dict):
        raise SystemExit("config.yaml 的 semantics.phase7.task_defaults 必须是字典。")
    return _strip_meta_keys(defaults)


def resolve_phase7_task_file(
    *,
    argv: Optional[List[str]] = None,
    config_path: Optional[Path] = None,
) -> Tuple[Optional[Path], Dict[str, Any], Optional[str]]:
    """返回 (参数来源路径, 合并后的有效键值, 内容指纹)。

    - 若命令行显式 ``--task-config``：必须存在。
    - 根 ``config.yaml`` 的 Phase7 默认值始终先加载。
    - 不会自动发现或加载仓库中的其他 JSON。
    """
    explicit = peek_explicit_task_config_path(argv)
    root_path = Path(config_path).expanduser().resolve() if config_path else project_config.ROOT_CONFIG_PATH
    payload = phase7_task_defaults(root_path, platform_key=peek_explicit_platform_key(argv))
    source_path: Optional[Path] = root_path if payload else None

    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise SystemExit(f"Phase7 任务文件不存在: {path}")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Phase7 任务 JSON 解析失败 {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise SystemExit(f"Phase7 任务文件必须是 JSON 对象: {path}")
        payload = project_config.deep_merge_dicts(payload, _strip_meta_keys(raw))
        source_path = path

    if not payload:
        return source_path, {}, None
    return source_path, payload, _fingerprint_payload(payload)


def _find_action(parser: argparse.ArgumentParser, dest: str) -> Optional[argparse.Action]:
    for act in parser._actions:
        if getattr(act, "dest", None) == dest:
            return act
    return None


def _coerce_for_action(action: argparse.Action, value: Any) -> Any:
    if value is None:
        return None
    cls_name = type(action).__name__
    if cls_name in ("_StoreTrueAction", "_StoreFalseAction"):
        if not isinstance(value, bool):
            raise ValueError("布尔选项必须使用 JSON/YAML 的 true 或 false")
        return value
    if cls_name == "_AppendAction":
        if isinstance(value, list):
            return [str(x) for x in value]
        return [str(value)]
    typ = getattr(action, "type", None)
    if typ is int:
        return int(value)
    if typ is float:
        return float(value)
    if typ is not None and callable(typ):
        try:
            return typ(value)
        except Exception:
            return value
    # 未指定 type 的字符串选项
    if isinstance(value, (dict, list)) and cls_name == "_StoreAction":
        return value
    return value


def apply_task_defaults_to_parser(parser: argparse.ArgumentParser, data: Dict[str, Any]) -> None:
    """将任务 dict 中合法 dest 合并为 parser 默认值（在 parse_args 之前调用）。"""
    skip = {"task_config"}
    for key, val in data.items():
        if key in skip:
            continue
        act = _find_action(parser, key)
        if act is None:
            raise SystemExit(f"Phase7 任务配置包含未知键: {key!r}")
        try:
            coerced = _coerce_for_action(act, val)
        except (TypeError, ValueError) as exc:
            raise SystemExit(f"任务配置键 {key!r} 的值无法转换: {val!r} ({exc})") from exc
        if coerced is not None and getattr(act, "choices", None) is not None:
            if coerced not in act.choices:
                allowed = ", ".join(repr(x) for x in act.choices)
                raise SystemExit(f"任务配置键 {key!r} 的值必须是: {allowed}")
        parser.set_defaults(**{key: coerced})


def apply_cli_append_overrides(
    namespace: argparse.Namespace,
    parser: argparse.ArgumentParser,
    argv: Optional[List[str]] = None,
) -> None:
    """让显式 CLI 列表参数覆盖任务快照，而不是被 argparse 追加。

    ``argparse`` 的 ``append`` action 会把命令行值附加到 ``set_defaults`` 设置的
    列表。Phase7 的合并契约要求 CLI 优先，因此仅在用户显式给出该 flag 时，以
    命令行中同一 flag 的全部值替换任务快照值。
    """
    tokens = list(argv if argv is not None else sys.argv[1:])
    for action in parser._actions:
        if type(action).__name__ != "_AppendAction":
            continue
        values: List[str] = []
        found = False
        i = 0
        while i < len(tokens):
            token = str(tokens[i])
            matched = False
            for option in action.option_strings:
                if token == option:
                    if i + 1 < len(tokens):
                        values.append(str(tokens[i + 1]))
                    found = True
                    i += 1
                    matched = True
                    break
                prefix = option + "="
                if token.startswith(prefix):
                    values.append(token[len(prefix):])
                    found = True
                    matched = True
                    break
            i += 1
            if matched:
                continue
        if found:
            setattr(namespace, action.dest, values)


def attach_task_fingerprint_namespace(ns: argparse.Namespace, *, path: Optional[Path], fp: Optional[str]) -> None:
    """供断点续跑签名与 manifest 使用。"""
    setattr(ns, "phase7_task_loaded_from", str(path) if path else None)
    setattr(ns, "phase7_task_fingerprint", fp)
