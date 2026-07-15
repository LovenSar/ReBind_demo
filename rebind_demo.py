#!/usr/bin/env python3
"""
ReBind Demo 综合脚本
用于统一调用 Ghidra 和 IDA Headless 分析工具
"""

import argparse
import atexit
import concurrent.futures
import http.client
import json
import os
import platform
import re
import select as _select_mod
import shutil
import shlex
import signal
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import yaml

# 添加工具目录到 Python 路径
tools_dir = Path(__file__).parent / "tools"
sys.path.insert(0, str(tools_dir / "Ghidra_Headless_Demo"))
sys.path.insert(0, str(tools_dir / "IDA_Headless_Demo"))

try:
    from ghidra_adapter import GhidraAdapter
except ImportError as e:
    print(f"警告: 无法导入 GhidraAdapter: {e}")
    GhidraAdapter = None

try:
    from ida_adapter import IDAAdapter
except ImportError as e:
    print(f"警告: 无法导入 IDAAdapter: {e}")
    IDAAdapter = None


_SA = Path(__file__).resolve().parent / "tools" / "Semantics_Alignment"
SEMANTIC_ALIGN_SCRIPT = _SA / "breadth" / "pipeline.py"
DEEP_PATH_DFS_SCRIPT = _SA / "depth" / "deep_path_dfs.py"
GOAL_DEEP_ENGINE_SCRIPT = _SA / "depth" / "engine.py"
ALIGNMENT_LOADER_SCRIPT = _SA / "breadth" / "alignment_loader.py"
IDAT_EXIT_PORT = 12345
_IDAT_EXIT_TIMEOUT = 2.0

from project_config import (
    ROOT_CONFIG_PATH as GLOBAL_CONFIG_PATH,
    deep_merge_dicts as _deep_merge_dicts,
    detect_platform_key as _detect_platform_key,
    load_yaml_file as _load_yaml_file,
    merge_semantics_config_dict,
    merge_tool_config,
)
_TEMP_MERGED_CONFIGS: List[Path] = []


def _cleanup_temp_configs() -> None:
    """Remove any temporary config files created during runtime."""
    for temp_path in _TEMP_MERGED_CONFIGS[:]:
        try:
            temp_path.unlink()
        except Exception:
            pass


atexit.register(_cleanup_temp_configs)


def _write_temp_config(config: Dict[str, Any], prefix: str) -> Path:
    """Dump merged config dict to a temporary YAML file."""

    fd, temp_path = tempfile.mkstemp(prefix=prefix, suffix=".yaml")
    os.close(fd)
    temp_path = Path(temp_path)
    with temp_path.open("w", encoding="utf-8") as fp:
        yaml.safe_dump(config, fp, default_flow_style=False, sort_keys=False)

    _TEMP_MERGED_CONFIGS.append(temp_path)
    return temp_path


def _notify_idat_exit(port: int = IDAT_EXIT_PORT, ida_url: Optional[str] = None) -> None:
    """Send a save_and_exit request to the headless IDA HTTP server."""
    payload = json.dumps({"action": "save_and_exit"}).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": str(len(payload)),
    }

    scheme = "http"
    host = "127.0.0.1"
    target_port = port
    path = "/"

    if ida_url:
        parsed = urlparse(str(ida_url))
        scheme = (parsed.scheme or "http").lower()
        host = parsed.hostname or host
        if parsed.port:
            target_port = parsed.port
        else:
            target_port = 443 if scheme == "https" else IDAT_EXIT_PORT
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

    conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection

    conn = None
    try:
        conn = conn_cls(host, target_port, timeout=_IDAT_EXIT_TIMEOUT)
        conn.request("POST", path, body=payload, headers=headers)
        resp = conn.getresponse()
        resp.read()
        if not (200 <= resp.status < 300):
            print(
                f"[ReBindDemo] IDAT exit request returned HTTP {resp.status}", file=sys.stderr
            )
        else:
            print("[ReBindDemo] 请求已发送到 IDAT，等待其退出。")
    except Exception as exc:
        print(f"[ReBindDemo] 无法联系 IDAT HTTP 服务: {exc}", file=sys.stderr)
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _handle_sigint(signum, frame):
    """Forward SIGINT (Ctrl+C) to the IDAT server before exiting."""
    print("\n[ReBindDemo] 捕获到 Ctrl+C，通知 IDAT 退出...")
    _notify_idat_exit()
    sys.exit(0)


def _rebind_workspace_dir(sample_path: Path) -> Path:
    """返回该样本专属的 _rebind_demo 工作目录。

    规则：``<sample_parent>/<sanitized>_rebind_demo``，
    与 layout_helpers.rebind_workspace_dir 保持一致。
    """
    base_name = sample_path.name.replace(".", "_")
    return sample_path.parent / f"{base_name}_rebind_demo"


def _expected_output_dir(sample_path: Path, dir_suffix: str) -> Path:
    """返回 Ghidra/IDA 工具在 _rebind_demo 内的输出目录。"""
    base_name = sample_path.name.replace(".", "_")
    return _rebind_workspace_dir(sample_path) / f"{base_name}{dir_suffix}"


def _export_dir_has_content(output_dir: Path) -> bool:
    """Return True if *output_dir* looks like a completed Ghidra/IDA export
    (exists and contains at least one sub-directory such as ``*_output``)."""
    if not output_dir.is_dir():
        return False
    return any(child.is_dir() for child in output_dir.iterdir())


def _prompt_use_cache(cached_labels: List[str], timeout: int = 5) -> bool:
    """倒计时交互提示：检测到缓存时询问用户是否继续使用。

    Returns True to reuse cache, False to re-export.
    """
    print(f"\n[ReBindDemo] 检测到以下样本已有导出缓存:")
    for label in cached_labels:
        print(f"  - {label}")
    print(f"\n[ReBindDemo] {timeout} 秒后将自动使用缓存继续。输入 no 回车可重新导出。")

    try:
        if not sys.stdin.isatty():
            raise OSError("non-interactive")

        for remaining in range(timeout, 0, -1):
            sys.stdout.write(f"\r  使用缓存继续？({remaining}s) [Y/no]: ")
            sys.stdout.flush()
            ready, _, _ = _select_mod.select([sys.stdin], [], [], 1.0)
            if ready:
                user_input = sys.stdin.readline().strip().lower()
                if user_input in ("no", "n"):
                    print("[ReBindDemo] 用户选择重新导出。\n")
                    return False
                print("[ReBindDemo] 使用缓存继续。\n")
                return True

        sys.stdout.write(f"\r  使用缓存继续？     [Y/no]: Y (自动)\n")
        sys.stdout.flush()
        return True
    except (OSError, ValueError):
        print("[ReBindDemo] 非交互模式，自动使用缓存。\n")
        return True


def _phase7_workspace_dir(input_path: Path) -> Path:
    if str(input_path.parent.name or "").endswith("_goal_deep"):
        return input_path.parent
    suffix = str(input_path.suffix or "").lower()
    raw_name = input_path.stem if suffix in {".db", ".i64", ".idb"} else input_path.name
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(raw_name or "").strip()).strip("._-")
    if not safe_name:
        safe_name = "sample"
    return input_path.parent / f"{safe_name}_goal_deep"


def _parse_phase7_task_json_run_id(task_config_path: Optional[Path]) -> Optional[str]:
    """读取任务 JSON 中的 ``run_id``（忽略 ``_`` 元键）；无则 ``None``。"""
    if not task_config_path or not task_config_path.is_file():
        return None
    try:
        data = json.loads(task_config_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    rid = data.get("run_id")
    if rid is None:
        return None
    s = str(rid).strip()
    return s or None


def _phase7_predict_run_dir(
    input_path: Path,
    *,
    db_path: Path,
    runs_root: Optional[Path],
    run_id_cli: Optional[str],
    task_config_path: Optional[Path],
) -> Optional[Path]:
    """预测显式 run_id 的目录，用于碰撞检测与交互式续跑。

    未指定 run_id 时引擎生成高精度时间戳，预检没有稳定目标，直接返回 ``None``。
    """
    if str(_SA) not in sys.path:
        sys.path.insert(0, str(_SA))
    from depth.run_management import _build_run_layout

    rid = (run_id_cli or "").strip() or None
    if not rid:
        rid = _parse_phase7_task_json_run_id(task_config_path)
    if not rid:
        return None
    er = runs_root or (_phase7_workspace_dir(input_path) / "runs")
    er = Path(er).expanduser().resolve()
    layout = _build_run_layout(
        db_path=db_path,
        input_path=str(input_path),
        explicit_output=None,
        runs_root=str(er),
        run_id=rid,
        resume=False,
    )
    return layout.run_dir


def _interactive_resolve_phase7_run_collision(run_dir: Path) -> Optional[str]:
    """交互式处理已存在的 run 目录。

    返回 ``\"resume\"``、``\"new:<run_id>\"``，或 ``None`` 表示退出。
    非 TTY 时打印说明并返回 ``None``。
    """
    if not sys.stdin.isatty():
        print(
            "\n[ReBindDemo] run 目录已存在:\n"
            f"  {run_dir}\n"
            "当前为非交互终端：请显式添加 --phase7-resume（续跑）或 "
            "--phase7-run-id <新id>（新 run）后重试。\n",
            file=sys.stderr,
        )
        return None
    print(f"\n[ReBindDemo] run 目录已存在:\n  {run_dir}")
    print("  [r] 续跑（--resume）")
    print("  [n] 使用新的 run-id（覆盖任务 JSON 中的默认 run-id）")
    print("  [q] 退出")
    while True:
        try:
            raw = input("请选择 [r/n/q]: ").strip().lower()
        except EOFError:
            return None
        if raw in ("q", "quit"):
            return None
        if raw in ("r", "resume"):
            return "resume"
        if raw in ("n", "new"):
            try:
                nid = input("请输入新的 run-id（字母数字、点、下划线等）: ").strip()
            except EOFError:
                return None
            if not nid:
                print("run-id 不能为空。", file=sys.stderr)
                continue
            return f"new:{nid}"
        print("请输入 r、n 或 q。")


def _phase7_legacy_db_path(input_path: Path) -> Path:
    """返回由常规流水线生成的对齐 DB 路径（用于 Phase7 自动迁移检测）。

    优先返回新布局路径（_rebind_demo 内），若不存在则回退到旧的平铺路径
    （``<parent>/<sample.name>.db``），以兼容历史数据。
    """
    new_path = _rebind_workspace_dir(input_path) / f"{input_path.name}.db"
    if new_path.exists():
        return new_path
    return input_path.parent / f"{input_path.name}.db"


def _phase7_default_db_name(input_path: Path) -> str:
    suffix = str(input_path.suffix or "").lower()
    if suffix in {".db", ".i64", ".idb"}:
        return input_path.stem or "sample"
    return input_path.name or "sample"


def _probe_openai_keys() -> None:
    """在执行 Ghidra/IDA 之前，进行 OpenAI API Key 的启动检查。
    
    如果某个 key 已处于限流（429）状态，会在启动时移除该 key（不修改 .env）。
    """
    try:
        # 动态导入 kp_llm 以获取启动检查函数
        kp_llm_path = Path(__file__).resolve().parent / "tools" / "Semantics_Alignment" / "kp"
        sys.path.insert(0, str(kp_llm_path.parent))
        
        from kp.kp_llm import require_openai
        
        print("[ReBindDemo] 开始检查 OpenAI API Keys...")
        try:
            # 调用 require_openai 会自动执行启动探测并移除已限流的 keys
            require_openai({})
            print("[ReBindDemo] OpenAI API Keys 检查完毕。")
        except SystemExit:
            # 如果全部 key 都不可用，require_openai 可能会调用 sys.exit
            raise
        except Exception as e:
            # 其他错误（如未配置 key）不应该阻挡 Ghidra/IDA 执行，仅发出警告
            print(f"[ReBindDemo] OpenAI API Keys 检查警告: {e}", file=sys.stderr)
    except Exception as e:
        # 如果无法导入或执行探测，仅发出警告（可能 kp_llm 不可用或配置缺失）
        print(f"[ReBindDemo] 跳过 OpenAI API Keys 启动检查: {e}", file=sys.stderr)


def run_semantic_align(
    sample_paths: List[Path],
    *,
    semantics_config_path: Optional[Path] = None,
    ghidra_dir_suffix: str = "_ghidemo",
    ida_dir_suffix: str = "_idademo",
    semantics_runtime: Optional[Dict[str, Any]] = None,
    phase5_only: bool = False,
    phase5_only_force_all: bool = False,
    db_path_override: Optional[Path] = None,
    dump_db_only: bool = False,
    sync_ida_before_dump: bool = False,
    unlock_locked_on_sync: bool = False,
    reuse_aligned_db_samples: Optional[Set[Path]] = None,
) -> None:
    """Call semantic_align.py for each sample after both headless tools finish."""

    if not sample_paths:
        return

    runtime = semantics_runtime or {}
    reuse_samples: Set[Path] = {Path(p).resolve() for p in (reuse_aligned_db_samples or set())}

    for sample_path in sample_paths:
        cmd = [sys.executable, str(SEMANTIC_ALIGN_SCRIPT), "--sample", str(sample_path)]
        db_for_sample = db_path_override
        # DB 位于样本专属 _rebind_demo 工作目录内
        default_db_path = _rebind_workspace_dir(sample_path) / f"{sample_path.name}.db"

        if dump_db_only:
            target_db = db_for_sample or default_db_path
            if not target_db.exists():
                raise SystemExit(
                    "[ReBindDemo] 未找到数据库，无法导出：\n"
                    f"  - db={target_db}\n"
                    "请使用 --db 指定已有 DB，或先运行完整流水线生成 DB。"
                )
            cmd.extend(["--db", str(target_db), "--dump-db-only"])
            if sync_ida_before_dump:
                cmd.append("--sync-ida-before-dump")
            if unlock_locked_on_sync:
                cmd.append("--unlock-locked-on-sync")
        elif phase5_only or phase5_only_force_all:
            target_db = db_for_sample or default_db_path
            if not target_db.exists():
                raise SystemExit(
                    "[ReBindDemo] 未找到对齐数据库，无法仅运行 Phase 5：\n"
                    f"  - db={target_db}\n"
                    "请先完整运行一次（生成 DB），或手动将 DB 放到上述路径。"
                )
            cmd.extend(["--db", str(target_db), "--no-align"])
            if phase5_only_force_all:
                cmd.append("--phase5-only-force-all")
            else:
                cmd.append("--phase5-only")
        else:
            ghidra_dir = _expected_output_dir(sample_path, ghidra_dir_suffix)
            ida_dir = _expected_output_dir(sample_path, ida_dir_suffix)
            if not ghidra_dir.exists() or not ida_dir.exists():
                print(
                    "[ReBindDemo] 跳过语义对齐：未找到输出目录：\n"
                    f"  - ghidra_dir={ghidra_dir} (exists={ghidra_dir.exists()})\n"
                    f"  - ida_dir={ida_dir} (exists={ida_dir.exists()})",
                    file=sys.stderr,
                )
                continue
            cmd.extend(["--ghidra-dir", str(ghidra_dir), "--ida-dir", str(ida_dir)])
            if db_for_sample:
                cmd.extend(["--db", str(db_for_sample)])

            # 若该样本选择了“导出缓存继续”，且存在对齐 DB，则复用 DB 跳过 alignment_loader。
            # 这样可避免每次都从对齐构建重新开始，保持语义阶段进度可续跑。
            reuse_db_candidate = db_for_sample or default_db_path
            if sample_path.resolve() in reuse_samples and reuse_db_candidate.exists():
                if not db_for_sample:
                    cmd.extend(["--db", str(reuse_db_candidate)])
                cmd.append("--no-align")
                print(
                    f"[ReBindDemo] 检测到 {sample_path.name} 已有对齐 DB，"
                    f"将复用并跳过 alignment_loader: {reuse_db_candidate}"
                )
            elif sample_path.resolve() in reuse_samples:
                print(
                    f"[ReBindDemo] {sample_path.name} 选择了导出缓存，但未找到可复用对齐 DB，"
                    "将执行 alignment_loader 重建。"
                )

        if semantics_config_path:
            cmd.extend(["--config", str(semantics_config_path)])

        idat_exe = runtime.get("idat_exe")
        if idat_exe:
            cmd.extend(["--idat-exe", str(idat_exe)])

        ida_url = runtime.get("ida_url")
        if ida_url:
            cmd.extend(["--ida-url", str(ida_url)])

        ida_script = runtime.get("ida_script")
        if ida_script:
            cmd.extend(["--ida-script", str(ida_script)])

        ida_start_delay = runtime.get("ida_start_delay")
        if ida_start_delay is not None:
            cmd.extend(["--ida-start-delay", str(ida_start_delay)])

        if runtime.get("no_ida") is True:
            cmd.append("--no-ida")
        if runtime.get("no_align") is True:
            cmd.append("--no-align")

        print("\n[ReBindDemo] 执行 semantic_align.py 以推进语义对齐...")
        print("  命令:", " ".join(cmd))
        result = subprocess.run(cmd, cwd=str(Path(__file__).resolve().parent))
        if result.returncode != 0:
            print("[ReBindDemo] semantic_align.py 返回非零退出码，正在请求 IDA 退出...", file=sys.stderr)
            _notify_idat_exit(ida_url=ida_url)
            raise SystemExit(
                f"[ReBindDemo] semantic_align.py 返回非零退出码：{result.returncode}"
            )


def _phase7_target_db_path(input_path: Path, db_path_override: Optional[Path]) -> Path:
    if db_path_override:
        return db_path_override
    if str(input_path.suffix or "").lower() == ".db":
        return input_path
    workspace_dir = _phase7_workspace_dir(input_path)
    return workspace_dir / f"{_phase7_default_db_name(input_path)}.db"


def _run_alignment_loader_ida_only(
    sample_paths: List[Path],
    *,
    ida_dir_suffix: str,
    db_path_override: Optional[Path] = None,
) -> None:
    if db_path_override and len(sample_paths) != 1:
        raise SystemExit("[ReBindDemo] IDA-only 对齐生成 DB 时，--db 仅支持单个输入。")

    for sample_path in sample_paths:
        ida_dir = _expected_output_dir(sample_path, ida_dir_suffix)
        if not ida_dir.exists():
            raise SystemExit(
                "[ReBindDemo] 仅 IDA 模式构建 DB 失败：未找到 IDA 导出目录。\n"
                f"  - sample={sample_path}\n"
                f"  - ida_dir={ida_dir}"
            )

        target_db = _phase7_target_db_path(sample_path, db_path_override)
        workspace_dir = _phase7_workspace_dir(sample_path)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        dump_txt = workspace_dir / f"{sample_path.name}_dump.txt"
        dump_xlsx = workspace_dir / f"{sample_path.name}_dump.xlsx"
        cmd = [
            sys.executable,
            str(ALIGNMENT_LOADER_SCRIPT),
            "--db",
            str(target_db),
            "--ida-dir",
            str(ida_dir),
            "--dump-db",
            "--dump-db-output",
            str(dump_txt),
            "--dump-db-workbook",
            str(dump_xlsx),
            "--delete-db",
        ]

        print("\n[ReBindDemo] 执行 alignment_loader.py（仅 IDA 视图）生成 Phase7 所需 DB ...")
        print(f"  sample: {sample_path}")
        print(f"  workspace: {workspace_dir}")
        print(f"  ida_dir: {ida_dir}")
        print(f"  db: {target_db}")
        print("  命令:", " ".join(cmd))
        result = subprocess.run(cmd, cwd=str(Path(__file__).resolve().parent))
        if result.returncode != 0:
            raise SystemExit(
                f"[ReBindDemo] alignment_loader.py(IDA-only) 返回非零退出码：{result.returncode}"
            )
        if not target_db.exists():
            raise SystemExit(
                "[ReBindDemo] alignment_loader.py(IDA-only) 执行后未发现目标 DB：\n"
                f"  - db={target_db}"
            )


def ensure_phase7_db_for_inputs(
    demo: "ReBindDemo",
    sample_paths: List[Path],
    *,
    db_path_override: Optional[Path] = None,
) -> None:
    """For --phase7: auto bootstrap missing DB via IDA-only export + loader."""

    if not sample_paths:
        return

    if db_path_override and len(sample_paths) != 1:
        raise SystemExit("[ReBindDemo] --phase7 + --db 当前仅支持单个输入。")

    missing_inputs: List[Path] = []
    for sample_path in sample_paths:
        target_db = _phase7_target_db_path(sample_path, db_path_override)
        if not target_db.exists():
            if not db_path_override:
                legacy_db = _phase7_legacy_db_path(sample_path)
                if legacy_db.exists():
                    workspace_dir = _phase7_workspace_dir(sample_path)
                    workspace_dir.mkdir(parents=True, exist_ok=True)
                    target_db.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(legacy_db, target_db)
                    for suffix in ("-wal", "-shm"):
                        legacy_sidecar = legacy_db.with_name(legacy_db.name + suffix)
                        if legacy_sidecar.exists():
                            target_sidecar = target_db.with_name(target_db.name + suffix)
                            shutil.copy2(legacy_sidecar, target_sidecar)
                    for ext in ("txt", "xlsx"):
                        legacy_dump = sample_path.parent / f"{sample_path.name}_dump.{ext}"
                        target_dump = workspace_dir / f"{sample_path.name}_dump.{ext}"
                        if legacy_dump.exists() and not target_dump.exists():
                            shutil.copy2(legacy_dump, target_dump)
                    print(
                        "[ReBindDemo] 发现旧路径 DB，已复制到 Phase7 工作目录：\n"
                        f"  legacy_db={legacy_db}\n"
                        f"  target_db={target_db}"
                    )
                    continue
            missing_inputs.append(sample_path)

    if not missing_inputs:
        return

    if not demo.ida_adapter:
        raise SystemExit(
            "[ReBindDemo] --phase7 检测到 DB 缺失，尝试自动补齐时 IDA 适配器不可用。\n"
            "请先修复 IDA 配置，或手动提供 --db。"
        )

    print(
        "[ReBindDemo] --phase7 检测到缺失 DB，开始自动执行 IDA-only 前置流程"
        "（仅 IDA，不触发 Ghidra）。"
    )
    staged_inputs: List[Path] = []
    for sample_path in missing_inputs:
        workspace_dir = _phase7_workspace_dir(sample_path)
        workspace_dir.mkdir(parents=True, exist_ok=True)
        staged_path = workspace_dir / sample_path.name
        if sample_path.resolve() != staged_path.resolve():
            shutil.copy2(sample_path, staged_path)
            print(f"[ReBindDemo] 已复制样本到 Phase7 工作目录: {staged_path}")
        staged_inputs.append(staged_path)

    print("[ReBindDemo] 步骤 1/2：运行 IDA Headless 导出 *_idademo 文本...")
    demo.analyze_with_ida([str(p) for p in staged_inputs])

    ida_suffix = (
        (demo.ida_adapter.config.get("output", {}) or {}).get("dir_suffix", "_idademo")
        if demo.ida_adapter
        else "_idademo"
    )

    print("[ReBindDemo] 步骤 2/2：使用 alignment_loader.py(IDA-only) 生成对齐 DB ...")
    _run_alignment_loader_ida_only(
        staged_inputs,
        ida_dir_suffix=str(ida_suffix),
        db_path_override=db_path_override,
    )


def run_deep_path_analysis(
    input_paths: List[Path],
    *,
    semantics_config_path: Optional[Path] = None,
    db_path_override: Optional[Path] = None,
    max_depth: Optional[int] = None,
    max_paths: Optional[int] = None,
    llm_mode: Optional[str] = None,
    llm_dry_run: bool = False,
    llm_verbose: bool = False,
    llm_prompt_preview_chars: Optional[int] = None,
    llm_raw_preview_chars: Optional[int] = None,
    llm_log_file: Optional[Path] = None,
    top: Optional[int] = None,
    entries: Optional[List[str]] = None,
    output_path: Optional[Path] = None,
) -> None:
    """Call deep_path_dfs.py from the unified project entry."""

    if not input_paths:
        raise SystemExit("[ReBindDemo] deep-path 模式需要至少一个输入路径（exe/idb/i64/db）。")

    if db_path_override and len(input_paths) != 1:
        raise SystemExit("[ReBindDemo] deep-path 模式下使用 --db 时仅支持单个输入。")
    if output_path and len(input_paths) != 1:
        raise SystemExit("[ReBindDemo] deep-path 模式下使用 --deep-output 时仅支持单个输入。")

    def _safe_name(text: str) -> str:
        raw = str(text or "").strip()
        sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._-")
        return sanitized or "sample"

    for idx, input_path in enumerate(input_paths, 1):
        cmd = [sys.executable, str(DEEP_PATH_DFS_SCRIPT), str(input_path)]
        llm_mode_norm = str(llm_mode or "").lower()
        deep_llm_enabled = llm_mode_norm in {"auto", "on"}
        run_dir: Optional[Path] = None

        if db_path_override:
            cmd.extend(["--db", str(db_path_override)])
        if semantics_config_path:
            cmd.extend(["--llm-config", str(semantics_config_path)])
        if max_depth is not None:
            cmd.extend(["--max-depth", str(int(max_depth))])
        if max_paths is not None:
            cmd.extend(["--max-paths", str(int(max_paths))])
        if top is not None:
            cmd.extend(["--top", str(int(top))])
        if llm_mode:
            cmd.extend(["--llm-mode", str(llm_mode)])
            if str(llm_mode).lower() in {"auto", "on"}:
                print(
                    "[ReBindDemo] 提示: deep-path 已启用 LLM 轮询，可能因网络/限流等待较久；"
                    "如需快速仅看路径请使用 --deep-llm-mode off。"
                )
        if llm_dry_run:
            cmd.append("--llm-dry-run")
        if llm_verbose:
            cmd.append("--llm-verbose")
        if llm_prompt_preview_chars is not None:
            cmd.extend(["--llm-prompt-preview-chars", str(int(llm_prompt_preview_chars))])
        if llm_raw_preview_chars is not None:
            cmd.extend(["--llm-raw-preview-chars", str(int(llm_raw_preview_chars))])
        if entries:
            for entry in entries:
                if str(entry or "").strip():
                    cmd.extend(["--entry", str(entry).strip()])

        if deep_llm_enabled:
            runs_root = Path.cwd() / "deep_llm_runs"
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base = f"{stamp}_{idx:02d}_{_safe_name(input_path.stem)}"
            run_dir = runs_root / base
            suffix = 1
            while run_dir.exists():
                run_dir = runs_root / f"{base}_{suffix:02d}"
                suffix += 1
            run_dir.mkdir(parents=True, exist_ok=True)

            auto_out = run_dir / "deep_dfs_output.json"
            effective_out = output_path or auto_out
            cmd.extend(["--output", str(effective_out)])

            auto_log = run_dir / "deep_llm_log.jsonl"
            effective_log = auto_log
            if llm_log_file:
                # 自定义日志路径：单输入直连；多输入自动加序号避免覆盖。
                if len(input_paths) > 1:
                    stem = llm_log_file.stem or "deep_llm_log"
                    suffix = llm_log_file.suffix or ".jsonl"
                    indexed_name = f"{stem}_{idx:02d}{suffix}"
                    if llm_log_file.is_absolute():
                        effective_log = llm_log_file.parent / indexed_name
                    else:
                        effective_log = run_dir / indexed_name
                else:
                    effective_log = (
                        llm_log_file
                        if llm_log_file.is_absolute()
                        else run_dir / llm_log_file
                    )
            cmd.extend(["--llm-log-file", str(effective_log)])
        else:
            if output_path:
                cmd.extend(["--output", str(output_path)])
            elif len(input_paths) > 1:
                auto_out = input_path.parent / f"{input_path.name}.deep_dfs.json"
                cmd.extend(["--output", str(auto_out)])

        print("\n[ReBindDemo] 执行 deep_path_dfs.py 深路径分析...")
        print(f"  输入[{idx}/{len(input_paths)}]: {input_path}")
        if run_dir is not None:
            print(f"  deep-llm 工作目录: {run_dir}")
        print("  命令:", " ".join(cmd))
        result = subprocess.run(cmd, cwd=str(Path(__file__).resolve().parent))
        if result.returncode != 0:
            raise SystemExit(
                f"[ReBindDemo] deep_path_dfs.py 返回非零退出码：{result.returncode}"
            )


def run_phase7_analysis(
    input_paths: List[Path],
    *,
    platform_key: Optional[str] = None,
    db_path_override: Optional[Path] = None,
    output_path: Optional[Path] = None,
    runs_root: Optional[Path] = None,
    run_id: Optional[str] = None,
    resume: bool = False,
    force_resume: bool = False,
    log_raw_llm: bool = False,
    apply_db: bool = False,
    apply_max_rows: Optional[int] = None,
    apply_min_confidence: Optional[int] = None,
    extra_args: Optional[List[str]] = None,
    no_console_progress: bool = False,
    task_config_path: Optional[Path] = None,
) -> None:
    """Call goal_deep_engine.py (Phase7) from the unified project entry."""

    if not input_paths:
        raise SystemExit("[ReBindDemo] Phase7 模式需要至少一个输入路径（exe/idb/i64/db）。")

    if db_path_override and len(input_paths) != 1:
        raise SystemExit("[ReBindDemo] Phase7 模式下使用 --db 时仅支持单个输入。")
    if output_path and len(input_paths) != 1:
        raise SystemExit("[ReBindDemo] Phase7 模式下使用 --phase7-output 时仅支持单个输入。")

    forwarded = [str(x).strip() for x in (extra_args or []) if str(x or "").strip()]

    for idx, input_path in enumerate(input_paths, 1):
        cmd = [sys.executable, str(GOAL_DEEP_ENGINE_SCRIPT), str(input_path)]

        preferred_db = _phase7_target_db_path(input_path, db_path_override)
        legacy_db = _phase7_legacy_db_path(input_path)
        if db_path_override:
            effective_db = preferred_db
        elif preferred_db.exists():
            effective_db = preferred_db
        elif legacy_db.exists():
            effective_db = legacy_db
        else:
            effective_db = preferred_db

        cmd.extend(["--db", str(effective_db)])
        if platform_key:
            cmd.extend(["--platform", str(platform_key)])
        if output_path:
            cmd.extend(["--output", str(output_path)])
        effective_runs_root = runs_root or (_phase7_workspace_dir(input_path) / "runs")

        explicit_run_id: Optional[str] = None
        if run_id:
            explicit_run_id = str(run_id)
            if len(input_paths) > 1:
                explicit_run_id = f"{explicit_run_id}_{idx:02d}"

        final_resume = bool(resume or force_resume)
        if (
            len(input_paths) == 1
            and not final_resume
        ):
            pred = _phase7_predict_run_dir(
                input_path,
                db_path=effective_db,
                runs_root=runs_root,
                run_id_cli=explicit_run_id,
                task_config_path=task_config_path,
            )
            if pred is not None and pred.is_dir():
                choice = _interactive_resolve_phase7_run_collision(pred)
                if choice is None:
                    raise SystemExit(1)
                if choice == "resume":
                    final_resume = True
                elif choice.startswith("new:"):
                    explicit_run_id = choice.split(":", 1)[1]

        cmd.extend(["--runs-root", str(effective_runs_root)])
        if explicit_run_id:
            cmd.extend(["--run-id", explicit_run_id])
        if final_resume:
            cmd.append("--resume")
        if force_resume:
            cmd.append("--force-resume")
        if log_raw_llm:
            cmd.append("--log-raw-llm")
        if apply_db:
            cmd.append("--apply-db")
        if apply_max_rows is not None:
            cmd.extend(["--apply-max-rows", str(int(apply_max_rows))])
        if apply_min_confidence is not None:
            cmd.extend(["--apply-min-confidence", str(int(apply_min_confidence))])
        if no_console_progress:
            cmd.append("--no-console-progress")
        if task_config_path:
            cmd.extend(["--task-config", str(task_config_path)])

        for raw in forwarded:
            try:
                cmd.extend(shlex.split(raw))
            except ValueError:
                cmd.append(raw)

        print("\n[ReBindDemo] 执行 Phase7 goal_deep_engine.py ...")
        print(f"  输入[{idx}/{len(input_paths)}]: {input_path}")
        print(f"  使用 DB: {effective_db}")
        print(f"  runs_root: {effective_runs_root}")
        print("  命令:", " ".join(cmd))
        result = subprocess.run(cmd, cwd=str(Path(__file__).resolve().parent))
        if result.returncode != 0:
            raise SystemExit(
                f"[ReBindDemo] goal_deep_engine.py 返回非零退出码：{result.returncode}"
            )


def _warn_if_missing_executable(label: str, value: Optional[str]) -> None:
    if not value:
        return
    expanded = os.path.expandvars(os.path.expanduser(str(value)))
    expanded = expanded.replace(r"\\\"", '"').replace(r"\\'", "'")
    expanded = expanded.replace(r"\"", '"').replace(r"\'", "'")
    expanded = expanded.strip()
    if len(expanded) >= 2 and ((expanded[0] == expanded[-1] == '"') or (expanded[0] == expanded[-1] == "'")):
        expanded = expanded[1:-1].strip()
    try:
        path = Path(expanded)
    except Exception:
        return
    if not path.exists():
        print(f"[ReBindDemo] 警告: 未找到 {label}: {value}", file=sys.stderr)


class ReBindDemo:
    """ReBind Demo 综合分析工具"""
    
    def __init__(
        self,
        global_config_path: Optional[str] = None,
        platform_key: Optional[str] = None,
    ):
        """初始化综合分析工具；配置仅来自根目录 config.yaml（或 --global-config 指定路径）。"""
        self.platform_key = _detect_platform_key(platform_key)
        if global_config_path:
            resolved_global_path = Path(global_config_path).expanduser().resolve()
            allow_missing_global = False
        else:
            resolved_global_path = GLOBAL_CONFIG_PATH
            allow_missing_global = True

        self.global_config_path = resolved_global_path
        self.global_config = _load_yaml_file(
            resolved_global_path, allow_missing=allow_missing_global
        )
        self.ghidra_adapter = None
        self.ida_adapter = None

        self.ghidra_config_path = self._prepare_module_config(
            module_dir_name="Ghidra_Headless_Demo",
            section_key="ghidra",
        )
        self.ida_config_path = self._prepare_module_config(
            module_dir_name="IDA_Headless_Demo",
            section_key="ida",
        )
        self.semantics_config_path = self._prepare_module_config(
            module_dir_name="Semantics_Alignment",
            section_key="semantics",
        )
        self.semantics_config = _load_yaml_file(self.semantics_config_path)
        runtime = self.semantics_config.get("runtime", {})
        self.semantics_runtime = runtime if isinstance(runtime, dict) else {}

        # 初始化适配器
        if GhidraAdapter:
            try:
                self.ghidra_adapter = GhidraAdapter(str(self.ghidra_config_path))
            except Exception as e:
                print(f"警告: 初始化 GhidraAdapter 失败: {e}")
        
        if IDAAdapter:
            try:
                self.ida_adapter = IDAAdapter(str(self.ida_config_path))
            except Exception as e:
                print(f"警告: 初始化 IDAAdapter 失败: {e}")

    def _prepare_module_config(
        self,
        module_dir_name: str,
        section_key: str,
    ) -> Path:
        """从根 config.yaml 合并平台覆盖，写入临时 YAML（供适配器 / 子进程使用）。"""

        if section_key == "semantics":
            merged_section = merge_semantics_config_dict(self.global_config, self.platform_key)
        else:
            merged_section = merge_tool_config(self.global_config, section_key, self.platform_key)
        merged_config = merged_section
        prefix = f"{module_dir_name.lower()}_config_"
        return _write_temp_config(merged_config, prefix=prefix)
    
    def analyze_with_ghidra(self, input_files: List[str]) -> List[Path]:
        """使用 Ghidra 分析文件
        
        Args:
            input_files: 输入文件路径列表
            
        Returns:
            输出目录路径列表
        """
        if not self.ghidra_adapter:
            raise RuntimeError("Ghidra 适配器未初始化")
        
        return self.ghidra_adapter.analyze_files(input_files)
    
    def analyze_with_ida(self, input_files: List[str]) -> List[Path]:
        """使用 IDA 分析文件
        
        Args:
            input_files: 输入文件路径列表
            
        Returns:
            输出目录路径列表
        """
        if not self.ida_adapter:
            raise RuntimeError("IDA 适配器未初始化")
        
        return self.ida_adapter.analyze_files(input_files)
    
    def analyze_with_both(self, input_files: List[str]) -> dict:
        """使用 Ghidra 和 IDA 并行分析文件。
        
        两个工具写入独立的输出目录（_ghidemo / _idademo），无共享状态，
        可安全并发执行。subprocess.run 通过 cwd= 参数指定工作目录，
        不依赖 os.chdir，线程安全。

        Args:
            input_files: 输入文件路径列表
            
        Returns:
            包含两种工具输出目录的字典
        """
        tasks: Dict[str, Any] = {}
        if self.ghidra_adapter:
            tasks['ghidra'] = self.analyze_with_ghidra
        if self.ida_adapter:
            tasks['ida'] = self.analyze_with_ida

        if not tasks:
            return {}

        results: Dict[str, List[Path]] = {}

        if len(tasks) == 1:
            # 只有一个工具可用，直接串行执行
            name, fn = next(iter(tasks.items()))
            label = "Ghidra" if name == "ghidra" else "IDA"
            try:
                print(f"使用 {label} 分析文件...")
                results[name] = fn(input_files)
            except Exception as e:
                print(f"{label} 分析失败: {e}")
                results[name] = []
            return results

        # 两个工具都可用，并行执行
        print("[ReBindDemo] Ghidra 和 IDA 并行启动...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_ghidra = executor.submit(self.analyze_with_ghidra, input_files)
            future_ida    = executor.submit(self.analyze_with_ida,    input_files)

            for name, future, label in [
                ("ghidra", future_ghidra, "Ghidra"),
                ("ida",    future_ida,    "IDA"),
            ]:
                try:
                    results[name] = future.result()
                    print(f"[ReBindDemo] {label} 分析完成。")
                except Exception as e:
                    print(f"[ReBindDemo] {label} 分析失败: {e}")
                    results[name] = []

        return results


def main():
    """主函数 - 命令行接口"""
    parser = argparse.ArgumentParser(
        description="ReBind Demo 综合分析工具 - 统一调用 Ghidra 和 IDA Headless 分析工具",
    )
    
    # 工具选择参数
    tool_group = parser.add_mutually_exclusive_group()
    tool_group.add_argument(
        "--ghidra",
        action="store_true",
        help="仅使用 Ghidra 分析"
    )
    tool_group.add_argument(
        "--ida",
        action="store_true",
        help="仅使用 IDA 分析"
    )
    tool_group.add_argument(
        "--both",
        action="store_true",
        default=True,
        help="同时使用 Ghidra 和 IDA 分析（默认）"
    )
    
    # 通用参数
    parser.add_argument(
        "input_files",
        nargs="+",
        help="要分析的文件路径（支持多个文件）"
    )
    parser.add_argument(
        "--global-config",
        help="唯一配置文件路径（默认: 项目根目录 config.yaml）",
    )
    parser.add_argument(
        "--platform",
        choices=["windows", "macos", "linux"],
        default=None,
        help="显式指定平台（默认: 自动检测）",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="启用详细输出"
    )
    parser.add_argument(
        "--force-export",
        action="store_true",
        help="强制重新运行 Ghidra/IDA 导出，即使输出目录已存在。",
    )
    parser.add_argument(
        "--phase5-only",
        action="store_true",
        help="跳过 Ghidra/IDA headless 分析，直接运行语义对齐 Phase 5（要求已存在 <sample>.db）。",
    )
    parser.add_argument(
        "--phase5-only-force-all",
        action="store_true",
        help="Phase5-only 进阶：强制对所有可用伪代码的物理函数跑一次 Phase 5（要求已存在 <sample>.db）。",
    )
    parser.add_argument(
        "--db",
        help="已有 SQLite 对齐数据库路径。可与 --phase5-only / --phase5-only-force-all / --dump-db-only 配合使用。",
    )
    parser.add_argument(
        "--dump-db-only",
        action="store_true",
        help="仅基于已有 DB 导出 TXT/XLSX 快照（不会运行 Ghidra/IDA/Phase1-5）。",
    )
    parser.add_argument(
        "--sync-ida-before-dump",
        action="store_true",
        help="导出前先从 IDA 同步函数名到 DB（需配合 --dump-db-only 使用，会启动 IDA）。",
    )
    parser.add_argument(
        "--unlock-locked-on-sync",
        action="store_true",
        help="同步 IDA 时解锁所有 LOCKED 状态（配合 --sync-ida-before-dump 使用）。",
    )
    parser.add_argument(
        "--deep-path",
        action="store_true",
        help="直接执行深路径分析（支持输入 exe/idb/i64/db），跳过 Ghidra/IDA headless。",
    )
    parser.add_argument(
        "--deep-max-depth",
        type=int,
        default=None,
        help="深路径 DFS 深度上限（默认不传，交由 deep_path_dfs 自动取全局最深）。",
    )
    parser.add_argument(
        "--deep-max-paths",
        type=int,
        default=None,
        help="深路径最多保留多少条叶子路径（默认使用 deep_path_dfs 内置值）。",
    )
    parser.add_argument(
        "--deep-llm-mode",
        choices=["auto", "on", "off"],
        default="off",
        help="深路径 LLM 模式：auto/on/off（默认 off，避免长时间网络等待）。",
    )
    parser.add_argument(
        "--deep-llm-dry-run",
        action="store_true",
        help="深路径逐层 LLM 仅生成 prompt 预览，不实际请求模型。",
    )
    parser.add_argument(
        "--deep-llm-verbose",
        action="store_true",
        help="深路径 LLM 轮询时打印每一步发送内容和回复预览。",
    )
    parser.add_argument(
        "--deep-llm-prompt-preview-chars",
        type=int,
        default=None,
        help="deep-llm-verbose 时每步 prompt 预览最大字符数。",
    )
    parser.add_argument(
        "--deep-llm-raw-preview-chars",
        type=int,
        default=None,
        help="deep-llm-verbose 时每步原始回复预览最大字符数。",
    )
    parser.add_argument(
        "--deep-llm-log-file",
        default=None,
        help=(
            "深路径 LLM 逐层日志 JSONL 路径。"
            "不传时，deep-llm 会自动写入 ./deep_llm_runs/<run>/deep_llm_log.jsonl。"
        ),
    )
    parser.add_argument(
        "--deep-top",
        type=int,
        default=None,
        help="深路径终端打印前 N 条路径（默认使用 deep_path_dfs 内置值）。",
    )
    parser.add_argument(
        "--deep-entry",
        action="append",
        default=[],
        help="深路径入口点（可重复），支持地址或名称关键词；不传则自动选入口。",
    )
    parser.add_argument(
        "--deep-output",
        default=None,
        help="深路径输出 JSON 路径（仅单输入时有效）。",
    )
    parser.add_argument(
        "--phase7",
        action="store_true",
        help="直接执行 Phase7（goal_deep_engine）；若缺失 DB，会自动执行仅 IDA 前置（不跑 Ghidra）后再进入 Phase7。",
    )
    parser.add_argument(
        "--phase7-after-align",
        action="store_true",
        help="在 both + semantic_align 完成后继续执行 Phase7。",
    )
    parser.add_argument(
        "--phase7-output",
        default=None,
        help="Phase7 输出 JSON 路径（仅单输入时有效）。",
    )
    parser.add_argument(
        "--phase7-runs-root",
        default=None,
        help="Phase7 运行目录根路径（透传到 goal_deep_engine.py 的 --runs-root）。",
    )
    parser.add_argument(
        "--phase7-run-id",
        default=None,
        help="Phase7 运行 ID（透传到 goal_deep_engine.py 的 --run-id）。",
    )
    parser.add_argument(
        "--phase7-resume",
        action="store_true",
        help="Phase7 从 checkpoint 续跑（透传 --resume）。",
    )
    parser.add_argument(
        "--phase7-force-resume",
        action="store_true",
        help="Phase7 强制续跑（透传 --force-resume）。",
    )
    parser.add_argument(
        "--phase7-log-raw-llm",
        action="store_true",
        help="Phase7 落盘原始 LLM 请求/响应（透传 --log-raw-llm）。",
    )
    parser.add_argument(
        "--phase7-apply-db",
        action="store_true",
        help="Phase7 启用 DB 回填（透传 --apply-db）。",
    )
    parser.add_argument(
        "--phase7-apply-max-rows",
        type=int,
        default=None,
        help="Phase7 DB 回填最大行数（透传 --apply-max-rows）。",
    )
    parser.add_argument(
        "--phase7-apply-min-confidence",
        type=int,
        default=None,
        help="Phase7 DB 回填最小置信度（透传 --apply-min-confidence）。",
    )
    parser.add_argument(
        "--phase7-extra-arg",
        action="append",
        default=[],
        help="额外透传给 goal_deep_engine.py 的参数片段（可重复）。",
    )
    parser.add_argument(
        "--phase7-task-config",
        default=None,
        help="Phase7 单次任务 JSON（透传 --task-config；默认值来自根 config.yaml）。",
    )
    parser.add_argument(
        "--phase7-no-console-progress",
        action="store_true",
        default=False,
        help="关闭 Phase7 终端阶段性进度（默认会打印 Phase7.5/建图/DFS/LLM 简要信息）。",
    )

    args = parser.parse_args()
    
    # 验证输入文件
    sample_paths = []
    for input_file in args.input_files:
        path = Path(input_file)
        if not path.exists():
            print(f"错误: 输入文件不存在: {input_file}", file=sys.stderr)
            sys.exit(1)
        sample_paths.append(path.resolve())
    
    try:
        # 创建综合分析工具
        demo = ReBindDemo(args.global_config, args.platform)
        print(f"[ReBindDemo] 平台检测: {demo.platform_key} (system={platform.system()}, release={platform.release()})")
        
        # 在执行分析之前，进行 OpenAI API Key 启动检查；纯导出或 deep-path+llm-off 时跳过
        deep_llm_mode = str(args.deep_llm_mode or "auto").lower()
        if not args.dump_db_only and not (args.deep_path and deep_llm_mode == "off"):
            _probe_openai_keys()
        
        if demo.ghidra_adapter:
            _warn_if_missing_executable(
                "Ghidra cmd_path",
                (demo.ghidra_adapter.config.get("ghidra", {}) or {}).get("cmd_path"),
            )
        if demo.ida_adapter:
            _warn_if_missing_executable(
                "IDA cmd_path",
                (demo.ida_adapter.config.get("ida", {}) or {}).get("cmd_path"),
            )
        _warn_if_missing_executable(
            "Semantics runtime.idat_exe",
            (demo.semantics_runtime or {}).get("idat_exe"),
        )

        if args.db and len(sample_paths) != 1:
            print("错误: 当前 --db 仅支持单个输入样本。", file=sys.stderr)
            sys.exit(1)
        db_override = Path(args.db).expanduser().resolve() if args.db else None

        if args.dump_db_only and (args.phase5_only or args.phase5_only_force_all):
            print("错误: --dump-db-only 不可与 --phase5-only/--phase5-only-force-all 同时使用。", file=sys.stderr)
            sys.exit(1)
        if args.deep_path and (args.dump_db_only or args.phase5_only or args.phase5_only_force_all):
            print("错误: --deep-path 不可与 --dump-db-only/--phase5-only/--phase5-only-force-all 同时使用。", file=sys.stderr)
            sys.exit(1)
        if args.phase7 and (args.dump_db_only or args.phase5_only or args.phase5_only_force_all or args.deep_path):
            print("错误: --phase7 不可与 --dump-db-only/--phase5-only/--phase5-only-force-all/--deep-path 同时使用。", file=sys.stderr)
            sys.exit(1)
        if args.phase7_after_align and (args.dump_db_only or args.phase5_only or args.phase5_only_force_all or args.deep_path or args.phase7):
            print("错误: --phase7-after-align 不可与 --dump-db-only/--phase5-only/--phase5-only-force-all/--deep-path/--phase7 同时使用。", file=sys.stderr)
            sys.exit(1)
        if args.phase7_after_align and (args.ghidra or args.ida):
            print("错误: --phase7-after-align 仅适用于 both 流程。", file=sys.stderr)
            sys.exit(1)
        if args.deep_llm_log_file and not args.deep_path:
            print("错误: --deep-llm-log-file 仅在 --deep-path 模式下可用。", file=sys.stderr)
            sys.exit(1)
        if args.phase7_output and not (args.phase7 or args.phase7_after_align):
            print("错误: --phase7-output 仅在 --phase7 或 --phase7-after-align 模式下可用。", file=sys.stderr)
            sys.exit(1)
        if (
            args.phase7_runs_root
            or args.phase7_run_id
            or args.phase7_resume
            or args.phase7_force_resume
            or args.phase7_log_raw_llm
            or args.phase7_no_console_progress
            or args.phase7_apply_db
            or args.phase7_apply_max_rows is not None
            or args.phase7_apply_min_confidence is not None
            or args.phase7_extra_arg
            or args.phase7_task_config
        ) and not (args.phase7 or args.phase7_after_align):
            print("错误: phase7 相关参数仅在 --phase7 或 --phase7-after-align 模式下可用。", file=sys.stderr)
            sys.exit(1)

        if args.deep_output and len(sample_paths) != 1:
            print("错误: --deep-output 仅支持单个输入。", file=sys.stderr)
            sys.exit(1)
        if args.phase7_output and len(sample_paths) != 1:
            print("错误: --phase7-output 仅支持单个输入。", file=sys.stderr)
            sys.exit(1)

        if args.phase7:
            if args.phase7_task_config:
                _tcp = Path(args.phase7_task_config).expanduser().resolve()
                if not _tcp.is_file():
                    print(
                        "[ReBindDemo] 错误: --phase7-task-config 指向的文件不存在:\n"
                        f"  {_tcp}\n"
                        "请先创建该 JSON，或传入已存在的 preset/任务文件路径。\n"
                        "省略该参数时使用根 config.yaml 的 semantics.phase7.task_defaults。",
                        file=sys.stderr,
                    )
                    sys.exit(1)
            phase7_output = Path(args.phase7_output).expanduser().resolve() if args.phase7_output else None
            phase7_runs_root = Path(args.phase7_runs_root).expanduser().resolve() if args.phase7_runs_root else None
            ensure_phase7_db_for_inputs(
                demo,
                sample_paths,
                db_path_override=db_override,
            )
            run_phase7_analysis(
                sample_paths,
                platform_key=demo.platform_key,
                db_path_override=db_override,
                output_path=phase7_output,
                runs_root=phase7_runs_root,
                run_id=args.phase7_run_id,
                resume=bool(args.phase7_resume),
                force_resume=bool(args.phase7_force_resume),
                log_raw_llm=bool(args.phase7_log_raw_llm),
                apply_db=bool(args.phase7_apply_db),
                apply_max_rows=args.phase7_apply_max_rows,
                apply_min_confidence=args.phase7_apply_min_confidence,
                extra_args=list(args.phase7_extra_arg or []),
                no_console_progress=bool(args.phase7_no_console_progress),
                task_config_path=(
                    Path(args.phase7_task_config).expanduser().resolve()
                    if args.phase7_task_config
                    else None
                ),
            )
            return

        if args.dump_db_only:
            run_semantic_align(
                sample_paths,
                semantics_config_path=demo.semantics_config_path,
                semantics_runtime=demo.semantics_runtime,
                db_path_override=db_override,
                dump_db_only=True,
                sync_ida_before_dump=args.sync_ida_before_dump,
                unlock_locked_on_sync=args.unlock_locked_on_sync,
            )
            return

        if args.deep_path:
            deep_output = Path(args.deep_output).expanduser().resolve() if args.deep_output else None
            deep_llm_log_file = Path(args.deep_llm_log_file).expanduser() if args.deep_llm_log_file else None
            run_deep_path_analysis(
                sample_paths,
                semantics_config_path=demo.semantics_config_path,
                db_path_override=db_override,
                max_depth=args.deep_max_depth,
                max_paths=args.deep_max_paths,
                llm_mode=args.deep_llm_mode,
                llm_dry_run=bool(args.deep_llm_dry_run),
                llm_verbose=bool(args.deep_llm_verbose),
                llm_prompt_preview_chars=args.deep_llm_prompt_preview_chars,
                llm_raw_preview_chars=args.deep_llm_raw_preview_chars,
                llm_log_file=deep_llm_log_file,
                top=args.deep_top,
                entries=list(args.deep_entry or []),
                output_path=deep_output,
            )
            return

        if args.phase5_only_force_all:
            run_semantic_align(
                sample_paths,
                semantics_config_path=demo.semantics_config_path,
                semantics_runtime=demo.semantics_runtime,
                phase5_only_force_all=True,
                db_path_override=db_override,
            )
            return
        if args.phase5_only:
            run_semantic_align(
                sample_paths,
                semantics_config_path=demo.semantics_config_path,
                semantics_runtime=demo.semantics_runtime,
                phase5_only=True,
                db_path_override=db_override,
            )
            return
        
        # 设置详细输出
        if args.verbose:
            if demo.ghidra_adapter:
                demo.ghidra_adapter.logger.setLevel(10)  # DEBUG level
                for handler in demo.ghidra_adapter.logger.handlers:
                    handler.setLevel(10)
            if demo.ida_adapter:
                demo.ida_adapter.logger.setLevel(10)  # DEBUG level
                for handler in demo.ida_adapter.logger.handlers:
                    handler.setLevel(10)
        
        # 确定使用的工具
        force_export = bool(args.force_export)

        if args.ghidra:
            if not demo.ghidra_adapter:
                print("错误: Ghidra 适配器不可用", file=sys.stderr)
                sys.exit(1)

            ghidra_suffix = (
                demo.ghidra_adapter.config.get("output", {}) or {}
            ).get("dir_suffix", "_ghidemo")

            cached, uncached = [], []
            for sp, raw in zip(sample_paths, args.input_files):
                out = _expected_output_dir(sp, ghidra_suffix)
                if _export_dir_has_content(out):
                    cached.append((sp, raw, out))
                else:
                    uncached.append(raw)

            files_to_run = list(uncached)
            if cached and not force_export:
                use_cache = _prompt_use_cache(
                    [f"{sp.name}  (Ghidra: {out})" for sp, _, out in cached]
                )
                if not use_cache:
                    files_to_run.extend(raw for _, raw, _ in cached)
            elif force_export and cached:
                files_to_run.extend(raw for _, raw, _ in cached)

            if files_to_run:
                output_dirs = demo.analyze_with_ghidra(files_to_run)
                print("\n" + "="*60)
                print("Ghidra 分析完成!")
                print("输出目录:")
                for output_dir in output_dirs:
                    print(f"  - {output_dir}")
                print("="*60)

        elif args.ida:
            if not demo.ida_adapter:
                print("错误: IDA 适配器不可用", file=sys.stderr)
                sys.exit(1)

            ida_suffix = (
                demo.ida_adapter.config.get("output", {}) or {}
            ).get("dir_suffix", "_idademo")

            cached, uncached = [], []
            for sp, raw in zip(sample_paths, args.input_files):
                out = _expected_output_dir(sp, ida_suffix)
                if _export_dir_has_content(out):
                    cached.append((sp, raw, out))
                else:
                    uncached.append(raw)

            files_to_run = list(uncached)
            if cached and not force_export:
                use_cache = _prompt_use_cache(
                    [f"{sp.name}  (IDA: {out})" for sp, _, out in cached]
                )
                if not use_cache:
                    files_to_run.extend(raw for _, raw, _ in cached)
            elif force_export and cached:
                files_to_run.extend(raw for _, raw, _ in cached)

            if files_to_run:
                output_dirs = demo.analyze_with_ida(files_to_run)
                print("\n" + "="*60)
                print("IDA 分析完成!")
                print("输出目录:")
                for output_dir in output_dirs:
                    print(f"  - {output_dir}")
                print("="*60)

        else:
            # 默认使用两个工具
            if not demo.ghidra_adapter and not demo.ida_adapter:
                print("错误: 没有可用的分析适配器", file=sys.stderr)
                sys.exit(1)

            ghidra_suffix = (
                (demo.ghidra_adapter.config.get("output", {}) or {}).get("dir_suffix", "_ghidemo")
                if demo.ghidra_adapter else "_ghidemo"
            )
            ida_suffix = (
                (demo.ida_adapter.config.get("output", {}) or {}).get("dir_suffix", "_idademo")
                if demo.ida_adapter else "_idademo"
            )

            cached, uncached = [], []
            for sp, raw in zip(sample_paths, args.input_files):
                ghidra_out = _expected_output_dir(sp, ghidra_suffix)
                ida_out = _expected_output_dir(sp, ida_suffix)
                ghidra_ok = _export_dir_has_content(ghidra_out) if demo.ghidra_adapter else True
                ida_ok = _export_dir_has_content(ida_out) if demo.ida_adapter else True
                if ghidra_ok and ida_ok:
                    cached.append((sp, raw))
                else:
                    uncached.append(raw)

            files_needing_export = list(uncached)
            reuse_aligned_db_samples: Set[Path] = set()
            if cached and not force_export:
                use_cache = _prompt_use_cache(
                    [f"{sp.name}  (Ghidra + IDA 导出)" for sp, _ in cached]
                )
                if not use_cache:
                    files_needing_export.extend(raw for _, raw in cached)
                else:
                    reuse_aligned_db_samples.update(sp.resolve() for sp, _ in cached)
            elif force_export and cached:
                files_needing_export.extend(raw for _, raw in cached)

            if files_needing_export:
                results = demo.analyze_with_both(files_needing_export)

                print("\n" + "="*60)
                print("分析完成!")

                if results.get('ghidra'):
                    print("\nGhidra 输出目录:")
                    for output_dir in results['ghidra']:
                        print(f"  - {output_dir}")

                if results.get('ida'):
                    print("\nIDA 输出目录:")
                    for output_dir in results['ida']:
                        print(f"  - {output_dir}")

                print("="*60)

            # 语义对齐仅在同时使用 Ghidra + IDA 后执行
            if args.both and demo.ghidra_adapter and demo.ida_adapter:
                run_semantic_align(
                    sample_paths,
                    semantics_config_path=demo.semantics_config_path,
                    ghidra_dir_suffix=ghidra_suffix,
                    ida_dir_suffix=ida_suffix,
                    semantics_runtime=demo.semantics_runtime,
                    db_path_override=db_override,
                    reuse_aligned_db_samples=reuse_aligned_db_samples,
                )
                if args.phase7_after_align:
                    phase7_output = Path(args.phase7_output).expanduser().resolve() if args.phase7_output else None
                    phase7_runs_root = Path(args.phase7_runs_root).expanduser().resolve() if args.phase7_runs_root else None
                    run_phase7_analysis(
                        sample_paths,
                        platform_key=demo.platform_key,
                        db_path_override=db_override,
                        output_path=phase7_output,
                        runs_root=phase7_runs_root,
                        run_id=args.phase7_run_id,
                        resume=bool(args.phase7_resume),
                        force_resume=bool(args.phase7_force_resume),
                        log_raw_llm=bool(args.phase7_log_raw_llm),
                        apply_db=bool(args.phase7_apply_db),
                        apply_max_rows=args.phase7_apply_max_rows,
                        apply_min_confidence=args.phase7_apply_min_confidence,
                        extra_args=list(args.phase7_extra_arg or []),
                        no_console_progress=bool(args.phase7_no_console_progress),
                        task_config_path=(
                            Path(args.phase7_task_config).expanduser().resolve()
                            if args.phase7_task_config
                            else None
                        ),
                    )
        
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, _handle_sigint)
    main()
