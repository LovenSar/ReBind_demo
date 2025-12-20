#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""semantic_align.py

一键执行“对齐加载 + 语义传播(Phase1-5) + IDA 同步”的流水线：

1) 调用 alignment_loader.py 从 Ghidra / IDA 导出的目录构建 SQLite 数据库；
2) （可选）启动 IDA（idat）并运行 idat_server.py；
3) 在本进程内依次执行 Phase1~Phase5（模块化实现位于 tools/Semantics_Alignment/phases/）。

说明：此脚本是新的工作流入口，避免再通过子进程调用 knowledge_propagation.py。
公共能力已下沉到 kp/（日志、配置、建图、评分等），工作流不再依赖 knowledge_propagation.py。
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import subprocess
import sys
import time
import builtins
import inspect
import http.client
import json
import signal
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import sqlite3

from urllib.parse import urlparse

from dynamic_batching import yield_dynamic_batch
from kp.kp_ida import IDAService
from kp.kp_llm import estimate_token_usage
from kp.kp_logging import install_stdout_tee, setup_logging
from kp.kp_settings import build_llm_settings, load_semantics_config
from kp.kp_graph import build_unified_graph
from kp.kp_scoring import compute_unified_scores
from kp.kp_schema import ensure_analysis_rows_for_binary, ensure_analysis_schema, load_analysis_info
from kp.kp_types import DEFAULT_FUNC_NAME_PATTERN, SUBFUNC_NAME_PATTERN, UnifiedFunctionNode, UnifiedGraph
from kp.kp_unified_prompt import build_unified_batch_prompt, build_unified_prompt
from tqdm import tqdm
from phases.phase1_kp import analyze_one_unified_function as phase1_analyze_one_unified_function
from phases.phase1_kp import analyze_unified_batch as phase1_analyze_unified_batch
from phases.phase2_validation import run_validation_phase as phase2_run_validation_phase
from phases.phase3_globals import run_global_var_phase as phase3_run_global_var_phase
from phases.phase4_lvar import run_local_var_phase as phase4_run_local_var_phase
from phases.phase5_annotation import run_annotation_phase as phase5_run_annotation_phase


SCRIPT_PATH = Path(__file__).resolve()
TOOLS_DIR = SCRIPT_PATH.parent
REPO_ROOT = SCRIPT_PATH.parents[2]

DEFAULT_IDA_HTTP_PORT = 12345
DEFAULT_IDA_URL = f"http://127.0.0.1:{DEFAULT_IDA_HTTP_PORT}"
DEFAULT_IDAT_EXE = "/Applications/IDA Professional 9.2.app/Contents/MacOS/idat"
LIBRARY_INIT_FAILURE_MESSAGE = "Library initialization failed with result: 4"

_CTRL_C_EXIT_REQUESTED = False
_CTRL_C_EXIT_URL = DEFAULT_IDA_URL


def _set_ctrl_c_exit_url(url: str) -> None:
    """Remember which IDA HTTP address the Ctrl+C handler should target."""
    global _CTRL_C_EXIT_URL
    normalized = (url or "").strip()
    if not normalized:
        normalized = DEFAULT_IDA_URL
    _CTRL_C_EXIT_URL = normalized


def _send_ida_save_and_exit(timeout_s: float = 2.0) -> None:
    """POST {'action': 'save_and_exit'} to the configured IDA URL."""
    url = _CTRL_C_EXIT_URL
    if not url:
        return
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = urlparse(f"http://{url}")
    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if scheme == "https" else DEFAULT_IDA_HTTP_PORT)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    payload = json.dumps({"action": "save_and_exit"}).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": str(len(payload)),
    }

    conn_cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
    conn = None
    try:
        conn = conn_cls(host, port, timeout=float(timeout_s))
        conn.request("POST", path, body=payload, headers=headers)
        resp = conn.getresponse()
        resp.read()
        print(f"[SemanticAlign] 已向 {url} 发送 save_and_exit 请求 (HTTP {resp.status}).")
    except Exception as exc:
        print(f"[SemanticAlign] 发送 save_and_exit 请求失败: {exc}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _handle_ctrl_c(signum, frame):
    """Signal handler that tells IDA to exit before propagating KeyboardInterrupt."""
    global _CTRL_C_EXIT_REQUESTED
    if not _CTRL_C_EXIT_REQUESTED:
        _CTRL_C_EXIT_REQUESTED = True
        print("[SemanticAlign] 捕获 Ctrl+C，正在请求 IDA save_and_exit...")
        _send_ida_save_and_exit()
    signal.default_int_handler(signum, frame)


def _install_print_with_location() -> None:
    """Prefix every print with absolute file path and line number."""
    if getattr(builtins, "_original_print", None):
        return

    builtins._original_print = builtins.print  # type: ignore[attr-defined]

    def _print_with_location(*args, **kwargs):
        frame = inspect.currentframe()
        if frame and frame.f_back:
            caller = frame.f_back
            path = Path(caller.f_code.co_filename).resolve()
            lineno = caller.f_lineno
            prefix = f"{path}:{lineno} "
        else:
            prefix = ""
        message = " ".join(str(a) for a in args)
        builtins._original_print(f"{prefix}{message}", **kwargs)

    builtins.print = _print_with_location  # type: ignore[assignment]


_install_print_with_location()


def derive_tmp_layout(sample_path: Path) -> dict:
    """Generate tmp layout adjacent to the provided sample."""

    sample_path = sample_path.expanduser().resolve()
    tmp_root = sample_path.parent
    tmp_root.mkdir(parents=True, exist_ok=True)

    sanitized = re.sub(r"[^A-Za-z]", "_", sample_path.name)
    sample_name = sample_path.name

    defaults = {
        "tmp_root": tmp_root,
        "db_path": tmp_root / f"{sample_name}.db",
        "dump_txt": tmp_root / "db_sample_dump.txt",
        "dump_xlsx": tmp_root / "db_sample_dump.xlsx",
        "ida_log": tmp_root / "idat_log.txt",
        "ghidra_dir": tmp_root / f"{sanitized}_ghidemo",
        "ida_dir": tmp_root / f"{sanitized}_idademo",
    }
    return defaults


def run_alignment_loader(
    db_path: Path,
    ghidra_dir: Path,
    ida_dir: Path,
    dump_txt: Path,
    dump_xlsx: Path,
    delete_db: bool = True,
) -> None:
    """
    调用 alignment_loader.py 构建对齐数据库，并导出文本/Excel 快照。
    """
    cmd = [
        sys.executable,
        str(TOOLS_DIR / "alignment_loader.py"),
        "--db",
        str(db_path),
        "--ghidra-dir",
        str(ghidra_dir),
        "--ida-dir",
        str(ida_dir),
        "--dump-db",
        "--dump-db-output",
        str(dump_txt),
        "--dump-db-workbook",
        str(dump_xlsx),
    ]

    # if delete_db:
    #     cmd.append("--delete-db")

    print("[SemanticAlign] 运行 alignment_loader.py 构建对齐数据库...")
    print("  命令:", " ".join(cmd))
    result = subprocess.run(cmd, cwd=str(REPO_ROOT))
    if result.returncode != 0:
        raise SystemExit(
            f"[SemanticAlign] alignment_loader.py 执行失败，退出码={result.returncode}"
        )


def launch_idat_server(
    idat_exe: str,
    ida_script: Path,
    sample_path: Path,
    log_path: Path,
) -> subprocess.Popen:
    """
    启动 IDA（idat），在其中加载 sample 并运行 idat_server.py。
    返回子进程对象，供后续等待。
    """
    cmd = [
        idat_exe,
        "-A",
        f"-L{log_path}",
        f"-S{ida_script}",
        str(sample_path),
    ]
    print("[SemanticAlign] 启动 IDA(idat) + idat_server...")
    print("  命令:", " ".join(str(c) for c in cmd))
    try:
        # 让 idat 运行在独立的 session/process group 中，避免用户在终端按 Ctrl+C
        # 中断主流程时把 idat_server 一起 SIGINT 掉，导致后续出现 Connection refused。
        proc = subprocess.Popen(cmd, cwd=str(REPO_ROOT), start_new_session=True)
    except FileNotFoundError:
        raise SystemExit(
            f"[SemanticAlign] 无法找到可执行文件 {idat_exe!r}，"
            "请确认 IDA 的 idat 已添加到 PATH，或通过 --idat-exe 指定完整路径。"
        )
    return proc


def _read_log_tail(log_path: Path, max_bytes: int = 64 * 1024) -> str:
    """Return the last chunk of the IDA log to help detect startup failures."""
    if not log_path.exists():
        return ""
    try:
        with log_path.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            end_pos = fh.tell()
            start_pos = max(0, end_pos - int(max_bytes))
            fh.seek(start_pos, os.SEEK_SET)
            return fh.read().decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _log_indicates_library_failure(log_path: Path) -> bool:
    chunk = _read_log_tail(log_path)
    return LIBRARY_INIT_FAILURE_MESSAGE in chunk


def _exit_if_library_init_failed(log_path: Path, ida_proc: subprocess.Popen) -> None:
    if not _log_indicates_library_failure(log_path):
        return

    msg = (
        "[SemanticAlign] 发现 IDA 报错“Library initialization failed with result: 4”，"
        "说明资源已锁定。已停止后续流水线。"
    )
    print(msg)
    if ida_proc.poll() is None:
        try:
            ida_proc.terminate()
            ida_proc.wait(timeout=5)
        except Exception:
            try:
                ida_proc.kill()
            except Exception:
                pass
    raise SystemExit(msg)


def _wait_for_ida_process_exit(proc: subprocess.Popen, *, timeout: float = 300.0) -> None:
    """Wait for the IDA(idat) process to exit, printing status or timing out."""

    if proc.poll() is not None:
        print(f"[SemanticAlign] IDA(idat) 进程已退出，退出码={proc.returncode}")
        return

    try:
        exit_code = proc.wait(timeout=timeout)
        print(f"[SemanticAlign] IDA(idat) 进程已退出，退出码={exit_code}")
    except subprocess.TimeoutExpired:
        print(
            "[SemanticAlign] 等待 IDA(idat) 进程退出超时，如需强制终止请手动结束 idat 进程。"
        )
        try:
            proc.kill()
        except Exception:
            pass


def _pick_single_binary_id(conn: sqlite3.Connection) -> int:
    cur = conn.cursor()
    cur.execute("SELECT id FROM binaries ORDER BY id LIMIT 1;")
    row = cur.fetchone()
    if not row:
        raise RuntimeError("数据库中不存在 binaries 记录，无法确定 binary_id。")
    return int(row[0])


def _phase1_pending_nodes(
    graph: UnifiedGraph, analysis_info: Dict[int, dict]
) -> List[UnifiedFunctionNode]:
    """Return the Phase1 candidates that still have default/empty names."""
    locked_states = {"ANALYZED", "LOCKED"}
    analyzed_entry_vas = set()
    for node in graph.nodes.values():
        for fid in node.function_ids:
            info = analysis_info.get(int(fid))
            if info and info.get("analysis_state") in locked_states:
                analyzed_entry_vas.add(int(node.entry_va))
                break

    targets = []
    for entry_va, node in graph.nodes.items():
        if int(entry_va) in analyzed_entry_vas:
            continue
        if node.names:
            if any((name and not DEFAULT_FUNC_NAME_PATTERN.fullmatch(name)) for name in node.names):
                continue
        if not _node_has_ida_subfunc_candidate(node, graph):
            continue
        targets.append(node)
    return targets


def _node_has_ida_subfunc_candidate(node: UnifiedFunctionNode, graph: UnifiedGraph) -> bool:
    """Only keep nodes backed by IDA's default sub_ function entries."""
    ida_present = any(graph.func_tool.get(fid, "").lower() == "ida" for fid in node.function_ids)
    if not ida_present:
        return False
    ida_names = node.names_by_tool.get("ida")
    if not ida_names:
        return False
    return any(SUBFUNC_NAME_PATTERN.fullmatch(name or "") for name in ida_names)


def run_semantic_pipeline(
    *,
    db_path: Path,
    ida_url: str,
    ida_sync: bool,
    semantics_config_path: Optional[str] = None,
    phases: Optional[Iterable[int]] = None,
    phase5_force_all: bool = False,
) -> None:
    """Run selected phases in-process (no subprocess)."""

    logger = logging.getLogger(__name__)

    phases_to_run = {1, 2, 3, 4, 5}
    if phases is not None:
        phases_to_run = {int(x) for x in phases if int(x) in (1, 2, 3, 4, 5)}
        if not phases_to_run:
            raise ValueError("phases 为空或无效，允许值为 1..5。")

    # 统一日志输出，便于回溯（沿用 knowledge_propagation 的日志格式）
    setup_logging(TOOLS_DIR / "log.log", input_db=db_path)
    install_stdout_tee(logger)
    logger.info("知识传播管线启动，数据库: %s", db_path)

    semantics_config = load_semantics_config(semantics_config_path)
    llm_settings = build_llm_settings(
        semantics_config,
        model=None,
        temperature=None,
        max_tokens=None,
    )

    ida = IDAService(ida_url, enabled=ida_sync)

    conn = sqlite3.connect(str(db_path))
    try:
        binary_id = _pick_single_binary_id(conn)

        # 若对齐库未正确加载视图，后续建图会失败；这里提前给出更明确的引导。
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM binary_views WHERE binary_id = ?;", (int(binary_id),))
        view_cnt = int(cur.fetchone()[0] or 0)
        if view_cnt <= 0:
            raise RuntimeError(
                "对齐数据库中缺少 binary_views 记录，无法建图。\n"
                f"  binary_id={binary_id}, binary_views.count={view_cnt}\n"
                "通常原因：alignment_loader 未成功加载 Ghidra/IDA 输出目录（例如缺少 *_binaryinfo），或复用了旧 DB。\n"
                "建议：重新运行 alignment_loader（在本脚本中不要使用 --no-align），并确认输出目录包含 *_binaryinfo / *_disassembly / *_pseudocode(或 *_pesudocode)。"
            )

        ensure_analysis_schema(conn)
        ensure_analysis_rows_for_binary(conn, binary_id)

        unified_graph = build_unified_graph(conn, binary_id)

        # ---------------------
        # Phase 1: Knowledge Propagation (unified analysis)
        # ---------------------
        if 1 in phases_to_run:
            print("[SemanticAlign] Phase 1: Knowledge Propagation")
            processed = 0

            initial_analysis_info = load_analysis_info(conn)
            phase1_targets = _phase1_pending_nodes(unified_graph, initial_analysis_info)
            phase1_total_targets = len(phase1_targets)
            phase1_progress: Optional[tqdm] = None
            if phase1_total_targets:
                print(f"[SemanticAlign] Phase 1 即将重命名 {phase1_total_targets} 个函数：")
                for node in sorted(phase1_targets, key=lambda n: n.entry_va):
                    if node.names:
                        name_repr = ", ".join(sorted(node.names))
                    else:
                        name_repr = "(当前无语义命名)"
                    print(f"  - entry_va=0x{int(node.entry_va):08X}, 原始名称={name_repr}")
                phase1_progress = tqdm(
                    total=phase1_total_targets,
                    desc="[SemanticAlign] Phase 1",
                    unit="func",
                    leave=True,
                )
            else:
                print("[SemanticAlign] Phase 1 当前无需要重命名的函数。")

            while True:
                analysis_info = load_analysis_info(conn)
                candidates = _phase1_pending_nodes(unified_graph, analysis_info)
                if not candidates:
                    break

                # 对候选集计算分数，并取 Top-N
                scores = {}
                try:
                    scores = compute_unified_scores(unified_graph, analysis_info)
                except Exception:
                    scores = {}

                candidates.sort(key=lambda n: int(scores.get(n.entry_va, 0)), reverse=True)

                requested_nodes = candidates[: min(50, len(candidates))]

                def _phase1_builder(nodes):
                    if len(nodes) == 1:
                        return build_unified_prompt(conn, unified_graph, nodes[0], analysis_info)
                    return build_unified_batch_prompt(conn, unified_graph, nodes, analysis_info)

                try:
                    batch = next(
                        yield_dynamic_batch(
                            requested_nodes,
                            prompt_builder=_phase1_builder,
                            max_prompt_tokens=llm_settings.max_tokens,
                            token_estimator=estimate_token_usage,
                            initial_batch_size=len(requested_nodes),
                            min_batch_size=1,
                        )
                    )
                except StopIteration:
                    break

                selected_nodes = batch.items
                if not selected_nodes:
                    break

                if len(selected_nodes) > 1:
                    phase1_analyze_unified_batch(
                        conn=conn,
                        graph=unified_graph,
                        nodes=selected_nodes,
                        analysis_info=analysis_info,
                        llm_settings=llm_settings,
                        prompt=batch.prompt,
                        estimated_tokens=batch.estimated_tokens,
                        dry_run=False,
                        ida_sync=ida_sync,
                        ida_url=ida_url,
                    )
                    processed += len(selected_nodes)
                    if phase1_progress:
                        phase1_progress.update(len(selected_nodes))
                else:
                    node = selected_nodes[0]
                    phase1_analyze_one_unified_function(
                        conn=conn,
                        graph=unified_graph,
                        entry_va=node.entry_va,
                        analysis_info=analysis_info,
                        llm_settings=llm_settings,
                        dry_run=False,
                        ida_sync=ida_sync,
                        ida_url=ida_url,
                    )
                    processed += 1
                    if phase1_progress:
                        phase1_progress.update(1)

            if phase1_progress:
                phase1_progress.close()
            print(f"[SemanticAlign] Phase 1 完成，处理物理函数数量：{processed}")
        else:
            print("[SemanticAlign] 跳过 Phase 1（未选中）。")

        # ---------------------
        # Phase 2: Top-down validation
        # ---------------------
        if 2 in phases_to_run:
            print("[SemanticAlign] Phase 2: Validation")
            phase2_run_validation_phase(
                conn=conn,
                graph=unified_graph,
                llm_settings=llm_settings,
                ida_sync=ida_sync,
                ida_url=ida_url,
                dry_run=False,
                batch_size=10,
            )
        else:
            print("[SemanticAlign] 跳过 Phase 2（未选中）。")

        # ---------------------
        # Phase 3: Globals
        # ---------------------
        if 3 in phases_to_run:
            print("[SemanticAlign] Phase 3: Globals")
            phase3_run_global_var_phase(
                conn=conn,
                graph=unified_graph,
                llm_settings=llm_settings,
                max_globals=None,
                ida_sync=ida_sync,
                ida_url=ida_url,
                dry_run=False,
                batch_size=10,
            )
        else:
            print("[SemanticAlign] 跳过 Phase 3（未选中）。")

        # ---------------------
        # Phase 4: Local vars
        # ---------------------
        if 4 in phases_to_run:
            print("[SemanticAlign] Phase 4: Local Vars")
            phase4_run_local_var_phase(
                conn=conn,
                graph=unified_graph,
                llm_settings=llm_settings,
                ida_sync=ida_sync,
                ida_url=ida_url,
                semantics_config=semantics_config,
                dry_run=False,
                batch_size=3,
                only_sub=False,
                ida_only=ida_sync,
                min_pseudo_lines=6,
                exclude_import_export=True,
            )
        else:
            print("[SemanticAlign] 跳过 Phase 4（未选中）。")

        # ---------------------
        # Phase 5: Annotation
        # ---------------------
        if 5 in phases_to_run:
            print("[SemanticAlign] Phase 5: Annotation")
            phase5_run_annotation_phase(
                conn=conn,
                graph=unified_graph,
                llm_settings=llm_settings,
                ida_sync=ida_sync,
                ida_url=ida_url,
                semantics_config=semantics_config,
                dry_run=False,
                batch_size=5,
                min_pseudo_lines=6,
                force_all=bool(phase5_force_all),
            )
        else:
            print("[SemanticAlign] 跳过 Phase 5（未选中）。")

    finally:
        conn.close()

    # 请求 IDA 保存并退出（可选）
    if ida_sync:
        try:
            print(f"[SemanticAlign] 请求 IDA 保存并退出: {ida_url}")
            ida.save_and_exit(timeout=2.0)
        except Exception:
            # 连接中断通常是 IDA 正在关闭，属于预期
            pass


def main(argv: Optional[Iterable[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="一键执行 alignment_loader + IDA(idat_server) + Phase(默认 1-5，可选仅跑 Phase5) 的语义对齐流水线。",
    )
    parser.add_argument(
        "--db",
        default=None,
        help="SQLite 对齐数据库路径（默认: 在样本目录下生成 {sample_name}.db，例如 tmp/Malware_sample.exe.db）",
    )
    parser.add_argument(
        "--ghidra-dir",
        default=None,
        help="Ghidra 输出目录（默认: 基于 --sample 自动生成 tmp/<sample>_ghidemo）",
    )
    parser.add_argument(
        "--ida-dir",
        default=None,
        help="IDA 输出目录（默认: 基于 --sample 自动生成 tmp/<sample>_idademo）",
    )
    parser.add_argument(
        "--sample",
        required=True,
        help="待分析二进制样本路径（必填）",
    )
    parser.add_argument(
        "--config",
        default=None,
        help=(
            "语义对齐模块配置文件路径（默认: "
            f"{TOOLS_DIR / 'config.yaml'})"
        ),
    )
    parser.add_argument(
        "--idat-exe",
        default=DEFAULT_IDAT_EXE,
        help=f"IDA 命令行可执行文件名或完整路径（默认: {DEFAULT_IDAT_EXE})",
    )
    parser.add_argument(
        "--ida-script",
        default=str(TOOLS_DIR / "idat_server.py"),
        help="在 IDA 中运行的 idat_server.py 脚本路径（默认: tools/Semantics_Alignment/idat_server.py）。",
    )
    parser.add_argument(
        "--ida-url",
        default=DEFAULT_IDA_URL,
        help=f"连接的 IDA HTTP 服务地址（默认: {DEFAULT_IDA_URL})",
    )
    parser.add_argument(
        "--no-align",
        action="store_true",
        help="跳过 alignment_loader 阶段，仅执行 IDA + 语义阶段（默认 Phase1-5；可配合 --phase5-only）。",
    )
    parser.add_argument(
        "--no-ida",
        action="store_true",
        help="不启动 IDA / idat_server，仅离线运行语义阶段（默认 Phase1-5；可配合 --phase5-only；不会做 IDA 同步）。",
    )
    parser.add_argument(
        "--phase5-only",
        action="store_true",
        help="仅运行 Phase 5（逐行注释注入），跳过 Phase 1-4。",
    )
    parser.add_argument(
        "--phase5-only-force-all",
        action="store_true",
        help="Phase5-only 进阶：忽略“是否已注释”状态，强制对所有可用伪代码的物理函数跑一次 Phase 5（不改变 min_pseudo_lines 过滤）。",
    )
    parser.add_argument(
        "--ida-start-delay",
        type=float,
        default=3.0,
        help="启动 idat 后在本地等待的秒数，再启动语义阶段（默认 3 秒）。",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    selected_phases = [5] if (args.phase5_only or args.phase5_only_force_all) else None
    if args.phase5_only_force_all:
        print("[SemanticAlign] 仅运行 Phase 5（--phase5-only-force-all），并强制覆盖候选集。")
    elif args.phase5_only:
        print("[SemanticAlign] 仅运行 Phase 5（--phase5-only），跳过 Phase 1-4。")

    sample_path = Path(args.sample).expanduser().resolve()
    tmp_defaults = derive_tmp_layout(sample_path)

    if args.db:
        db_path = Path(args.db).expanduser().resolve()
    else:
        db_path = tmp_defaults["db_path"]

    if args.ghidra_dir:
        ghidra_dir = Path(args.ghidra_dir).expanduser().resolve()
    else:
        ghidra_dir = tmp_defaults["ghidra_dir"]

    if args.ida_dir:
        ida_dir = Path(args.ida_dir).expanduser().resolve()
    else:
        ida_dir = tmp_defaults["ida_dir"]

    dump_txt = tmp_defaults["dump_txt"]
    dump_xlsx = tmp_defaults["dump_xlsx"]
    ida_script = Path(args.ida_script).resolve()
    idat_exe = args.idat_exe
    ida_url = args.ida_url

    if not args.no_align:
        run_alignment_loader(
            db_path=db_path,
            ghidra_dir=ghidra_dir,
            ida_dir=ida_dir,
            dump_txt=dump_txt,
            dump_xlsx=dump_xlsx,
            delete_db=True,
        )
    else:
        print("[SemanticAlign] 跳过 alignment_loader 阶段（--no-align）。")

    # 如果不需要 IDA，同步逻辑会关闭，仅离线跑 knowledge_propagation
    if args.no_ida:
        print("[SemanticAlign] 不启动 IDA / idat_server，仅离线运行 Phase1-5（不做 IDA 同步）。")
        run_semantic_pipeline(
            db_path=db_path,
            ida_url=ida_url,
            ida_sync=False,
            semantics_config_path=args.config,
            phases=selected_phases,
            phase5_force_all=bool(args.phase5_only_force_all),
        )
        return

    _set_ctrl_c_exit_url(ida_url)
    signal.signal(signal.SIGINT, _handle_ctrl_c)

    # 启动 IDA(idat) + idat_server
    ida_log = tmp_defaults["ida_log"]
    ida_proc = launch_idat_server(
        idat_exe=idat_exe,
        ida_script=ida_script,
        sample_path=sample_path,
        log_path=ida_log,
    )

    # 给 IDA 一点时间启动（真正的连接检测由各 Phase 内的 wait_for_ida_server 负责）
    if args.ida_start_delay > 0:
        print(f"[SemanticAlign] 等待 {args.ida_start_delay:.1f} 秒以便 IDA 启动...")
        time.sleep(args.ida_start_delay)

    _exit_if_library_init_failed(ida_log, ida_proc)

    # 运行语义传播 Phase1-5（会在内部与 idat_server 建立连接）
    try:
        run_semantic_pipeline(
            db_path=db_path,
            ida_url=ida_url,
            ida_sync=True,
            semantics_config_path=args.config,
            phases=selected_phases,
            phase5_force_all=bool(args.phase5_only_force_all),
        )
    except Exception:
        print("[SemanticAlign] 语义流水线异常终止，正在请求 IDA(save_and_exit)...")
        _send_ida_save_and_exit()
        _wait_for_ida_process_exit(ida_proc, timeout=30.0)
        raise

    # 运行成功后等待 IDA 进程退出
    print("[SemanticAlign] 等待 IDA(idat) 进程退出...")
    _wait_for_ida_process_exit(ida_proc)


    # 若 run_semantic_pipeline 中无异常，则整体成功


if __name__ == "__main__":
    main()
