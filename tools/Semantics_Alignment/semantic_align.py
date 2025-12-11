#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
semantic_align.py

一键执行“对齐加载 + 语义传播 + IDA 同步”的流水线：

1. 调用 alignment_loader.py 从 Ghidra / IDA 导出的目录构建 SQLite 数据库；
2. 启动 IDA（idat）加载 Malware_sample.exe，并在其中运行 idat_server.py；
3. 以 --ida-sync 全量运行 knowledge_propagation.py，与 IDA 端保持联动。

默认等价于依次执行：
  python tools/Semantics_Alignment/alignment_loader.py --delete-db --db tmp/Malware_sample.exe.db ^
         --ghidra-dir tmp/Malware_sample_exe_ghidemo ^
         --ida-dir    tmp/Malware_sample_exe_idademo ^
         --dump-db --dump-db-output tmp/db_sample_dump.txt ^
         --dump-db-workbook tmp/db_sample_dump.xlsx

  idat -A -L"idat_log.txt" ^
       -S"tools/Semantics_Alignment/idat_server.py" "tmp/Malware_sample.exe"

  python tools/Semantics_Alignment/knowledge_propagation.py ^
      --db tmp/Malware_sample.exe.db ^
      --ida-sync
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
import builtins
import inspect
from pathlib import Path
from typing import Iterable, Optional


SCRIPT_PATH = Path(__file__).resolve()
TOOLS_DIR = SCRIPT_PATH.parent
REPO_ROOT = SCRIPT_PATH.parents[2]

DEFAULT_IDA_URL = "http://127.0.0.1:12345"
DEFAULT_IDAT_EXE = "idat"


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
        proc = subprocess.Popen(cmd, cwd=str(REPO_ROOT))
    except FileNotFoundError:
        raise SystemExit(
            f"[SemanticAlign] 无法找到可执行文件 {idat_exe!r}，"
            "请确认 IDA 的 idat 已添加到 PATH，或通过 --idat-exe 指定完整路径。"
        )
    return proc


def run_knowledge_propagation(
    db_path: Path,
    ida_url: str,
    ida_sync: bool = True,
) -> int:
    """
    调用 knowledge_propagation.py 执行语义传播与（可选）IDA 同步。
    """
    cmd = [
        sys.executable,
        str(TOOLS_DIR / "knowledge_propagation.py"),
        "--db",
        str(db_path),
    ]
    if ida_sync:
        cmd.append("--ida-sync")
        cmd.extend(["--ida-url", ida_url])

    print("[SemanticAlign] 运行 knowledge_propagation.py 进行语义传播...")
    print("  命令:", " ".join(cmd))
    result = subprocess.run(cmd, cwd=str(REPO_ROOT))
    if result.returncode != 0:
        print(
            f"[SemanticAlign] knowledge_propagation.py 返回非零退出码：{result.returncode}"
        )
    return result.returncode


def main(argv: Optional[Iterable[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        description="一键执行 alignment_loader + IDA(idat_server) + knowledge_propagation 的语义对齐流水线。",
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
        help=f"knowledge_propagation.py 连接的 IDA HTTP 服务地址（默认: {DEFAULT_IDA_URL})",
    )
    parser.add_argument(
        "--no-align",
        action="store_true",
        help="跳过 alignment_loader 阶段，仅执行 IDA + knowledge_propagation。",
    )
    parser.add_argument(
        "--no-ida",
        action="store_true",
        help="不启动 IDA / idat_server，仅离线运行 knowledge_propagation（不会做 IDA 同步）。",
    )
    parser.add_argument(
        "--ida-start-delay",
        type=float,
        default=3.0,
        help="启动 idat 后在本地等待的秒数，再启动 knowledge_propagation（默认 3 秒）。",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

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
        print("[SemanticAlign] 不启动 IDA / idat_server，仅离线运行 knowledge_propagation。")
        run_knowledge_propagation(
            db_path=db_path,
            ida_url=ida_url,
            ida_sync=False,
        )
        return

    # 启动 IDA(idat) + idat_server
    ida_log = tmp_defaults["ida_log"]
    ida_proc = launch_idat_server(
        idat_exe=idat_exe,
        ida_script=ida_script,
        sample_path=sample_path,
        log_path=ida_log,
    )

    # 给 IDA 一点时间启动（真正的连接检测由 knowledge_propagation 内部 wait_for_ida_server 负责）
    if args.ida_start_delay > 0:
        print(f"[SemanticAlign] 等待 {args.ida_start_delay:.1f} 秒以便 IDA 启动...")
        time.sleep(args.ida_start_delay)

    # 运行 knowledge_propagation（会在内部与 idat_server 建立连接，并在结束时发出 save_and_exit）
    kp_ret = run_knowledge_propagation(
        db_path=db_path,
        ida_url=ida_url,
        ida_sync=True,
    )

    # 等待 IDA 进程退出（save_and_exit 通常会触发有序关闭）
    print("[SemanticAlign] 等待 IDA(idat) 进程退出...")
    try:
        ida_exit = ida_proc.wait(timeout=300)
        print(f"[SemanticAlign] IDA(idat) 进程已退出，退出码={ida_exit}")
    except subprocess.TimeoutExpired:
        print(
            "[SemanticAlign] 等待 IDA 退出超时，如需强制终止请手动结束 idat 进程。"
        )

    # 将 knowledge_propagation 的退出码作为整个脚本的退出码
    if kp_ret != 0:
        raise SystemExit(kp_ret)


if __name__ == "__main__":
    main()
