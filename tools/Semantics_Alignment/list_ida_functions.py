#!/usr/bin/env python3
"""Utility to launch IDA with idat_server and dump functions from an .i64 DB.

Usage:
    python list_ida_functions.py \
        --sample path/to/target.exe \
        --idb path/to/target.i64 \
        --idat-path "C:/Program Files/IDA Pro 8.2/idat64.exe"

The script prints the exact idat64 launch command using idat_server.py and then
runs a headless IDA pass to list all functions found in the provided .i64.
"""
from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path


def _build_idat_command(idat_path: Path, idat_server: Path, target: Path) -> list[str]:
    """Assemble the idat command list."""
    return [str(idat_path), "-A", f"-S{idat_server}", str(target)]


def _pretty_cmd(cmd: list[str]) -> str:
    """Windows-friendly pretty print for the command line."""
    return subprocess.list2cmdline(cmd)


def _dump_functions(idat_path: Path, idb_path: Path) -> str:
    """Run IDA headlessly to dump function names to a temp file, then read it."""
    idb_path = idb_path.resolve()
    
    # 1. 创建一个临时文件来存储结果
    # delete=False 因为 IDA 进程需要通过路径访问它
    with tempfile.NamedTemporaryFile("w", delete=False, encoding='utf-8') as res_tmp:
        result_path = Path(res_tmp.name).resolve()

    # 2. 构建 IDAPython 脚本
    # 我们将 result_path 硬编码进脚本，让 IDA 往这里写数据
    # 注意：Windows路径中的反斜杠需要转义，或者使用 forward slash
    safe_res_path = str(result_path).replace("\\", "/")
    
    payload = f"""\
import ida_funcs
import ida_pro
import idautils

def main():
    try:
        # 等待自动分析完成 (可选，但在已有 .i64 上通常不需要)
        # ida_auto.auto_wait() 
        
        with open("{safe_res_path}", "w", encoding="utf-8") as f:
            for ea in idautils.Functions():
                name = ida_funcs.get_func_name(ea) or f"sub_{{ea:08X}}"
                f.write(name + "\\n")
    except Exception as e:
        with open("{safe_res_path}", "w", encoding="utf-8") as f:
            f.write(f"ERROR: {{str(e)}}")
    finally:
        ida_pro.qexit(0)

if __name__ == "__main__":
    main()
"""

    script_path: Path | None = None
    try:
        # 3. 写入 IDAPython 脚本
        with tempfile.NamedTemporaryFile("w", suffix="_list_funcs.py", delete=False, encoding='utf-8') as tmp:
            tmp.write(payload)
            script_path = Path(tmp.name)

        print(f"Running IDA with script: {script_path}")
        print(f"Expecting results in: {result_path}")

        # 4. 运行 IDA
        # 注意：这里我们可以忽略 capture_output，因为我们不依赖 stdout 了
        proc = subprocess.run(
            [str(idat_path), "-A", f"-S{script_path}", str(idb_path)],
            capture_output=True, # 依然捕获以便调试报错
            text=True,
            check=False,
        )

        if proc.returncode != 0:
            msg = proc.stderr.strip() or f"idat exited with {proc.returncode}"
            # 如果 IDA 崩溃了，打印 stdout 看看有什么线索
            print(f"IDA Stdout: {proc.stdout}")
            raise RuntimeError(msg)

        # 5. 读取结果文件
        if result_path.exists():
            with open(result_path, "r", encoding='utf-8') as f:
                content = f.read()
            return content
        else:
            return ""

    finally:
        # 6. 清理临时文件
        if script_path and script_path.exists():
            try: script_path.unlink()
            except OSError: pass
        if result_path.exists():
            try: result_path.unlink()
            except OSError: pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Launch idat_server and list functions from an IDA DB")
    parser.add_argument("--sample", required=True, help="Path to the input sample (exe/elf/etc.)")
    parser.add_argument("--idb", required=True, help="Path to the existing .i64 database")
    parser.add_argument("--idat-path", default="idat", help="Path to idat64.exe (default: idat64 on PATH)")
    parser.add_argument(
        "--idat-server",
        default=Path(__file__).with_name("idat_server.py"),
        help="Path to idat_server.py (defaults to sibling file)",
    )

    args = parser.parse_args()

    idat_path = Path(args.idat_path)
    sample_path = Path(args.sample)
    idb_path = Path(args.idb)
    idat_server = Path(args.idat_server)

    for p, label in ((sample_path, "sample"), (idb_path, "idb"), (idat_server, "idat_server")):
        if not p.exists():
            raise FileNotFoundError(f"{label} not found: {p}")

    launch_cmd = _build_idat_command(idat_path, idat_server.resolve(), sample_path.resolve())
    print("IDA launch command:")
    print(_pretty_cmd(launch_cmd))

    print("\nFunctions found in DB:")
    try:
        output = _dump_functions(idat_path, idb_path)
    except RuntimeError as exc:
        print(f"Failed to dump functions: {exc}")
        return

    for line in output.splitlines():
        if line.strip():
            print(line.rstrip())


if __name__ == "__main__":
    main()
