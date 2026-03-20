"""breadth/ida_launcher.py

IDA（idat/idat64）进程管理：启动、监控、优雅退出与 Ctrl+C 信号处理。

从 pipeline.py 拆分而来，与流水线调度逻辑解耦，便于独立测试和复用。
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import platform
import signal
import subprocess
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────
# 路径常量
# ──────────────────────────────────────────
_BREADTH_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _BREADTH_DIR.parents[2]

# ──────────────────────────────────────────
# IDA HTTP 默认值
# ──────────────────────────────────────────
DEFAULT_IDA_HTTP_PORT = 12345
DEFAULT_IDA_URL = f"http://127.0.0.1:{DEFAULT_IDA_HTTP_PORT}"

DEFAULT_IDAT_EXE_MACOS = "/Applications/IDA Professional 9.2.app/Contents/MacOS/idat"
DEFAULT_IDAT_EXE_WINDOWS = "idat.exe"
DEFAULT_IDAT_EXE_LINUX = "idat"

LIBRARY_INIT_FAILURE_MESSAGE = "Library initialization failed with result: 4"

# ──────────────────────────────────────────
# Ctrl+C 信号状态（模块级，故意保持单例）
# ──────────────────────────────────────────
_CTRL_C_EXIT_REQUESTED = False
_CTRL_C_EXIT_URL = DEFAULT_IDA_URL


def set_ctrl_c_exit_url(url: str) -> None:
    """记录 Ctrl+C 信号处理器应向哪个 IDA HTTP 地址发 save_and_exit。"""
    global _CTRL_C_EXIT_URL
    normalized = (url or "").strip()
    _CTRL_C_EXIT_URL = normalized if normalized else DEFAULT_IDA_URL


def send_ida_save_and_exit(timeout_s: float = 2.0) -> None:
    """向已配置的 IDA HTTP 地址 POST ``{'action': 'save_and_exit'}``。"""
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
        print(f"[IDALauncher] 已向 {url} 发送 save_and_exit 请求 (HTTP {resp.status}).")
    except Exception as exc:
        print(f"[IDALauncher] 发送 save_and_exit 请求失败: {exc}")
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def handle_ctrl_c(signum, frame) -> None:
    """Ctrl+C 信号处理器：先通知 IDA 退出，再传播 KeyboardInterrupt。"""
    global _CTRL_C_EXIT_REQUESTED
    if not _CTRL_C_EXIT_REQUESTED:
        _CTRL_C_EXIT_REQUESTED = True
        print("[IDALauncher] 捕获 Ctrl+C，正在请求 IDA save_and_exit...")
        send_ida_save_and_exit()
    signal.default_int_handler(signum, frame)


def install_ctrl_c_handler(ida_url: str) -> None:
    """注册 Ctrl+C 信号处理器并记录目标 IDA URL。"""
    set_ctrl_c_exit_url(ida_url)
    try:
        signal.signal(signal.SIGINT, handle_ctrl_c)
    except (OSError, ValueError):
        pass


def default_idat_exe_for_platform() -> str:
    """根据当前操作系统返回默认的 idat 可执行文件名。"""
    sys_name = platform.system().strip().lower()
    if sys_name.startswith(("win", "msys", "cygwin", "mingw")):
        return DEFAULT_IDAT_EXE_WINDOWS
    if sys_name.startswith("darwin") or sys_name.startswith("mac"):
        return DEFAULT_IDAT_EXE_MACOS
    if sys_name.startswith("linux"):
        return DEFAULT_IDAT_EXE_LINUX
    return DEFAULT_IDAT_EXE_WINDOWS if os.name == "nt" else DEFAULT_IDAT_EXE_LINUX


def coerce_float(value: object, default: float) -> float:
    """将任意值强转为 float，失败时返回 default。"""
    if value is None:
        return default
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def launch_idat_server(
    idat_exe: str,
    ida_script: Path,
    sample_path: Path,
    log_path: Path,
) -> subprocess.Popen:
    """启动 IDA（idat），在其中加载 sample 并运行 idat_server.py。

    Returns:
        子进程对象，供后续等待或强制终止。

    Raises:
        SystemExit: 找不到 idat 可执行文件。
    """
    cmd = [
        idat_exe,
        "-A",
        f"-L{log_path}",
        f"-S{ida_script}",
        str(sample_path),
    ]
    print("[IDALauncher] 启动 IDA(idat) + idat_server...")
    print("  命令:", " ".join(str(c) for c in cmd))
    try:
        # 独立 session，防止主进程 Ctrl+C 把 idat_server 一起杀掉
        proc = subprocess.Popen(cmd, cwd=str(_REPO_ROOT), start_new_session=True)
    except FileNotFoundError:
        raise SystemExit(
            f"[IDALauncher] 无法找到可执行文件 {idat_exe!r}，"
            "请确认 IDA 的 idat 已添加到 PATH，或通过 --idat-exe 指定完整路径。"
        )
    return proc


def read_log_tail(log_path: Path, max_bytes: int = 64 * 1024) -> str:
    """返回 IDA 日志末尾片段，用于检测启动失败。"""
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


def log_indicates_library_failure(log_path: Path) -> bool:
    """检查日志是否包含 IDA 库初始化失败标志。"""
    return LIBRARY_INIT_FAILURE_MESSAGE in read_log_tail(log_path)


def exit_if_library_init_failed(log_path: Path, ida_proc: subprocess.Popen) -> None:
    """若日志中发现库初始化失败，终止 IDA 进程并 raise SystemExit。"""
    if not log_indicates_library_failure(log_path):
        return
    msg = (
        '[IDALauncher] 发现 IDA 报错 "Library initialization failed with result: 4"，'
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


def wait_for_ida_process_exit(proc: subprocess.Popen, *, timeout: float = 300.0) -> None:
    """等待 IDA(idat) 进程退出，超时后输出提示（不强制 kill）。"""
    if proc.poll() is not None:
        print(f"[IDALauncher] IDA(idat) 进程已退出，退出码={proc.returncode}")
        return
    try:
        exit_code = proc.wait(timeout=timeout)
        print(f"[IDALauncher] IDA(idat) 进程已退出，退出码={exit_code}")
    except subprocess.TimeoutExpired:
        print("[IDALauncher] 等待 IDA(idat) 进程退出超时，如需强制终止请手动结束 idat 进程。")
        try:
            proc.kill()
        except Exception:
            pass


def run_alignment_loader(
    db_path: Path,
    ghidra_dir: Path,
    ida_dir: Path,
    dump_txt: Path,
    dump_xlsx: Path,
    repo_root: Optional[Path] = None,
    delete_db: bool = False,
) -> None:
    """以子进程方式调用 alignment_loader.py 构建对齐数据库，并导出文本/Excel 快照。

    Args:
        repo_root:  仓库根目录，默认自动推断（breadth 父级的三层上）。
        delete_db:  若为 True，向 alignment_loader.py 传递 --delete-db 标志，
                    在写入前删除已存在的数据库文件。
    """
    cwd = repo_root or _REPO_ROOT
    cmd = [
        sys.executable,
        str(_BREADTH_DIR / "alignment_loader.py"),
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
    if delete_db:
        cmd.append("--delete-db")
    print("[IDALauncher] 运行 alignment_loader.py 构建对齐数据库...")
    print("  命令:", " ".join(cmd))
    result = subprocess.run(cmd, cwd=str(cwd))
    if result.returncode != 0:
        raise SystemExit(
            f"[IDALauncher] alignment_loader.py 执行失败，退出码={result.returncode}"
        )
