#!/usr/bin/env python3
"""
ReBind Demo 综合脚本
用于统一调用 Ghidra 和 IDA Headless 分析工具
"""

import argparse
import atexit
import copy
import http.client
import json
import os
import platform
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
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


SEMANTIC_ALIGN_SCRIPT = Path(__file__).resolve().parent / "tools" / "Semantics_Alignment" / "semantic_align.py"
IDAT_EXIT_PORT = 12345
_IDAT_EXIT_TIMEOUT = 2.0
GLOBAL_CONFIG_PATH = Path(__file__).resolve().parent / "config.yaml"
_TEMP_MERGED_CONFIGS: List[Path] = []


def _cleanup_temp_configs() -> None:
    """Remove any temporary config files created during runtime."""
    for temp_path in _TEMP_MERGED_CONFIGS[:]:
        try:
            temp_path.unlink()
        except Exception:
            pass


atexit.register(_cleanup_temp_configs)


def _load_yaml_file(path: Path, *, allow_missing: bool = False) -> Dict[str, Any]:
    """Load a YAML file and ensure it returns a dictionary."""

    if not path.exists():
        if allow_missing:
            return {}
        raise FileNotFoundError(f"配置文件不存在: {path}")

    with path.open("r", encoding="utf-8") as fp:
        data = yaml.safe_load(fp)

    if data is None:
        return {}
    if not isinstance(data, dict):
        raise RuntimeError(f"配置文件 {path} 必须是一个字典结构。")
    return data


def _deep_merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge two dictionaries, giving precedence to override."""

    merged = copy.deepcopy(base)
    for key, value in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(value, dict)
        ):
            merged[key] = _deep_merge_dicts(merged[key], value)
        else:
            merged[key] = value

    return merged


def _detect_platform_key(explicit: Optional[str] = None) -> str:
    if explicit:
        key = explicit.strip().lower()
        if key in {"windows", "macos", "linux"}:
            return key
        raise ValueError(f"不支持的 --platform={explicit!r}，仅支持 windows/macos/linux")

    sys_name = platform.system().strip().lower()
    if sys_name.startswith("win"):
        return "windows"
    if sys_name.startswith("darwin") or sys_name.startswith("mac"):
        return "macos"
    if sys_name.startswith("linux"):
        return "linux"
    return sys_name or "unknown"


def _normalize_module_overrides(section_key: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    """Accept either module-shaped overrides or shorthand overrides and normalize."""

    if not raw:
        return {}
    if not isinstance(raw, dict):
        return {}

    # If the user already wrote module-shaped config, keep it.
    if section_key == "ghidra":
        if any(k in raw for k in ("ghidra", "output", "scripts", "filename", "logging")):
            return raw
        ghidra_keys = ("cmd_path", "workspace", "project_name_prefix")
        nested = {k: raw[k] for k in ghidra_keys if k in raw}
        result: Dict[str, Any] = {"ghidra": nested} if nested else {}
        for k in ("output", "scripts", "filename", "logging"):
            if k in raw:
                result[k] = raw[k]
        return result or raw

    if section_key == "ida":
        if any(k in raw for k in ("ida", "output", "scripts", "filename", "logging")):
            return raw
        ida_keys = ("cmd_path", "args")
        nested = {k: raw[k] for k in ida_keys if k in raw}
        result = {"ida": nested} if nested else {}
        for k in ("output", "scripts", "filename", "logging"):
            if k in raw:
                result[k] = raw[k]
        return result or raw

    # semantics already matches its module config shape (llm/pipeline) + optional runtime.
    return raw


def _platform_overrides(global_config: Dict[str, Any], platform_key: str, section_key: str) -> Dict[str, Any]:
    platforms = global_config.get("platforms", {})
    if not isinstance(platforms, dict):
        return {}
    by_os = platforms.get(platform_key, {})
    if not isinstance(by_os, dict):
        return {}
    section = by_os.get(section_key, {})
    return section if isinstance(section, dict) else {}


def _select_module_config_path(
    module_config_arg: Optional[str],
    module_dir_name: str,
    default_path: Path,
) -> Path:
    """Prefer a user-specified config if it is rooted in the requested module."""

    if module_config_arg:
        candidate = Path(module_config_arg).expanduser().resolve()
        if candidate.exists() and candidate.parent.name == module_dir_name:
            return candidate
    return default_path


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


def _expected_output_dir(sample_path: Path, dir_suffix: str) -> Path:
    base_name = sample_path.name.replace(".", "_")
    return sample_path.parent / f"{base_name}{dir_suffix}"


def run_semantic_align(
    sample_paths: List[Path],
    *,
    semantics_config_path: Optional[Path] = None,
    ghidra_dir_suffix: str = "_ghidemo",
    ida_dir_suffix: str = "_idademo",
    semantics_runtime: Optional[Dict[str, Any]] = None,
) -> None:
    """Call semantic_align.py for each sample after both headless tools finish."""

    if not sample_paths:
        return

    for sample_path in sample_paths:
        semantics_runtime = semantics_runtime or {}
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

        cmd = [
            sys.executable,
            str(SEMANTIC_ALIGN_SCRIPT),
            "--sample",
            str(sample_path),
            "--ghidra-dir",
            str(ghidra_dir),
            "--ida-dir",
            str(ida_dir),
        ]
        if semantics_config_path:
            cmd.extend(["--config", str(semantics_config_path)])

        idat_exe = semantics_runtime.get("idat_exe")
        if idat_exe:
            cmd.extend(["--idat-exe", str(idat_exe)])

        ida_url = semantics_runtime.get("ida_url")
        if ida_url:
            cmd.extend(["--ida-url", str(ida_url)])

        ida_script = semantics_runtime.get("ida_script")
        if ida_script:
            cmd.extend(["--ida-script", str(ida_script)])

        ida_start_delay = semantics_runtime.get("ida_start_delay")
        if ida_start_delay is not None:
            cmd.extend(["--ida-start-delay", str(ida_start_delay)])

        if semantics_runtime.get("no_ida") is True:
            cmd.append("--no-ida")
        if semantics_runtime.get("no_align") is True:
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
        module_config_path: Optional[str] = None,
        global_config_path: Optional[str] = None,
        platform_key: Optional[str] = None,
    ):
        """初始化综合分析工具
        
        Args:
            module_config_path: 模块级配置文件路径（若在对应模块目录下则会被使用）
            global_config_path: 全局配置文件路径（优先级最高，若不指定则使用项目根的 config.yaml）
        """
        self.module_config_path = module_config_path
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

        ghidra_default_config = tools_dir / "Ghidra_Headless_Demo" / "config.yaml"
        ida_default_config = tools_dir / "IDA_Headless_Demo" / "config.yaml"
        semantics_default_config = tools_dir / "Semantics_Alignment" / "config.yaml"

        self.ghidra_config_path = self._prepare_module_config(
            module_dir_name="Ghidra_Headless_Demo",
            section_key="ghidra",
            default_config_path=ghidra_default_config,
            module_override_arg=self.module_config_path,
        )
        self.ida_config_path = self._prepare_module_config(
            module_dir_name="IDA_Headless_Demo",
            section_key="ida",
            default_config_path=ida_default_config,
            module_override_arg=self.module_config_path,
        )
        self.semantics_config_path = self._prepare_module_config(
            module_dir_name="Semantics_Alignment",
            section_key="semantics",
            default_config_path=semantics_default_config,
            module_override_arg=None,
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
        default_config_path: Path,
        module_override_arg: Optional[str],
    ) -> Path:
        """Load module config, merge global overrides, and write to a temp file."""

        base_path = _select_module_config_path(
            module_override_arg, module_dir_name, default_config_path
        )
        base_config = _load_yaml_file(base_path)
        overrides_common = self.global_config.get(section_key, {})
        overrides_common_dict = overrides_common if isinstance(overrides_common, dict) else {}
        overrides_platform_dict = _platform_overrides(self.global_config, self.platform_key, section_key)
        normalized_common = _normalize_module_overrides(section_key, overrides_common_dict)
        normalized_platform = _normalize_module_overrides(section_key, overrides_platform_dict)
        merged_overrides = _deep_merge_dicts(normalized_common, normalized_platform)
        merged_config = _deep_merge_dicts(base_config, merged_overrides)
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
        """使用 Ghidra 和 IDA 分析文件
        
        Args:
            input_files: 输入文件路径列表
            
        Returns:
            包含两种工具输出目录的字典
        """
        results = {}
        
        if self.ghidra_adapter:
            try:
                print("使用 Ghidra 分析文件...")
                results['ghidra'] = self.analyze_with_ghidra(input_files)
            except Exception as e:
                print(f"Ghidra 分析失败: {e}")
                results['ghidra'] = []
        
        if self.ida_adapter:
            try:
                print("使用 IDA 分析文件...")
                results['ida'] = self.analyze_with_ida(input_files)
            except Exception as e:
                print(f"IDA 分析失败: {e}")
                results['ida'] = []
        
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
        "-c", "--config",
        help="配置文件路径（默认: 使用各工具的默认配置）"
    )
    parser.add_argument(
        "--global-config",
        help="全局配置文件路径（默认: rebind_demo.py 所在目录的 config.yaml）"
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
        demo = ReBindDemo(args.config, args.global_config, args.platform)
        print(f"[ReBindDemo] 平台检测: {demo.platform_key} (system={platform.system()}, release={platform.release()})")
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
        if args.ghidra:
            if not demo.ghidra_adapter:
                print("错误: Ghidra 适配器不可用", file=sys.stderr)
                sys.exit(1)
            
            output_dirs = demo.analyze_with_ghidra(args.input_files)
            
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
            
            output_dirs = demo.analyze_with_ida(args.input_files)
            
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
            
            results = demo.analyze_with_both(args.input_files)
            
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
                ghidra_suffix = (
                    demo.ghidra_adapter.config.get("output", {}) or {}
                ).get("dir_suffix", "_ghidemo")
                ida_suffix = (
                    demo.ida_adapter.config.get("output", {}) or {}
                ).get("dir_suffix", "_idademo")
                run_semantic_align(
                    sample_paths,
                    semantics_config_path=demo.semantics_config_path,
                    ghidra_dir_suffix=str(ghidra_suffix),
                    ida_dir_suffix=str(ida_suffix),
                    semantics_runtime=demo.semantics_runtime,
                )
        
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, _handle_sigint)
    main()
