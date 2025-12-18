#!/usr/bin/env python3
"""
ReBind Demo 综合脚本
用于统一调用 Ghidra 和 IDA Headless 分析工具
"""

import argparse
import http.client
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

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


def _notify_idat_exit(port: int = IDAT_EXIT_PORT) -> None:
    """Send a save_and_exit request to the headless IDA HTTP server."""
    payload = json.dumps({"action": "save_and_exit"}).encode("utf-8")
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": str(len(payload)),
    }
    conn = None
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=_IDAT_EXIT_TIMEOUT)
        conn.request("POST", "/", body=payload, headers=headers)
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


def run_semantic_align(sample_paths: List[Path]) -> None:
    """Call semantic_align.py for each sample after both headless tools finish."""

    if not sample_paths:
        return

    for sample_path in sample_paths:
        cmd = [
            sys.executable,
            str(SEMANTIC_ALIGN_SCRIPT),
            "--sample",
            str(sample_path),
        ]
        print("\n[ReBindDemo] 执行 semantic_align.py 以推进语义对齐...")
        print("  命令:", " ".join(cmd))
        result = subprocess.run(cmd, cwd=str(Path(__file__).resolve().parent))
        if result.returncode != 0:
            raise SystemExit(
                f"[ReBindDemo] semantic_align.py 返回非零退出码：{result.returncode}"
            )


class ReBindDemo:
    """ReBind Demo 综合分析工具"""
    
    def __init__(self, config_path: Optional[str] = None):
        """初始化综合分析工具
        
        Args:
            config_path: 配置文件路径，如果为None则使用默认路径
        """
        self.config_path = config_path
        self.ghidra_adapter = None
        self.ida_adapter = None
        
        # 初始化适配器
        if GhidraAdapter:
            try:
                ghidra_config = config_path
                if ghidra_config and not Path(ghidra_config).parent.name == "Ghidra_Headless_Demo":
                    # 如果配置文件不在 Ghidra 目录下，使用默认配置
                    ghidra_config = None
                self.ghidra_adapter = GhidraAdapter(ghidra_config)
            except Exception as e:
                print(f"警告: 初始化 GhidraAdapter 失败: {e}")
        
        if IDAAdapter:
            try:
                ida_config = config_path
                if ida_config and not Path(ida_config).parent.name == "IDA_Headless_Demo":
                    # 如果配置文件不在 IDA 目录下，使用默认配置
                    ida_config = None
                self.ida_adapter = IDAAdapter(ida_config)
            except Exception as e:
                print(f"警告: 初始化 IDAAdapter 失败: {e}")
    
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
        demo = ReBindDemo(args.config)
        
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
            if args.both:
                run_semantic_align(sample_paths)
        
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, _handle_sigint)
    main()
