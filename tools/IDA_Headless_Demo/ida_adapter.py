#!/usr/bin/env python3
"""
IDA Headless 分析工具 - Python 适配器
用于替代 input_prehandle_start.bat 的 Python 版本
"""

import os
import sys
import yaml
import shutil
import logging
import argparse
import subprocess
import re
from pathlib import Path
from typing import Optional, List, Dict, Any


class IDAAdapter:
    """IDA Headless 分析适配器"""
    
    def __init__(self, config_path: Optional[str] = None):
        """初始化适配器
        
        Args:
            config_path: 配置文件路径，如果为None则使用默认路径
        """
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        
    def _load_config(self, config_path: Optional[str]) -> Dict[str, Any]:
        """加载配置文件
        
        Args:
            config_path: 配置文件路径
            
        Returns:
            配置字典
        """
        if config_path is None:
            config_path = Path(__file__).parent / "config.yaml"
        else:
            config_path = Path(config_path)
            
        if not config_path.exists():
            raise FileNotFoundError(f"配置文件不存在: {config_path}")
            
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            
        return config
    
    def _setup_logging(self) -> logging.Logger:
        """设置日志系统
        
        Returns:
            日志记录器
        """
        log_config = self.config.get('logging', {})
        log_level = getattr(logging, log_config.get('level', 'INFO'))
        
        logger = logging.getLogger('ida_adapter')
        logger.setLevel(log_level)
        
        # 控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        # 文件处理器
        if log_config.get('log_to_file', True):
            log_file_path = log_config.get('log_file_path')
            if not log_file_path:
                log_file_path = Path(__file__).parent / "ida_adapter.log"
                
            file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
            file_handler.setLevel(log_level)
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
            
        return logger
    
    def sanitize_filename(self, filename: str) -> str:
        """清理文件名，移除非法字符
        
        Args:
            filename: 原始文件名
            
        Returns:
            清理后的文件名
        """
        if not self.config.get('filename', {}).get('sanitize', True):
            return filename
            
        pattern = self.config['filename'].get('allowed_chars_pattern', '[A-Za-z0-9]')
        replacement = self.config['filename'].get('replacement_char', '_')
        
        # 清理完整文件名（包含扩展名），与Ghidra适配器行为一致
        sanitized = re.sub(f'[^{pattern}]', replacement, filename)
        
        self.logger.debug(f"文件名清理: {filename} -> {sanitized}")
        return sanitized
    
    def prepare_working_directory(self, input_file: str) -> Path:
        """准备工作目录
        
        Args:
            input_file: 输入文件路径
            
        Returns:
            工作目录路径
        """
        input_path = Path(input_file).resolve()
        
        if not input_path.exists():
            raise FileNotFoundError(f"输入文件不存在: {input_file}")
            
        if input_path.is_dir():
            raise ValueError("不支持目录输入，请提供单个文件")
            
        # 确定输出目录
        output_config = self.config.get('output', {})
        dir_suffix = output_config.get('dir_suffix', '_idademo')
        # 使用文件名（包含扩展名，但去除点号）作为基础名称
        base_name = input_path.name.replace('.', '_')
        output_dir = input_path.parent / f"{base_name}{dir_suffix}"
        
        self.logger.info(f"准备工作目录: {output_dir}")
        
        # 创建目录
        output_dir.mkdir(exist_ok=True)
        
        # 复制Python脚本
        script_dir = Path(__file__).parent
        for script_file in script_dir.glob("*.py"):
            if script_file.name != "ida_adapter.py":
                shutil.copy2(script_file, output_dir)
                self.logger.debug(f"复制脚本: {script_file.name}")
        
        # 复制输入文件
        if output_config.get('keep_input_copy', False):
            shutil.copy2(input_path, output_dir / input_path.name)
            self.logger.debug(f"复制输入文件: {input_path.name}")
        
        return output_dir
    
    def build_ida_command(self, input_file: str, script_file: str, output_dir: Path) -> List[str]:
        """构建IDA命令
        
        Args:
            input_file: 输入文件路径
            script_file: 要执行的脚本文件名
            output_dir: 输出目录
            
        Returns:
            命令参数列表
        """
        ida_config = self.config.get('ida', {})
        
        cmd_path = ida_config.get('cmd_path', '')
        if not cmd_path:
            raise ValueError("配置文件中未设置 ida.cmd_path")
            
        # 构建命令
        command = [
            cmd_path,
            ida_config.get('args', '-A -c'),
            f'-S"{script_file}"',
            input_file
        ]
        
        self.logger.debug(f"构建的命令: {' '.join(command)}")
        return command
    
    def process_output_files(self, output_dir: Path, sanitized_name: str):
        """处理输出文件（清理）
        
        Args:
            output_dir: 输出目录
            sanitized_name: 清理后的文件名
        """
        self.logger.info("处理输出文件...")
        self.logger.debug(f"清理后的文件名: {sanitized_name}")
        self.logger.debug(f"输出目录: {output_dir}")
        self.logger.debug(f"当前工作目录: {Path.cwd()}")
        
        # 列出输出目录内容以帮助调试
        self.logger.debug(f"输出目录内容 ({output_dir}):")
        for item in output_dir.iterdir():
            self.logger.debug(f"  - {item.name}")
        
        # 清理临时文件
        output_config = self.config.get('output', {})
        if not output_config.get('keep_python_scripts', False):
            for py_file in output_dir.glob("*.py"):
                if py_file.name != "ida_adapter.py":
                    py_file.unlink()
                    self.logger.debug(f"删除临时脚本: {py_file.name}")
        
        # 清理原始文件副本
        if not output_config.get('keep_input_copy', False):
            input_file = Path(__file__).parent.name
            input_copy = output_dir / input_file
            if input_copy.exists():
                input_copy.unlink()
                self.logger.debug(f"删除输入文件副本: {input_file}")
    
    def analyze_file(self, input_file: str) -> Path:
        """分析单个文件
        
        Args:
            input_file: 输入文件路径
            
        Returns:
            输出目录路径
        """
        self.logger.info(f"开始分析文件: {input_file}")
        
        # 准备工作目录
        output_dir = self.prepare_working_directory(input_file)
        
        # 切换到工作目录
        original_dir = Path.cwd()
        os.chdir(output_dir)
        
        try:
            # 获取要执行的脚本列表
            scripts = self.config.get('scripts', {}).get('scripts', [])
            if not scripts:
                raise ValueError("配置文件中未设置要执行的脚本")
            
            # 执行每个脚本
            for i, script in enumerate(scripts, 1):
                self.logger.info(f"[{i}/{len(scripts)}] 执行脚本: {script}")
                
                # 构建并执行命令
                command = self.build_ida_command(input_file, script, output_dir)
                self.logger.debug(f"完整命令: {' '.join(command)}")
                self.logger.debug(f"当前工作目录: {Path.cwd()}")
                
                try:
                    result = subprocess.run(
                        command,
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='ignore'
                    )
                    
                    # 输出所有脚本输出（DEBUG级别）
                    if result.stdout:
                        self.logger.debug(f"脚本 {script} 标准输出:")
                        for line in result.stdout.split('\n'):
                            if line.strip():
                                self.logger.debug(f"  {line}")
                    
                    if result.stderr:
                        self.logger.debug(f"脚本 {script} 标准错误:")
                        for line in result.stderr.split('\n'):
                            if line.strip():
                                self.logger.debug(f"  {line}")
                    
                    if result.returncode != 0:
                        self.logger.warning(f"脚本 {script} 执行失败，返回码: {result.returncode}")
                        self.logger.warning(f"标准错误: {result.stderr}")
                    else:
                        self.logger.info(f"脚本 {script} 执行完成")
                        
                except Exception as e:
                    self.logger.error(f"执行脚本 {script} 时出错: {e}")
                    continue
            
            self.logger.info("所有脚本执行完成")
            # 列出当前目录和原始目录内容以帮助调试
            self.logger.debug(f"当前工作目录内容 ({Path.cwd()}):")
            for item in Path.cwd().iterdir():
                self.logger.debug(f"  - {item.name}")
            
            original_parent_dir = output_dir.parent
            self.logger.debug(f"原始目录内容 ({original_parent_dir}):")
            for item in original_parent_dir.iterdir():
                self.logger.debug(f"  - {item.name}")
            
        finally:
            # 切换回原始目录
            os.chdir(original_dir)
        
        # 处理输出文件
        sanitized_name = self.sanitize_filename(Path(input_file).name)
        self.process_output_files(output_dir, sanitized_name)
        
        self.logger.info(f"分析完成，输出目录: {output_dir}")
        return output_dir
    
    def analyze_files(self, input_files: List[str]) -> List[Path]:
        """分析多个文件
        
        Args:
            input_files: 输入文件路径列表
            
        Returns:
            输出目录路径列表
        """
        output_dirs = []
        for input_file in input_files:
            try:
                output_dir = self.analyze_file(input_file)
                output_dirs.append(output_dir)
            except Exception as e:
                self.logger.error(f"分析文件 {input_file} 时出错: {e}")
                continue
                
        return output_dirs


def main():
    """主函数 - 命令行接口"""
    parser = argparse.ArgumentParser(
        description="IDA Headless 分析工具 - Python 适配器"
    )
    parser.add_argument(
        "input_files",
        nargs="+",
        help="要分析的文件路径（支持多个文件）"
    )
    parser.add_argument(
        "-c", "--config",
        help="配置文件路径（默认: config.yaml）"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="启用详细输出"
    )
    
    args = parser.parse_args()
    
    try:
        # 创建适配器
        adapter = IDAAdapter(args.config)
        
        if args.verbose:
            adapter.logger.setLevel(logging.DEBUG)
            for handler in adapter.logger.handlers:
                handler.setLevel(logging.DEBUG)
        
        # 分析文件
        output_dirs = adapter.analyze_files(args.input_files)
        
        print("\n" + "="*60)
        print("分析完成!")
        print("输出目录:")
        for output_dir in output_dirs:
            print(f"  - {output_dir}")
        print("="*60)
        
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()