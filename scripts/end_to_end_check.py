#!/usr/bin/env python3
"""
ReBind Demo 端到端链路检查
使用 tmp/client_b 测试完整的导出和分析链路
"""

import sys
import subprocess
import time
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools" / "Ghidra_Headless_Demo"))
sys.path.insert(0, str(REPO_ROOT / "tools" / "IDA_Headless_Demo"))

BINARY_FILE = REPO_ROOT / "tmp" / "client_b"
TEST_TIMEOUT = 300  # 5分钟超时


def check_output_dir(output_dir: Path, tool_name: str, binary_name: Optional[str] = None) -> tuple[bool, str]:
    """检查导出目录和文件"""
    if not output_dir.exists():
        return False, f"{tool_name} 输出目录不存在: {output_dir}"
    
    # 确定二进制文件名（从输出目录名推断，或使用传入的 binary_name）
    if binary_name is None:
        # 从输出目录名推断：client_b_ghidemo -> client_b
        base_name = output_dir.name
        if "_ghidemo" in base_name:
            binary_name = base_name.replace("_ghidemo", "")
        elif "_idademo" in base_name:
            binary_name = base_name.replace("_idademo", "")
        else:
            binary_name = base_name
    
    # 检查关键输出文件
    expected_dirs = [
        output_dir / f"{binary_name}_output",
        output_dir / f"{binary_name}_disassembly",
        output_dir / f"{binary_name}_pseudocode",
    ]
    
    found_dirs = []
    for expected in expected_dirs:
        if expected.exists() and expected.is_dir():
            found_dirs.append(expected.name)
    
    if not found_dirs:
        return False, f"{tool_name} 未找到预期的输出子目录（{binary_name}_output, {binary_name}_disassembly, {binary_name}_pseudocode）"
    
    return True, f"找到输出目录: {', '.join(found_dirs)}"


def test_ghidra_export() -> tuple[bool, str]:
    """测试 Ghidra 导出"""
    print("\n" + "=" * 60)
    print("测试 Ghidra 导出链路")
    print("=" * 60)
    
    if not BINARY_FILE.exists():
        return False, f"测试二进制文件不存在: {BINARY_FILE}"
    
    print(f"输入文件: {BINARY_FILE}")
    print(f"文件大小: {BINARY_FILE.stat().st_size} 字节")
    
    # 运行 Ghidra 导出
    print("\n运行 rebind_demo.py --ghidra ...")
    try:
        cmd = [
            sys.executable,
            str(REPO_ROOT / "rebind_demo.py"),
            "--ghidra",
            str(BINARY_FILE),
            "-v"
        ]
        
        print(f"执行命令: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=TEST_TIMEOUT
        )
        
        if result.returncode != 0:
            error_msg = result.stderr[:500] if result.stderr else result.stdout[-500:]
            return False, f"Ghidra 导出失败 (退出码: {result.returncode})\n错误: {error_msg}"
        
        # 查找输出目录
        expected_output_dir = BINARY_FILE.parent / f"{BINARY_FILE.stem}_ghidemo"
        success, msg = check_output_dir(expected_output_dir, "Ghidra", BINARY_FILE.stem)
        
        if success:
            print(f"✓ {msg}")
            return True, "Ghidra 导出成功"
        else:
            return False, msg
            
    except subprocess.TimeoutExpired:
        return False, f"Ghidra 导出超时（>{TEST_TIMEOUT}秒）"
    except Exception as e:
        return False, f"Ghidra 导出异常: {e}"


def test_ida_export() -> tuple[bool, str]:
    """测试 IDA 导出"""
    print("\n" + "=" * 60)
    print("测试 IDA 导出链路")
    print("=" * 60)
    
    if not BINARY_FILE.exists():
        return False, f"测试二进制文件不存在: {BINARY_FILE}"
    
    print(f"输入文件: {BINARY_FILE}")
    print(f"文件大小: {BINARY_FILE.stat().st_size} 字节")
    
    # 运行 IDA 导出
    print("\n运行 rebind_demo.py --ida ...")
    try:
        cmd = [
            sys.executable,
            str(REPO_ROOT / "rebind_demo.py"),
            "--ida",
            str(BINARY_FILE),
            "-v"
        ]
        
        print(f"执行命令: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=TEST_TIMEOUT
        )
        
        if result.returncode != 0:
            error_msg = result.stderr[:500] if result.stderr else result.stdout[-500:]
            return False, f"IDA 导出失败 (退出码: {result.returncode})\n错误: {error_msg}"
        
        # 查找输出目录
        expected_output_dir = BINARY_FILE.parent / f"{BINARY_FILE.stem}_idademo"
        success, msg = check_output_dir(expected_output_dir, "IDA", BINARY_FILE.stem)
        
        if success:
            print(f"✓ {msg}")
            return True, "IDA 导出成功"
        else:
            return False, msg
            
    except subprocess.TimeoutExpired:
        return False, f"IDA 导出超时（>{TEST_TIMEOUT}秒）"
    except Exception as e:
        return False, f"IDA 导出异常: {e}"


def test_semantics_pipeline_entry() -> tuple[bool, str]:
    """测试语义对齐流水线入口（不实际运行，只检查可调用性）"""
    print("\n" + "=" * 60)
    print("测试语义对齐流水线入口")
    print("=" * 60)
    
    try:
        # 检查广度流水线
        pipeline_script = REPO_ROOT / "tools" / "Semantics_Alignment" / "breadth" / "pipeline.py"
        if not pipeline_script.exists():
            return False, f"流水线脚本不存在: {pipeline_script}"
        
        # 尝试导入主函数（不执行）
        sys.path.insert(0, str(pipeline_script.parent))
        import importlib.util
        spec = importlib.util.spec_from_file_location("pipeline", pipeline_script)
        if spec is None or spec.loader is None:
            return False, "无法加载 pipeline.py 模块规范"
        
        # 检查 alignment_loader
        loader_script = REPO_ROOT / "tools" / "Semantics_Alignment" / "breadth" / "alignment_loader.py"
        if not loader_script.exists():
            return False, f"对齐加载器脚本不存在: {loader_script}"
        
        # 检查深度引擎
        engine_script = REPO_ROOT / "tools" / "Semantics_Alignment" / "depth" / "engine.py"
        if not engine_script.exists():
            return False, f"深度引擎脚本不存在: {engine_script}"
        
        deep_path_script = REPO_ROOT / "tools" / "Semantics_Alignment" / "depth" / "deep_path_dfs.py"
        if not deep_path_script.exists():
            return False, f"深路径 DFS 脚本不存在: {deep_path_script}"
        
        return True, "所有语义对齐脚本存在且可访问"
        
    except Exception as e:
        return False, f"检查语义对齐入口时异常: {e}"


def test_database_creation() -> tuple[bool, str]:
    """测试数据库创建（需要先有导出结果）"""
    print("\n" + "=" * 60)
    print("测试数据库创建链路")
    print("=" * 60)
    
    # 检查是否有 Ghidra 和 IDA 的导出结果
    ghidra_output = BINARY_FILE.parent / f"{BINARY_FILE.stem}_ghidemo"
    ida_output = BINARY_FILE.parent / f"{BINARY_FILE.stem}_idademo"
    
    if not ghidra_output.exists() and not ida_output.exists():
        return False, "需要先运行 Ghidra 或 IDA 导出才能测试数据库创建"
    
    # 检查 alignment_loader 是否可以调用
    try:
        loader_script = REPO_ROOT / "tools" / "Semantics_Alignment" / "breadth" / "alignment_loader.py"
        if not loader_script.exists():
            return False, "alignment_loader.py 不存在"
        
        # 尝试运行 --help 检查脚本是否可执行
        cmd = [sys.executable, str(loader_script), "--help"]
        result = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 or "--help" in result.stdout or "--help" in result.stderr:
            return True, "alignment_loader.py 可正常调用"
        else:
            return False, f"alignment_loader.py 调用异常: {result.stderr[:200]}"
            
    except Exception as e:
        return False, f"测试数据库创建链路时异常: {e}"


def main():
    """主函数"""
    print("ReBind Demo 端到端链路检查")
    print("=" * 60)
    print(f"测试二进制文件: {BINARY_FILE}")
    
    if not BINARY_FILE.exists():
        print(f"错误: 测试二进制文件不存在: {BINARY_FILE}")
        return 1
    
    results = []
    
    # 1. 测试 Ghidra 导出
    success, msg = test_ghidra_export()
    results.append(("Ghidra 导出", success, msg))
    
    # 2. 测试 IDA 导出
    success, msg = test_ida_export()
    results.append(("IDA 导出", success, msg))
    
    # 3. 测试语义对齐流水线入口
    success, msg = test_semantics_pipeline_entry()
    results.append(("语义对齐入口", success, msg))
    
    # 4. 测试数据库创建
    success, msg = test_database_creation()
    results.append(("数据库创建", success, msg))
    
    # 生成报告
    print("\n" + "=" * 60)
    print("端到端检查报告")
    print("=" * 60)
    
    for name, success, msg in results:
        status = "✓" if success else "✗"
        print(f"{status} {name}: {msg}")
    
    total = len(results)
    passed = sum(1 for _, s, _ in results if s)
    failed = total - passed
    
    print(f"\n总计: {total} 项测试")
    print(f"通过: {passed} 项")
    print(f"失败: {failed} 项")
    print("=" * 60)
    
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
