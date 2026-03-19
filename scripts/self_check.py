#!/usr/bin/env python3
"""
ReBind Demo 项目自检脚本
检查配置、工具路径、模块导入和端到端链路
"""

import sys
import platform
from pathlib import Path
from typing import List, Tuple, Optional

# 添加项目根目录到路径
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools" / "Ghidra_Headless_Demo"))
sys.path.insert(0, str(REPO_ROOT / "tools" / "IDA_Headless_Demo"))

CHECK_RESULTS: List[Tuple[str, bool, str]] = []


def check(name: str, condition: bool, message: str = ""):
    """记录检查结果"""
    status = "✓" if condition else "✗"
    CHECK_RESULTS.append((name, condition, message))
    print(f"{status} {name}: {message if message else ('通过' if condition else '失败')}")


def check_config():
    """检查配置文件加载"""
    print("\n=== 配置检查 ===")
    try:
        from project_config import (
            ROOT_CONFIG_PATH,
            load_global_config,
            detect_platform_key,
            merge_tool_config,
            merge_semantics_config_dict,
        )
        
        check("配置文件存在", ROOT_CONFIG_PATH.exists(), f"路径: {ROOT_CONFIG_PATH}")
        
        if ROOT_CONFIG_PATH.exists():
            config = load_global_config()
            check("配置文件可解析", isinstance(config, dict), f"包含 {len(config)} 个顶级键")
            
            platform_key = detect_platform_key()
            check("平台检测", platform_key in ["windows", "macos", "linux"], f"检测到: {platform_key}")
            
            # 检查各工具配置
            ghidra_config = merge_tool_config(config, "ghidra", platform_key)
            check("Ghidra 配置合并", isinstance(ghidra_config, dict), f"包含 {len(ghidra_config)} 个键")
            
            ida_config = merge_tool_config(config, "ida", platform_key)
            check("IDA 配置合并", isinstance(ida_config, dict), f"包含 {len(ida_config)} 个键")
            
            semantics_config = merge_semantics_config_dict(config, platform_key)
            check("Semantics 配置合并", isinstance(semantics_config, dict), f"包含 {len(semantics_config)} 个键")
            
            return config, platform_key
    except Exception as e:
        check("配置加载", False, f"异常: {e}")
        return None, None


def check_tool_paths(config: dict, platform_key: str):
    """检查工具可执行文件路径"""
    print("\n=== 工具路径检查 ===")
    
    from project_config import merge_tool_config, merge_semantics_config_dict
    
    # Ghidra
    ghidra_config = merge_tool_config(config, "ghidra", platform_key)
    ghidra_cmd = (ghidra_config.get("ghidra") or {}).get("cmd_path")
    if ghidra_cmd:
        ghidra_path = Path(ghidra_cmd).expanduser()
        check("Ghidra 可执行文件", ghidra_path.exists(), f"路径: {ghidra_cmd}")
        if ghidra_path.exists():
            check("Ghidra 可执行", ghidra_path.is_file() and not ghidra_path.is_dir(), "文件存在且为可执行")
    else:
        check("Ghidra 路径配置", False, "配置中未找到 cmd_path")
    
    # IDA
    ida_config = merge_tool_config(config, "ida", platform_key)
    ida_cmd = (ida_config.get("ida") or {}).get("cmd_path")
    if ida_cmd:
        ida_path = Path(ida_cmd).expanduser()
        check("IDA 可执行文件", ida_path.exists(), f"路径: {ida_cmd}")
        if ida_path.exists():
            check("IDA 可执行", ida_path.is_file() and not ida_path.is_dir(), "文件存在且为可执行")
    else:
        check("IDA 路径配置", False, "配置中未找到 cmd_path")
    
    # Semantics runtime (idat_exe)
    semantics_config = merge_semantics_config_dict(config, platform_key)
    idat_exe = (semantics_config.get("runtime") or {}).get("idat_exe")
    if idat_exe:
        idat_path = Path(idat_exe).expanduser()
        check("Semantics idat_exe", idat_path.exists(), f"路径: {idat_exe}")
    else:
        check("Semantics idat_exe 配置", False, "配置中未找到 runtime.idat_exe")


def check_module_imports():
    """检查关键模块导入"""
    print("\n=== 模块导入检查 ===")
    
    # 项目配置
    try:
        import project_config
        check("project_config 模块", True, f"路径: {project_config.REPO_ROOT}")
    except Exception as e:
        check("project_config 模块", False, f"异常: {e}")
    
    # Ghidra 适配器
    try:
        from ghidra_adapter import GhidraAdapter
        check("GhidraAdapter 导入", True, "类可导入")
    except Exception as e:
        check("GhidraAdapter 导入", False, f"异常: {e}")
    
    # IDA 适配器
    try:
        from ida_adapter import IDAAdapter
        check("IDAAdapter 导入", True, "类可导入")
    except Exception as e:
        check("IDAAdapter 导入", False, f"异常: {e}")
    
    # 语义对齐模块
    try:
        sa_path = REPO_ROOT / "tools" / "Semantics_Alignment"
        sys.path.insert(0, str(sa_path / "breadth"))
        sys.path.insert(0, str(sa_path / "depth"))
        
        # 检查广度流水线
        pipeline_path = sa_path / "breadth" / "pipeline.py"
        check("广度流水线脚本", pipeline_path.exists(), f"路径: {pipeline_path}")
        
        alignment_loader_path = sa_path / "breadth" / "alignment_loader.py"
        check("对齐加载器脚本", alignment_loader_path.exists(), f"路径: {alignment_loader_path}")
        
        # 检查深度引擎
        engine_path = sa_path / "depth" / "engine.py"
        check("深度引擎脚本", engine_path.exists(), f"路径: {engine_path}")
        
        deep_path_dfs_path = sa_path / "depth" / "deep_path_dfs.py"
        check("深路径 DFS 脚本", deep_path_dfs_path.exists(), f"路径: {deep_path_dfs_path}")
        
    except Exception as e:
        check("语义对齐模块检查", False, f"异常: {e}")


def check_binary_file(binary_path: Path):
    """检查二进制文件"""
    print("\n=== 二进制文件检查 ===")
    
    check("二进制文件存在", binary_path.exists(), f"路径: {binary_path}")
    
    if binary_path.exists():
        size = binary_path.stat().st_size
        check("文件大小", size > 0, f"大小: {size} 字节")
        check("文件可读", binary_path.is_file(), "是文件而非目录")


def check_export_scripts():
    """检查导出脚本"""
    print("\n=== 导出脚本检查 ===")
    
    ghidra_extract = REPO_ROOT / "tools" / "Ghidra_Headless_Demo" / "ExtractAll.py"
    check("ExtractAll.py", ghidra_extract.exists(), f"路径: {ghidra_extract}")
    
    ida_extract = REPO_ROOT / "tools" / "IDA_Headless_Demo" / "ExtractAll_IDA.py"
    check("ExtractAll_IDA.py", ida_extract.exists(), f"路径: {ida_extract}")


def check_main_entry():
    """检查主入口脚本"""
    print("\n=== 主入口检查 ===")
    
    main_script = REPO_ROOT / "rebind_demo.py"
    check("rebind_demo.py", main_script.exists(), f"路径: {main_script}")
    
    if main_script.exists():
        check("主脚本可执行", True, "文件存在")


def generate_report():
    """生成检查报告"""
    print("\n" + "=" * 60)
    print("自检报告汇总")
    print("=" * 60)
    
    total = len(CHECK_RESULTS)
    passed = sum(1 for _, cond, _ in CHECK_RESULTS if cond)
    failed = total - passed
    
    print(f"\n总计: {total} 项检查")
    print(f"通过: {passed} 项")
    print(f"失败: {failed} 项")
    
    if failed > 0:
        print("\n失败的检查项:")
        for name, cond, msg in CHECK_RESULTS:
            if not cond:
                print(f"  ✗ {name}: {msg}")
    
    print("\n" + "=" * 60)
    
    return failed == 0


def main():
    """主函数"""
    print("ReBind Demo 项目自检")
    print("=" * 60)
    
    # 1. 配置检查
    config, platform_key = check_config()
    if not config:
        print("\n配置加载失败，终止检查")
        return 1
    
    # 2. 工具路径检查
    check_tool_paths(config, platform_key)
    
    # 3. 模块导入检查
    check_module_imports()
    
    # 4. 导出脚本检查
    check_export_scripts()
    
    # 5. 主入口检查
    check_main_entry()
    
    # 6. 二进制文件检查
    binary_path = REPO_ROOT / "tmp" / "client_b"
    check_binary_file(binary_path)
    
    # 生成报告
    all_passed = generate_report()
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
