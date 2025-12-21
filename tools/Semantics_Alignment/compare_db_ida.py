#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""compare_db_ida.py

对比 SQLite DB 中记录的函数名与 IDA 中实际的函数名，找出不同步的函数。

用法：
    在 IDA 中运行此脚本（通过 idat -A -S<script> 或 File->Script file）
    或者使用 idat_server.py 提供的 HTTP 接口远程查询
"""

import sqlite3
import sys
from pathlib import Path
from typing import Dict, Set, Tuple

try:
    import idaapi
    import idautils
    import idc
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


def get_functions_from_db(db_path: Path) -> Dict[int, str]:
    """从 DB 中获取所有函数的 entry_va -> name 映射"""
    conn = sqlite3.connect(str(db_path))
    functions = {}
    
    try:
        cur = conn.cursor()
        # 从 functions 表获取 IDA 视图的函数（工具名全小写）
        cur.execute("""
            SELECT f.entry_va, f.name 
            FROM functions f
            JOIN binary_views bv ON f.view_id = bv.id
            JOIN tools t ON bv.tool_id = t.id
            WHERE t.name = 'ida'
            ORDER BY f.entry_va
        """)
        
        for entry_va, name in cur.fetchall():
            functions[entry_va] = name or ""
            
    finally:
        conn.close()
    
    return functions


def get_functions_from_ida() -> Dict[int, str]:
    """从 IDA 中获取所有函数的 entry_va -> name 映射"""
    if not IDA_AVAILABLE:
        raise RuntimeError("此脚本需要在 IDA 环境中运行")
    
    functions = {}
    
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        functions[func_ea] = func_name or ""
    
    return functions


def compare_functions(db_funcs: Dict[int, str], ida_funcs: Dict[int, str]) -> Tuple[Set[int], Dict[int, Tuple[str, str]]]:
    """
    对比 DB 和 IDA 中的函数
    
    返回:
        - missing_in_ida: DB 中有但 IDA 中没有的函数地址
        - name_mismatches: 名称不匹配的函数 {entry_va: (db_name, ida_name)}
    """
    missing_in_ida = set()
    name_mismatches = {}
    
    for entry_va, db_name in db_funcs.items():
        if entry_va not in ida_funcs:
            missing_in_ida.add(entry_va)
        elif db_name != ida_funcs[entry_va]:
            name_mismatches[entry_va] = (db_name, ida_funcs[entry_va])
    
    return missing_in_ida, name_mismatches


def main_ida():
    """在 IDA 中运行的主函数"""
    if not IDA_AVAILABLE:
        print("错误: 此脚本需要在 IDA 环境中运行")
        return
    
    # 获取当前 IDB 对应的 DB 路径（假设在同一目录下）
    input_path = idaapi.get_input_file_path()
    db_path = Path(input_path).with_suffix('.db')
    
    if not db_path.exists():
        print(f"错误: 未找到数据库文件: {db_path}")
        return
    
    print(f"[CompareDBIDA] 正在对比数据库: {db_path}")
    print(f"[CompareDBIDA] IDA 输入文件: {input_path}")
    
    db_funcs = get_functions_from_db(db_path)
    ida_funcs = get_functions_from_ida()
    
    print(f"\n[CompareDBIDA] DB 中函数数量: {len(db_funcs)}")
    print(f"[CompareDBIDA] IDA 中函数数量: {len(ida_funcs)}")
    
    missing_in_ida, name_mismatches = compare_functions(db_funcs, ida_funcs)
    
    if missing_in_ida:
        print(f"\n[CompareDBIDA] DB 中有但 IDA 中缺失的函数 ({len(missing_in_ida)} 个):")
        for entry_va in sorted(missing_in_ida)[:20]:  # 只显示前20个
            print(f"  0x{entry_va:08X}: {db_funcs[entry_va]}")
        if len(missing_in_ida) > 20:
            print(f"  ... (还有 {len(missing_in_ida) - 20} 个)")
    
    if name_mismatches:
        print(f"\n[CompareDBIDA] 名称不同步的函数 ({len(name_mismatches)} 个):")
        for entry_va in sorted(name_mismatches.keys())[:50]:  # 只显示前50个
            db_name, ida_name = name_mismatches[entry_va]
            print(f"  0x{entry_va:08X}:")
            print(f"    DB:  {db_name}")
            print(f"    IDA: {ida_name}")
        if len(name_mismatches) > 50:
            print(f"  ... (还有 {len(name_mismatches) - 50} 个)")
    
    if not missing_in_ida and not name_mismatches:
        print("\n[CompareDBIDA] ✓ DB 和 IDA 完全同步!")


def main_standalone(db_path: str):
    """独立运行模式（不依赖 IDA）"""
    db_path = Path(db_path)
    if not db_path.exists():
        print(f"错误: 未找到数据库文件: {db_path}")
        return
    
    print(f"[CompareDBIDA] 正在分析数据库: {db_path}")
    
    db_funcs = get_functions_from_db(db_path)
    print(f"[CompareDBIDA] DB 中 IDA 工具的函数数量: {len(db_funcs)}")
    
    # 统计默认命名的函数
    default_named = [
        (va, name) for va, name in db_funcs.items()
        if name.startswith(('sub_', 'fun_', 'loc_', 'nullsub_'))
    ]
    
    print(f"\n[CompareDBIDA] DB 中默认命名的函数 ({len(default_named)} 个):")
    for entry_va, name in sorted(default_named)[:30]:
        print(f"  0x{entry_va:08X}: {name}")
    if len(default_named) > 30:
        print(f"  ... (还有 {len(default_named) - 30} 个)")


if __name__ == "__main__":
    if IDA_AVAILABLE:
        # 在 IDA 中运行
        main_ida()
    elif len(sys.argv) > 1:
        # 独立运行模式
        main_standalone(sys.argv[1])
    else:
        print("用法:")
        print("  1. 在 IDA 中: File -> Script file -> 选择此脚本")
        print("  2. 独立运行: python compare_db_ida.py <db_path>")
