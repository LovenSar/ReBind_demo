#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""export_analysis_summary.py

导出语义分析结果的汇总报告，展示 Phase 1-5 的实际命名结果。

用法:
    python export_analysis_summary.py <db_path> [--output summary.txt]
"""

import argparse
import sqlite3
from pathlib import Path
from typing import Dict, List, Tuple


def get_analyzed_functions(db_path: Path) -> List[Dict]:
    """获取所有经过语义分析的函数信息"""
    conn = sqlite3.connect(str(db_path))
    functions = []
    
    try:
        cur = conn.cursor()
        
        # 联合查询获取完整信息
        cur.execute("""
            SELECT 
                f.entry_va,
                f.name as original_name,
                a.summary_signature as analyzed_name,
                a.semantic_summary,
                a.analysis_state,
                a.confidence_score,
                a.annotation_status,
                bv.tool_id,
                t.name as tool_name
            FROM functions f
            LEFT JOIN analysis_status a ON f.id = a.function_id
            JOIN binary_views bv ON f.view_id = bv.id
            JOIN tools t ON bv.tool_id = t.id
            WHERE t.name = 'ida'
            ORDER BY f.entry_va
        """)
        
        for row in cur.fetchall():
            entry_va, orig_name, analyzed_name, summary, state, conf, annot, tool_id, tool_name = row
            functions.append({
                'entry_va': entry_va,
                'original_name': orig_name or '',
                'analyzed_name': analyzed_name or '',
                'semantic_summary': summary or '',
                'analysis_state': state or 'PENDING',
                'confidence': conf or 0,
                'annotation_status': annot or 0,
                'tool': tool_name,
            })
    finally:
        conn.close()
    
    return functions


def export_summary_report(db_path: Path, output_path: Path):
    """导出分析汇总报告"""
    functions = get_analyzed_functions(db_path)
    
    # 统计信息
    total = len(functions)
    analyzed = sum(1 for f in functions if f['analyzed_name'])
    locked = sum(1 for f in functions if f['analysis_state'] == 'LOCKED')
    annotated = sum(1 for f in functions if f['annotation_status'] > 0)
    
    with output_path.open('w', encoding='utf-8') as out:
        out.write(f"语义分析结果汇总报告\n")
        out.write(f"=" * 80 + "\n")
        out.write(f"数据库: {db_path}\n")
        out.write(f"导出时间: {Path(__file__).stat().st_mtime}\n\n")
        
        out.write(f"统计信息:\n")
        out.write(f"  总函数数: {total}\n")
        out.write(f"  已分析: {analyzed} ({analyzed/total*100:.1f}%)\n")
        out.write(f"  已锁定: {locked} ({locked/total*100:.1f}%)\n")
        out.write(f"  已注释: {annotated} ({annotated/total*100:.1f}%)\n\n")
        
        out.write(f"=" * 80 + "\n")
        out.write(f"详细函数列表\n")
        out.write(f"=" * 80 + "\n\n")
        
        for func in functions:
            out.write(f"地址: 0x{func['entry_va']:08X}\n")
            out.write(f"原始名称: {func['original_name']}\n")
            
            if func['analyzed_name']:
                out.write(f"分析后名称: {func['analyzed_name']}\n")
            else:
                out.write(f"分析后名称: (未分析)\n")
            
            out.write(f"状态: {func['analysis_state']} (置信度: {func['confidence']})\n")
            
            if func['semantic_summary']:
                # 截断过长的摘要
                summary = func['semantic_summary']
                if len(summary) > 200:
                    summary = summary[:197] + "..."
                out.write(f"摘要: {summary}\n")
            
            if func['annotation_status'] > 0:
                out.write(f"注释状态: 已注释\n")
            
            out.write(f"-" * 80 + "\n\n")
    
    print(f"[ExportSummary] 分析报告已导出到: {output_path}")
    print(f"[ExportSummary] 总函数数: {total}, 已分析: {analyzed}, 已锁定: {locked}, 已注释: {annotated}")


def export_renamed_functions_csv(db_path: Path, output_path: Path):
    """导出重命名函数的 CSV 列表（用于导入 IDA）"""
    functions = get_analyzed_functions(db_path)
    
    # 只导出有分析结果的函数
    renamed = [f for f in functions if f['analyzed_name'] and f['analyzed_name'] != f['original_name']]
    
    with output_path.open('w', encoding='utf-8') as out:
        out.write("entry_va,original_name,new_name,confidence\n")
        for func in renamed:
            # 从 summary_signature 中提取函数名（通常是第一个单词或括号前的部分）
            analyzed_name = func['analyzed_name']
            # 简单提取函数名（去掉参数和返回值）
            if '(' in analyzed_name:
                func_name = analyzed_name.split('(')[0].strip().split()[-1]
            else:
                func_name = analyzed_name.strip().split()[0]
            
            out.write(f"0x{func['entry_va']:08X},{func['original_name']},{func_name},{func['confidence']}\n")
    
    print(f"[ExportSummary] 重命名函数列表已导出到: {output_path}")
    print(f"[ExportSummary] 共 {len(renamed)} 个函数需要重命名")


def main():
    parser = argparse.ArgumentParser(
        description="导出语义分析结果汇总报告"
    )
    parser.add_argument(
        "db_path",
        help="SQLite 数据库路径"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="输出文件路径（默认: <db_path>_analysis_summary.txt）"
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="同时导出 CSV 格式的重命名列表"
    )
    
    args = parser.parse_args()
    
    db_path = Path(args.db_path).expanduser().resolve()
    if not db_path.exists():
        print(f"错误: 数据库文件不存在: {db_path}")
        return 1
    
    if args.output:
        output_path = Path(args.output).expanduser().resolve()
    else:
        output_path = db_path.with_name(f"{db_path.stem}_analysis_summary.txt")
    
    export_summary_report(db_path, output_path)
    
    if args.csv:
        csv_path = output_path.with_suffix('.csv')
        export_renamed_functions_csv(db_path, csv_path)
    
    return 0


if __name__ == "__main__":
    exit(main())
