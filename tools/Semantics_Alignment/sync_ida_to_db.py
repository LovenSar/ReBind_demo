#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sync_ida_to_db.py

从 IDA idb 同步函数名回本地 DB，并可选地解锁 LOCKED 状态。

用法:
    python sync_ida_to_db.py <db_path> --ida-url http://127.0.0.1:12345 [--unlock-locked]
"""

import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path
from typing import Dict, List, Set
from urllib import request
from urllib.error import URLError


def get_ida_functions(ida_url: str, timeout: int = 5) -> Dict[int, str]:
    """从 IDA HTTP 服务获取所有函数的 entry_va -> name 映射"""
    print(f"[SyncIDAToDb] 正在从 IDA 获取函数列表: {ida_url}")
    
    # 构造请求获取函数列表
    req_data = json.dumps({"action": "get_functions"}).encode('utf-8')
    req = request.Request(
        ida_url,
        data=req_data,
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    
    try:
        with request.urlopen(req, timeout=timeout) as response:
            result = json.loads(response.read().decode('utf-8'))
            
            if result.get('status') != 'success':
                raise RuntimeError(f"IDA 返回错误: {result.get('message', 'unknown')}")
            
            functions = result.get('functions', {})
            # 转换键为整数
            return {int(k, 16) if isinstance(k, str) and k.startswith('0x') else int(k): v 
                    for k, v in functions.items()}
    
    except URLError as e:
        raise RuntimeError(f"无法连接到 IDA 服务: {e}")
    except Exception as e:
        raise RuntimeError(f"获取 IDA 函数列表失败: {e}")


def sync_functions_to_db(
    db_path: Path,
    ida_functions: Dict[int, str],
    unlock_locked: bool = False
) -> Dict[str, int]:
    """同步 IDA 函数名到 DB"""
    conn = sqlite3.connect(str(db_path))
    stats = {
        'total': 0,
        'updated': 0,
        'unlocked': 0,
        'not_found': 0,
    }
    
    try:
        cur = conn.cursor()
        
        # 获取 IDA 视图的所有函数
        cur.execute("""
            SELECT f.id, f.entry_va, f.name
            FROM functions f
            JOIN binary_views bv ON f.view_id = bv.id
            JOIN tools t ON bv.tool_id = t.id
            WHERE t.name = 'ida'
        """)
        
        db_functions = {row[1]: (row[0], row[2]) for row in cur.fetchall()}
        stats['total'] = len(db_functions)
        
        print(f"[SyncIDAToDb] DB 中有 {len(db_functions)} 个 IDA 函数")
        print(f"[SyncIDAToDb] IDA 中有 {len(ida_functions)} 个函数")
        
        # 更新函数名
        for entry_va, ida_name in ida_functions.items():
            if entry_va not in db_functions:
                stats['not_found'] += 1
                continue
            
            func_id, db_name = db_functions[entry_va]
            
            if ida_name != db_name:
                print(f"[SyncIDAToDb] 更新 0x{entry_va:08X}: {db_name} -> {ida_name}")
                cur.execute(
                    "UPDATE functions SET name = ? WHERE id = ?",
                    (ida_name, func_id)
                )
                stats['updated'] += 1
        
        # 可选：解锁 LOCKED 状态
        if unlock_locked:
            cur.execute("""
                UPDATE analysis_status 
                SET analysis_state = 'PENDING'
                WHERE analysis_state = 'LOCKED'
                AND function_id IN (
                    SELECT f.id FROM functions f
                    JOIN binary_views bv ON f.view_id = bv.id
                    JOIN tools t ON bv.tool_id = t.id
                    WHERE t.name = 'ida'
                )
            """)
            stats['unlocked'] = cur.rowcount
            print(f"[SyncIDAToDb] 已解锁 {stats['unlocked']} 个 LOCKED 函数")
        
        conn.commit()
        
    finally:
        conn.close()
    
    return stats


def wait_for_ida_server(ida_url: str, max_wait: int = 30) -> bool:
    """等待 IDA 服务启动"""
    print(f"[SyncIDAToDb] 等待 IDA 服务启动...")
    
    for i in range(max_wait):
        try:
            req = request.Request(
                ida_url,
                data=json.dumps({"action": "ping"}).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            with request.urlopen(req, timeout=2) as response:
                result = json.loads(response.read().decode('utf-8'))
                if result.get('status') == 'success':
                    print(f"[SyncIDAToDb] IDA 服务已就绪")
                    return True
        except Exception:
            if i < max_wait - 1:
                time.sleep(1)
    
    return False


def main():
    parser = argparse.ArgumentParser(
        description="从 IDA idb 同步函数名回本地 DB"
    )
    parser.add_argument(
        "db_path",
        help="SQLite 数据库路径"
    )
    parser.add_argument(
        "--ida-url",
        default="http://127.0.0.1:12345",
        help="IDA HTTP 服务地址（默认: http://127.0.0.1:12345）"
    )
    parser.add_argument(
        "--unlock-locked",
        action="store_true",
        help="解锁所有 LOCKED 状态的函数，允许重新分析"
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="等待 IDA 服务启动"
    )
    
    args = parser.parse_args()
    
    db_path = Path(args.db_path).expanduser().resolve()
    if not db_path.exists():
        print(f"错误: 数据库文件不存在: {db_path}")
        return 1
    
    # 可选：等待 IDA 服务
    if args.wait:
        if not wait_for_ida_server(args.ida_url):
            print(f"错误: IDA 服务未响应: {args.ida_url}")
            return 1
    
    try:
        # 从 IDA 获取函数列表
        ida_functions = get_ida_functions(args.ida_url)
        
        # 同步到 DB
        stats = sync_functions_to_db(db_path, ida_functions, args.unlock_locked)
        
        print(f"\n[SyncIDAToDb] 同步完成:")
        print(f"  总函数数: {stats['total']}")
        print(f"  已更新: {stats['updated']}")
        if args.unlock_locked:
            print(f"  已解锁: {stats['unlocked']}")
        if stats['not_found'] > 0:
            print(f"  未在 DB 中找到: {stats['not_found']}")
        
        return 0
    
    except Exception as e:
        print(f"错误: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    exit(main())
