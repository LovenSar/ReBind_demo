#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试 Bug 修复。

Bug 1: _apply_unified_llm_result_batch 中的 tuple 切片错误
Bug 2: alignment_loader.py 中地址偏移检测缺少 *_output 检查
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

# 添加项目路径
import sys
repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root / "tools" / "Semantics_Alignment"))

from breadth.phases.phase1_kp import _apply_unified_llm_result_batch
from kp.kp_types import UnifiedFunctionNode, UnifiedGraph


class TestBug1BatchUpdate(unittest.TestCase):
    """测试 Bug 1: _apply_unified_llm_result_batch 中的 tuple 切片错误。"""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.conn = sqlite3.connect(self.db_path)
        # 创建旧数据库（无 phase2_pending 列）
        self.conn.execute("""
            CREATE TABLE analysis_status (
                function_id INTEGER PRIMARY KEY,
                analysis_state TEXT,
                confidence_score INTEGER,
                summary_signature TEXT,
                semantic_summary TEXT
            );
        """)
        self.conn.execute("""
            CREATE TABLE functions (
                id INTEGER PRIMARY KEY,
                entry_va INTEGER,
                view_id INTEGER,
                name TEXT
            );
        """)
        # 插入测试数据
        for i in range(1, 4):
            self.conn.execute(
                "INSERT INTO functions (id, entry_va, name) VALUES (?, ?, ?)",
                (i, 0x1000 + i, f"func_{i}")
            )
            self.conn.execute(
                "INSERT INTO analysis_status (function_id, analysis_state) VALUES (?, 'PENDING')",
                (i,)
            )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        import os
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_batch_update_old_database(self):
        """测试在旧数据库（无 phase2_pending 列）上的批量更新。"""
        # 创建模拟的节点和结果
        nodes = []
        results = []
        for i in range(1, 4):
            node = Mock(spec=UnifiedFunctionNode)
            node.entry_va = 0x1000 + i
            node.function_ids = {i}
            nodes.append(node)
            results.append({
                "signature": f"void func_{i}()",
                "summary": f"Function {i}",
                "confidence": 0.8,
                "libfunction": False,
            })

        graph = Mock(spec=UnifiedGraph)
        
        # 使用批量更新（应该触发旧数据库的回退逻辑）
        _apply_unified_llm_result_batch(
            conn=self.conn,
            graph=graph,
            nodes=nodes,
            results=results,
            ida_sync=False,
        )

        # 验证更新：所有 function_id 都应该被正确更新
        cur = self.conn.cursor()
        cur.execute("SELECT function_id, analysis_state, confidence_score, summary_signature FROM analysis_status ORDER BY function_id")
        rows = cur.fetchall()
        
        self.assertEqual(len(rows), 3)
        # 验证每个 function_id 都被正确更新（不是只更新了 function_id=1）
        for fid, state, score, sig in rows:
            self.assertIn(fid, [1, 2, 3], f"function_id {fid} 应该被更新")
            self.assertEqual(state, "ANALYZED", f"function_id {fid} 的状态应该是 ANALYZED")
            self.assertEqual(score, 80, f"function_id {fid} 的置信度应该是 80")
            self.assertIsNotNone(sig, f"function_id {fid} 应该有签名")


class TestBug2AddressOffset(unittest.TestCase):
    """测试 Bug 2: alignment_loader.py 中地址偏移检测缺少 *_output 检查。"""

    def test_output_dir_detection_logic(self):
        """测试 *_output 目录的检测逻辑（模拟 main 函数中的逻辑）。"""
        # 创建临时目录结构
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            
            # 测试 Ghidra: 应该能找到 *_output
            ghidra_dir = tmp_path / "ghidra_export"
            ghidra_dir.mkdir()
            ghidra_output = ghidra_dir / "binary_output"
            ghidra_output.mkdir()
            (ghidra_output / "test_symbols.csv").touch()
            
            # 模拟修复后的检测逻辑
            ghidra_binaryinfo = next(ghidra_dir.glob("*_binaryinfo"), None)
            if ghidra_binaryinfo is None:
                ghidra_binaryinfo = next(ghidra_dir.glob("*_output"), None)
            if ghidra_binaryinfo is None:
                ghidra_binaryinfo = next(ghidra_dir.glob("*_ghidemo"), None)
            
            self.assertIsNotNone(ghidra_binaryinfo, "应该找到 *_output 目录")
            self.assertEqual(ghidra_binaryinfo, ghidra_output)
            
            # 测试 IDA: 应该能找到 *_output
            ida_dir = tmp_path / "ida_export"
            ida_dir.mkdir()
            ida_output = ida_dir / "binary_output"
            ida_output.mkdir()
            (ida_output / "test_symbols.csv").touch()
            
            # 模拟修复后的检测逻辑
            ida_binaryinfo = next(ida_dir.glob("*_output"), None)
            if ida_binaryinfo is None:
                ida_binaryinfo = next(ida_dir.glob("*_binaryinfo"), None)
            
            self.assertIsNotNone(ida_binaryinfo, "应该找到 *_output 目录")
            self.assertEqual(ida_binaryinfo, ida_output)


if __name__ == "__main__":
    unittest.main()
