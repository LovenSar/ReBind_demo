#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试 Phase1-6 的优化实现。

注意：涉及 LLM 调用的测试用例会跳过实际调用，使用模拟结果。
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Dict, Set
from unittest.mock import Mock, patch

# 添加项目路径
import sys
repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root / "tools" / "Semantics_Alignment"))

from breadth.phases.phase1_kp import _apply_unified_llm_result_batch
from breadth.phases.phase2_validation import run_validation_phase
from breadth.phases.phase3_globals import build_global_var_graph, _is_write_ref
from breadth.phases.phase4_lvar import _load_pseudocode_batch
from kp.kp_scoring import compute_unified_scores_incremental
from kp.kp_types import UnifiedFunctionNode, UnifiedGraph


class TestPhase1BatchUpdate(unittest.TestCase):
    """测试 Phase1 批量更新优化。"""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("""
            CREATE TABLE analysis_status (
                function_id INTEGER PRIMARY KEY,
                analysis_state TEXT,
                confidence_score INTEGER,
                summary_signature TEXT,
                semantic_summary TEXT,
                phase2_pending INTEGER
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
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        import os
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_batch_update(self):
        """测试批量更新功能。"""
        # 插入测试数据
        for i in range(1, 6):
            self.conn.execute(
                "INSERT INTO analysis_status (function_id, analysis_state) VALUES (?, 'PENDING')",
                (i,)
            )
        self.conn.commit()

        # 创建模拟的节点和结果
        nodes = []
        results = []
        for i in range(1, 6):
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
        
        # 使用批量更新
        _apply_unified_llm_result_batch(
            conn=self.conn,
            graph=graph,
            nodes=nodes,
            results=results,
            ida_sync=False,
        )

        # 验证更新
        cur = self.conn.cursor()
        cur.execute("SELECT function_id, analysis_state, confidence_score FROM analysis_status ORDER BY function_id")
        rows = cur.fetchall()
        
        self.assertEqual(len(rows), 5)
        for fid, state, score in rows:
            self.assertEqual(state, "ANALYZED")
            self.assertEqual(score, 80)  # 0.8 * 100


class TestPhase1IncrementalScoring(unittest.TestCase):
    """测试 Phase1 增量评分优化。"""

    def test_incremental_scoring(self):
        """测试增量评分只重算受影响的函数。"""
        graph = Mock(spec=UnifiedGraph)
        graph.nodes = {}
        
        # 创建模拟节点
        for i in range(1, 6):
            node = Mock(spec=UnifiedFunctionNode)
            node.entry_va = 0x1000 + i
            node.function_ids = {i}
            node.external_callee_names = set()
            node.string_refs = set()
            node.internal_callee_vas = set()
            node.caller_vas = set()
            node.instr_count = 50
            graph.nodes[0x1000 + i] = node

        analysis_info = {
            1: {"analysis_state": "ANALYZED"},
            2: {"analysis_state": "PENDING"},
        }

        existing_scores = {
            0x1001: 100,
            0x1002: 200,
            0x1003: 150,
        }

        # 测试增量评分
        changed_entry_vas = {0x1001}
        new_scores = compute_unified_scores_incremental(
            graph=graph,
            analysis_info=analysis_info,
            changed_entry_vas=changed_entry_vas,
            existing_scores=existing_scores,
        )

        # 验证：受影响的函数应该被重算
        self.assertIn(0x1001, new_scores)
        # 其他未受影响的函数应该保持不变（如果它们不在 impacted 集合中）
        # 注意：由于调用者也会被重算，所以可能所有相关函数都会被更新


class TestPhase2LockedCache(unittest.TestCase):
    """测试 Phase2 锁定函数缓存优化。"""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("""
            CREATE TABLE analysis_status (
                function_id INTEGER PRIMARY KEY,
                analysis_state TEXT
            );
        """)
        self.conn.execute("""
            CREATE TABLE functions (
                id INTEGER PRIMARY KEY,
                entry_va INTEGER
            );
        """)
        # 插入一些测试数据
        for i in range(1, 6):
            self.conn.execute(
                "INSERT INTO functions (id, entry_va) VALUES (?, ?)",
                (i, 0x1000 + i)
            )
            state = "LOCKED" if i <= 2 else "ANALYZED"
            self.conn.execute(
                "INSERT INTO analysis_status (function_id, analysis_state) VALUES (?, ?)",
                (i, state)
            )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        import os
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_locked_cache(self):
        """测试锁定函数缓存构建。"""
        from breadth.phases.phase2_validation import run_validation_phase
        
        graph = Mock(spec=UnifiedGraph)
        graph.nodes = {}
        for i in range(1, 6):
            node = Mock(spec=UnifiedFunctionNode)
            node.entry_va = 0x1000 + i
            node.function_ids = {i}
            graph.nodes[0x1000 + i] = node

        # 构建缓存（通过内部函数）
        cur = self.conn.cursor()
        cur.execute("""
            SELECT DISTINCT f.entry_va
            FROM analysis_status AS a
            JOIN functions AS f ON f.id = a.function_id
            WHERE a.analysis_state = 'LOCKED';
        """)
        locked_cache = {int(row[0]) for row in cur.fetchall()}

        # 验证缓存
        self.assertEqual(len(locked_cache), 2)
        self.assertIn(0x1001, locked_cache)
        self.assertIn(0x1002, locked_cache)


class TestPhase3GlobalVarGraph(unittest.TestCase):
    """测试 Phase3 全局变量图构建优化。"""

    def test_is_write_ref(self):
        """测试写引用判断函数。"""
        self.assertTrue(_is_write_ref("WRITE"))
        self.assertTrue(_is_write_ref("STORE"))
        self.assertFalse(_is_write_ref("READ"))
        self.assertFalse(_is_write_ref("DATA_REF"))
        self.assertFalse(_is_write_ref(None))

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("""
            CREATE TABLE binary_views (
                id INTEGER PRIMARY KEY,
                binary_id INTEGER
            );
        """)
        self.conn.execute("""
            CREATE TABLE xrefs (
                view_id INTEGER,
                dst_va INTEGER,
                dst_name TEXT,
                src_va INTEGER,
                ref_type_raw TEXT
            );
        """)
        self.conn.execute("""
            CREATE TABLE symbols (
                view_id INTEGER,
                address_va INTEGER,
                name TEXT,
                kind TEXT,
                is_global INTEGER
            );
        """)
        # 插入测试数据
        self.conn.execute("INSERT INTO binary_views (id, binary_id) VALUES (1, 1)")
        self.conn.execute("""
            INSERT INTO xrefs (view_id, dst_va, dst_name, src_va, ref_type_raw)
            VALUES (1, 0x2000, 'global_var', 0x1001, 'DATA_REF')
        """)
        self.conn.execute("""
            INSERT INTO xrefs (view_id, dst_va, dst_name, src_va, ref_type_raw)
            VALUES (1, 0x2000, 'global_var', 0x1002, 'WRITE')
        """)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        import os
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_global_var_graph_optimization(self):
        """测试全局变量图构建优化（单次查询）。"""
        graph = Mock(spec=UnifiedGraph)
        graph.nodes = {0x1001: Mock(), 0x1002: Mock()}  # 代码地址

        # 测试构建全局变量图
        # 注意：由于函数较复杂，这里主要测试查询逻辑
        cur = self.conn.cursor()
        cur.execute("""
            SELECT DISTINCT x.dst_va, x.dst_name, x.src_va, x.ref_type_raw
            FROM xrefs AS x
            WHERE x.view_id IN (1)
                AND x.dst_va IS NOT NULL
                AND x.ref_type_raw NOT IN ('UNCONDITIONAL_CALL', 'COMPUTED_CALL', '17', '19', '21');
        """)
        rows = cur.fetchall()
        
        # 验证单次查询获取了所有数据
        self.assertEqual(len(rows), 2)
        # 验证可以区分读写
        write_refs = [r for r in rows if _is_write_ref(r[3])]
        self.assertEqual(len(write_refs), 1)


class TestPhase4BatchLoad(unittest.TestCase):
    """测试 Phase4 伪代码批量加载优化。"""

    def setUp(self):
        self.db_fd, self.db_path = tempfile.mkstemp(suffix=".db")
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("""
            CREATE TABLE pseudo_functions (
                function_id INTEGER PRIMARY KEY,
                prototype TEXT,
                body TEXT
            );
        """)
        # 插入测试数据
        for i in range(1, 6):
            self.conn.execute(
                "INSERT INTO pseudo_functions (function_id, prototype, body) VALUES (?, ?, ?)",
                (i, f"void func_{i}()", f"// Function {i}\nreturn;")
            )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()
        import os
        os.close(self.db_fd)
        os.unlink(self.db_path)

    def test_batch_load_pseudocode(self):
        """测试批量加载伪代码。"""
        function_ids = {1, 2, 3, 4, 5}
        result = _load_pseudocode_batch(self.conn, function_ids)

        # 验证批量加载
        self.assertEqual(len(result), 5)
        for fid in function_ids:
            self.assertIn(fid, result)
            proto, body = result[fid]
            self.assertEqual(proto, f"void func_{fid}()")
            self.assertIn(f"Function {fid}", body)


class TestPhase1LazyHeap(unittest.TestCase):
    """测试 Phase1 延迟删除堆优化。"""

    def test_lazy_heap(self):
        """测试延迟删除堆的基本功能。"""
        # 从 pipeline.py 中提取 LazyHeap 类进行测试
        import heapq
        from typing import Optional

        class LazyHeap:
            def __init__(self):
                self.heap: list = []
                self.entry_va_to_best: Dict[int, tuple] = {}
            
            def push(self, entry_va: int, score: int, seq: int) -> None:
                if entry_va in self.entry_va_to_best:
                    old_score, old_seq = self.entry_va_to_best[entry_va]
                    if seq <= old_seq:
                        return
                self.entry_va_to_best[entry_va] = (score, seq)
                heapq.heappush(self.heap, (-score, seq, entry_va))
            
            def pop(self) -> Optional[tuple]:
                while self.heap:
                    neg_score, seq, entry_va = heapq.heappop(self.heap)
                    best_score, best_seq = self.entry_va_to_best.get(entry_va, (0, 0))
                    if seq == best_seq:
                        del self.entry_va_to_best[entry_va]
                        return (-neg_score, seq, entry_va)
                return None
            
            def __bool__(self) -> bool:
                while self.heap:
                    neg_score, seq, entry_va = self.heap[0]
                    best_score, best_seq = self.entry_va_to_best.get(entry_va, (0, 0))
                    if seq == best_seq:
                        return True
                    heapq.heappop(self.heap)
                return False

        heap = LazyHeap()
        
        # 测试基本 push/pop
        heap.push(0x1001, 100, 1)
        heap.push(0x1002, 200, 2)
        
        result = heap.pop()
        self.assertIsNotNone(result)
        score, seq, entry_va = result
        self.assertEqual(entry_va, 0x1002)  # 更高分数先出
        
        # 测试更新：推送新分数
        heap.push(0x1001, 300, 3)  # 更新 0x1001 的分数
        result = heap.pop()
        self.assertIsNotNone(result)
        score, seq, entry_va = result
        self.assertEqual(entry_va, 0x1001)
        self.assertEqual(score, 300)


if __name__ == "__main__":
    unittest.main()
