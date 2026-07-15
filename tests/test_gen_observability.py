#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_observability 单测（unittest，不依赖 pytest）。"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SA_ROOT = _PROJECT_ROOT / "tools" / "Semantics_Alignment"
if str(_SA_ROOT) not in sys.path:
    sys.path.insert(0, str(_SA_ROOT))

from depth.gen_observability import (  # noqa: E402
    append_generations_index,
    generation_dir,
    write_subtree_tree_json,
)
from kp.kp_types import UnifiedFunctionNode, UnifiedGraph  # noqa: E402


class TestGenObservability(unittest.TestCase):
    def test_generation_dir_path(self) -> None:
        base = Path("/tmp/x/artifacts")
        self.assertEqual(
            generation_dir(base, 3, 2),
            Path("/tmp/x/artifacts/generations/goal_03_gen_2"),
        )

    def test_append_generations_index(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ad = Path(td) / "artifacts"
            append_generations_index(ad, {"goal_index": 1, "generation": 1, "k": "a"})
            append_generations_index(ad, {"goal_index": 1, "generation": 2, "k": "b"})
            append_generations_index(ad, {"goal_index": 1, "generation": 1, "k": "updated"})
            idx = ad / "generations" / "INDEX.json"
            self.assertTrue(idx.read_text(encoding="utf-8").strip())
            data = json.loads(idx.read_text(encoding="utf-8"))
            self.assertEqual(len(data), 2)
            self.assertEqual(data[0]["k"], "updated")
            self.assertFalse(idx.with_suffix(".json.tmp").exists())

    def test_write_subtree_tree_json_minimal(self) -> None:
        va = 0x140001000
        vb = 0x140002000
        a = UnifiedFunctionNode(entry_va=va, binary_id=1, names={"main"})
        b = UnifiedFunctionNode(entry_va=vb, binary_id=1, names={"sub"})
        a.internal_callee_vas.add(vb)
        g = UnifiedGraph(binary_id=1, nodes={va: a, vb: b}, tool_map={}, func_tool={})
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.json"
            write_subtree_tree_json(
                p,
                graph=g,
                goal_index=1,
                generation_index=1,
                label="t",
                root_vas=[va],
                allowed_nodes={va, 0x140002000},
                lambda_dist={va: 0.0, 0x140002000: 1.2},
                paths=[{"depth": 1, "path_vas": ["0x140001000", "0x140002000"], "path_names": ["main", "sub"]}],
            )
            doc = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(doc["generation"], 1)
            self.assertIn("call_tree", doc)


if __name__ == "__main__":
    unittest.main()
