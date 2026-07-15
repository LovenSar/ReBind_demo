#!/usr/bin/env python3
"""entry 模式的全局 Gen1 主干只执行一次。"""

from __future__ import annotations

import io
import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SA_ROOT = _PROJECT_ROOT / "tools" / "Semantics_Alignment"
if str(_SA_ROOT) not in sys.path:
    sys.path.insert(0, str(_SA_ROOT))

from depth import engine  # noqa: E402
from depth.goal_collector import GoalItem  # noqa: E402
from kp.kp_types import UnifiedFunctionNode, UnifiedGraph  # noqa: E402


def _fake_graph() -> UnifiedGraph:
    nodes = {
        0x1000: UnifiedFunctionNode(
            entry_va=0x1000,
            binary_id=1,
            function_ids={1},
            names={"entry"},
            internal_callee_vas={0x2000},
        ),
        0x2000: UnifiedFunctionNode(
            entry_va=0x2000,
            binary_id=1,
            function_ids={2},
            names={"goal_a"},
        ),
        0x3000: UnifiedFunctionNode(
            entry_va=0x3000,
            binary_id=1,
            function_ids={3},
            names={"goal_b"},
        ),
    }
    return UnifiedGraph(binary_id=1, nodes=nodes, tool_map={}, func_tool={1: "ida", 2: "ida", 3: "ida"})


class TestPhase7SharedGen1(unittest.TestCase):
    def test_entry_gen1_runs_once_for_multiple_goals_and_is_checkpointed(self) -> None:
        graph = _fake_graph()
        fake_status = SimpleNamespace(
            enabled=False,
            degraded=False,
            reason="test",
            total_candidates=0,
            selected_candidates=0,
            incremental_applied=False,
        )

        def fake_generation(**_kwargs: object) -> dict[str, object]:
            return {
                "label": "mock",
                "entries": ["0x00001000"],
                "max_depth": 1,
                "stats": {"total_paths": 1},
                "paths": [
                    {
                        "entry_va": "0x00001000",
                        "entry_name": "entry",
                        "depth": 1,
                        "path_vas": ["0x00001000", "0x00002000"],
                        "path_names": ["entry", "goal_a"],
                        "edge_conditions": [],
                    }
                ],
                "llm": {"status": "skipped", "reason": "llm_mode_off"},
            }

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            db_path = root / "sample.db"
            sqlite3.connect(str(db_path)).close()
            argv = [
                "engine.py",
                str(root / "sample.exe"),
                "--db", str(db_path),
                "--runs-root", str(root / "runs"),
                "--run-id", "shared",
                "--max-generations", "1",
                "--goal-limit", "2",
                "--llm-mode", "off",
                "--no-console-progress",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.object(engine, "run_phase7_5_strict_align", return_value={"status": "aligned", "profile_diff_count": 0}),
                patch.object(engine, "pick_binary_id", return_value=1),
                patch.object(engine, "build_unified_graph", return_value=graph),
                patch.object(engine, "_load_analysis_info_safe", return_value={}),
                patch.object(engine, "_collect_indirect_edges", return_value=([], fake_status)),
                patch.object(engine, "_build_mixed_graph", return_value=({0x1000: {0x2000: {"call"}}, 0x2000: {0x1000: {"call"}}, 0x3000: {}}, {}, {})),
                patch.object(engine, "_pick_manual_goals", return_value=[]),
                patch.object(
                    engine,
                    "_pick_auto_goals",
                    return_value=[
                        GoalItem(0x2000, "auto", 1, 1, 0),
                        GoalItem(0x3000, "auto", 1, 1, 0),
                    ],
                ),
                patch.object(engine, "resolve_entry_points", return_value=[0x1000]),
                patch.object(engine, "_rank_nodes_for_compare", return_value=[]),
                patch.object(engine, "_run_deep_generation", side_effect=fake_generation) as run_generation,
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(engine.main(), 0)

            self.assertEqual(run_generation.call_count, 1)
            state_path = root / "runs" / "sample.exe" / "shared" / "checkpoints" / "state.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["shared_entry_gen1"]["source_goal_index"], 1)
            self.assertEqual(state["shared_entry_gen1"]["root_vas"], [0x1000])
            index_path = root / "runs" / "sample.exe" / "shared" / "artifacts" / "generations" / "INDEX.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            self.assertEqual(
                [row.get("shared_source_goal_index") for row in index],
                [1, 1],
            )


if __name__ == "__main__":
    unittest.main()
