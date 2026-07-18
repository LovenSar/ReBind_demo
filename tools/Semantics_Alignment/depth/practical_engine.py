#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase7 practical-accuracy entrypoint.

The legacy engine remains unchanged. This entrypoint installs conservative
runtime patches before delegating to ``depth.engine.main``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

_DEPTH_DIR = Path(__file__).resolve().parent
_SA_ROOT = _DEPTH_DIR.parent
if str(_SA_ROOT) not in sys.path:
    sys.path.insert(0, str(_SA_ROOT))

from depth import engine
from depth.practical_accuracy import PracticalSettings, install_practical_patches
from depth.practical_evidence import install_evidence_extensions


def _parse_practical_args(argv: List[str]) -> tuple[argparse.Namespace, List[str]]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--practical-node-budget", type=int, default=24)
    parser.add_argument("--practical-evidence-threshold", type=float, default=0.25)
    parser.add_argument("--practical-min-signals", type=int, default=1)
    parser.add_argument("--practical-min-profile-confidence", type=int, default=70)
    parser.add_argument("--practical-profile-max-tokens", type=int, default=1600)
    parser.add_argument("--practical-profile-max-disasm-lines", type=int, default=80)
    parser.add_argument("--practical-profile-max-pseudo-chars", type=int, default=1400)
    parser.add_argument("--practical-profile-max-strings", type=int, default=8)
    parser.add_argument("--practical-max-compare-nodes", type=int, default=2)
    parser.add_argument(
        "--practical-fast",
        action="store_true",
        help="低延迟目标确认：只比较目标函数，并将路径 LLM 限制为前两步。",
    )
    practical, remaining = parser.parse_known_args(argv)
    return practical, remaining


def main() -> int:
    practical, remaining = _parse_practical_args(sys.argv[1:])
    settings = PracticalSettings(
        node_budget=max(1, int(practical.practical_node_budget)),
        evidence_threshold=max(0.0, min(1.0, float(practical.practical_evidence_threshold))),
        min_evidence_signals=max(0, int(practical.practical_min_signals)),
        min_profile_confidence=max(0, min(100, int(practical.practical_min_profile_confidence))),
    )
    install_practical_patches(engine, settings)
    install_evidence_extensions()

    # The legacy parser still owns all standard Phase7 options. The practical
    # neighborhood interprets lambda as a node budget, so append the selected
    # budget as the final CLI override.
    fast_compare_nodes = 1 if practical.practical_fast else int(practical.practical_max_compare_nodes)
    fast_llm_max_steps = 2 if practical.practical_fast else None

    sys.argv = [
        sys.argv[0],
        *remaining,
        "--lambda-radius",
        str(settings.node_budget),
        "--profile-max-tokens",
        str(max(1, int(practical.practical_profile_max_tokens))),
        "--profile-max-disasm-lines",
        str(max(0, int(practical.practical_profile_max_disasm_lines))),
        "--profile-max-pseudo-chars",
        str(max(0, int(practical.practical_profile_max_pseudo_chars))),
        "--profile-max-strings",
        str(max(0, int(practical.practical_profile_max_strings))),
        "--max-compare-nodes",
        str(max(1, fast_compare_nodes)),
    ]
    if fast_llm_max_steps is not None:
        sys.argv.extend(["--llm-max-steps", str(fast_llm_max_steps)])

    print(
        "[Phase7 Practical] call-only neighborhood enabled: "
        f"node_budget={settings.node_budget} "
        f"evidence_threshold={settings.evidence_threshold:.2f} "
        f"min_signals={settings.min_evidence_signals} "
        f"fast={bool(practical.practical_fast)}",
        flush=True,
    )
    return int(engine.main())


if __name__ == "__main__":
    raise SystemExit(main())
