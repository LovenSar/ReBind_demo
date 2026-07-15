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


def _parse_practical_args(argv: List[str]) -> tuple[argparse.Namespace, List[str]]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--practical-node-budget", type=int, default=24)
    parser.add_argument("--practical-evidence-threshold", type=float, default=0.25)
    parser.add_argument("--practical-min-signals", type=int, default=1)
    parser.add_argument("--practical-min-profile-confidence", type=int, default=70)
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

    # The legacy parser still owns all standard Phase7 options. The practical
    # neighborhood interprets lambda as a node budget, so append the selected
    # budget as the final CLI override.
    sys.argv = [sys.argv[0], *remaining, "--lambda-radius", str(settings.node_budget)]

    print(
        "[Phase7 Practical] call-only neighborhood enabled: "
        f"node_budget={settings.node_budget} "
        f"evidence_threshold={settings.evidence_threshold:.2f} "
        f"min_signals={settings.min_evidence_signals}",
        flush=True,
    )
    return int(engine.main())


if __name__ == "__main__":
    raise SystemExit(main())
