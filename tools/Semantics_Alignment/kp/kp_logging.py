"""kp_logging.py

Logging helpers extracted from knowledge_propagation.py.

Provides a consistent log format across semantic_align and phases.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional


ACTIVE_INPUT_DB: str = ""


def _derive_db_log_path(input_db: Path) -> Path:
    resolved = input_db
    try:
        resolved = input_db.expanduser().resolve()
    except Exception:
        resolved = input_db
    return resolved.with_suffix(resolved.suffix + ".knowledge.log")


def setup_logging(log_path: Optional[Path] = None, *, input_db: Optional[Path] = None) -> None:
    """Initialize logging handlers once.

    - File handler: DEBUG+ to log_path (default: tools/Semantics_Alignment/log.log)
    - If input_db provided: also write DEBUG+ to <db>.knowledge.log (legacy behavior)
    - Console handler: INFO+ to stderr
    """

    root = logging.getLogger()
    if root.handlers:
        return

    global ACTIVE_INPUT_DB
    if input_db is not None:
        try:
            ACTIVE_INPUT_DB = str(Path(input_db).resolve())
        except Exception:
            ACTIVE_INPUT_DB = str(input_db)

    class _DBPathFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            record.db_path = ACTIVE_INPUT_DB or "N/A"
            return True

    if log_path is None:
        log_path = Path(__file__).resolve().parents[1] / "log.log"

    log_paths = [log_path]
    if input_db is not None:
        try:
            db_log_path = _derive_db_log_path(Path(input_db))
            if db_log_path != log_path:
                log_paths.append(db_log_path)
        except Exception:
            pass

    for p in log_paths:
        p.parent.mkdir(parents=True, exist_ok=True)

    root.setLevel(logging.DEBUG)

    file_handlers: list[logging.Handler] = []
    for p in log_paths:
        fh = logging.FileHandler(str(p), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s %(pathname)s:%(lineno)d - [db=%(db_path)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        file_handlers.append(fh)

    ch = logging.StreamHandler(stream=sys.stderr)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("%(name)s %(pathname)s:%(lineno)d [db=%(db_path)s] %(message)s"))

    db_filter = _DBPathFilter()
    for fh in file_handlers:
        fh.addFilter(db_filter)
    ch.addFilter(db_filter)

    for fh in file_handlers:
        root.addHandler(fh)
    root.addHandler(ch)


def install_stdout_tee(target_logger: logging.Logger) -> None:
    """Mirror stdout to logger (DEBUG), useful for CLI trace."""

    class _StdoutTee:
        def __init__(self, original, logger_obj: logging.Logger) -> None:
            self._original = original
            self._logger = logger_obj
            self._buffer = ""

        def write(self, s: str) -> int:
            self._original.write(s)
            if not s:
                return 0
            self._buffer += s
            while "\n" in self._buffer:
                line, self._buffer = self._buffer.split("\n", 1)
                if line.strip():
                    self._logger.debug(line)
            return len(s)

        def flush(self) -> None:
            self._original.flush()

    if isinstance(sys.stdout, _StdoutTee):
        return

    sys.stdout = _StdoutTee(sys.stdout, target_logger)  # type: ignore[assignment]
