"""kp_schema.py

SQLite schema helpers for analysis_status.

Kept separate from the main entrypoint to avoid circular imports when phases are
moved to standalone modules.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Dict, Iterable, List


def ensure_analysis_schema(conn: sqlite3.Connection) -> None:
    """Ensure analysis_status table and expected columns exist."""

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analysis_status (
            function_id       INTEGER PRIMARY KEY,
            analysis_state    TEXT,
            confidence_score  INTEGER,
            summary_signature TEXT,
            semantic_summary  TEXT,
            FOREIGN KEY(function_id) REFERENCES functions(id)
        );
        """
    )

    # Phase1/Phase2: pipeline queue markers (resumable / inspectable)
    try:
        conn.execute("ALTER TABLE analysis_status ADD COLUMN phase1_pending INTEGER DEFAULT 0;")
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute("ALTER TABLE analysis_status ADD COLUMN phase2_pending INTEGER DEFAULT 0;")
    except sqlite3.OperationalError:
        pass

    # Phase4: resumable flag
    try:
        conn.execute("ALTER TABLE analysis_status ADD COLUMN lvar_optimized INTEGER DEFAULT 0;")
    except sqlite3.OperationalError:
        pass

    # Phase5: resumable flag
    try:
        conn.execute("ALTER TABLE analysis_status ADD COLUMN annotation_status INTEGER DEFAULT 0;")
    except sqlite3.OperationalError:
        pass

    # Phase5: structured analysis json
    try:
        conn.execute("ALTER TABLE analysis_status ADD COLUMN structured_analysis TEXT;")
    except sqlite3.OperationalError:
        pass

    # Helpful indices for large-scale scheduling / filtering
    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analysis_status_state ON analysis_status(analysis_state);")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_analysis_status_confidence ON analysis_status(confidence_score);"
        )
    except sqlite3.OperationalError:
        pass

    try:
        conn.execute("CREATE INDEX IF NOT EXISTS idx_analysis_status_phase2 ON analysis_status(phase2_pending);")
    except sqlite3.OperationalError:
        # phase2_pending may not exist in old DBs
        pass

    conn.commit()


def ensure_analysis_rows_for_view(conn: sqlite3.Connection, view_id: int) -> None:
    """Ensure every functions.id under the view has a row in analysis_status."""
    conn.execute(
        """
        INSERT OR IGNORE INTO analysis_status (function_id, analysis_state, confidence_score)
        SELECT id, 'PENDING', 0
        FROM functions
        WHERE view_id = ?;
        """,
        (int(view_id),),
    )
    conn.commit()


def ensure_analysis_rows_for_binary(conn: sqlite3.Connection, binary_id: int) -> None:
    """Ensure every functions.id under the binary has a row in analysis_status."""
    conn.execute(
        """
        INSERT OR IGNORE INTO analysis_status (function_id, analysis_state, confidence_score)
        SELECT f.id, 'PENDING', 0
        FROM functions AS f
        JOIN binary_views AS bv ON f.view_id = bv.id
        WHERE bv.binary_id = ?;
        """,
        (int(binary_id),),
    )
    conn.commit()


def load_analysis_info(conn: sqlite3.Connection) -> Dict[int, dict]:
    """Load all analysis_status rows into a dict keyed by function_id."""

    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT function_id, analysis_state, confidence_score,
                   summary_signature, semantic_summary,
                   COALESCE(phase1_pending, 0) AS phase1_pending,
                   COALESCE(phase2_pending, 0) AS phase2_pending,
                   COALESCE(annotation_status, 0) AS annotation_status,
                   structured_analysis
            FROM analysis_status;
            """
        )
        with_annotation_cols = True
    except sqlite3.OperationalError:
        cur.execute(
            """
            SELECT function_id, analysis_state, confidence_score,
                   summary_signature, semantic_summary,
                   COALESCE(phase1_pending, 0) AS phase1_pending,
                   COALESCE(phase2_pending, 0) AS phase2_pending
            FROM analysis_status;
            """
        )
        with_annotation_cols = False

    info: Dict[int, Dict[str, Any]] = {}
    for row in cur.fetchall():
        if with_annotation_cols:
            fid, state, score, sig, summary, p1_pending, p2_pending, ann_status, structured = row
        else:
            fid, state, score, sig, summary, p1_pending, p2_pending = row
            ann_status, structured = 0, None

        info[int(fid)] = {
            "analysis_state": state or "PENDING",
            "confidence_score": int(score or 0),
            "summary_signature": sig,
            "semantic_summary": summary,
            "phase1_pending": int(p1_pending or 0),
            "phase2_pending": int(p2_pending or 0),
            "annotation_status": int(ann_status or 0),
            "structured_analysis": structured,
        }

    return info


def _iter_chunks(items: List[int], *, chunk_size: int) -> Iterable[List[int]]:
    if chunk_size <= 0:
        yield items
        return
    for i in range(0, len(items), chunk_size):
        yield items[i : i + chunk_size]


def load_analysis_info_for_fids(conn: sqlite3.Connection, function_ids: Iterable[int]) -> Dict[int, dict]:
    """Load analysis_status rows for a subset of function_ids (large DB fast-path)."""

    ids = sorted({int(x) for x in function_ids if x is not None})
    if not ids:
        return {}

    cur = conn.cursor()

    info: Dict[int, Dict[str, Any]] = {}
    for chunk in _iter_chunks(ids, chunk_size=900):
        placeholders = ",".join("?" for _ in chunk)
        try:
            cur.execute(
                f"""
                SELECT function_id, analysis_state, confidence_score,
                       summary_signature, semantic_summary,
                       COALESCE(phase1_pending, 0) AS phase1_pending,
                       COALESCE(phase2_pending, 0) AS phase2_pending,
                       COALESCE(annotation_status, 0) AS annotation_status,
                       structured_analysis
                FROM analysis_status
                WHERE function_id IN ({placeholders});
                """,
                chunk,
            )
            with_annotation_cols = True
        except sqlite3.OperationalError:
            cur.execute(
                f"""
                SELECT function_id, analysis_state, confidence_score,
                       summary_signature, semantic_summary,
                       COALESCE(phase1_pending, 0) AS phase1_pending,
                       COALESCE(phase2_pending, 0) AS phase2_pending
                FROM analysis_status
                WHERE function_id IN ({placeholders});
                """,
                chunk,
            )
            with_annotation_cols = False

        for row in cur.fetchall():
            if with_annotation_cols:
                fid, state, score, sig, summary, p1_pending, p2_pending, ann_status, structured = row
            else:
                fid, state, score, sig, summary, p1_pending, p2_pending = row
                ann_status, structured = 0, None

            info[int(fid)] = {
                "analysis_state": state or "PENDING",
                "confidence_score": int(score or 0),
                "summary_signature": sig,
                "semantic_summary": summary,
                "phase1_pending": int(p1_pending or 0),
                "phase2_pending": int(p2_pending or 0),
                "annotation_status": int(ann_status or 0),
                "structured_analysis": structured,
            }

    return info
