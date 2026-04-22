"""uhsg_schema.py

SQLite schema extension for the Unified Heterogeneous Semantic Graph.

All new tables use ``IF NOT EXISTS`` so they can be applied on top of the
existing alignment DB created by ``alignment_loader.init_db`` without
breaking anything.  Call ``init_uhsg_tables(conn)`` once after ``init_db``.
"""

from __future__ import annotations

import sqlite3
from typing import Optional


# ────────────────────────────────────────────────────────────────────
# DDL statements
# ────────────────────────────────────────────────────────────────────

_UHSG_TABLES = """
-- ═══════════════════════════════════════════════════════════════
-- UHSG Extension Tables (backward-compatible with alignment DB)
-- ═══════════════════════════════════════════════════════════════

-- Variables recovered from pseudocode / LLM / constraint propagation
CREATE TABLE IF NOT EXISTS uhsg_variables (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    function_id     INTEGER NOT NULL,
    entry_va        INTEGER NOT NULL,       -- owning function entry VA
    name            TEXT,                    -- original name (var_10, a1, …)
    inferred_name   TEXT,                    -- LLM-inferred meaningful name
    offset_or_reg   TEXT,                    -- stack offset or register
    inferred_type   TEXT,                    -- LLM-predicted type string
    constraint_type TEXT,                    -- Datalog-propagated type
    final_type      TEXT,                    -- consensus final type
    confidence      REAL    DEFAULT 0.0,
    source          TEXT    DEFAULT 'unknown',  -- ghidra|ida|llm|constraint|api_kg
    round_number    INTEGER DEFAULT 0,
    FOREIGN KEY (function_id) REFERENCES functions(id)
);
CREATE INDEX IF NOT EXISTS idx_uhsg_var_func   ON uhsg_variables(function_id);
CREATE INDEX IF NOT EXISTS idx_uhsg_var_entry  ON uhsg_variables(entry_va);

-- Type nodes (primitive, pointer, struct, enum, typedef, array, …)
CREATE TABLE IF NOT EXISTS uhsg_type_nodes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    kind            TEXT    NOT NULL,        -- primitive|pointer|struct|enum|typedef|array|function_ptr|unknown
    size_bytes      INTEGER,
    layout_json     TEXT,                    -- struct field layout as JSON
    source          TEXT    DEFAULT 'unknown',
    confidence      REAL    DEFAULT 0.0
);

-- API knowledge bridged from Windows_API_PDF_OCR_Graph
CREATE TABLE IF NOT EXISTS uhsg_api_knowledge (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    api_name        TEXT    NOT NULL,
    param_index     INTEGER,
    param_name      TEXT,
    param_type      TEXT,
    return_type     TEXT,
    description     TEXT,
    related_structs TEXT,                    -- JSON array of struct names
    kg_entity_id    TEXT                     -- original entity id from KG JSON
);
CREATE INDEX IF NOT EXISTS idx_uhsg_api_name ON uhsg_api_knowledge(api_name);

-- UHSG edges (heterogeneous typed edges between any pair of nodes)
CREATE TABLE IF NOT EXISTS uhsg_edges (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id       TEXT    NOT NULL,        -- UHSG node_id of source
    target_id       TEXT    NOT NULL,        -- UHSG node_id of target
    edge_type       TEXT    NOT NULL,        -- calls|data_flow|type_of|field_of|api_usage|string_ref|global_ref|alias|constraint
    weight          REAL    DEFAULT 1.0,
    confidence      REAL    DEFAULT 1.0,
    metadata_json   TEXT                     -- optional JSON blob
);
CREATE INDEX IF NOT EXISTS idx_uhsg_edge_src  ON uhsg_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_uhsg_edge_dst  ON uhsg_edges(target_id);
CREATE INDEX IF NOT EXISTS idx_uhsg_edge_type ON uhsg_edges(edge_type);

-- Constraint propagation log
CREATE TABLE IF NOT EXISTS uhsg_constraint_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name       TEXT    NOT NULL,        -- TYPE_PROPAGATION|API_TYPE_INJECTION|…
    source_func_va  INTEGER,
    target_func_va  INTEGER,
    variable_name   TEXT,
    old_value       TEXT,
    new_value       TEXT,
    confidence_delta REAL,
    round_number    INTEGER,
    timestamp       TEXT    DEFAULT (datetime('now'))
);

-- Cross-view consensus records (one per aligned function pair)
CREATE TABLE IF NOT EXISTS uhsg_cross_view_consensus (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_va                INTEGER NOT NULL UNIQUE,
    ghidra_name             TEXT,
    ida_name                TEXT,
    llm_name                TEXT,
    consensus_name          TEXT,
    agreement_score         REAL    DEFAULT 0.0,  -- 0.0–1.0
    name_source             TEXT,                  -- ghidra|ida|llm|consensus
    type_agreement          REAL    DEFAULT 0.0,
    variable_count_ghidra   INTEGER DEFAULT 0,
    variable_count_ida      INTEGER DEFAULT 0,
    pseudo_similarity       REAL    DEFAULT 0.0,   -- cosine / jaccard of pseudocode tokens
    callee_overlap          REAL    DEFAULT 0.0,
    string_ref_overlap      REAL    DEFAULT 0.0
);
CREATE INDEX IF NOT EXISTS idx_uhsg_cv_entry ON uhsg_cross_view_consensus(entry_va);

-- Prediction provenance (multi-source tracking per symbol)
CREATE TABLE IF NOT EXISTS uhsg_predictions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id         TEXT    NOT NULL,        -- UHSG node_id
    source          TEXT    NOT NULL,        -- ghidra|ida|llm|constraint|api_kg|consensus
    field_name      TEXT    NOT NULL,        -- 'name'|'type'|'comment'
    value           TEXT,
    confidence      REAL    DEFAULT 0.0,
    round_number    INTEGER DEFAULT 0,
    reasoning       TEXT,
    timestamp       TEXT    DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_uhsg_pred_node ON uhsg_predictions(node_id);
"""


# ────────────────────────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────────────────────────

def init_uhsg_tables(conn: sqlite3.Connection, *, verbose: bool = True) -> None:
    """Create all UHSG extension tables (idempotent).

    Safe to call after ``alignment_loader.init_db``.
    """
    lines = _UHSG_TABLES.strip().splitlines()
    buf: list[str] = []
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        buf.append(raw_line)
        if stripped.endswith(";"):
            stmt = "\n".join(buf)
            buf.clear()
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError as exc:
                if "already exists" in str(exc).lower():
                    continue
                if "locked" in str(exc).lower():
                    if verbose:
                        print("[UHSG] DB locked — skipping table creation (non-fatal).")
                    return
                raise

    conn.commit()
    if verbose:
        print("[UHSG] Extension tables created / verified.", flush=True)


def drop_uhsg_tables(conn: sqlite3.Connection, *, verbose: bool = True) -> None:
    """Drop all UHSG extension tables (for clean rebuild)."""
    tables = [
        "uhsg_predictions",
        "uhsg_cross_view_consensus",
        "uhsg_constraint_log",
        "uhsg_edges",
        "uhsg_api_knowledge",
        "uhsg_type_nodes",
        "uhsg_variables",
    ]
    for tbl in tables:
        conn.execute(f"DROP TABLE IF EXISTS {tbl};")
    conn.commit()
    if verbose:
        print("[UHSG] Extension tables dropped.", flush=True)


def uhsg_table_stats(conn: sqlite3.Connection) -> dict:
    """Return row counts for all UHSG tables."""
    tables = [
        "uhsg_variables",
        "uhsg_type_nodes",
        "uhsg_api_knowledge",
        "uhsg_edges",
        "uhsg_constraint_log",
        "uhsg_cross_view_consensus",
        "uhsg_predictions",
    ]
    stats: dict = {}
    for tbl in tables:
        try:
            row = conn.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()
            stats[tbl] = row[0] if row else 0
        except sqlite3.OperationalError:
            stats[tbl] = -1  # table doesn't exist yet
    return stats
