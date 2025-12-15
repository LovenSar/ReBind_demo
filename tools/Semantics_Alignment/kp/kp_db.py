"""kp_db.py

数据库访问层：集中管理 analysis_status / pseudo_functions / symbols 等表的常用读写。

目标：让 pipeline/phase 代码不再散落 cursor/commit 样板代码。
"""

from __future__ import annotations

import sqlite3
from typing import Any, Dict, Iterable, List, Optional, Tuple


class DBRepository:
    """封装常用的 SQLite 读写，减少散落的 cursor/commit 样板代码。"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def update_symbol_name(self, address_va: int, name: str) -> None:
        self.conn.execute(
            "UPDATE symbols SET name = ? WHERE address_va = ?;",
            (name, int(address_va)),
        )
        self.conn.commit()

    def update_pseudocode(
        self,
        function_id: int,
        body: Optional[str] = None,
        prototype: Optional[str] = None,
        name: Optional[str] = None,
    ) -> None:
        updates: List[str] = []
        params: List[Any] = []
        if body is not None:
            updates.append("body = ?")
            params.append(body)
        if prototype is not None:
            updates.append("prototype = ?")
            params.append(prototype)
        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if not updates:
            return
        params.append(int(function_id))
        sql = f"UPDATE pseudo_functions SET {', '.join(updates)} WHERE function_id = ?;"
        self.conn.execute(sql, tuple(params))
        self.conn.commit()

    def update_functions_name(self, function_ids: Iterable[int], name: str) -> None:
        ids = [int(x) for x in function_ids]
        if not ids:
            return
        cur = self.conn.cursor()
        for fid in ids:
            cur.execute("UPDATE functions SET name = ? WHERE id = ?;", (name, fid))
        self.conn.commit()

    # ===== analysis_status =====
    def get_summary_signature(self, function_id: int) -> str:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT summary_signature FROM analysis_status WHERE function_id = ?;",
            (int(function_id),),
        )
        row = cur.fetchone()
        return (row[0] or "") if row else ""

    def get_signature_and_summary(self, function_id: int) -> Tuple[str, str]:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT summary_signature, semantic_summary FROM analysis_status WHERE function_id = ?;",
            (int(function_id),),
        )
        row = cur.fetchone()
        if not row:
            return "", ""
        return (row[0] or ""), (row[1] or "")

    def update_analysis_status(self, function_id: int, **fields: Any) -> None:
        if not fields:
            return
        assignments: List[str] = []
        params: List[Any] = []
        for k, v in fields.items():
            assignments.append(f"{k} = ?")
            params.append(v)
        params.append(int(function_id))
        sql = f"UPDATE analysis_status SET {', '.join(assignments)} WHERE function_id = ?;"
        self.conn.execute(sql, tuple(params))
        self.conn.commit()

    def update_analysis_status_bulk(self, function_ids: Iterable[int], **fields: Any) -> None:
        ids = [int(x) for x in function_ids]
        if not ids or not fields:
            return
        assignments: List[str] = []
        params: List[Any] = []
        for k, v in fields.items():
            assignments.append(f"{k} = ?")
            params.append(v)
        placeholders = ",".join("?" for _ in ids)
        sql = f"UPDATE analysis_status SET {', '.join(assignments)} WHERE function_id IN ({placeholders});"
        self.conn.execute(sql, tuple(params + ids))
        self.conn.commit()

    def set_analysis_state_bulk(self, function_ids: Iterable[int], state: str) -> None:
        self.update_analysis_status_bulk(function_ids, analysis_state=str(state))

    def set_lvar_optimized(self, function_id: int, optimized: bool) -> None:
        self.update_analysis_status(int(function_id), lvar_optimized=1 if optimized else 0)

    def set_confidence_scores_bulk(self, rows: Iterable[Tuple[int, int]]) -> None:
        pairs = [(int(score), int(fid)) for score, fid in rows]
        if not pairs:
            return
        self.conn.executemany(
            "UPDATE analysis_status SET confidence_score = ? WHERE function_id = ?;",
            pairs,
        )
        self.conn.commit()

    # ===== pseudo_functions =====
    def get_pseudocode_body(self, function_id: int) -> str:
        cur = self.conn.cursor()
        cur.execute(
            "SELECT COALESCE(body, '') FROM pseudo_functions WHERE function_id = ? LIMIT 1;",
            (int(function_id),),
        )
        row = cur.fetchone()
        return (row[0] or "") if row else ""

    def delete_pseudocode(self, function_id: int) -> None:
        self.conn.execute(
            "DELETE FROM pseudo_functions WHERE function_id = ?;",
            (int(function_id),),
        )
        self.conn.commit()

    def set_pseudocode_body(self, function_id: int, body: str) -> None:
        self.conn.execute(
            "UPDATE pseudo_functions SET body = ? WHERE function_id = ?;",
            (body, int(function_id)),
        )
        self.conn.commit()

    def set_pseudocode_body_bulk(self, bodies: Dict[int, str]) -> None:
        if not bodies:
            return
        rows = [(body, int(fid)) for fid, body in bodies.items()]
        self.conn.executemany(
            "UPDATE pseudo_functions SET body = ? WHERE function_id = ?;",
            rows,
        )
        self.conn.commit()

    def set_pseudocode_name_and_body(self, function_id: int, name: str, body: str) -> None:
        self.conn.execute(
            "UPDATE pseudo_functions SET name = ?, body = ? WHERE function_id = ?;",
            (name, body, int(function_id)),
        )
        self.conn.commit()

    def set_pseudocode_name_and_body_bulk(self, rows: Iterable[Tuple[int, str, str]]) -> None:
        payload = [(name, body, int(fid)) for fid, name, body in rows]
        if not payload:
            return
        self.conn.executemany(
            "UPDATE pseudo_functions SET name = ?, body = ? WHERE function_id = ?;",
            payload,
        )
        self.conn.commit()

    def update_pseudocode_and_analysis_status_bulk(
        self,
        function_ids: Iterable[int],
        *,
        pseudocode_bodies: Optional[Dict[int, str]] = None,
        **analysis_fields: Any,
    ) -> None:
        ids = [int(x) for x in function_ids]
        if not ids:
            return

        cur = self.conn.cursor()
        if pseudocode_bodies:
            rows = [(body, int(fid)) for fid, body in pseudocode_bodies.items()]
            cur.executemany(
                "UPDATE pseudo_functions SET body = ? WHERE function_id = ?;",
                rows,
            )

        if analysis_fields:
            assignments: List[str] = []
            params: List[Any] = []
            for k, v in analysis_fields.items():
                assignments.append(f"{k} = ?")
                params.append(v)
            placeholders = ",".join("?" for _ in ids)
            sql = (
                f"UPDATE analysis_status SET {', '.join(assignments)} "
                f"WHERE function_id IN ({placeholders});"
            )
            cur.execute(sql, tuple(params + ids))

        self.conn.commit()
