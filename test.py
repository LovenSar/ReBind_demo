"""
简单的 SQLite 浏览脚本：
1）打印所有表名
2）打印建表语句（schema）
3）打印每个表的行数
4）将每个表的「全量数据」导出到文本文件，方便在编辑器里查看
"""

import sqlite3
import textwrap
from pathlib import Path

# 这里可以切换查看的数据库文件
DB_PATH = Path("tmp/demo.db")
SAMPLE_OUTPUT = Path("tmp/db_sample_dump.txt")

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

print("=== 所有表 ===")
tables = [
    name
    for (name,) in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
    )
]
for name in tables:
    print("-", name)

print("\n=== 每个表的建表语句 ===")
for name in tables:
    (sql,) = cur.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name = ?;",
        (name,),
    ).fetchone()
    print(f"\n-- {name} --")
    print(textwrap.indent(sql or "", "  "))

print("\n=== 每个表的行数 ===")
for name in tables:
    # 跳过 SQLite 内部维护表
    if name.startswith("sqlite_"):
        continue
    (cnt,) = cur.execute(f"SELECT COUNT(*) FROM {name};").fetchone()
    print(f"{name:20s} {cnt}")

# 将每个表的「全量数据」导出到文本文件，方便用编辑器浏览
SAMPLE_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
with SAMPLE_OUTPUT.open("w", encoding="utf-8") as out:
    out.write(f"DB: {DB_PATH}\n")
    out.write("=== 每个表的全量数据（注意：可能较大） ===\n")
    for name in tables:
        if name.startswith("sqlite_"):
            continue
        out.write(f"\n-- {name} (ALL ROWS) --\n")
        # 执行查询时不加 LIMIT，流式遍历整个结果集
        cur.execute(f"SELECT * FROM {name};")
        colnames = [d[0] for d in cur.description] if cur.description else []
        if colnames:
            out.write("\t".join(colnames) + "\n")
        for row in cur:
            out.write(
                "\t".join("" if v is None else str(v) for v in row) + "\n"
            )

conn.close()
print(f"\n全量数据已导出到: {SAMPLE_OUTPUT}")
