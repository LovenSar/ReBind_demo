#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
alignment_loader.py

阶段 1 的对齐数据加载模块：
从 Ghidra / IDA 的现有 CSV / ASM / C 输出中，构建一个统一的 SQLite 数据库，
为后续的物理层 / 结构层 / 函数级语义层对齐提供基础数据。

设计目标（阶段 1）：
- 只依赖当前已经生成的文件，不修改 Ghidra / IDA 的脚本：
  - *_binaryinfo/*.csv  （segments / sections / symbols / strings / xrefs）
  - *_disassembly/*.asm （每个函数一个反汇编）
  - *_pseudocode/*.c 或 *_pesudocode/*.c （每个函数一个伪代码）
- 不做 basic block 和语句级拆分，仅精确到：
  - 段 / 节 / 符号 / 字符串 / 引用关系（xrefs）
  - 函数 + 指令序列
  - 函数级伪代码文本

后续阶段可以在此基础上扩展：
- 新增语句 / token / 变量层的表结构
- 在 Ghidra / IDA 的导出脚本中加入 “语句/变量 ↔ 指令 EA” 的映射，再填充扩展表
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import re
import sqlite3
import textwrap
import builtins
import inspect
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional, Tuple, List, Set, Dict

try:
    from openpyxl import Workbook
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
except Exception:  # pragma: no cover - optional dependency
    Workbook = None  # type: ignore[assignment]
    ILLEGAL_CHARACTERS_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F]")


def _install_print_with_location() -> None:
    """Prefix every print with absolute file path and line number."""
    if getattr(builtins, "_original_print", None):
        return

    builtins._original_print = builtins.print  # type: ignore[attr-defined]

    def _print_with_location(*args, **kwargs):
        frame = inspect.currentframe()
        if frame and frame.f_back:
            caller = frame.f_back
            path = Path(caller.f_code.co_filename).resolve()
            lineno = caller.f_lineno
            prefix = f"{path}:{lineno} "
        else:
            prefix = ""
        message = " ".join(str(a) for a in args)
        builtins._original_print(f"{prefix}{message}", **kwargs)

    builtins.print = _print_with_location  # type: ignore[assignment]


_install_print_with_location()


@dataclass
class ToolInfo:
    """表示一个分析工具（Ghidra / IDA）的基本信息。"""

    name: str          # "ghidra" / "ida"
    version: str = ""  # 可选：工具版本号，留空表示未知


def init_db(conn: sqlite3.Connection) -> None:
    """
    初始化 SQLite 数据库的表结构。

    如果表已存在则跳过（使用 IF NOT EXISTS），方便重复执行。
    """
    # 开启外键约束（SQLite 默认关闭）
    conn.execute("PRAGMA foreign_keys = ON;")
    # 本地离线流水线默认启用更高吞吐的 SQLite 参数。
    try:
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA temp_store = MEMORY;")
        # Negative means KiB; 128 MiB page cache for large imports.
        conn.execute("PRAGMA cache_size = -131072;")
    except Exception:
        pass

    # 工具表：记录 Ghidra / IDA 等工具
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tools (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,  -- 工具名: ghidra / ida
            version     TEXT,                 -- 版本号，可为空
            extra       TEXT                  -- 预留字段，存 JSON 配置等
        );
        """
    )

    # 二进制文件表：记录逻辑上的“同一个二进制”
    # 注意：这里不强求真实路径唯一，仅用 filename 作为简化的逻辑键。
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS binaries (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            filename    TEXT NOT NULL,   -- 逻辑名称，例如 Malware_sample_exe
            path        TEXT,            -- 实际路径（如果能推断）
            hash_md5    TEXT,            -- 可选：二进制 MD5
            hash_sha256 TEXT,            -- 可选：二进制 SHA256
            arch        TEXT,            -- 架构信息，例如 x86_64
            bits        INTEGER          -- 位宽，例如 32 / 64
        );
        """
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_binaries_filename "
        "ON binaries(filename);"
    )

    # binary_views：某个工具对某个二进制的一次分析视图
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS binary_views (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            binary_id   INTEGER NOT NULL,
            tool_id     INTEGER NOT NULL,
            output_dir  TEXT NOT NULL,   -- 对应 *_ghidemo / *_idademo 目录
            image_base  INTEGER,         -- 该视图认为的 ImageBase
            created_at  TEXT,            -- 分析时间，当前版本不强制填写
            config_path TEXT,            -- 可选：分析时的配置文件路径
            FOREIGN KEY(binary_id) REFERENCES binaries(id),
            FOREIGN KEY(tool_id) REFERENCES tools(id)
        );
        """
    )

    # 段信息（segments）
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS segments (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            view_id     INTEGER NOT NULL,
            name        TEXT NOT NULL,
            start_va    INTEGER NOT NULL,
            end_va      INTEGER NOT NULL,
            length      INTEGER,
            perm_r      INTEGER,         -- 0/1 代表 False/True
            perm_w      INTEGER,
            perm_x      INTEGER,
            raw_perm    TEXT,            -- Ghidra: R/W/X 字段组合；IDA: Perm 原始值
            FOREIGN KEY(view_id) REFERENCES binary_views(id)
        );
        """
    )

    # 节信息（sections）
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sections (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            view_id     INTEGER NOT NULL,
            name        TEXT NOT NULL,
            start_va    INTEGER NOT NULL,
            end_va      INTEGER NOT NULL,
            length      INTEGER,
            FOREIGN KEY(view_id) REFERENCES binary_views(id)
        );
        """
    )

    # 符号（symbols）
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS symbols (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            view_id     INTEGER NOT NULL,
            name        TEXT NOT NULL,
            address_va  INTEGER,         -- 可解析的真实 VA；外部符号则可能为 NULL
            raw_address TEXT,            -- 原始地址字符串，例如 "0xEXTERNAL:00000001"
            kind        TEXT,            -- 归一化类型: function/label/data/import/other
            raw_type    TEXT,            -- 工具原始类型字段，例如 FUNC / Function
            source      TEXT,            -- 来源：auto / IMPORTED / N/A 等
            is_global   INTEGER,
            is_primary  INTEGER,
            is_external INTEGER,
            namespace   TEXT,
            FOREIGN KEY(view_id) REFERENCES binary_views(id)
        );
        """
    )

    # 字符串（仅 IDA 输出有）
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS strings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            view_id     INTEGER NOT NULL,
            value       TEXT NOT NULL,
            address_va  INTEGER NOT NULL,
            length      INTEGER,
            FOREIGN KEY(view_id) REFERENCES binary_views(id)
        );
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_strings_view_addr ON strings(view_id, address_va);"
    )

    # 函数表（统一视图）
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS functions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            view_id         INTEGER NOT NULL,
            entry_va        INTEGER NOT NULL,  -- 函数入口地址
            name            TEXT NOT NULL,     -- 此工具视角下的函数名
            demangled_name  TEXT,             -- 预留：去修饰后的名字
            size_bytes      INTEGER,          -- 可选：函数大小（字节）
            source_symbol_id INTEGER,         -- 关联到 symbols.id
            raw_file        TEXT,             -- 对应的 .asm 或 .c 文件名
            FOREIGN KEY(view_id) REFERENCES binary_views(id),
            FOREIGN KEY(source_symbol_id) REFERENCES symbols(id)
        );
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_functions_view_entry "
        "ON functions(view_id, entry_va);"
    )

    # 指令表
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS instructions (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            view_id             INTEGER NOT NULL,
            function_id         INTEGER NOT NULL,
            index_in_function   INTEGER NOT NULL, -- 函数内顺序号
            address_va          INTEGER NOT NULL,
            bytes               TEXT,             -- 十六进制机器码字符串
            mnemonic            TEXT,
            op_str              TEXT,
            raw_line            TEXT,
            FOREIGN KEY(view_id) REFERENCES binary_views(id),
            FOREIGN KEY(function_id) REFERENCES functions(id)
        );
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_instructions_view_addr "
        "ON instructions(view_id, address_va);"
    )

    # 引用关系（xrefs）
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS xrefs (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            view_id             INTEGER NOT NULL,
            src_va              INTEGER NOT NULL, -- 引用来源地址
            dst_va              INTEGER,          -- 被引用目标地址（从文件名解析）
            dst_name            TEXT,             -- 目标名称（从文件名或符号推断）
            ref_type_raw        TEXT,             -- 引用类型原文（字符串或数字）
            containing_function TEXT,             -- 所在函数名（原文）
            is_primary          INTEGER,          -- Ghidra 的 Primary Ref；IDA 置 NULL/0
            raw_file            TEXT,             -- 该 xrefs CSV 文件名
            FOREIGN KEY(view_id) REFERENCES binary_views(id)
        );
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_xrefs_view_src ON xrefs(view_id, src_va);"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_xrefs_view_dst ON xrefs(view_id, dst_va);"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_xrefs_view_ref ON xrefs(view_id, ref_type_raw);"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_instructions_view_func ON instructions(view_id, function_id);"
    )

    # 伪代码函数（函数级语义视图）
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pseudo_functions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            view_id         INTEGER NOT NULL,
            function_id     INTEGER NOT NULL,
            entry_va        INTEGER NOT NULL,
            name            TEXT NOT NULL,
            prototype       TEXT,        -- 函数声明行
            body            TEXT,        -- 函数体文本（包含大括号）
            raw_file        TEXT,        -- 对应的 .c 文件名
            FOREIGN KEY(view_id) REFERENCES binary_views(id),
            FOREIGN KEY(function_id) REFERENCES functions(id)
        );
        """
    )
    conn.commit()


def check_db_compatibility(db_path: Path) -> Tuple[bool, str]:
    """检查现有 SQLite 数据库是否包含阶段 1 所需的核心表。"""

    required_tables = {
        "tools",
        "binaries",
        "binary_views",
        "segments",
        "sections",
        "symbols",
        "strings",
        "functions",
        "instructions",
        "xrefs",
        "pseudo_functions",
    }

    if not db_path.exists():
        return True, "数据库不存在"

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    except Exception as exc:
        return False, f"无法以只读方式打开: {exc}"

    try:
        cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
        existing = {row[0] for row in cur.fetchall()}
    except Exception as exc:
        conn.close()
        return False, f"读取表结构失败: {exc}"

    conn.close()

    missing = required_tables - existing
    if missing:
        return False, "缺少必要表: " + ", ".join(sorted(missing))

    return True, "表结构兼容"


def prompt_overwrite_existing(db_path: Path, compatible: bool, detail: str) -> bool:
    """与用户交互，确认是否覆盖已有数据库。仅 Yes/Y/y/空输入 视为同意。"""

    status = "兼容" if compatible else "不兼容/可能损坏"
    print(f"检测到已存在数据库: {db_path}")
    print(f"兼容性检查: {status}（{detail}）")

    prompt = (
        "是否覆盖现有数据库? 输入 Y/Yes 继续覆盖；"
        "输入 N/n/No/直接回车 保留并退出（默认保留）: "
    )

    while True:
        choice = input(prompt).strip()
        if choice == "":
            return False
        if choice.lower() in {"y", "yes"}:
            return True
        if choice.lower() in {"n", "no"}:
            return False
        print("请输入 Yes/Y/y/直接回车 覆盖，或 N/n/No 取消。")


# =========================
# 内部工具函数：获取 / 创建工具和二进制记录
# =========================


def _get_or_create_tool(conn: sqlite3.Connection, tool: ToolInfo) -> int:
    """
    查找或创建 tools 表中的记录。
    按 name 唯一，如果存在则更新 version（可选），否则插入。
    """
    cur = conn.execute("SELECT id, version FROM tools WHERE name = ?;", (tool.name,))
    row = cur.fetchone()
    if row:
        tool_id = row[0]
        # 如果用户传入了版本信息且与记录不一致，可以选择更新
        if tool.version and tool.version != (row[1] or ""):
            conn.execute(
                "UPDATE tools SET version = ? WHERE id = ?;",
                (tool.version, tool_id),
            )
            conn.commit()
        return tool_id

    cur = conn.execute(
        "INSERT INTO tools(name, version, extra) VALUES (?, ?, NULL);",
        (tool.name, tool.version),
    )
    conn.commit()
    return int(cur.lastrowid)


def _detect_binary_logical_name(view_dir: Path) -> str:
    """
    根据视图目录名推测逻辑上的二进制名称。

    例如：
    - Malware_sample_exe_ghidemo -> Malware_sample_exe
    - Malware_sample_exe_idademo -> Malware_sample_exe

    这是一个简化的“逻辑键”，用来把 Ghidra / IDA 的两个视图挂在同一个 binaries 记录上。
    """
    name = view_dir.name
    # 去掉后缀
    for suffix in ("_ghidemo", "_idademo"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _try_find_real_binary_path(view_dir: Path) -> Optional[Path]:
    """
    尝试在视图目录及其上级目录中寻找真正的 .exe / .dll 等文件。

    这里采用尽量保守的策略：
    - 优先在视图目录中寻找单一的 .exe；
    - 如找不到，再在父目录中寻找；
    - 多个候选时返回 None（避免“瞎匹配”）。
    """
    candidates: List[Path] = []
    for pattern in ("*.exe", "*.dll"):
        candidates.extend(view_dir.glob(pattern))
    if len(candidates) == 1:
        return candidates[0]

    # 视图目录找不到明确目标，再去父目录尝试
    parent = view_dir.parent
    parent_candidates: List[Path] = []
    for pattern in ("*.exe", "*.dll"):
        parent_candidates.extend(parent.glob(pattern))
    if len(parent_candidates) == 1:
        return parent_candidates[0]

    # 找不到或存在多个候选，返回 None，由调用方决定是否使用逻辑名
    return None


def _compute_file_hashes(path: Path) -> Tuple[Optional[str], Optional[str]]:
    """
    计算文件的 MD5 / SHA256。
    如果文件不存在或读取失败，返回 (None, None)。
    """
    try:
        md5 = hashlib.md5()
        sha = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
                sha.update(chunk)
        return md5.hexdigest(), sha.hexdigest()
    except OSError:
        return None, None


def _get_or_create_binary(conn: sqlite3.Connection, view_dir: Path) -> int:
    """
    查找或创建 binaries 表中的记录。

    逻辑：
    1. 使用视图目录名推导逻辑 filename（例如 Malware_sample_exe）；
    2. 尝试在视图目录或父目录找到真实二进制路径，并计算 hash（如果找到）；
    3. 按 filename 作为唯一键查找记录，没有则插入。

    注意：
    - 这里的 filename 是“逻辑名”，不强制等于真实文件名，只要 Ghidra / IDA 共用即可。
    """
    view_dir = view_dir.resolve()
    logical_name = _detect_binary_logical_name(view_dir)

    cur = conn.execute(
        "SELECT id FROM binaries WHERE filename = ?;",
        (logical_name,),
    )
    row = cur.fetchone()
    if row:
        return int(row[0])

    real_path = _try_find_real_binary_path(view_dir)
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    path_str: Optional[str] = None
    if real_path is not None:
        path_str = str(real_path)
        hash_md5, hash_sha256 = _compute_file_hashes(real_path)

    cur = conn.execute(
        """
        INSERT INTO binaries(filename, path, hash_md5, hash_sha256, arch, bits)
        VALUES (?, ?, ?, ?, NULL, NULL);
        """,
        (logical_name, path_str, hash_md5, hash_sha256),
    )
    conn.commit()
    return int(cur.lastrowid)


def _create_binary_view(
    conn: sqlite3.Connection,
    binary_id: int,
    tool_id: int,
    output_dir: Path,
    image_base: Optional[int],
    config_path: Optional[str] = None,
) -> int:
    """
    在 binary_views 表中插入一条记录。
    当前不强制写入 created_at，可在后续需要时扩展。
    """
    cur = conn.execute(
        """
        INSERT INTO binary_views(binary_id, tool_id, output_dir, image_base, created_at, config_path)
        VALUES (?, ?, ?, ?, NULL, ?);
        """,
        (binary_id, tool_id, str(output_dir.resolve()), image_base, config_path),
    )
    conn.commit()
    return int(cur.lastrowid)


# =========================
# CSV / 文本解析工具函数
# =========================


def _parse_hex_int(value: str) -> Optional[int]:
    """
    把各种十六进制字符串解析为整数。

    支持的形式：
    - "0x00401C0E"
    - "00401C0E"
    - 带其他前后缀时（例如 Ghidra 外部符号的 "0xEXTERNAL:00000001"）返回 None。

    注意：SQLite 的 INTEGER 是 signed int64。
    - 若解析值落在 [0, 2^64-1] 但超过 2^63-1，则按二补码转换为负数后返回。
    - 若超过 64-bit（或无法可靠解释），返回 None。
    """

    SQLITE_INT64_MIN = -(1 << 63)
    SQLITE_INT64_MAX = (1 << 63) - 1
    UINT64_MAX = (1 << 64) - 1

    def _normalize_for_sqlite_int64(n: int) -> Optional[int]:
        if SQLITE_INT64_MIN <= n <= SQLITE_INT64_MAX:
            return n
        # 支持把无符号 64-bit 地址映射到 signed int64（两者比特位一致）
        if 0 <= n <= UINT64_MAX:
            return n - (1 << 64)
        return None

    value = value.strip()
    if not value:
        return None

    # 纯 0x 前缀形式
    if value.startswith("0x") and ":" not in value:
        try:
            parsed = int(value, 16)
        except ValueError:
            return None

        return _normalize_for_sqlite_int64(parsed)

    # 纯十六进制数字，不带 0x
    if re.fullmatch(r"[0-9A-Fa-f]+", value):
        try:
            parsed = int(value, 16)
        except ValueError:
            return None

        return _normalize_for_sqlite_int64(parsed)

    # 其他复杂形式（例如 0xEXTERNAL:00000001）不解析
    return None


def _bool_from_str(value: str) -> Optional[int]:
    """把 CSV 中的 True/False 文本转换为 1/0/None。"""
    v = value.strip().lower()
    if v in ("true", "t", "1", "yes"):
        return 1
    if v in ("false", "f", "0", "no"):
        return 0
    return None


def _read_csv(path: Path) -> Iterable[dict]:
    """
    读取一个 CSV 文件，返回每行的 dict。
    使用 UTF-8 编码，如果失败可以在调用方按需调整。
    """
    with path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # DictReader 返回的是 OrderedDict，这里统一转成普通 dict
            yield dict(row)


def _parse_segments_ghidra(
    conn: sqlite3.Connection,
    view_id: int,
    csv_path: Path,
    address_offset: int = 0,
) -> Optional[int]:
    """
    解析 Ghidra 的 segments.csv。
    同时返回推测的 image_base（通常为 Headers 段的起始地址）。

    特殊约定：
    - 如果 view_id < 0，则仅做“干跑”（dry run）：计算 image_base，但不写入数据库。
    """
    image_base: Optional[int] = None
    dry_run = view_id < 0

    for row in _read_csv(csv_path):
        name = row.get("Name", "")
        start_va = _parse_hex_int(row.get("Start Address", "") or "")
        end_va = _parse_hex_int(row.get("End Address", "") or "")
        length = int(row.get("Length", "0") or 0)
        if start_va is None or end_va is None:
            continue

        if address_offset:
            start_va -= address_offset
            end_va -= address_offset

        # 保险起见：避免 SQLite INTEGER 溢出
        if start_va < -(1 << 63) or start_va > ((1 << 63) - 1):
            continue
        if end_va < -(1 << 63) or end_va > ((1 << 63) - 1):
            continue

        perm_r = _bool_from_str(row.get("Read", "") or "")
        perm_w = _bool_from_str(row.get("Write", "") or "")
        perm_x = _bool_from_str(row.get("Execute", "") or "")
        raw_perm = f"R={row.get('Read')},W={row.get('Write')},X={row.get('Execute')}"

        if not dry_run:
            conn.execute(
                """
                INSERT INTO segments(view_id, name, start_va, end_va, length, perm_r, perm_w, perm_x, raw_perm)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (view_id, name, start_va, end_va, length, perm_r, perm_w, perm_x, raw_perm),
            )

        # Ghidra 中 Headers 段通常从 ImageBase 开始
        if name == "Headers":
            image_base = start_va

    if not dry_run:
        conn.commit()
    return image_base


def _parse_segments_ida(
    conn: sqlite3.Connection,
    view_id: int,
    csv_path: Path,
) -> Optional[int]:
    """
    解析 IDA 的 segments.csv。
    返回推测的 image_base（简单策略：所有 Start Address 的最小值）。

    特殊约定：
    - 如果 view_id < 0，则仅做“干跑”（dry run）：计算 image_base，但不写入数据库。
    """
    image_base: Optional[int] = None
    dry_run = view_id < 0

    for row in _read_csv(csv_path):
        name = row.get("Name", "")
        start_va = _parse_hex_int(row.get("Start Address", "") or "")
        end_va = _parse_hex_int(row.get("End Address", "") or "")
        length = int(row.get("Length", "0") or 0)
        if start_va is None or end_va is None:
            continue

        # IDA 的 Perm 是一个位掩码：0x1 = X, 0x2 = W, 0x4 = R
        perm_val = row.get("Perm", "") or ""
        perm_int = _parse_hex_int(perm_val)
        perm_r = perm_w = perm_x = None
        if perm_int is not None:
            perm_r = 1 if (perm_int & 0x4) else 0
            perm_w = 1 if (perm_int & 0x2) else 0
            perm_x = 1 if (perm_int & 0x1) else 0
        raw_perm = perm_val

        if not dry_run:
            conn.execute(
                """
                INSERT INTO segments(view_id, name, start_va, end_va, length, perm_r, perm_w, perm_x, raw_perm)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (view_id, name, start_va, end_va, length, perm_r, perm_w, perm_x, raw_perm),
            )

        if image_base is None or start_va < image_base:
            image_base = start_va

    if not dry_run:
        conn.commit()
    return image_base


def _parse_sections(
    conn: sqlite3.Connection,
    view_id: int,
    csv_path: Path,
    address_offset: int = 0,
) -> None:
    """解析 Ghidra / IDA 统一格式的 sections.csv。"""
    for row in _read_csv(csv_path):
        name = row.get("Name", "")
        start_va = _parse_hex_int(row.get("Start Address", "") or "")
        end_va = _parse_hex_int(row.get("End Address", "") or "")
        length = int(row.get("Length", "0") or 0)
        if start_va is None or end_va is None:
            continue
        if address_offset:
            start_va -= address_offset
            end_va -= address_offset

        if start_va < -(1 << 63) or start_va > ((1 << 63) - 1):
            continue
        if end_va < -(1 << 63) or end_va > ((1 << 63) - 1):
            continue

        conn.execute(
            """
            INSERT INTO sections(view_id, name, start_va, end_va, length)
            VALUES (?, ?, ?, ?, ?);
            """,
            (view_id, name, start_va, end_va, length),
        )
    conn.commit()


def _normalize_symbol_kind(raw_type: str, is_external: Optional[int]) -> str:
    """
    把工具原始 symbol 类型归一化为较粗粒度的 kind。
    - 对 Ghidra: Function / Label / Data / ...
    - 对 IDA: FUNC / LABEL / ...
    """
    t = (raw_type or "").strip().upper()
    if t in ("FUNCTION", "FUNC"):
        if is_external:
            return "import"
        return "function"
    if t in ("LABEL",):
        return "label"
    if t in ("DATA", "OBJ", "OBJECT"):
        return "data"
    # 其他情况暂时归为 other
    return "other"


def _parse_symbols(
    conn: sqlite3.Connection,
    view_id: int,
    csv_path: Path,
    address_offset: int = 0,
) -> None:
    """解析 Ghidra / IDA 的 symbols.csv。"""
    for row in _read_csv(csv_path):
        name = row.get("Name", "") or ""
        raw_address = row.get("Address", "") or ""
        raw_type = row.get("Type", "") or ""
        source = row.get("Source", "") or ""
        is_global = _bool_from_str(row.get("Is Global", "") or "")
        is_primary = _bool_from_str(row.get("Is Primary", "") or "")
        is_external = _bool_from_str(row.get("Is External", "") or "")
        namespace = row.get("Namespace", "") or ""

        address_va = _parse_hex_int(raw_address)
        if address_va is not None and address_offset:
            address_va -= address_offset
        if address_va is not None and (address_va < -(1 << 63) or address_va > ((1 << 63) - 1)):
            address_va = None
        kind = _normalize_symbol_kind(raw_type, is_external)

        conn.execute(
            """
            INSERT INTO symbols(
                view_id, name, address_va, raw_address,
                kind, raw_type, source,
                is_global, is_primary, is_external, namespace
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                view_id,
                name,
                address_va,
                raw_address,
                kind,
                raw_type,
                source,
                is_global,
                is_primary,
                is_external,
                namespace,
            ),
        )
    conn.commit()


def _collect_function_symbols_from_csv(csv_path: Path) -> Dict[str, int]:
    """
    从 symbols.csv 中提取函数符号映射：name(lower) -> address_va。
    若同名函数出现多次，保留第一个解析成功的地址。
    """
    result: Dict[str, int] = {}
    for row in _read_csv(csv_path):
        name = (row.get("Name") or "").strip()
        if not name:
            continue
        raw_address = row.get("Address", "") or ""
        raw_type = row.get("Type", "") or ""
        is_external = _bool_from_str(row.get("Is External", "") or "")
        kind = _normalize_symbol_kind(raw_type, is_external)
        if kind != "function":
            continue
        address_va = _parse_hex_int(raw_address)
        if address_va is None:
            continue
        key = name.lower()
        # 若存在多个同名函数，简单保留第一个地址
        if key not in result:
            result[key] = address_va
    return result


def calculate_address_offset(
    ghidra_symbols_csv: Path,
    ida_symbols_csv: Path,
    min_matches: int = 3,
) -> Optional[int]:
    """
    基于 Ghidra / IDA 的 symbols.csv，通过同名函数的入口 VA 估算两者之间的基址偏移。

    返回值含义：
    - 返回 d 表示 Ghidra_VA - IDA_VA 的众数为 d，
      即在将 Ghidra 视图写入数据库前，应统一执行 VA' = VA - d；
    - 若匹配过少或差值不稳定，则返回 None。
    """
    ghidra_map = _collect_function_symbols_from_csv(ghidra_symbols_csv)
    ida_map = _collect_function_symbols_from_csv(ida_symbols_csv)

    if not ghidra_map or not ida_map:
        return None

    common_names = set(ghidra_map.keys()) & set(ida_map.keys())
    if not common_names:
        return None

    diffs: List[int] = []
    for name in common_names:
        g_va = ghidra_map.get(name)
        i_va = ida_map.get(name)
        if g_va is None or i_va is None:
            continue
        diffs.append(g_va - i_va)

    if not diffs:
        return None

    counter = Counter(diffs)
    most_common_diff, count = counter.most_common(1)[0]

    # 要求至少若干个函数支持该偏移；若所有差值一致，则放宽限制
    if count < max(1, min_matches) and len(counter) > 1:
        return None

    return most_common_diff


def _parse_strings_ida(conn: sqlite3.Connection, view_id: int, csv_path: Path) -> None:
    """解析 IDA 的 strings.csv。"""
    for row in _read_csv(csv_path):
        value = row.get("String", "") or ""
        addr_va = _parse_hex_int(row.get("Address", "") or "")
        length = int(row.get("Length", "0") or 0)
        if addr_va is None:
            continue
        conn.execute(
            """
            INSERT INTO strings(view_id, value, address_va, length)
            VALUES (?, ?, ?, ?);
            """,
            (view_id, value, addr_va, length),
        )
    conn.commit()


def _extract_dst_from_xrefs_filename(filename: str, is_ghidra: bool) -> Tuple[Optional[int], Optional[str]]:
    """
    从 xrefs CSV 文件名中提取“被引用目标”的地址和名称。

    约定：
    - Ghidra: Malware_sample_exe_00402240_text_refs.csv
      -> dst_va = 0x00402240, dst_name = "text"（中间那段）
    - IDA:    Malware_sample_exe_0x401C0E_main_refs.csv
      -> dst_va = 0x401C0E, dst_name = "main"
    """
    stem = Path(filename).stem

    if is_ghidra:
        # 形如 Malware_sample_exe_00402240_text_refs
        parts = stem.split("_")
        if len(parts) < 4:
            return None, None
        addr_part = parts[-3]  # 倒数第三个是地址
        name_part = parts[-2]  # 倒数第二个是名称
        dst_va = _parse_hex_int(addr_part if addr_part.startswith("0x") else f"0x{addr_part}")
        return dst_va, name_part

    # IDA: Malware_sample_exe_0x401C0E_main_refs
    parts = stem.split("_")
    if len(parts) < 4:
        return None, None
    addr_part = parts[-3]  # "0x401C0E"
    name_part = parts[-2]  # "main"
    dst_va = _parse_hex_int(addr_part)
    return dst_va, name_part


def _parse_xrefs(
    conn: sqlite3.Connection,
    view_id: int,
    xrefs_dir: Path,
    is_ghidra: bool,
    address_offset: int = 0,
) -> None:
    """
    解析 Ghidra / IDA 的 xrefs 目录下所有 CSV 文件。

    - Ghidra CSV 列: Reference From Address,Reference Type,Containing Function,Primary Ref
    - IDA   CSV 列: Reference From Address,Reference Type,Containing Function
    """
    if not xrefs_dir.is_dir():
        return

    for csv_path in sorted(xrefs_dir.glob("*.csv")):
        dst_va, dst_name = _extract_dst_from_xrefs_filename(csv_path.name, is_ghidra=is_ghidra)
        if address_offset and dst_va is not None:
            dst_va -= address_offset

        if dst_va is not None and (dst_va < -(1 << 63) or dst_va > ((1 << 63) - 1)):
            dst_va = None
        for row in _read_csv(csv_path):
            src_va = _parse_hex_int(row.get("Reference From Address", "") or "")
            if src_va is None:
                continue
            if address_offset:
                src_va -= address_offset

            if src_va < -(1 << 63) or src_va > ((1 << 63) - 1):
                # src_va 是 NOT NULL，超界则跳过该行以避免 SQLite OverflowError
                continue
            ref_type_raw = row.get("Reference Type", "") or ""
            containing_function = row.get("Containing Function", "") or ""
            is_primary = None
            if is_ghidra:
                is_primary = _bool_from_str(row.get("Primary Ref", "") or "")

            conn.execute(
                """
                INSERT INTO xrefs(
                    view_id, src_va, dst_va, dst_name,
                    ref_type_raw, containing_function, is_primary, raw_file
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    view_id,
                    src_va,
                    dst_va,
                    dst_name,
                    ref_type_raw,
                    containing_function,
                    is_primary,
                    csv_path.name,
                ),
            )
    conn.commit()


def _parse_asm_functions_and_instructions(
    conn: sqlite3.Connection,
    view_id: int,
    disasm_dir: Path,
    address_offset: int = 0,
) -> None:
    """
    解析 *_disassembly 目录下的每个 .asm 文件，填充：
    - functions：函数入口地址 + 名称
    - instructions：函数内指令序列

    兼容 Ghidra / IDA 的输出格式。
    """
    if not disasm_dir.is_dir():
        return

    # 只处理以 0x 开头的函数级文件，忽略其他杂项
    asm_files = sorted(f for f in disasm_dir.glob("*.asm") if f.stem.startswith("0x"))

    for asm_path in asm_files:
        with asm_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()

        # 解析头部注释，获取函数名和入口地址
        func_name = None
        entry_va = None
        for line in lines[:5]:  # 前几行足够
            s = line.strip()
            if s.startswith("; Function:"):
                # 统一截取冒号后部分
                func_name = s.split(":", 1)[1].strip()
            if "Address:" in s or "Start EA:" in s:
                m = re.search(r"0x[0-9A-Fa-f]+", s)
                if m:
                    entry_va = _parse_hex_int(m.group(0))
        # 如果头部未解析出函数信息，尝试从文件名中解析地址
        if entry_va is None:
            m = re.match(r"0x([0-9A-Fa-f]+)_", asm_path.stem)
            if m:
                entry_va = _parse_hex_int(m.group(1))
        if entry_va is None:
            continue
        if address_offset:
            entry_va -= address_offset

        if entry_va < -(1 << 63) or entry_va > ((1 << 63) - 1):
            continue
        if func_name is None:
            # 从文件名中截取函数名部分
            m = re.match(r"0x[0-9A-Fa-f]+_(.+)", asm_path.stem)
            if m:
                func_name = m.group(1)
            else:
                func_name = asm_path.stem

        # 查找或插入 functions 记录
        cur = conn.execute(
            "SELECT id FROM functions WHERE view_id = ? AND entry_va = ?;",
            (view_id, entry_va),
        )
        row = cur.fetchone()
        if row:
            function_id = int(row[0])
        else:
            cur = conn.execute(
                """
                INSERT INTO functions(view_id, entry_va, name, demangled_name, size_bytes, source_symbol_id, raw_file)
                VALUES (?, ?, ?, NULL, NULL, NULL, ?);
                """,
                (view_id, entry_va, func_name, asm_path.name),
            )
            function_id = int(cur.lastrowid)

        # 解析指令行
        index_in_function = 0
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith(";"):
                continue

            # 兼容 Ghidra / IDA：
            # Ghidra: "0x00401C0E   PUSH       RBP              ; 55"
            # IDA:    "00401C0E  push       rbp                           ; 55"
            # 处理步骤：
            # 1. 拿到行首地址
            m = re.match(r"^(0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)\s+(.*)$", stripped)
            if not m:
                continue
            addr_str, rest = m.groups()
            addr_va = _parse_hex_int(addr_str)
            if addr_va is None:
                continue
            if address_offset:
                addr_va -= address_offset

            if addr_va < -(1 << 63) or addr_va > ((1 << 63) - 1):
                continue

            # 2. 拆分出 mnemonic + 操作数 + 注释
            # 去掉前导空格，再按 ';' 分割成 代码部分 / 注释部分
            code_part, *comment_parts = rest.split(";", 1)
            comment = comment_parts[0] if comment_parts else ""
            code_part = code_part.strip()
            if not code_part:
                continue

            # 第一个 token 是 mnemonic，后面是操作数
            code_tokens = code_part.split()
            mnemonic = code_tokens[0]
            op_str = code_part[len(mnemonic) :].strip() or None

            # 3. 从注释部分提取字节序列（如果存在）
            bytes_str: Optional[str] = None
            if comment:
                # comment 中通常是类似 "55" / "48 89 E5" 这样的机器码
                m_bytes = re.search(r"([0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*)", comment)
                if m_bytes:
                    bytes_str = m_bytes.group(1).strip()

            conn.execute(
                """
                INSERT INTO instructions(
                    view_id, function_id, index_in_function,
                    address_va, bytes, mnemonic, op_str, raw_line
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    view_id,
                    function_id,
                    index_in_function,
                    addr_va,
                    bytes_str,
                    mnemonic,
                    op_str,
                    line.rstrip("\n"),
                ),
            )
            index_in_function += 1

    conn.commit()


def _parse_pseudocode_functions(
    conn: sqlite3.Connection,
    view_id: int,
    pseudo_dir: Path,
    address_offset: int = 0,
) -> None:
    """
    解析 *_pseudocode / *_pesudocode 目录下每个函数级 .c 文件，
    填充 pseudo_functions 表。

    规则：
    - 仅处理形如 "0x00401C0E_main.c" / "0x401C0E_main.c" 的文件；
    - 根据文件头注释提取函数名和入口地址：
      - // Function: main
      - // Address: 0x00401C0E      （Ghidra）
      - // Start EA: 0x401C0E      （IDA）
    - prototype：文件中第一行非注释、非空行；
    - body：prototype 之后的所有内容（包含大括号）。
    """
    if not pseudo_dir.is_dir():
        return

    c_files = sorted(
        f
        for f in pseudo_dir.glob("*.c")
        if re.match(r"0x[0-9A-Fa-f]+_.*\.c$", f.name)
    )

    for c_path in c_files:
        with c_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()

        func_name = None
        entry_va = None
        # 解析前几行注释
        for line in lines[:6]:
            s = line.strip()
            if s.startswith("// Function:"):
                func_name = s.split(":", 1)[1].strip()
            if "Address:" in s or "Start EA:" in s:
                m = re.search(r"0x[0-9A-Fa-f]+", s)
                if m:
                    entry_va = _parse_hex_int(m.group(0))
        if entry_va is None:
            m = re.match(r"0x([0-9A-Fa-f]+)_", c_path.stem)
            if m:
                entry_va = _parse_hex_int(m.group(1))
        if entry_va is None:
            continue
        if address_offset:
            entry_va -= address_offset

        if entry_va < -(1 << 63) or entry_va > ((1 << 63) - 1):
            continue
        if func_name is None:
            m = re.match(r"0x[0-9A-Fa-f]+_(.+)\.c", c_path.name)
            if m:
                func_name = m.group(1)
            else:
                func_name = c_path.stem

        # 查找或创建对应的 functions 记录
        cur = conn.execute(
            "SELECT id FROM functions WHERE view_id = ? AND entry_va = ?;",
            (view_id, entry_va),
        )
        row = cur.fetchone()
        if row:
            function_id = int(row[0])
        else:
            cur = conn.execute(
                """
                INSERT INTO functions(view_id, entry_va, name, demangled_name, size_bytes, source_symbol_id, raw_file)
                VALUES (?, ?, ?, NULL, NULL, NULL, ?);
                """,
                (view_id, entry_va, func_name, c_path.name),
            )
            function_id = int(cur.lastrowid)

        # 寻找 prototype 行：跳过前面的注释和空行
        prototype = None
        proto_idx = None
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("//") or not stripped:
                continue
            # 第一个非注释、非空行视为 prototype
            prototype = stripped
            proto_idx = idx
            break

        body = ""
        if proto_idx is not None and proto_idx + 1 < len(lines):
            body = "".join(lines[proto_idx + 1 :]).strip()

        conn.execute(
            """
            INSERT INTO pseudo_functions(
                view_id, function_id, entry_va, name, prototype, body, raw_file
            )
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            (
                view_id,
                function_id,
                entry_va,
                func_name,
                prototype,
                body,
                c_path.name,
            ),
        )

    conn.commit()


# =========================
# 面向调用者的高层接口：加载 Ghidra / IDA 视图
# =========================


def load_ghidra_view(
    conn: sqlite3.Connection,
    output_dir: Path,
    config_path: Optional[str] = None,
    tool_version: str = "",
    address_offset: int = 0,
) -> int:
    """
    从一个 Ghidra 输出目录加载所有阶段 1 需要的数据。

    目录结构示例：
    tmp/Malware_sample_exe_ghidemo/
      ├── Malware_sample.exe
      ├── ghidra_adapter.py
      ├── Malware_sample_exe_binaryinfo/      （目录名前缀不强依赖，只要 *_binaryinfo 即可）
      │     ├── Malware_sample_exe_segments.csv
      │     ├── Malware_sample_exe_sections.csv
      │     ├── Malware_sample_exe_symbols.csv
      │     └── Malware_sample_exe_xrefs/*.csv
      ├── Malware_sample_exe_disassembly/*.asm
      └── Malware_sample_exe_pseudocode/*.c
    """
    output_dir = Path(output_dir).resolve()
    tool_id = _get_or_create_tool(conn, ToolInfo(name="ghidra", version=tool_version))
    binary_id = _get_or_create_binary(conn, output_dir)

    # ===== 解析 segments / sections / symbols / xrefs ===== #
    def _pick_ghidra_binaryinfo_dir(view_dir: Path) -> Optional[Path]:
        """Best-effort locate the directory containing *_segments/sections/symbols.csv and *_xrefs.

        Historically some exporters used a nested '*_ghidemo' folder instead of '*_binaryinfo'.
        We accept both to improve robustness.
        """

        # Preferred layout: <view>/*_binaryinfo/
        candidate = next(view_dir.glob("*_binaryinfo"), None)
        if candidate is not None and candidate.is_dir():
            return candidate

        # Common alternate layout observed in this repo: <view>/*_ghidemo/
        candidate = next(view_dir.glob("*_ghidemo"), None)
        if candidate is not None and candidate.is_dir():
            return candidate

        # Fallback: infer from presence of symbols/sections csv
        symbols_csv = next(view_dir.rglob("*_symbols.csv"), None)
        sections_csv = next(view_dir.rglob("*_sections.csv"), None)
        if symbols_csv is not None:
            return symbols_csv.parent
        if sections_csv is not None:
            return sections_csv.parent
        return None

    binaryinfo_dir = _pick_ghidra_binaryinfo_dir(output_dir)
    if binaryinfo_dir is None:
        raise FileNotFoundError(
            f"未找到 Ghidra binaryinfo 目录（期望 *_binaryinfo 或嵌套 *_ghidemo），且无法从 *_symbols.csv/_sections.csv 推断: {output_dir}"
        )

    segments_csv = next(binaryinfo_dir.glob("*_segments.csv"), None)
    sections_csv = next(binaryinfo_dir.glob("*_sections.csv"), None)
    symbols_csv = next(binaryinfo_dir.glob("*_symbols.csv"), None)
    xrefs_dir = next(binaryinfo_dir.glob("*_xrefs"), None)

    # 先用临时 view_id=-1 解析一次 segments，以获取 image_base，
    # 再创建 binary_view 记录，之后删除临时记录并重新插入一次。
    image_base: Optional[int] = None
    if segments_csv:
        image_base = _parse_segments_ghidra(
            conn,
            view_id=-1,
            csv_path=segments_csv,
            address_offset=address_offset,
        )

    view_id = _create_binary_view(conn, binary_id, tool_id, output_dir, image_base, config_path)

    # 我们刚才在 _parse_segments_ghidra 中用的是 view_id=-1，必须修正：
    if segments_csv:
        # 删除临时插入的段记录，重新解析一次，以正确的 view_id 写入
        conn.execute("DELETE FROM segments WHERE view_id = -1;")
        image_base = _parse_segments_ghidra(
            conn,
            view_id=view_id,
            csv_path=segments_csv,
            address_offset=address_offset,
        )
        conn.execute(
            "UPDATE binary_views SET image_base = ? WHERE id = ?;",
            (image_base, view_id),
        )
        conn.commit()

    if sections_csv:
        _parse_sections(
            conn,
            view_id=view_id,
            csv_path=sections_csv,
            address_offset=address_offset,
        )
    if symbols_csv:
        _parse_symbols(
            conn,
            view_id=view_id,
            csv_path=symbols_csv,
            address_offset=address_offset,
        )
    if xrefs_dir and xrefs_dir.is_dir():
        _parse_xrefs(
            conn,
            view_id=view_id,
            xrefs_dir=xrefs_dir,
            is_ghidra=True,
            address_offset=address_offset,
        )

    # ===== 解析函数反汇编 / 指令 =====
    disasm_dir = next(output_dir.glob("*_disassembly"), None)
    if disasm_dir and disasm_dir.is_dir():
        _parse_asm_functions_and_instructions(
            conn,
            view_id=view_id,
            disasm_dir=disasm_dir,
            address_offset=address_offset,
        )

    # ===== 解析伪代码函数 =====
    pseudo_dir = next(output_dir.glob("*_pseudocode"), None)
    if pseudo_dir and pseudo_dir.is_dir():
        _parse_pseudocode_functions(
            conn,
            view_id=view_id,
            pseudo_dir=pseudo_dir,
            address_offset=address_offset,
        )

    return view_id


def load_ida_view(
    conn: sqlite3.Connection,
    output_dir: Path,
    config_path: Optional[str] = None,
    tool_version: str = "",
) -> int:
    """
    从一个 IDA 输出目录加载所有阶段 1 需要的数据。

    目录结构示例：
    tmp/Malware_sample_exe_idademo/
      ├── Malware_sample_exe_binaryinfo/
      │     ├── Malware_sample_exe_segments.csv
      │     ├── Malware_sample_exe_sections.csv
      │     ├── Malware_sample_exe_symbols.csv
      │     ├── Malware_sample_exe_strings.csv
      │     └── Malware_sample_exe_xrefs/*.csv
      ├── Malware_sample_exe_disassembly/*.asm
      └── Malware_sample_exe_pesudocode/*.c
    """
    output_dir = Path(output_dir).resolve()
    tool_id = _get_or_create_tool(conn, ToolInfo(name="ida", version=tool_version))
    binary_id = _get_or_create_binary(conn, output_dir)

    # ===== 解析 segments / sections / symbols / xrefs / strings ===== #
    binaryinfo_dir = next(output_dir.glob("*_binaryinfo"), None)
    if binaryinfo_dir is None:
        raise FileNotFoundError(f"未找到 IDA binaryinfo 目录: {output_dir}")

    segments_csv = next(binaryinfo_dir.glob("*_segments.csv"), None)
    sections_csv = next(binaryinfo_dir.glob("*_sections.csv"), None)
    symbols_csv = next(binaryinfo_dir.glob("*_symbols.csv"), None)
    strings_csv = next(binaryinfo_dir.glob("*_strings.csv"), None)
    xrefs_dir = next(binaryinfo_dir.glob("*_xrefs"), None)

    image_base: Optional[int] = None
    if segments_csv:
        image_base = _parse_segments_ida(conn, view_id=-1, csv_path=segments_csv)

    view_id = _create_binary_view(conn, binary_id, tool_id, output_dir, image_base, config_path)

    # 修正 segments 的 view_id，同 Ghidra 逻辑
    if segments_csv:
        conn.execute("DELETE FROM segments WHERE view_id = -1;")
        image_base = _parse_segments_ida(conn, view_id=view_id, csv_path=segments_csv)
        conn.execute(
            "UPDATE binary_views SET image_base = ? WHERE id = ?;",
            (image_base, view_id),
        )
        conn.commit()

    if sections_csv:
        _parse_sections(conn, view_id=view_id, csv_path=sections_csv)
    if symbols_csv:
        _parse_symbols(conn, view_id=view_id, csv_path=symbols_csv)
    if strings_csv:
        _parse_strings_ida(conn, view_id=view_id, csv_path=strings_csv)
    if xrefs_dir and xrefs_dir.is_dir():
        _parse_xrefs(conn, view_id=view_id, xrefs_dir=xrefs_dir, is_ghidra=False)

    # ===== 解析函数反汇编 / 指令 =====
    disasm_dir = next(output_dir.glob("*_disassembly"), None)
    if disasm_dir and disasm_dir.is_dir():
        _parse_asm_functions_and_instructions(conn, view_id=view_id, disasm_dir=disasm_dir)

    # ===== 解析伪代码函数（注意目录名拼写: pesudocode）=====
    pseudo_dir = next(output_dir.glob("*_pesudocode"), None)
    if pseudo_dir and pseudo_dir.is_dir():
        _parse_pseudocode_functions(conn, view_id=view_id, pseudo_dir=pseudo_dir)

    return view_id


# =========================
# SQLite 检查辅助函数（来自 test.py）
# =========================


_INVALID_SHEET_TITLE_RE = re.compile(r"[:\\/?*\[\]]")
def _sanitize_sheet_title(name: str) -> str:
    """生成兼容 Excel 的 sheet 名称。"""

    cleaned = _INVALID_SHEET_TITLE_RE.sub("_", name.strip() if name else "table")
    title = cleaned[:31] or "table"
    return title


def _unique_sheet_title(base: str, used: Set[str]) -> str:
    """在已有 sheet 名称中生成不重复的名称。"""

    sanitized = _sanitize_sheet_title(base)
    candidate = sanitized
    counter = 1
    while candidate in used:
        suffix = f"_{counter}"
        available = 31 - len(suffix)
        trimmed = sanitized[:available] or "table"
        candidate = f"{trimmed}{suffix}"
        counter += 1
    used.add(candidate)
    return candidate


def _quote_sqlite_identifier(name: str) -> str:
    """对 SQLite 标识符加双引号以防注入。"""

    return '"' + name.replace('"', '""') + '"'


def export_sqlite_to_workbook(
    db_path: Path,
    workbook_path: Path,
    tables: Iterable[str],
) -> None:
    """导出所有表数据到 Excel 工作簿。"""
    if Workbook is None:
        raise RuntimeError(
            "导出 Excel 需要 openpyxl。请安装: pip install openpyxl"
        )

    def _excel_safe_cell_value(value: Any) -> Any:
        if value is None:
            return None

        if isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
            if not raw:
                return ""
            encoded = base64.b64encode(raw).decode("ascii")
            return f"base64:{encoded}"

        if isinstance(value, (int, float, bool)):
            return value

        if isinstance(value, str):
            if ILLEGAL_CHARACTERS_RE.search(value):
                value = ILLEGAL_CHARACTERS_RE.sub("", value)
            if len(value) > 32767:
                value = value[:32767]
            return value

        try:
            text = json.dumps(value, ensure_ascii=False, default=str)
        except Exception:
            text = str(value)
        if ILLEGAL_CHARACTERS_RE.search(text):
            text = ILLEGAL_CHARACTERS_RE.sub("", text)
        if len(text) > 32767:
            text = text[:32767]
        return text

    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.cursor()
        workbook = Workbook()
        first_sheet = workbook.active
        used_titles: Set[str] = set()
        created_sheet = False

        for name in tables:
            if name.startswith("sqlite_"):
                continue

            sheet_title = _unique_sheet_title(name, used_titles)
            if not created_sheet:
                sheet = first_sheet
                sheet.title = sheet_title
                created_sheet = True
            else:
                sheet = workbook.create_sheet(sheet_title)

            identifier = _quote_sqlite_identifier(name)
            cur.execute(f"SELECT * FROM {identifier};")
            colnames = [d[0] for d in (cur.description or [])]
            if colnames:
                sheet.append(colnames)
            for row in cur:
                sheet.append([_excel_safe_cell_value(v) for v in row])

        if not created_sheet:
            fallback = _unique_sheet_title("sqlite_meta", used_titles)
            first_sheet.title = fallback
            first_sheet.append(["(无可导出表)"])

        workbook_path.parent.mkdir(parents=True, exist_ok=True)
        workbook.save(str(workbook_path))
    finally:
        conn.close()


def inspect_sqlite_database(
    db_path: Path,
    export_path: Path,
    workbook_path: Optional[Path] = None,
) -> None:
    """打印元信息并导出全量数据（文本 + Excel）。"""

    conn = sqlite3.connect(str(db_path))
    try:
        cur = conn.cursor()
        tables = [
            name
            for (name,) in cur.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
            )
        ]
        print("=== 所有表 ===")
        for name in tables:
            print("-", name)

        print("\n=== 每个表的建表语句 ===")
        for name in tables:
            row = cur.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name = ?;",
                (name,),
            ).fetchone()
            sql = row[0] if row else ""
            print(f"\n-- {name} --")
            print(textwrap.indent(sql or "", "  "))

        print("\n=== 每个表的行数 ===")
        for name in tables:
            if name.startswith("sqlite_"):
                continue
            identifier = _quote_sqlite_identifier(name)
            (cnt,) = cur.execute(f"SELECT COUNT(*) FROM {identifier};").fetchone()
            print(f"{name:20s} {cnt}")

        export_path.parent.mkdir(parents=True, exist_ok=True)
        with export_path.open("w", encoding="utf-8") as out:
            out.write(f"DB: {db_path}\n")
            out.write("=== 每个表的全量数据（注意：可能较大） ===\n")
            for name in tables:
                if name.startswith("sqlite_"):
                    continue
                out.write(f"\n-- {name} (ALL ROWS) --\n")
                identifier = _quote_sqlite_identifier(name)
                cur.execute(f"SELECT * FROM {identifier};")
                colnames = [d[0] for d in (cur.description or [])]
                if colnames:
                    out.write("\t".join(colnames) + "\n")
                for row in cur:
                    out.write("\t".join("" if v is None else str(v) for v in row) + "\n")

        print(f"\n全量数据已导出到: {export_path}")
        if workbook_path:
            export_sqlite_to_workbook(
                db_path=db_path,
                workbook_path=workbook_path,
                tables=tables,
            )
            print(f"Workbook 已导出到: {workbook_path}")
    finally:
        conn.close()


# =========================
# 命令行入口：快速测试加载
# =========================


def main(argv: Optional[Iterable[str]] = None) -> None:
    """
    简单的命令行入口，方便在本地快速测试：

    示例：
      python alignment_loader.py --db tmp/alignment.db ^
          --ghidra-dir tmp/Malware_sample_exe_ghidemo ^
          --ida-dir    tmp/Malware_sample_exe_idademo
    """
    parser = argparse.ArgumentParser(
        description="从 Ghidra / IDA 输出目录构建统一 SQLite 对齐数据库（阶段 1）"
    )
    parser.add_argument(
        "--db",
        help="输出 SQLite 数据库路径：可为文件或目录；若未指定或为目录，则自动生成 {sample_name}.db。",
    )
    parser.add_argument(
        "--ghidra-dir",
        help="Ghidra 输出目录，例如 tmp/Malware_sample_exe_ghidemo",
    )
    parser.add_argument(
        "--ida-dir",
        help="IDA 输出目录，例如 tmp/Malware_sample_exe_idademo",
    )
    parser.add_argument(
        "--ghidra-version",
        default="",
        help="可选：Ghidra 版本号，记录在 tools 表中",
    )
    parser.add_argument(
        "--ida-version",
        default="",
        help="可选：IDA 版本号，记录在 tools 表中",
    )
    parser.add_argument(
        "--dump-db",
        action="store_true",
        help="打印目标数据库的各表信息并导出全量数据",
    )
    parser.add_argument(
        "--dump-db-output",
        default="tmp/db_sample_dump.txt",
        help="与 --dump-db 配合使用，指定导出全量数据的文件路径",
    )
    parser.add_argument(
        "--dump-db-workbook",
        default="tmp/db_sample_dump.xlsx",
        help="与 --dump-db 配合使用，导出所有表数据到 Excel 工作簿",
    )
    parser.add_argument(
        "-d",
        "--delete-db",
        action="store_true",
        help="删除已有的数据库文件再重新创建",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    # 解析输出目录
    ghidra_dir: Optional[Path] = Path(args.ghidra_dir).resolve() if args.ghidra_dir else None
    ida_dir: Optional[Path] = Path(args.ida_dir).resolve() if args.ida_dir else None

    # 推断样本逻辑名，用于默认数据库文件名
    view_for_name: Optional[Path] = ghidra_dir or ida_dir
    sample_name = "alignment"
    if view_for_name is not None:
        sample_name = _detect_binary_logical_name(view_for_name)

    # 解析 / 推断数据库路径
    if args.db:
        db_candidate = Path(args.db).expanduser().resolve()
        if db_candidate.is_dir():
            db_path = db_candidate / f"{sample_name}.db"
        else:
            db_path = db_candidate
    else:
        if view_for_name is None:
            raise SystemExit(
                "未提供 --db，且无法从 --ghidra-dir / --ida-dir 推断样本名用于生成默认数据库路径。"
            )
        db_path = (view_for_name.parent / f"{sample_name}.db").resolve()

    if args.delete_db:
        for suffix in ("", "-journal", "-wal", "-shm"):
            candidate = db_path.with_name(db_path.name + suffix)
            if candidate.exists():
                candidate.unlink()
    elif db_path.exists():
        compatible, detail = check_db_compatibility(db_path)
        if not prompt_overwrite_existing(db_path, compatible, detail):
            print("已选择保留现有数据库，操作终止。")
            return
        for suffix in ("", "-journal", "-wal", "-shm"):
            candidate = db_path.with_name(db_path.name + suffix)
            if candidate.exists():
                candidate.unlink()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # 若同时提供 Ghidra / IDA 输出目录，则基于 symbols.csv 自动推断 Ghidra/IDA 基址偏移
    address_offset = 0
    if ghidra_dir is not None and ida_dir is not None:
        # Ghidra 导出目录在历史版本中可能使用嵌套的 *_ghidemo 目录存放 csv。
        ghidra_binaryinfo = next(ghidra_dir.glob("*_binaryinfo"), None)
        if ghidra_binaryinfo is None:
            ghidra_binaryinfo = next(ghidra_dir.glob("*_ghidemo"), None)
        ida_binaryinfo = next(ida_dir.glob("*_binaryinfo"), None)
        if ghidra_binaryinfo is not None and ida_binaryinfo is not None:
            ghidra_symbols_csv = next(ghidra_binaryinfo.glob("*_symbols.csv"), None)
            ida_symbols_csv = next(ida_binaryinfo.glob("*_symbols.csv"), None)
            if ghidra_symbols_csv is not None and ida_symbols_csv is not None:
                offset = calculate_address_offset(ghidra_symbols_csv, ida_symbols_csv)
                if offset is not None and offset != 0:
                    address_offset = offset
                    print(
                        f"[AlignmentLoader] 检测到 Ghidra/IDA 基址偏移: "
                        f"offset=0x{offset:X} ({offset})，将在写入数据库前对 Ghidra VA 执行 va-offset 对齐到 IDA 坐标系。"
                    )
                else:
                    print(
                        "[AlignmentLoader] 未能可靠推断 Ghidra/IDA 基址偏移，使用默认 offset=0。"
                    )
        else:
            print(
                "[AlignmentLoader] 未找到完整的 *_binaryinfo 目录，跳过基址偏移自动推断（使用 offset=0）。"
            )

    conn = sqlite3.connect(str(db_path))
    try:
        init_db(conn)
        if ghidra_dir is not None:
            load_ghidra_view(
                conn,
                output_dir=ghidra_dir,
                config_path=None,
                tool_version=args.ghidra_version,
                address_offset=address_offset,
            )
        if ida_dir is not None:
            load_ida_view(
                conn,
                output_dir=ida_dir,
                config_path=None,
                tool_version=args.ida_version,
            )
    finally:
        conn.close()

    if args.dump_db:
        workbook_path = (
            Path(args.dump_db_workbook)
            if args.dump_db_workbook
            else None
        )
        inspect_sqlite_database(
            db_path=db_path,
            export_path=Path(args.dump_db_output),
            workbook_path=workbook_path,
        )


if __name__ == "__main__":
    main()
