"""breadth/layout_helpers.py

临时文件布局辅助函数：根据样本路径或 IDA 数据库路径推导输出目录结构。

从 pipeline.py 拆分而来，职责单一，便于在 pipeline 以外的场景复用。

目录约定
--------
每个样本的所有分析产物（Ghidra 输出、IDA 输出、SQLite DB、导出文件）
均集中在同一个专属工作目录中，命名规则为::

    <sample_parent>/<sanitized_name>_rebind_demo/

其中 ``sanitized_name = re.sub(r"[^A-Za-z]", "_", sample.name)``。
例如 ``InSpectre.exe`` → ``InSpectre_exe_rebind_demo/``。
"""

from __future__ import annotations

import re
from pathlib import Path


def rebind_workspace_dir(sample_path: Path) -> Path:
    """返回该样本专属的 _rebind_demo 工作目录路径（不自动创建）。

    Args:
        sample_path: 样本文件的绝对路径（需已 resolve）。

    Returns:
        形如 ``<parent>/<sanitized>_rebind_demo`` 的目录路径。
    """
    sanitized = re.sub(r"[^A-Za-z]", "_", sample_path.name)
    return sample_path.parent / f"{sanitized}_rebind_demo"


def derive_tmp_layout(sample_path: Path) -> dict:
    """根据样本路径生成专属工作目录内的输出布局。

    所有产物均置于 ``<sample_parent>/<sanitized>_rebind_demo/`` 内：

    Returns:
        包含 tmp_root / db_path / dump_txt / dump_xlsx / ida_log /
        ghidra_dir / ida_dir 等路径的字典。
    """
    sample_path = sample_path.expanduser().resolve()
    tmp_root = rebind_workspace_dir(sample_path)
    tmp_root.mkdir(parents=True, exist_ok=True)

    sanitized = re.sub(r"[^A-Za-z]", "_", sample_path.name)
    sample_name = sample_path.name
    dump_basename = f"{sample_name}_dump"

    return {
        "tmp_root": tmp_root,
        "db_path": tmp_root / f"{sample_name}.db",
        "dump_txt": tmp_root / f"{dump_basename}.txt",
        "dump_xlsx": tmp_root / f"{dump_basename}.xlsx",
        "ida_log": tmp_root / "idat_log.txt",
        "ghidra_dir": tmp_root / f"{sanitized}_ghidemo",
        "ida_dir": tmp_root / f"{sanitized}_idademo",
    }


def derive_tmp_layout_from_ida_db(ida_db_path: Path) -> dict:
    """根据已生成的 IDA 数据库路径（.i64）推导临时输出目录布局。

    适用于 Phase 6 only 模式（仅刷新 IDA 导出，不重建数据库）。

    路径推断策略：
    - 若 IDA DB 位于 ``*_idademo/`` 子目录内（正常新布局），则上移两层
      得到 ``_rebind_demo`` 工作目录。
    - 否则将父目录本身视为工作目录（兼容旧布局/手动指定）。

    Returns:
        与 :func:`derive_tmp_layout` 相同结构的字典。
    """
    ida_db_path = ida_db_path.expanduser().resolve()

    sample_name = ida_db_path.stem
    m = re.match(r"^(.+?\.(?:exe|dll|sys|bin))(?:[-_].*)?$", sample_name, flags=re.IGNORECASE)
    if m:
        sample_name = m.group(1)
    sanitized = re.sub(r"[^A-Za-z]", "_", sample_name)

    # 新布局：.i64 在 _rebind_demo/_idademo/ 内，上移两层即为工作目录
    parent = ida_db_path.parent
    if parent.name.endswith("_idademo") or parent.name.endswith("_ghidemo"):
        tmp_root = parent.parent
    else:
        # 旧布局或手动指定：父目录作为工作目录
        tmp_root = parent
    tmp_root.mkdir(parents=True, exist_ok=True)

    dump_basename = f"{sample_name}_dump"

    return {
        "tmp_root": tmp_root,
        "db_path": tmp_root / f"{sample_name}.db",
        "dump_txt": tmp_root / f"{dump_basename}.txt",
        "dump_xlsx": tmp_root / f"{dump_basename}.xlsx",
        "ida_log": tmp_root / "idat_log.txt",
        "ghidra_dir": tmp_root / f"{sanitized}_ghidemo",
        "ida_dir": tmp_root / f"{sanitized}_idademo",
    }
