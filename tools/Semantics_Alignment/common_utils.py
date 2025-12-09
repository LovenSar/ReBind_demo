#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
common_utils.py

共享的工具函数、数据结构和配置管理，供四个阶段模块共同使用。
"""

from __future__ import annotations

import logging
import os
import sqlite3
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import re
import yaml

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover
    requests = None


logger = logging.getLogger(__name__)
ACTIVE_INPUT_DB: str = ""

# 超时：连续收到空响应时持续重试的最长等待时间（秒）
EMPTY_RESPONSE_RETRY_TIMEOUT = 90.0

# 单个函数在第四阶段局部变量重命名中，最多尝试的分析轮数
MAX_LVAR_PASSES = 1

# 第四阶段：用于检测仍然存在的"默认局部变量名"（a1/v1/var_10 等）
GENERIC_LVAR_PATTERN = re.compile(
    r"\b(?:a\d+|arg\d+|arg_\d+|v\d+|var_[0-9A-Fa-f]+)\b"
)


# =========================
# 数据结构定义
# =========================


@dataclass
class FunctionNode:
    """单个函数在依赖图中的节点信息。"""

    id: int
    view_id: int
    entry_va: int
    name: str
    instr_count: int = 0
    internal_callees: Set[int] = field(default_factory=set)
    external_callees: Set[int] = field(default_factory=set)
    external_callee_names: Set[str] = field(default_factory=set)
    callers: Set[int] = field(default_factory=set)
    string_ids: Set[int] = field(default_factory=set)


@dataclass
class FunctionGraph:
    """某个 binary_view 下的函数依赖图。"""

    view_id: int
    functions: Dict[int, FunctionNode]
    string_values: Dict[int, str]
    symbol_names: Dict[int, str]


@dataclass
class UnifiedFunctionNode:
    """跨视图统一的物理函数节点。"""

    entry_va: int
    binary_id: int
    function_ids: Set[int] = field(default_factory=set)
    names: Set[str] = field(default_factory=set)
    instr_count: int = 0
    primary_function_id: Optional[int] = None
    pseudocodes: Dict[str, str] = field(default_factory=dict)
    internal_callee_vas: Set[int] = field(default_factory=set)
    external_callee_names: Set[str] = field(default_factory=set)
    string_refs: Set[str] = field(default_factory=set)
    caller_vas: Set[int] = field(default_factory=set)


@dataclass
class UnifiedGraph:
    """跨视图统一的函数级依赖图。"""

    binary_id: int
    nodes: Dict[int, UnifiedFunctionNode]
    tool_map: Dict[int, str]
    func_tool: Dict[int, str]


@dataclass
class GlobalVarNode:
    """全局变量节点（按 address_va 聚合）。"""

    address_va: int
    names: Set[str] = field(default_factory=set)
    readers: Set[int] = field(default_factory=set)
    writers: Set[int] = field(default_factory=set)


@dataclass
class ValidationTask:
    """调用链校验任务。"""
    entry_va: int
    function_ids: Set[int]
    caller_va: int
    call_site: int
    call_ctx: str


# LLM 配置与设置
DEFAULT_LLM_MODEL = "gpt-4.1-mini"
DEFAULT_LLM_TEMPERATURE = 0.1
DEFAULT_LLM_MAX_TOKENS = 512
DEFAULT_API_KEY_ENV = "OPENAI_API_KEY"
SEMANTICS_CONFIG_FILE = Path(__file__).parent / "config.yaml"
WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
DOTENV_PATH = WORKSPACE_ROOT / ".env"


@dataclass
class LLMSettings:
    """LLM 参数与 OpenAI API 设置。"""
    model: str
    temperature: float
    max_tokens: int
    api_settings: Dict[str, Any]
    chat_completion_kwargs: Dict[str, Any]


# =========================
# 日志设置
# =========================


def setup_logging(log_path: Path, input_db: Optional[Path] = None) -> None:
    """
    初始化日志系统：
    - 文件：DEBUG 及以上写入 log_path；
    - 控制台：INFO 及以上，简洁输出。
    多次调用时只在第一次生效，避免重复添加 handler。
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

    log_path.parent.mkdir(parents=True, exist_ok=True)

    root.setLevel(logging.DEBUG)

    # 文件日志：详细记录
    fh = logging.FileHandler(str(log_path), encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s - [db=%(db_path)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    # 控制台日志：简要输出
    ch = logging.StreamHandler(stream=sys.stderr)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter("[db=%(db_path)s] %(message)s"))

    db_filter = _DBPathFilter()
    fh.addFilter(db_filter)
    ch.addFilter(db_filter)

    root.addHandler(fh)
    root.addHandler(ch)


def install_stdout_tee(target_logger: logging.Logger) -> None:
    """将 stdout 同步写入日志文件，便于回溯命令行输出。"""

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

    # 避免重复安装
    if isinstance(sys.stdout, _StdoutTee):
        return

    sys.stdout = _StdoutTee(sys.stdout, target_logger)  # type: ignore[assignment]


# =========================
# IDA 服务器连接
# =========================


def wait_for_ida_server(ida_url: str) -> None:
    """
    检查与 idat_server 的连接情况。
    - 若可用：立即返回；
    - 若断开：进入循环，每 30 秒自动重试一次；
      在等待过程中，若用户按下回车，则立即触发一次重试。
    """
    if requests is None:
        # 未安装 requests 时无法主动探测，直接返回，由后续 HTTP 调用自行报错
        return

    while True:
        try:
            resp = requests.post(
                ida_url,
                json={"action": "ping"},
                timeout=3.0,
            )
            if resp.status_code == 200:
                return
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        except Exception as exc:
            msg = (
                f"[IDA-Sync] 无法连接到 IDA 服务器 {ida_url}: {exc}。"
                " 将在 30 秒后自动重试，按回车可立即重试，Ctrl+C 终止。"
            )
            print(msg)
            logger.warning("%s", msg)

            # 等待 30 秒或用户按下回车
            user_triggered: List[Optional[bool]] = [None]

            def _wait_input() -> None:
                try:
                    input()
                    user_triggered[0] = True
                except EOFError:
                    user_triggered[0] = False

            t: Optional[threading.Thread] = None
            if sys.stdin and sys.stdin.isatty():
                t = threading.Thread(target=_wait_input, daemon=True)
                t.start()

            for _ in range(30):
                if user_triggered[0] is not None:
                    break
                import time
                time.sleep(1.0)


# =========================
# 配置文件读取
# =========================


def load_semantics_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """读取与解析 Semantics Alignment 的 YAML 配置文件。"""

    if config_path:
        path = Path(config_path)
    else:
        path = SEMANTICS_CONFIG_FILE

    if not path.exists():
        if config_path:
            raise FileNotFoundError(f"配置文件不存在: {path}")
        return {}

    try:
        with path.open("r", encoding="utf-8") as fp:
            data = yaml.safe_load(fp)
    except yaml.YAMLError as exc:
        raise RuntimeError(f"无法解析配置文件 {path}：{exc}") from exc

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise RuntimeError(f"配置文件 {path} 必须是一个字典结构。")

    return data


def load_dotenv(path: Path) -> Dict[str, str]:
    """从 .env 文件中读取键值并返回字典。"""

    if not path.exists():
        return {}

    env: Dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        env[key.strip()] = value.strip().strip('"')
    return env


def build_llm_settings(
    config: Dict[str, Any],
    model: Optional[str],
    temperature: Optional[float],
    max_tokens: Optional[int],
) -> LLMSettings:
    """合并命令行参数与 config.yaml 中的 LLM 配置。"""

    llm_section = config.get("llm") or {}
    if not isinstance(llm_section, dict):
        llm_section = {}

    def _coerce_float(value: Any, default: float) -> float:
        if value is None:
            return default
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def _coerce_int(value: Any, default: int) -> int:
        if value is None:
            return default
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    final_model = model or llm_section.get("model") or DEFAULT_LLM_MODEL
    final_temperature = (
        temperature
        if temperature is not None
        else _coerce_float(llm_section.get("temperature"), DEFAULT_LLM_TEMPERATURE)
    )
    final_max_tokens = (
        max_tokens
        if max_tokens is not None
        else _coerce_int(llm_section.get("max_tokens"), DEFAULT_LLM_MAX_TOKENS)
    )

    api_section = llm_section.get("api") or {}
    if not isinstance(api_section, dict):
        api_section = {}

    api_settings: Dict[str, Any] = {k: v for k, v in api_section.items() if v is not None}
    api_settings.setdefault("key_env_var", DEFAULT_API_KEY_ENV)

    raw_chat_kwargs = llm_section.get("chat_completion_kwargs") or {}
    chat_kwargs: Dict[str, Any] = dict(raw_chat_kwargs) if isinstance(raw_chat_kwargs, dict) else {}

    return LLMSettings(
        model=final_model,
        temperature=final_temperature,
        max_tokens=final_max_tokens,
        api_settings=api_settings,
        chat_completion_kwargs=chat_kwargs,
    )


# =========================
# 数据库 Schema 初始化
# =========================


def ensure_analysis_schema(conn: sqlite3.Connection) -> None:
    """确保 analysis_status 表已经存在。"""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS analysis_status (
            function_id INTEGER PRIMARY KEY,
            analysis_state TEXT DEFAULT 'PENDING',
            confidence_score INTEGER DEFAULT 0,
            summary_signature TEXT,
            semantic_summary TEXT,
            analysis_passes INTEGER DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    # 旧版本数据库可能缺少新增列，运行时补齐以避免查询报错。
    cur = conn.execute("PRAGMA table_info('analysis_status');")
    existing_cols = {row[1] for row in cur.fetchall()}

    def _add_column(name: str, ddl: str) -> None:
        if name not in existing_cols:
            if name == "last_updated":
                # SQLite ALTER COLUMN 不允许非常量默认值，先添加列再回填当前时间。
                conn.execute("ALTER TABLE analysis_status ADD COLUMN last_updated TIMESTAMP;")
                conn.execute(
                    "UPDATE analysis_status SET last_updated = CURRENT_TIMESTAMP WHERE last_updated IS NULL;"
                )
            else:
                conn.execute(f"ALTER TABLE analysis_status ADD COLUMN {ddl};")

    _add_column("confidence_score", "confidence_score INTEGER DEFAULT 0")
    _add_column("summary_signature", "summary_signature TEXT")
    _add_column("semantic_summary", "semantic_summary TEXT")
    _add_column("analysis_passes", "analysis_passes INTEGER DEFAULT 0")
    _add_column("last_updated", "last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP")

    conn.commit()


def ensure_analysis_rows_for_view(conn: sqlite3.Connection, view_id: int) -> None:
    """为指定视图的所有函数创建 analysis_status 行（若不存在）。"""
    conn.execute(
        """
        INSERT OR IGNORE INTO analysis_status (function_id, analysis_state, confidence_score)
        SELECT id, 'PENDING', 0
        FROM functions
        WHERE view_id = ?;
        """,
        (view_id,),
    )
    conn.commit()


def ensure_analysis_rows_for_binary(conn: sqlite3.Connection, binary_id: int) -> None:
    """为指定 binary 下所有视图的函数创建 analysis_status 行。"""
    conn.execute(
        """
        INSERT OR IGNORE INTO analysis_status (function_id, analysis_state, confidence_score)
        SELECT f.id, 'PENDING', 0
        FROM functions f
        JOIN binary_views bv ON f.view_id = bv.id
        WHERE bv.binary_id = ?;
        """,
        (binary_id,),
    )
    conn.commit()


def load_analysis_info(conn: sqlite3.Connection) -> Dict[int, dict]:
    """从 analysis_status 表中加载所有函数的分析状态信息。"""
    cur = conn.cursor()
    cur.execute(
        """
        SELECT function_id, analysis_state, confidence_score,
               summary_signature, semantic_summary, analysis_passes
        FROM analysis_status;
        """
    )
    info_map: Dict[int, dict] = {}
    for row in cur.fetchall():
        fid, state, score, sig, sem, passes = row
        info_map[fid] = {
            "analysis_state": state,
            "confidence_score": score,
            "summary_signature": sig,
            "semantic_summary": sem,
            "analysis_passes": passes,
        }
    return info_map


def ensure_global_vars_schema(conn: sqlite3.Connection) -> None:
    """确保 global_vars_status 表已经存在。"""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS global_vars_status (
            address INTEGER PRIMARY KEY,
            name TEXT,
            inferred_type TEXT,
            semantic_summary TEXT,
            analysis_state TEXT DEFAULT 'PENDING',
            confidence_score INTEGER DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
    )
    conn.commit()


# =========================
# 通用辅助函数
# =========================


def _find_generic_lvar_names(code: str) -> Set[str]:
    """从代码中找出所有匹配默认局部变量名模式的标识符。"""
    return set(GENERIC_LVAR_PATTERN.findall(code))


def require_openai(api_settings: Dict[str, Any]) -> Any:
    """根据 api_settings 动态导入并配置 OpenAI 客户端。"""
    try:
        import openai
    except ImportError as exc:
        raise RuntimeError(
            "无法导入 openai 库，请先安装: pip install openai"
        ) from exc

    key_env_var = api_settings.get("key_env_var", DEFAULT_API_KEY_ENV)
    api_key = os.environ.get(key_env_var)
    if not api_key:
        raise ValueError(
            f"环境变量 {key_env_var} 未设置，无法调用 OpenAI API。"
        )

    base_url = api_settings.get("base_url")
    if base_url:
        openai.api_base = base_url

    openai.api_key = api_key
    return openai


def build_chat_request(prompt: str, llm_settings: LLMSettings) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    """构建 OpenAI ChatCompletion 请求的消息和参数。"""
    messages = [{"role": "user", "content": prompt}]
    params = {
        "model": llm_settings.model,
        "temperature": llm_settings.temperature,
        "max_tokens": llm_settings.max_tokens,
        **llm_settings.chat_completion_kwargs,
    }
    return messages, params
