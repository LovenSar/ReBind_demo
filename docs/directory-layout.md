# 仓库目录说明

本仓库已**扁平化**：Git 根目录与可执行脚本、配置在同一层，不再使用 `ReBind_Demo/ReBind_demo` 双层嵌套。

| 路径 | 说明 |
|------|------|
| `rebind_demo.py` | 主入口：调度 Ghidra/IDA Headless、语义对齐、深路径与导出等子命令 |
| `config.yaml`（根目录） | **唯一**配置文件：`platforms` + `ghidra` + `ida` + `semantics` |
| `tools/Ghidra_Headless_Demo/` | Ghidra：`ExtractAll.py` 单次导出（`*_output` / `*_disassembly` / `*_pseudocode`）+ `ghidra_adapter.py` |
| `tools/IDA_Headless_Demo/` | IDA：`ExtractAll_IDA.py` 单次会话全量导出 + `ida_adapter.py` |
| `tools/Semantics_Alignment/` | 对齐数据库构建、Phase1–7 流水线、`kp/` 公共库、`phases/` 分阶段实现 |
| `tests/` | `unittest` 用例（按模块路径加载 `tools/...` 下脚本） |
| `scripts/` | 与主流程无关的示例/调试脚本（如第三方 Chat API 探测） |
| `docs/` | 架构说明、深度引擎规范、本目录索引 |
| `tmp/` | 本地临时产物（默认被 `.gitignore` 忽略） |
| `deep_llm_runs/` | 深度引擎运行输出目录（建议仅本地使用，已加入 `.gitignore`） |

## 关键脚本（语义对齐）

| 文件 | 角色 |
|------|------|
| `tools/Semantics_Alignment/breadth/` | **广度优先**：`pipeline.py`（6 步流水线入口）、`alignment_loader.py`、`phases/`（Phase1–6） |
| `tools/Semantics_Alignment/depth/` | **深度优先**：`engine.py`（深度分析入口）、`deep_path_dfs.py`、`strict_align.py`、`deep_path_step.py` |
| `tools/Semantics_Alignment/kp/`、`pmt/` 等 | 共享能力（两种工作流共用） |
| `tools/Semantics_Alignment/deep_path_dfs.py` | 深路径 DFS 分析 |

## 配置与密钥

- 根目录 `config.yaml` 为全项目唯一配置源；`project_config.py` 负责按平台合并各段。
- LLM 相关密钥可放在 `tools/Semantics_Alignment/.env`（勿提交仓库），或通过环境变量提供。详见 [getting-started.md](./getting-started.md)。
