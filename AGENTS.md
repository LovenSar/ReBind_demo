# AI 开发协作指南（ReBind Demo）

本文档面向使用 AI 工具（Cursor、Codex、Claude 等）在本仓库协作开发的场景，旨在帮助 AI 助手快速理解项目结构、关键约束和开发约定，减少无效改动与安全风险。

## 项目概述

**一句话描述**：二进制语义对齐工具集，集成 Ghidra / IDA 无头导出 → SQLite 对齐库 → LLM 驱动的多阶段分析（含 Phase7 Goal Deep Engine）。

**核心流程**：
1. 使用 Ghidra/IDA Headless 导出二进制信息（符号、反汇编、伪代码、xrefs）
2. 通过 `alignment_loader.py` 构建统一的 SQLite 对齐数据库
3. 运行广度优先流水线（Phase1-6）或深度优先引擎（Phase7/7.5）进行语义分析

## 关键路径（改代码前必读）

| 区域 | 说明 | 关键文件 |
|------|------|----------|
| **主入口** | 统一命令行调度 | `rebind_demo.py` |
| **配置系统** | 唯一配置源 | `config.yaml`（根目录）、`project_config.py`（合并逻辑） |
| **广度流水线** | 6 步语义对齐 | `tools/Semantics_Alignment/breadth/pipeline.py`、`alignment_loader.py`、`phases/`（Phase1-6） |
| **深度引擎** | 深度 FCG 分析 | `tools/Semantics_Alignment/depth/engine.py`、`deep_path_dfs.py`、`strict_align.py` |
| **共享库** | 公共能力 | `tools/Semantics_Alignment/kp/`、`pmt/` |
| **Ghidra 工具** | 导出适配器 | `tools/Ghidra_Headless_Demo/ghidra_adapter.py`、`ExtractAll.py` |
| **IDA 工具** | 导出适配器 | `tools/IDA_Headless_Demo/ida_adapter.py`、`ExtractAll_IDA.py` |
| **文档** | 架构与规范 | `docs/` 目录 |

更详细的目录结构见 [docs/directory-layout.md](docs/directory-layout.md)。

## 强约束（必须遵守）

### 1. 配置文件唯一性

- **根目录 `config.yaml` 是唯一配置源**，所有工具配置均在此维护
- **不再使用** `tools/*/config.yaml`（已废弃）
- 配置合并逻辑在 `project_config.py` 中实现：
  - 基础配置：`config.yaml` 中的 `ghidra` / `ida` / `semantics`
  - 平台覆盖：`platforms.<os>` 下的同名段（优先级更高）
- Phase7 默认值、presets 与预处理阈值分别位于
  `semantics.phase7.task_defaults` / `presets` / `preprocess`；预处理生成的任务 JSON
  是显式单次运行快照，不是隐式配置源
- **禁止**：在代码中硬编码路径、创建新的配置文件、使用 `-c` 参数指定模块配置

### 2. 路径与目录结构

- **仓库已扁平化**：Git 根目录即项目根，不再有 `ReBind_Demo/ReBind_demo` 嵌套
- **路径计算约定**：
  - `pipeline.py` 中：`REPO_ROOT = SCRIPT_PATH.parents[3]`、`TOOLS_DIR = SCRIPT_PATH.parents[1]`
  - `alignment_loader.py` 中：类似层级假设
  - **语义脚本必须留在 `tools/Semantics_Alignment/` 下**，否则需同步调整层级假设
- **输出目录命名**：
  - Ghidra：`*_ghidemo/`（包含 `*_output/`、`*_disassembly/`、`*_pseudocode/`）
  - IDA：`*_idademo/`（包含 `*_output/`、`*_disassembly/`、`*_pseudocode/`）
  - **注意**：Ghidra 的 xrefs 目录是 `*_cross_refs`（不是 `*_xrefs`），IDA 的是 `xrefs`（无前缀）

### 3. 模块导入与路径设置

- **`pipeline.py` 的路径设置**：
  - 必须在导入 `phases` 模块之前确保 `_BREADTH_DIR` 在 `sys.path[0]`
  - 因为 `kp_settings` 等模块可能会修改 `sys.path`，导致 `phases` 导入失败
  - 修复方案：在导入 `phases` 前，显式将 `_BREADTH_DIR` 移到 `sys.path[0]`
- **导入顺序**：
  1. 设置 `sys.path`（`_SA_ROOT`、`_BREADTH_DIR`）
  2. 导入共享模块（`kp.*`、`dynamic_batching` 等）
  3. **再次确保 `_BREADTH_DIR` 在 `sys.path[0]`**
  4. 导入 `phases.*` 模块

### 4. 导出文件格式与目录匹配

- **Ghidra 导出**（`ExtractAll.py`）：
  - 二进制信息：`*_output/` 目录（包含 `*_symbols.csv`、`*_sections.csv`、`*_segments.csv`）
  - xrefs：`*_output/*_cross_refs/` 目录（**注意是 `_cross_refs` 不是 `_xrefs`**）
  - 反汇编：`*_disassembly/` 目录
  - 伪代码：`*_pseudocode/` 目录
- **IDA 导出**（`ExtractAll_IDA.py`）：
  - 二进制信息：`*_output/` 目录（**不是 `*_binaryinfo`**）
  - xrefs：`*_output/xrefs/` 目录（**无前缀，直接是 `xrefs`**）
  - 反汇编：`*_disassembly/` 目录
  - 伪代码：`*_pseudocode/` 目录（**注意拼写，不是 `pesudocode`**）
- **`alignment_loader.py` 的兼容性**：
  - `load_ghidra_view`：支持 `*_binaryinfo`（旧）和 `*_output`（新），xrefs 搜索 `*_cross_refs`
  - `load_ida_view`：支持 `*_binaryinfo`（旧）和 `*_output`（新），xrefs 直接检查 `binaryinfo_dir / "xrefs"`

### 5. 数据库与事务

- **所有 DB 写入必须事务化**，失败回滚
- **幂等写入**：断点续跑时不得重复破坏已确认结果
- **SQLite 调优**：在 `config.yaml` 的 `semantics.pipeline.sqlite_tuning` 中配置

### 6. 可观测性与断点续跑

- **所有阶段必须落盘中间结果**，可追溯到 `run_id`、时间戳、输入样本与参数快照
- **每一步 LLM 处理必须记录**：请求上下文摘要、响应摘要、打分结果与决策原因
- **checkpoint 颗粒度**：每一步 LLM 交互 + 每个阶段结束
- **产物目录结构**：
  - `runs/<sample>/<run_id>/artifacts/`
  - `runs/<sample>/<run_id>/logs/`
  - `runs/<sample>/<run_id>/checkpoints/`
  - `runs/<sample>/<run_id>/reports/`

## 开发约定

### 代码修改范围

1. **只改与当前任务相关的文件**；避免顺手大重构、删注释或与需求无关的格式化
2. **保持代码风格一致**：与相邻代码一致（命名、类型、导入、`Path` 用法）
3. **优先复用**：新增逻辑优先复用 `kp/` 与现有 phase，避免重复实现

### 代码风格

- **路径处理**：统一使用 `pathlib.Path`，避免字符串拼接
- **类型提示**：使用类型注解（`from __future__ import annotations`）
- **导入顺序**：
  1. 标准库
  2. 第三方库
  3. 项目内部模块（按层级）
- **命名约定**：与现有代码保持一致（如 `_BREADTH_DIR`、`_SA_ROOT` 等私有变量使用下划线前缀）

### 测试与验证

- **有逻辑变更时运行测试**：
  ```bash
  python -m unittest discover -s tests -p 'test_*.py' -v
  ```
- **测试加载方式**：测试用例通过文件路径动态加载 `tools/...` 下的模块，不依赖 `PYTHONPATH`

### 安全与密钥

- **禁止提交密钥**：API Key、Token 等敏感信息不得写入仓库
- **LLM 密钥位置**：
  - 环境变量：`OPENAI_API_KEY`（推荐）
  - `.env` 文件：放在 `tools/Semantics_Alignment/`（已被 `.gitignore` 忽略）
- **即使 `.gitignore` 已忽略，仍勿提交明文密钥**

## 常见陷阱与已知问题

### 1. 工具路径配置

- **问题**：`ghidra.cmd_path`、`ida.cmd_path` 随机器变化
- **解决**：不要假设固定盘符或版本号，使用 `config.yaml` 中的平台覆盖配置
- **验证**：运行自检脚本 `python scripts/self_check.py` 检查工具路径

### 2. 输出目录命名不一致

- **问题**：历史遗留导致导出目录命名不统一
- **解决**：
  - `alignment_loader.py` 已实现 fallback 逻辑，支持新旧格式
  - 新代码应使用新格式（`*_output`、`*_cross_refs`、`xrefs`）

### 3. 模块导入失败

- **问题**：`pipeline.py` 直接运行时可能出现 `ModuleNotFoundError: No module named 'phases.phase1_kp'`
- **原因**：其他模块（如 `kp_settings`）修改 `sys.path`，导致 `_BREADTH_DIR` 被移出或位置靠后
- **解决**：已在 `pipeline.py` 第 69-74 行修复，在导入 `phases` 前显式确保 `_BREADTH_DIR` 在 `sys.path[0]`
- **验证**：可以从任何目录运行 `pipeline.py`，应正常工作

### 4. 临时文件与产物

- **`tmp/`、`deep_llm_runs/`**：默认作为运行产物，已被 `.gitignore` 忽略
- **禁止**：将大块二进制文件或密钥塞进版本库
- **清理**：定期清理临时文件，避免占用过多磁盘空间

### 5. IDA 适配器配置

- **`keep_input_copy`** 等配置在根 `config.yaml` 的 `ida.output` 段配置
- **不要**：在代码中硬编码这些选项

## AI 开发时的特殊注意事项

### 1. 理解上下文后再修改

- **先阅读相关代码**：修改前必须理解相关模块的职责和依赖关系
- **检查调用链**：确认修改不会影响其他模块
- **查看测试用例**：了解预期行为和边界情况

### 2. 路径相关的修改

- **修改路径计算时**：必须同步检查所有依赖该路径的代码
- **移动文件时**：必须更新所有导入路径和路径计算逻辑
- **添加新目录时**：考虑是否需要更新 `.gitignore`

### 3. 配置相关的修改

- **修改配置结构时**：必须同步更新 `project_config.py` 的合并逻辑
- **添加新配置项时**：考虑向后兼容性，提供默认值
- **平台特定配置**：使用 `platforms.<os>` 覆盖，不要硬编码

### 4. 数据库相关的修改

- **修改 Schema 时**：必须提供迁移脚本或兼容逻辑
- **修改查询逻辑时**：确保事务正确，考虑并发安全
- **性能优化**：利用 SQLite 调优配置（WAL、cache_size 等）

### 5. LLM 相关的修改

- **Prompt 修改**：必须考虑 token 限制和上下文窗口
- **API 调用**：使用 `kp/kp_llm.py` 中的统一接口，不要直接调用 API
- **错误处理**：必须处理网络错误、限流、超时等情况
- **日志记录**：所有 LLM 交互必须记录（摘要或完整，根据配置）

### 6. 测试相关的修改

- **添加新功能时**：必须添加对应的测试用例
- **修改现有功能时**：确保现有测试仍能通过
- **测试加载方式**：使用 `importlib.util.spec_from_file_location` 动态加载模块

## 文档更新约定

- **架构变更**：更新 `docs/architecture.md`
- **目录结构变更**：更新 `docs/directory-layout.md`
- **新入口脚本**：更新 `agents.md` 和 `docs/directory-layout.md`
- **配置变更**：更新 `config.yaml` 的注释和 `agents.md` 的配置说明

## 快速检查清单

在提交代码前，确认：

- [ ] 只修改了与任务相关的文件
- [ ] 代码风格与现有代码一致
- [ ] 路径计算正确（特别是层级假设）
- [ ] 配置变更已同步到 `config.yaml` 和 `project_config.py`
- [ ] 导出的目录命名与 `alignment_loader.py` 的搜索逻辑匹配
- [ ] 模块导入路径正确（特别是 `pipeline.py` 的 `phases` 导入）
- [ ] 数据库操作已事务化
- [ ] 测试用例通过
- [ ] 没有硬编码路径或密钥
- [ ] 文档已更新（如需要）

## 参考资源

- [目录结构说明](docs/directory-layout.md)
- [流水线架构](docs/architecture.md)
- [Goal Deep Engine 规范](docs/goal-deep-engine.md)
- [可观测与续跑](docs/observability.md)
- [快速开始](docs/getting-started.md)

---

**最后更新**：2026-03-20  
**维护者**：项目团队  
**反馈**：发现问题或需要补充内容时，请更新本文档
