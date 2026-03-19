# ReBind Demo

二进制语义对齐工具集：集成 **Ghidra** 与 **IDA** 无头导出，构建 SQLite 对齐库，并运行基于 LLM 的多阶段语义传播、校验与深度 FCG 分析（Phase7 / Goal Deep Engine）。

## 仓库结构（一览）

- **入口**：[`rebind_demo.py`](./rebind_demo.py) — 统一命令行
- **语义与阶段实现**：[`tools/Semantics_Alignment/`](./tools/Semantics_Alignment/)
- **文档**：[`docs/`](./docs/) — 建议从这里读起

## 文档导航

| 文档 | 内容 |
|------|------|
| [快速开始](docs/getting-started.md) | 虚拟环境、依赖、测试命令 |
| [目录说明](docs/directory-layout.md) | 各文件夹职责与关键脚本 |
| [流水线架构](docs/architecture.md) | Phase1–4 流程图（Mermaid） |
| [Goal Deep Engine](docs/goal-deep-engine.md) | Phase7 / 7.5 规范与参数 |
| [可观测与续跑](docs/observability.md) | 日志、checkpoint、`runs/` 约定 |

## 近期结构调整说明

- 原 `ReBind_Demo/ReBind_demo/` **已合并到本目录**：Git 根目录即项目根，避免多层同名文件夹。
- 根目录下的 `test.py` 已移至 [`scripts/example_longcat_chat.py`](./scripts/example_longcat_chat.py)（第三方 API 示例，与主流程无关）。

## 许可证与外部工具

Ghidra、IDA 及其许可由用户自行安装与配置；本仓库内脚本仅通过配置文件指向本地安装路径。
