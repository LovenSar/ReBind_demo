# Semantics Alignment — 两套工作流

本目录下语义对齐拆成**两套并列工作流**，入口与阶段分离，便于维护与扩展。

## 广度优先（6 步）

- **入口**：`breadth/pipeline.py`
- **步骤**：对齐加载（`alignment_loader.py`）→ Phase1 知识传播 → Phase2 校验 → Phase3 全局变量 → Phase4 局部变量 → Phase5 注释 → Phase6 刷新 IDA 导出
- **用途**：全量样本、按阶段批量跑、与 Ghidra/IDA 双视图对齐

## 深度优先

- **入口**：`depth/engine.py`（主）、`depth/deep_path_dfs.py`（轻量 DFS）
- **组件**：`strict_align.py`（Phase7.5 严格对齐）、`deep_path_step.py`（深度路径逐步 LLM）
- **用途**：目标/入口驱动、沿调用图深挖、断点续跑与回填

## 共享

- `kp/`、`pmt/`、`dynamic_batching.py`、`idat_server.py` 等留在本目录根，供上述两套工作流共用。
