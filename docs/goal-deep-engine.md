# Goal Deep Engine（Phase7）与 Phase7.5

本节作为 **深度优先** 入口 `tools/Semantics_Alignment/depth/engine.py`（原 goal_deep_engine）的实现规范摘要，面向「函数级 FCG 的深度语义轮询」；与广度 6 步流水线（`breadth/`）并列。  
引擎定义为 **Phase7 独立分析引擎**：可独立于 Phase1–6 运行，不修改 Phase1–6 既有流程与模块行为。

## 1) 图模型与主干定义

- 分析图使用函数级有向调用图（FCG），节点为函数，边为调用关系。
- 主干搜索只使用有向 `call` 边。
- 图存在环时，先做 `SCC 压缩 -> DAG`，再在 DAG 上做最长路。
- 第一代主干路径选择优先级为 `(depth, path_len, gating_strength)` 词典序最大，深度绝对优先。

## 2) 入口策略

- 入口优先级固定为：`手工 entry > 导出函数 > main/start > 入度低且出度高根节点`。
- 支持 `top-k` 入口并行求主干。
- 第一代采用「全图主干优先」，`goal` 仅用于补充分支或对照路径。

## 2.5) Phase7.5 严格对齐前置

- Phase7 在进入第一代子树搜索前，必须先执行 Phase7.5 严格对齐。
- Phase7.5 基于 `*_idademo` 导出重建一份 IDA-only 临时 DB，并与当前工作 DB 做哈希级一致性对账。
- 对账范围至少包含：
  - `symbols`（含导入/导出语义）、`strings`、`functions`、`instructions`、`xrefs`、`pseudo_functions`
  - `import_symbols`、`export_symbols`
  - `pseudo_variable_names`（基于 `prototype/body` 的变量命名摘要）
  - `FCG` 调用边（call xrefs）
  - `CFG` 函数内边（非 call xrefs）
- 若发现漂移，默认自动原子替换工作 DB，并保留替换前备份。
- Phase7.5 产出结构化报告：`artifacts/phase7_5_report.json`。
- 报告包含 `focus_metrics_summary`，显式给出 `imports/exports/variable_names` 三类的一致性状态。
- 运行参数：
  - `--phase7-5-mode strict|off`（默认 `strict`）
  - `--phase7-5-ida-dir <path>`（可显式指定 `*_idademo`）
  - `--phase7-5-keep-rebuilt-db`（调试时保留重建库）

## 3) λ（宽度）语义

- `lambda` 定义为节点数预算，不是混合距离半径。
- 在 FCG 上采用「caller 侧 + callee 侧 = λ」的邻域预算语义。
- `lambda` 邻域扩展仅针对函数调用邻域（caller/callee），不通过 `data/string/global/indirect` 扩点。
- 但在当前子树分析时，必须把与这些函数相关的 `data/string/global/indirect` 证据作为参数上下文一并注入。

## 4) LLM 轮询协议

- 轮询粒度固定为「每层一步」。
- 每一步上下文必须包含：当前节点信息、λ 邻域函数摘要、相关全局变量、相关字符串常量、关键调用点守卫（条件分支、比较语句等）。
- 采用分层 token 截断，保证核心证据优先保留。

## 5) 第二代子树策略

- 第二代子树通过「分析目标相关信息/xrefs」定位，不强制复用第一代选主干逻辑。
- 触发策略为「先固定对所有 anchor 运行」，后续再加入「低置信步骤回溯扩展」优化分支。

## 6) DB 回填策略

回填必须满足硬门槛：

- `selected = new`
- `new_score - old_score >= delta`
- `confidence >= C`

不满足门槛时只输出 JSON 结果，不写回 `analysis_status`。回填操作必须带事务，失败回滚。

## 7) 固定评估指标

- 主干深度（Main Trunk Depth）
- 覆盖函数数（Covered Functions）
- 平均步置信度（Average Step Confidence）
- 回填接受率（DB Apply Acceptance Rate）

---

## 深度引擎参数定值（已确认）

- `entry_top_k = 3`。
- `lambda` 两侧预算策略：caller/callee 动态均分，单侧不足时补给另一侧。
- 单步上下文采用平衡预算（默认目标总预算 `8000 tokens`）：
  - 当前节点函数信息：`25%`
  - λ 邻域函数摘要：`25%`
  - 全局变量/参数相关证据：`20%`
  - 字符串与常量证据：`15%`
  - 调用点守卫与条件链：`10%`
  - 元信息与安全余量：`5%`
- 第二代 anchor 策略：运行时动态选择，优先级为 `低置信步骤 xrefs > 目标关键词匹配 > 人工 seed`。
- 第二代 `topn`：运行时自适应（随候选规模、置信度分布动态调整）。
- 低置信回溯阈值：`step_confidence < 0.55`。
- DB 回填最小置信度：`C = 0.70`。
- 回填分差阈值：`delta = 0.10`（默认值，可配置覆盖）。
- 评估输出格式：同时输出 `JSON + CSV`。
- 评估统计窗口：`单样本 + 批量 + 家族分组（可用时）`。
