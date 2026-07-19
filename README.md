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
| [Phase7 实战准确度模式](docs/phase7-practical-mode.md) | 调用图预算、静态证据 Prompt、独立回填门槛 |
| [Phase7 实战压力测试](docs/phase7-stress-test.md) | Legacy/Practical A/B、资源指标和人工真值召回 |
| [可观测与续跑](docs/observability.md) | 日志、checkpoint、`runs/` 约定 |

## Phase7 实战入口

原有 `depth/engine.py` 保持兼容。需要降低混合图噪声时，可以改用：

```bash
python tools/Semantics_Alignment/depth/practical_engine.py \
  /path/to/sample.bin \
  --db /path/to/sample.db \
  --practical-node-budget 24 \
  --no-apply-db
```

这个入口只沿 caller/callee 调用关系扩展路径。字符串、全局变量、数据引用和间接调用会作为证据进入 Prompt，不会直接扩大函数邻域。新 Profile 还需要通过静态证据门槛。

## Phase7 A/B 压力测试

复制样本清单后，可以先进行无 API 成本检查：

```bash
cp examples/phase7_stress_manifest.example.json tmp/phase7_stress_manifest.json
python scripts/phase7_stress.py \
  --manifest tmp/phase7_stress_manifest.json \
  --profile smoke \
  --dry-run
```

真实测试会让同一批样本分别运行 legacy 和 practical，并输出耗时、内存、Token、路径覆盖和人工真值召回对比。

需要更完整的诊断时，使用三阶段详细套件（干跑门禁 → Practical 恢复稳定性 → A/B 矩阵）：

```bash
python scripts/phase7_stress.py \
  --manifest tmp/phase7_stress_manifest.json \
  --suite detailed \
  --plan-only

python scripts/phase7_stress.py \
  --manifest tmp/phase7_stress_ntoskrnl_manifest.json \
  --suite detailed \
  --out-dir tmp/phase7_stress_ntoskrnl_detailed
```

输出除原有汇总外，还会写入 `acceptance.json`，并在 `summary.md` 中报告耗时/Token 稳定性（CV）以及 JSON 截断后的 token 预算恢复路径。详见 [Phase7 实战压力测试](docs/phase7-stress-test.md)。

## MiniMax-M3 配置与鲁棒性

LLM 统一通过 [`kp/kp_llm.py`](tools/Semantics_Alignment/kp/kp_llm.py) 调用。MiniMax-M3 的模型名、
兼容接口和恢复策略只维护在根 [`config.yaml`](config.yaml)；密钥不要写进 YAML 或提交到 Git，
应放在 `tools/Semantics_Alignment/.env`：

```dotenv
MINIMAX_API_KEY=<your-key>
```

当前默认策略：

| 配置 | 默认值 | 作用 |
|---|---:|---|
| `semantics.llm.api.timeout` | 120 | 限制单次请求等待时间 |
| `startup_probe` | `false` | 单 Key 不发送额外启动探测，减少延迟和瞬时 429 误判 |
| `wait_on_rate_limit` | `false` | 单 Key 限流后做有界退避，不进入跨天等待 |
| `json_retry_token_multiplier` | 2.0 | JSON 为空、截断或不可解析时扩大恢复请求预算 |
| `json_retry_max_tokens` | 6000 | 限制恢复请求的最大输出预算 |

Practical Profile 的正常首轮上限仍为 1600 tokens。只有结构化响应失败时才会按
`1600 -> 3200 -> 6000` 扩大预算，同时压低温度并要求 MiniMax 只返回紧凑 JSON。
成功首轮不会承担额外请求或 Token。每次尝试只记录请求预算、响应长度、用量和结果状态，
默认不落原始回复或认证信息。

供应商网络、配额和服务状态无法由本仓库保证永不故障；项目端保证的是：空响应、截断、
推理块、分块内容、429、连接错误和超时都有明确的恢复或有界失败路径，不会无限等待，
也不会把“HTTP 成功但 JSON 不可消费”计为完整成功。

相关实现与测试：

- [`tools/Semantics_Alignment/kp/kp_llm.py`](tools/Semantics_Alignment/kp/kp_llm.py)：客户端、响应提取、JSON 恢复、限流与网络重试。
- [`tests/test_deep_path_step_resume.py`](tests/test_deep_path_step_resume.py)：空响应、截断、推理块、分块响应、连接错误和单 Key 429 故障注入。
- [`tests/test_api_key_rotation.py`](tests/test_api_key_rotation.py)：自定义密钥变量、单 Key 免探测、超时透传与多 Key 轮换。
- [`docs/phase7-practical-mode.md`](docs/phase7-practical-mode.md)：Practical 预算与 Profile 恢复策略。
- [`docs/phase7-stress-test.md`](docs/phase7-stress-test.md)：完整压力测试清单、矩阵和验收指标。

## 本轮 MiniMax 压测方案

先运行全部故障注入和回归测试：

```bash
python -m unittest discover -s tests -p 'test_*.py' -v
```

真实稳定性复测使用同一个样本、独立 SQLite 副本和 Practical b12，连续运行三次。样本清单
必须包含人工确认的 `goal_vas`、`path_subsequences` 和 `profile_tokens`；地址未确认时不要把
占位值当成准确率结论。

```bash
python scripts/phase7_stress.py \
  --manifest tmp/phase7_stress_manifest.json \
  --profile smoke \
  --repeat 3 \
  --practical-budgets 12 \
  --engines practical \
  --llm-mode on \
  --timeout-seconds 1800 \
  --out-dir tmp/phase7_stress_minimax_b12
```

Runner 会在命令末尾强制加入：

```text
--no-apply-db --no-log-raw-llm --no-resume --no-force-resume
```

只有输入文件、源 DB 和 IDA 导出完全相同时，压力测试才可通过样本
`extra_args` 复用已验证的 Phase7.5 报告；参数不匹配会拒绝运行。

2026-07-18 在 Windows Server 2022 `ntoskrnl.exe` 样本上的三轮复测结果：

| 指标 | 结果 |
|---|---:|
| 运行成功率 | 3/3（100%） |
| LLM 结构化交互 | 21/21（100%） |
| API 请求 | 23 次，网络失败 0 次 |
| 平均耗时 / P95 | 99.03s / 100.85s |
| 平均 Token | 28,726 |
| Goal Recall / Profile Token Recall | 1.0 / 1.0 |

其中两轮首个 Profile 响应耗尽 1600-token 预算并被截断，随后均由 3200-token 恢复请求完成，
证明故障不是被统计层忽略，而是实际进入并通过恢复路径。`Path Recall` 必须以正确的人工调用链
为准；本次清单中的旧链与实际候选路径不一致，因此不用于宣称路径准确率提升。

## 近期结构调整说明

- 原 `ReBind_Demo/ReBind_demo/` **已合并到本目录**：Git 根目录即项目根，避免多层同名文件夹。
- 根目录下的 `test.py` 已移至 [`scripts/example_longcat_chat.py`](./scripts/example_longcat_chat.py)（第三方 API 示例，与主流程无关）。

## 许可证与外部工具

Ghidra、IDA 及其许可由用户自行安装与配置；本仓库内脚本仅通过配置文件指向本地安装路径。
