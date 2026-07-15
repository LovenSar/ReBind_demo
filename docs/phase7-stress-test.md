# Phase7 实战压力测试

`phase7_stress.py` 对相同样本运行 legacy 与 practical 两套 Phase7。每次运行都会使用独立 SQLite 副本，并强制关闭数据库回填。

## 1. 准备样本清单

复制示例文件：

```bash
cp examples/phase7_stress_manifest.example.json tmp/phase7_stress_manifest.json
```

每个样本至少需要 `name` 和 `db`。建议同时设置 `input`、`ida_dir` 和 `binary_id`。

```json
{
  "samples": [
    {
      "name": "sample-a",
      "input": "/samples/sample-a.exe",
      "db": "/samples/sample-a.db",
      "ida_dir": "/samples/sample-a_idademo",
      "binary_id": 1,
      "goal_keywords": ["auth", "network"]
    }
  ]
}
```

## 2. 加入人工真值

没有真值时，压力测试可以比较速度、Token、内存和路径覆盖。加入真值后，脚本还会计算准确率代理指标。

```json
{
  "expectations": {
    "goal_vas": ["0x140001000"],
    "path_subsequences": [
      ["0x140000100", "0x140000800", "0x140001000"]
    ],
    "profile_tokens": {
      "0x140001000": ["auth", "packet"]
    }
  }
}
```

- `goal_vas` 用于计算目标函数召回率。
- `path_subsequences` 用于检查关键调用链是否按顺序出现。中间允许存在其他节点。
- `profile_tokens` 用于检查选中语义是否包含人工确认的关键词。

## 3. 先查看执行矩阵

```bash
python scripts/phase7_stress.py \
  --manifest tmp/phase7_stress_manifest.json \
  --profile balanced \
  --plan-only
```

预设只控制重复次数和 practical 节点预算，不会改变 Phase7 分析参数。

| 预设 | 每个变体重复次数 | Practical 节点预算 |
|---|---:|---|
| `smoke` | 1 | 24 |
| `balanced` | 2 | 12、24、40 |
| `soak` | 3 | 12、24、40、64 |

一份样本使用 `balanced` 时会产生 8 次运行：legacy 运行 2 次，三个 practical 预算各运行 2 次。

清单中的 `defaults.repeat` 和 `defaults.practical_budgets` 可以覆盖预设。命令行的 `--repeat` 和 `--practical-budgets` 优先级最高。脚本默认拒绝超过 100 次的矩阵，需要明确提高 `--max-runs` 才会继续。

## 4. 无 API 成本检查

```bash
python scripts/phase7_stress.py \
  --manifest tmp/phase7_stress_manifest.json \
  --profile smoke \
  --dry-run \
  --out-dir tmp/phase7_stress_dry
```

这一步会检查数据库、Phase7.5、图构建、路径搜索和报告解析，但不会发送 LLM 请求。

## 5. 真实 A/B 压力测试

```bash
python scripts/phase7_stress.py \
  --manifest tmp/phase7_stress_manifest.json \
  --profile balanced \
  --llm-mode on \
  --timeout-seconds 10800 \
  --out-dir tmp/phase7_stress_real
```

建议第一轮只使用 1 到 3 个有人工真值的样本。确认 API 费用和单次耗时后，再使用 `soak`。

## 6. 输出

```text
tmp/phase7_stress_real/
├── benchmark_plan.json
├── results.jsonl
├── results.json
├── results.csv
├── summary.json
├── summary.csv
├── comparisons.json
├── comparisons.csv
├── summary.md
└── runs/
    └── <sample>__<variant>__rXX/
        ├── command.json
        ├── stdout.log
        ├── stderr.log
        ├── report.json
        └── benchmark_result.json
```

`summary.md` 给出聚合结果。`comparisons.csv` 给出 practical 相对 legacy 的加速比、Token 减少比例和准确率变化。

## 7. 重点观察

- `wall_speedup > 1`：practical 更快。
- `token_reduction_pct > 0`：practical 使用更少 Token。
- `goal_recall_delta >= 0`：目标选择没有退化。
- `path_recall_delta >= 0`：关键路径没有退化。
- `profile_token_recall_delta > 0`：语义候选更接近人工真值。
- `success_rate`：用于识别超时、API 限流和异常退出。
- `peak_rss_mb_max`：安装 `psutil` 后可用。

不要只根据平均置信度判断准确率。置信度来自模型，人工真值召回更适合决定是否合并 practical 模式。
