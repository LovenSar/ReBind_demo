# Phase7 实战准确度模式

`practical_engine.py` 在不修改旧入口行为的前提下，为 Phase7 安装一组保守补丁。这个模式更适合真实样本的初步定位、调用链梳理和候选语义生成。

## 运行方式

```bash
python tools/Semantics_Alignment/depth/practical_engine.py \
  /path/to/sample.bin \
  --db /path/to/sample.db \
  --goal-keyword auth \
  --practical-node-budget 24 \
  --practical-evidence-threshold 0.25 \
  --practical-min-signals 1
```

原有 Phase7 参数仍然有效。实战入口会接管 `lambda` 的含义。`lambda` 会变成函数节点预算，不再表示混合图距离。

## 行为变化

### 调用图负责扩点

路径邻域只沿以下关系扩展：

- caller
- callee

以下关系不再扩大路径范围：

- data
- string
- global
- indirect

这些信息仍然会进入证据上下文。这样可以降低公共字符串、日志函数和共享全局变量带来的语义污染。

### caller 与 callee 共享预算

根节点占用一个预算。剩余预算会在 caller 侧和 callee 侧之间分配。某一侧没有足够节点时，剩余容量会转移到另一侧。

默认节点预算为 `24`。大型程序可以提高到 `40` 或 `64`。高度混淆的程序应该先保持较小预算。

### 深路径 Prompt 增加静态证据

每一步会增加以下内容：

- 外部 API
- 字符串
- 全局变量地址和引用次数
- caller/callee 邻居名称
- 数据库中已有的高置信语义

模型必须把无法验证的协议、算法、输入格式和安全结论标记为 `UNKNOWN`。

### Profile 回填增加独立门槛

新 Profile 只有同时满足以下条件时才会被选中：

1. LLM 选择新 Profile。
2. 新旧分差达到 `compare_min_delta`。
3. 新 Profile 状态为 `ok`。
4. 新语义与 API、字符串或调用邻居存在静态证据重合。

结果的 `selection.evidence_gate` 会记录：

- 静态证据分数
- 独立证据数量
- 重合 token
- 拒绝原因

建议继续保持 `--no-apply-db`。批量样本验证通过后，再开启数据库回填。

## 参数

| 参数 | 默认值 | 说明 |
|---|---:|---|
| `--practical-node-budget` | 24 | 每个根节点的函数邻域预算 |
| `--practical-evidence-threshold` | 0.25 | 新 Profile 的静态证据最低分数 |
| `--practical-min-signals` | 1 | 至少需要几类独立证据 |
| `--practical-min-profile-confidence` | 70 | Profile 完整度评分使用的最低置信度 |

## 建议评估方法

至少准备两组结果：

```text
legacy engine
practical engine
```

对同一批样本记录：

- 关键函数命中率
- 有效调用路径命中率
- 函数命名准确率
- 人工修正次数
- Prompt token 总量
- API 调用次数
- 总运行时间
- 错误数据库回填次数

首轮评估应该关闭数据库回填。人工确认结果后，再统计可接受率。
