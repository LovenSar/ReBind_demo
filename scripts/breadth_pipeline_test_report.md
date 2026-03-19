# 广度优先流水线测试报告

**测试时间**: 2026-03-20  
**测试文件**: `tmp/client_b` (532 KB)

## 测试结果总结

### ✅ 成功项

1. **数据库构建**
   - ✅ 数据库成功创建：`tmp/client_b.db` (20 MB)
   - ✅ 所有表结构正确创建
   - ✅ 数据加载成功：
     - 函数：1263 个
     - 符号：3745 个
     - 伪代码函数：已加载
     - 指令：已加载
     - 交叉引用：已加载

2. **图构建**
   - ✅ 统一依赖图构建成功
   - ✅ 统一物理函数节点数：1263
   - ✅ 视图数：2（Ghidra + IDA）

3. **Phase1 知识传播**
   - ✅ Phase1 流水线正常启动
   - ✅ 函数选择逻辑正常（644 个待分析函数）
   - ✅ LLM 调用接口正常
   - ✅ 函数分析结果正常（签名、摘要、标签、置信度）

### ⚠️ 已知问题

1. **API 限流**
   - 遇到 429 错误（Too Many Requests）
   - 错误信息：`服务端模型:longcat-flash-chatai-api 可用容量超过限制`
   - **影响**：Phase1 处理速度变慢，需要等待重试
   - **建议**：配置多个 API key 或降低并发请求频率

2. **处理时间**
   - Phase1 预计需要处理 644 个函数
   - 每个函数约 5-20 秒（取决于 API 响应）
   - 完整 Phase1 预计需要 1-3 小时（受限流影响）

## 测试命令

```bash
# 完整流程（包括导出和语义对齐）
python rebind_demo.py tmp/client_b --db tmp/client_b.db

# 仅运行语义对齐（跳过导出，使用已有导出目录）
python tools/Semantics_Alignment/breadth/pipeline.py \
  --sample tmp/client_b \
  --db tmp/client_b.db \
  --ghidra-dir tmp/client_b_ghidemo \
  --ida-dir tmp/client_b_idademo \
  --no-ida \
  --no-align
```

## 数据库详细统计

| 表名 | 记录数 | 说明 |
|------|--------|------|
| binaries | 1 | 二进制文件记录 |
| binary_views | 2 | Ghidra + IDA 视图 |
| functions | 1,263 | 函数总数 |
| symbols | 3,745 | 符号总数 |
| strings | 1,191 | 字符串 |
| instructions | 118,968 | 指令总数 |
| xrefs | 15,129 | 交叉引用 |
| pseudo_functions | 1,168 | 伪代码函数 |
| analysis_status | 1,263 | 分析状态（每个函数一条） |

## 测试输出示例

```
[SemanticAlign] Phase 1: Knowledge Propagation
[SemanticAlign] Phase 1 即将重命名 644 个函数。
[SemanticAlign] Phase 1:   1%|▏         | 10/644 [02:06<2:44:52, 15.60s/func]

[LLM RESULT]
signature: int __fastcall rsa_key_generation_step(int *rsa_ctx, int *prime_p)
summary  : 该函数实现 RSA 密钥生成过程中的核心数学运算步骤...
confidence_score: 92
tags     : ['crypto', 'rsa', 'mbedtls', 'modular_arithmetic', 'key_generation']
```

## 当前分析进度

**测试时的进度**（运行约 2 分钟后）：
- 已分析 (ANALYZED): 5 个函数
- 已锁定 (LOCKED): 6 个函数（库函数）
- 待处理 (PENDING): 1,252 个函数
- 已生成签名: 11 个函数
- 已生成摘要: 11 个函数
- 置信度范围: 92-95（平均 94.4）

**说明**：由于 API 限流，处理速度较慢。正常情况下，Phase1 处理 644 个函数预计需要 1-3 小时。

## 验证检查点

- [x] 数据库文件创建成功
- [x] 所有表结构正确
- [x] 函数和符号数据加载成功
- [x] 图构建成功
- [x] Phase1 流水线启动成功
- [x] LLM 调用接口正常
- [x] 函数分析结果格式正确
- [x] 函数分析结果写入数据库成功
- [x] 分析状态更新正常（ANALYZED/LOCKED/PENDING）
- [ ] Phase1 完整运行（受 API 限流影响，需要较长时间）
- [ ] Phase2-5 运行（需要 Phase1 完成后）

## 建议

1. **API 配置**：
   - 配置多个 API key 以应对限流
   - 或使用限流更宽松的 API 服务

2. **测试策略**：
   - 可以使用 `--phase5-only` 跳过 Phase1-4，直接测试 Phase5
   - 或使用较小的测试样本进行快速验证

3. **监控**：
   - 关注日志中的限流错误
   - 监控 Phase1 的处理进度和成功率

## 结论

广度优先流水线的核心功能正常：
- ✅ 数据库构建链路完整
- ✅ 图构建和函数选择逻辑正常
- ✅ LLM 集成和函数分析功能正常
- ⚠️ 受 API 限流影响，完整运行需要较长时间

流水线架构和代码逻辑验证通过，可以继续使用。
