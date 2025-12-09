# 知识传播管线模块化重构文档

## 概述

原 `knowledge_propagation.py` (4773行) 已成功拆分为9个模块，按功能职责清晰划分，大幅提升了代码的可维护性和可复用性。

## 新模块结构

```
tools/Semantics_Alignment/
├── common_utils.py                      # 共享工具和数据结构 (~450行)
├── graph_builder.py                     # 依赖图构建和评分 (~643行)
├── llm_interface.py                     # LLM交互接口 (~956行)
├── ida_synchronizer.py                  # IDA同步功能 (~1191行)
├── phase1_knowledge_propagation.py      # 第一阶段 (~493行)
├── phase2_validation.py                 # 第二阶段 (~991行)
├── phase3_global_vars.py                # 第三阶段 (~1078行)
├── phase4_local_vars.py                 # 第四阶段 (~1058行)
├── knowledge_propagation.py             # 主入口 (~340行)
└── knowledge_propagation_original_backup.py  # 原始备份
```

## 模块详细说明

### 1. common_utils.py
**职责**: 所有模块共享的基础设施

**包含内容:**
- 数据类: `FunctionNode`, `FunctionGraph`, `UnifiedFunctionNode`, `UnifiedGraph`, `GlobalVarNode`, `ValidationTask`, `LLMSettings`
- 日志配置: `setup_logging()`, `install_stdout_tee()`
- 配置加载: `load_semantics_config()`, `load_dotenv()`, `build_llm_settings()`
- Schema管理: `ensure_analysis_schema()`, `ensure_analysis_rows_for_binary()`, `load_analysis_info()`, `ensure_global_vars_schema()`
- 常量定义: `EMPTY_RESPONSE_RETRY_TIMEOUT`, `MAX_LVAR_PASSES`, `GENERIC_LVAR_PATTERN` 等
- IDA服务器连接: `wait_for_ida_server()`

### 2. graph_builder.py
**职责**: 依赖图构建和优先级评分系统

**核心函数:**
- `build_function_graph()` - 单视图函数依赖图构建
- `build_unified_graph()` - 跨视图统一依赖图构建
- `compute_function_scores()` - 单视图函数评分
- `compute_unified_scores()` - 统一图评分（考虑API调用、字符串、调用关系、已知子函数等）
- `update_scores_in_db()` / `update_unified_scores_in_db()` - 评分写回数据库
- `resolve_view_id()` - 视图ID解析
- `_get_any_function_id_for_va()` - 函数ID查找

**评分规则:**
- 外部API调用: +200 + 40×min(n, 5)
- 字符串引用: +120 + 15×min(n, 5)
- 叶子函数: +60
- 被调用次数: +6×min(n, 40)
- 已知子函数: +25×n

### 3. llm_interface.py
**职责**: 封装所有LLM交互逻辑

**核心功能:**
- `require_openai()` - OpenAI客户端初始化
- `call_llm_analyze_function()` - 通用LLM调用（带重试和超时处理）
- `build_chat_request()` - 请求构造

**Prompt构建器:**
- `build_prompt_for_function()` - 单视图函数分析prompt
- `build_unified_prompt()` - 多视图统一函数分析prompt
- `build_validation_prompt()` - 第二阶段校验prompt
- `build_global_var_prompt()` - 第三阶段全局变量分析prompt
- `build_local_var_prompt()` - 第四阶段局部变量重命名prompt
- `_build_name_alignment_prompt()` - 命名冲突解决prompt

**辅助函数:**
- `_coerce_libfunction_flag()` - 库函数标志转换
- `_extract_name_from_signature()` - 函数名提取
- `_resolve_name_collision_with_llm()` - LLM辅助命名冲突解决

### 4. ida_synchronizer.py
**职责**: IDA Pro与数据库的双向同步

**核心功能:**
- `_sync_with_ida_and_update_db()` - 函数重命名同步到IDA并刷新伪代码
- `_sync_global_with_ida_and_update_db()` - 全局变量同步
- `_sync_lvars_with_ida()` - 局部变量同步
- `_reconcile_ida_db_mismatch()` - IDA与DB差异对齐（使用LLM裁决）

**数据获取:**
- `_fetch_ida_pseudocode()` - 从IDA获取伪代码
- `_fetch_ida_function_info()` - 获取函数信息
- `_load_ida_subfunc_entries()` - 加载sub_前缀函数列表

**数据库操作:**
- `_force_ida_save_database()` - 强制IDA保存.i64
- `_save_and_refresh_pseudocode()` - 保存并刷新
- `_verify_lvar_persistence()` - 验证变量重命名持久化
- `_drop_function_record()` - 删除无效函数记录

### 5. phase1_knowledge_propagation.py
**职责**: 第一阶段 - 底向上知识传播

**核心流程:**
1. 计算所有函数的优先级评分
2. 按评分从高到低选择待分析函数
3. 构建包含已知子函数语义的prompt
4. 调用LLM进行分析
5. 将结果写入数据库
6. （可选）同步到IDA
7. 重新计算评分，继续下一轮

**主要函数:**
- `run_phase1()` - 第一阶段主流程
- `analyze_one_unified_function()` - 单个物理函数分析
- `analyze_one_function()` - 单视图函数分析（向后兼容）

**特性:**
- 支持断点续工（跳过已ANALYZED/LOCKED的函数）
- 动态优先级调整（子函数分析完成后，父函数优先级提升）
- 进度条显示
- 特殊处理sub_前缀函数

### 6. phase2_validation.py
**职责**: 第二阶段 - 调用链Top-down校验

**核心流程:**
1. 从入口点（main或高置信度函数）出发
2. 构建包含调用上下文的prompt
3. LLM校验函数语义的一致性
4. 根据置信度决定是否向下传播
5. 对失败节点进行重试

**主要函数:**
- `run_validation_phase()` - 第二阶段主流程
- `validate_one_function()` - 单个函数校验
- `_get_entry_points_for_validation()` - 选择入口点
- `_get_call_site_snippet()` - 提取调用点代码片段
- `_prompt_run_validation_with_timeout()` - 交互式倒计时

**特性:**
- 优先级队列（按路径置信度排序）
- 跳过已LOCKED节点但继续传播
- 自动重试失败节点（最多7次）
- 动态扩展进度条

### 7. phase3_global_vars.py
**职责**: 第三阶段 - 全局变量重命名与类型推断

**核心流程:**
1. 构建全局变量引用图
2. 计算变量优先级（考虑访问函数的置信度）
3. 提取变量使用代码片段
4. LLM推断变量类型和语义化名称
5. 同步到IDA并更新数据库

**主要函数:**
- `run_global_var_phase()` - 第三阶段主流程
- `build_global_var_graph()` - 构建全局变量引用图
- `compute_global_var_scores()` - 计算变量评分
- `analyze_one_global_var()` - 单个全局变量分析
- `_get_global_use_snippet()` - 提取使用代码片段

**评分规则:**
- 被高置信度函数访问: +权重×置信度
- 写访问权重=2.0，读访问权重=1.0
- 引用函数数量: +0.1×n

### 8. phase4_local_vars.py
**职责**: 第四阶段 - 局部变量易读性整理

**核心流程:**
1. 选择高置信度函数（优先IDA视图）
2. 检测通用变量名（a1, v1, var_10等）
3. LLM提供语义化重命名建议
4. 应用重命名到伪代码
5. 同步到IDA并验证持久化

**主要函数:**
- `run_local_var_phase()` - 第四阶段主流程
- `analyze_one_function_vars()` - 单个函数局部变量分析
- `apply_local_var_renames()` - 应用重命名
- `_find_generic_lvar_names()` - 检测通用变量名

**特性:**
- 仅处理通用名称变量
- 支持多轮分析（最多MAX_LVAR_PASSES轮）
- IDA持久化验证（保存后重新获取伪代码确认）

### 9. knowledge_propagation.py (重构后)
**职责**: 主入口和四阶段调度

**功能:**
- 命令行参数解析
- 配置加载（config.yaml + .env）
- 日志初始化
- 数据库连接管理
- 依次调用四个阶段
- IDA最终保存和退出

**命令行参数:**
```bash
python knowledge_propagation.py --db path/to/db \
    [--view-id ID | --tool {ghidra,ida}] \
    [--config path/to/config.yaml] \
    [--model MODEL_NAME] \
    [--max-functions N] \
    [--max-globals N] \
    [--temperature TEMP] \
    [--max-tokens N] \
    [--skip-validation] \
    [--skip-global] \
    [--skip-lvar] \
    [--max-lvar-funcs N] \
    [--dry-run] \
    [--ida-sync] \
    [--ida-url URL]
```

## 使用示例

### 作为命令行工具
```bash
# 完整的四阶段分析
python knowledge_propagation.py --db sample.db --max-functions 10 --ida-sync

# 仅第一阶段
python knowledge_propagation.py --db sample.db \
    --skip-validation --skip-global --skip-lvar

# Dry-run模式（不调用LLM）
python knowledge_propagation.py --db sample.db --dry-run
```

### 作为模块导入
```python
from knowledge_propagation import main

# 以编程方式调用
main(['--db', 'sample.db', '--max-functions', '5'])
```

### 单独使用某个阶段
```python
import sqlite3
from common_utils import build_llm_settings, load_semantics_config
from graph_builder import build_unified_graph
from phase1_knowledge_propagation import run_phase1

# 初始化
config = load_semantics_config()
llm_settings = build_llm_settings(config, None, None, None)
conn = sqlite3.connect('sample.db')
graph = build_unified_graph(conn, binary_id=1)

# 仅运行Phase 1
processed = run_phase1(
    conn=conn,
    binary_id=1,
    unified_graph=graph,
    llm_settings=llm_settings,
    max_functions=10,
    ida_sync=False,
    dry_run=False
)

print(f"Processed {processed} functions")
conn.close()
```

## 模块依赖关系

```
knowledge_propagation.py (主入口)
    │
    ├── common_utils.py
    ├── graph_builder.py
    │       └── common_utils.py
    ├── llm_interface.py
    │       └── common_utils.py
    ├── ida_synchronizer.py
    │       ├── common_utils.py
    │       └── llm_interface.py (部分函数)
    ├── phase1_knowledge_propagation.py
    │       ├── common_utils.py
    │       ├── graph_builder.py
    │       ├── llm_interface.py
    │       └── ida_synchronizer.py
    ├── phase2_validation.py
    │       ├── common_utils.py
    │       ├── graph_builder.py
    │       ├── llm_interface.py
    │       └── ida_synchronizer.py
    ├── phase3_global_vars.py
    │       ├── common_utils.py
    │       ├── graph_builder.py
    │       ├── llm_interface.py
    │       └── ida_synchronizer.py
    └── phase4_local_vars.py
            ├── common_utils.py
            ├── graph_builder.py
            ├── llm_interface.py
            └── ida_synchronizer.py
```

## 重构收益

### 1. 可维护性提升
- 原4773行拆分为9个文件，每个300-1200行
- 职责清晰，修改某个功能只需关注对应模块

### 2. 可读性增强
- 模块化结构清晰展现系统架构
- 函数名和文件名见名知意

### 3. 可测试性
- 各阶段可独立测试
- 共享组件可单独进行单元测试

### 4. 可复用性
- LLM接口可被其他工具复用
- 图构建和评分可用于其他分析任务
- IDA同步功能可独立使用

### 5. 向后兼容
- 主入口命令行接口完全保持不变
- 数据库Schema不变
- 原有功能100%保留

## 迁移指南

### 如果你有调用原knowledge_propagation.py的脚本：
**无需任何修改**，新的主入口完全兼容原有命令行接口。

### 如果你有导入knowledge_propagation.py中函数的代码：
需要更新import语句：

```python
# 旧的导入（不再可用）
from knowledge_propagation import build_unified_graph, compute_unified_scores

# 新的导入
from graph_builder import build_unified_graph, compute_unified_scores
```

**导入映射表:**
- `build_*_graph`, `compute_*_scores` → `graph_builder`
- `build_*_prompt`, `call_llm_*`, `require_openai` → `llm_interface`
- `_sync_*`, `_fetch_ida_*` → `ida_synchronizer`
- `run_*_phase`, `analyze_*` → `phase*_*.py`
- 数据类、工具函数 → `common_utils`

## 备份说明

原始完整文件已备份为:
```
knowledge_propagation_original_backup.py
```

如需回滚，可执行：
```bash
cp knowledge_propagation_original_backup.py knowledge_propagation.py
```

## 常见问题

**Q: 重构后性能有变化吗？**
A: 无变化。模块化不影响运行时性能，只是代码组织方式改变。

**Q: 可以只导入某个阶段吗？**
A: 可以。每个phase模块都可独立导入使用。

**Q: 模块间会循环导入吗？**
A: 不会。严格按依赖层次组织：common → graph/llm/ida → phases → main

**Q: 原有日志格式有变化吗？**
A: 无变化。日志输出完全保持一致。

## 后续优化建议

1. **添加单元测试**: 为各模块编写pytest测试用例
2. **类型检查**: 使用mypy进行静态类型检查
3. **文档生成**: 使用Sphinx生成API文档
4. **配置管理**: 将更多硬编码常量移至config.yaml
5. **异步支持**: 考虑使用async/await改进并发性能

---

**作者**: Claude Code
**日期**: 2025-12-09
**版本**: 2.0.0 (模块化重构版)
