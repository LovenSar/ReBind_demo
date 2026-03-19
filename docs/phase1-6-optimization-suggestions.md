# Phase1-6 算法优化建议

本文档分析 Phase1-6 的实现，识别算法层面的优化机会，并提供具体的改进方案。

## 目录

1. [Phase1: 知识传播优化](#phase1-知识传播优化)
2. [Phase2: 校验阶段优化](#phase2-校验阶段优化)
3. [Phase3: 全局变量分析优化](#phase3-全局变量分析优化)
4. [Phase4: 局部变量优化](#phase4-局部变量优化)
5. [Phase5: 注释注入优化](#phase5-注释注入优化)
6. [Phase6: 导出阶段优化](#phase6-导出阶段优化)
7. [跨阶段通用优化](#跨阶段通用优化)

---

## Phase1: 知识传播优化

### 1.1 评分算法优化

**当前问题：**
- `compute_unified_scores()` 每次全量计算所有候选函数的分数
- 增量更新只更新调用者（caller），但遗漏了被调用者（callee）的依赖关系
- 每 8 批次做一次全量重算，对于大型二进制文件（>1000 函数）开销较大

**优化方案：**

#### 方案 A: 增量评分传播（推荐）

```python
def compute_unified_scores_incremental(
    graph: UnifiedGraph,
    analysis_info: Dict[int, dict],
    *,
    changed_entry_vas: Set[int],  # 新分析的函数
    existing_scores: Dict[int, int],  # 已有分数缓存
    only_entry_vas: Optional[Iterable[int]] = None,
) -> Dict[int, int]:
    """增量更新评分：只重新计算受影响的函数。"""
    # 1. 受影响的函数集合 = 新分析函数的调用者 + 被调用者
    impacted = set(changed_entry_vas)
    for entry_va in changed_entry_vas:
        node = graph.nodes.get(entry_va)
        if node:
            # 调用者：因为子函数已分析，调用者分数应提升
            impacted.update(node.caller_vas)
            # 被调用者：如果被调用者依赖当前函数，也需要重算
            for callee_va in node.internal_callee_vas:
                callee_node = graph.nodes.get(callee_va)
                if callee_node and callee_va not in changed_entry_vas:
                    # 检查被调用者是否依赖当前函数的分析结果
                    if _has_dependency(callee_node, changed_entry_vas):
                        impacted.add(callee_va)
    
    # 2. 只重算 impacted 集合中的函数
    new_scores = {}
    for entry_va in impacted:
        if only_entry_vas and entry_va not in only_entry_vas:
            continue
        new_scores[entry_va] = _compute_single_score(
            graph, analysis_info, entry_va
        )
    
    # 3. 合并到现有分数
    existing_scores.update(new_scores)
    return existing_scores
```

**收益：** 对于 1000 函数的二进制，每次只重算 10-50 个函数，而非全部，预计提速 10-20 倍。

#### 方案 B: 分数缓存与失效策略

```python
class ScoreCache:
    """带失效策略的分数缓存。"""
    def __init__(self):
        self.scores: Dict[int, int] = {}
        self.dependencies: Dict[int, Set[int]] = {}  # entry_va -> 依赖的 entry_vas
    
    def invalidate(self, changed_entry_vas: Set[int]):
        """失效受影响的分数。"""
        to_recompute = set(changed_entry_vas)
        for entry_va in changed_entry_vas:
            # 反向查找：哪些函数依赖这个 entry_va
            for dependent_va, deps in self.dependencies.items():
                if entry_va in deps:
                    to_recompute.add(dependent_va)
        for entry_va in to_recompute:
            self.scores.pop(entry_va, None)
            self.dependencies.pop(entry_va, None)
```

### 1.2 堆排序优化

**当前问题：**
- 使用 `(neg_score, seq, entry_va)` 三元组避免重复，但每次 `heappop` 都要检查 `phase1_latest_seq`
- 堆中可能积累大量过期条目（已分析或分数已更新）

**优化方案：**

```python
# 使用延迟删除（lazy deletion）策略
class LazyHeap:
    def __init__(self):
        self.heap: List[tuple[int, int, int]] = []
        self.entry_va_to_best: Dict[int, tuple[int, int]] = {}  # entry_va -> (score, seq)
    
    def push(self, entry_va: int, score: int, seq: int):
        """只保留每个 entry_va 的最新分数。"""
        if entry_va in self.entry_va_to_best:
            old_score, old_seq = self.entry_va_to_best[entry_va]
            if seq <= old_seq:  # 旧序列号，忽略
                return
        self.entry_va_to_best[entry_va] = (score, seq)
        heapq.heappush(self.heap, (-score, seq, entry_va))
    
    def pop(self) -> Optional[tuple[int, int, int]]:
        """弹出时跳过过期条目。"""
        while self.heap:
            neg_score, seq, entry_va = heapq.heappop(self.heap)
            best_score, best_seq = self.entry_va_to_best.get(entry_va, (0, 0))
            if seq == best_seq:  # 是最新条目
                del self.entry_va_to_best[entry_va]
                return (-neg_score, seq, entry_va)
        return None
```

**收益：** 减少堆操作次数，避免重复检查，预计提速 15-30%。

### 1.3 数据库批量更新优化

**当前问题：**
- `_apply_unified_llm_result()` 中每个 `function_id` 单独执行 `UPDATE`
- 对于批处理（batch），每个函数都单独 `conn.commit()`

**优化方案：**

```python
def _apply_unified_llm_result_batch(
    conn: sqlite3.Connection,
    nodes: List[UnifiedFunctionNode],
    results: List[Dict[str, Any]],
) -> None:
    """批量更新多个函数的分析结果。"""
    cur = conn.cursor()
    updates = []
    for node, result in zip(nodes, results):
        signature = str(result.get("signature", "")).strip() or None
        summary = str(result.get("summary", "")).strip() or None
        confidence = result.get("confidence", 0)
        confidence_score = int(float(confidence) * 100) if confidence else 0
        analysis_state = "LOCKED" if result.get("libfunction") else "ANALYZED"
        phase2_pending = 1 if (not result.get("libfunction") and signature) else 0
        
        for fid in node.function_ids:
            updates.append((
                analysis_state, confidence_score, signature, summary,
                int(phase2_pending), int(fid)
            ))
    
    # 批量执行
    cur.executemany(
        """
        UPDATE analysis_status
        SET analysis_state = ?, confidence_score = ?, summary_signature = ?,
            semantic_summary = ?, phase2_pending = ?
        WHERE function_id = ?;
        """,
        updates,
    )
    conn.commit()  # 只提交一次
```

**收益：** 对于 25 函数的批次，从 25 次 `UPDATE` + 25 次 `commit` 减少到 1 次 `executemany` + 1 次 `commit`，预计提速 5-10 倍。

---

## Phase2: 校验阶段优化

### 2.1 调用链遍历优化

**当前问题：**
- `run_validation_phase()` 使用简单的优先级队列（heapq），但每次 `heappop` 后都要查询数据库检查 `_is_locked()`
- 调用链遍历是广度优先，但可能重复访问同一函数（如果它在多个调用链中）

**优化方案：**

#### 方案 A: 拓扑排序 + 动态规划

```python
def run_validation_phase_optimized(
    conn: sqlite3.Connection,
    graph: UnifiedGraph,
    entry_vas: List[int],
    ...
) -> None:
    """使用拓扑排序确保每个函数只处理一次。"""
    # 1. 构建调用图 DAG（处理循环）
    dag = _build_call_dag(graph, entry_vas)
    
    # 2. 拓扑排序
    topo_order = _topological_sort(dag)
    
    # 3. 按拓扑顺序处理，每个函数只处理一次
    for entry_va in topo_order:
        if _is_locked(entry_va):
            continue
        # 处理单个函数
        _validate_one_function(conn, graph, entry_va, ...)
```

**收益：** 避免重复处理，预计减少 20-40% 的 LLM 调用。

#### 方案 B: 调用链缓存

```python
class CallChainCache:
    """缓存已计算的调用链，避免重复遍历。"""
    def __init__(self, graph: UnifiedGraph):
        self.graph = graph
        self.chain_cache: Dict[int, List[int]] = {}  # entry_va -> 调用链
    
    def get_chain(self, entry_va: int, max_depth: int = 10) -> List[int]:
        """获取从 entry_va 开始的调用链（带缓存）。"""
        if entry_va in self.chain_cache:
            return self.chain_cache[entry_va]
        
        chain = []
        visited = set()
        def dfs(va: int, depth: int):
            if depth > max_depth or va in visited:
                return
            visited.add(va)
            chain.append(va)
            node = self.graph.nodes.get(va)
            if node:
                for callee_va in node.internal_callee_vas:
                    dfs(callee_va, depth + 1)
        
        dfs(entry_va, 0)
        self.chain_cache[entry_va] = chain
        return chain
```

### 2.2 数据库查询优化

**当前问题：**
- `_is_locked()` 每次都要执行 `SELECT COUNT(*)` 查询
- `_build_phase2_pseudocode_cache()` 一次性加载所有伪代码，内存占用大

**优化方案：**

```python
def _build_locked_cache(conn: sqlite3.Connection, graph: UnifiedGraph) -> Set[int]:
    """一次性查询所有 LOCKED 函数，构建缓存。"""
    cur = conn.cursor()
    cur.execute(
        """
        SELECT DISTINCT f.entry_va
        FROM analysis_status AS a
        JOIN functions AS f ON f.id = a.function_id
        WHERE a.analysis_state = 'LOCKED';
        """
    )
    return {int(row[0]) for row in cur.fetchall()}

# 在 run_validation_phase 开始时：
locked_cache = _build_locked_cache(conn, graph)

def _is_locked_cached(entry_va: int) -> bool:
    return entry_va in locked_cache
```

**收益：** 从每次 O(1) 查询减少到 O(1) 缓存查找，预计提速 50-100 倍（对于频繁调用）。

---

## Phase3: 全局变量分析优化

### 3.1 全局变量图构建优化

**当前问题：**
- `build_global_var_graph()` 中，对每个 xref 都要查询数据库
- `compute_global_var_scores()` 对每个全局变量都要遍历所有使用者（readers/writers）

**优化方案：**

```python
def build_global_var_graph_optimized(
    conn: sqlite3.Connection,
    binary_id: int,
    graph: UnifiedGraph,
) -> Dict[int, GlobalVarNode]:
    """使用单次 SQL 查询构建全局变量图。"""
    cur = conn.cursor()
    
    # 一次性查询所有 xrefs（只查询非 call 类型）
    cur.execute(
        """
        SELECT DISTINCT x.dst_va, x.dst_name, x.src_va, x.ref_type_raw
        FROM xrefs AS x
        JOIN binary_views AS bv ON x.view_id = bv.id
        WHERE bv.binary_id = ?
          AND x.dst_va IS NOT NULL
          AND x.ref_type_raw NOT IN ('UNCONDITIONAL_CALL', 'COMPUTED_CALL', '17', '19', '21');
        """,
        (binary_id,),
    )
    
    globals_by_addr: Dict[int, GlobalVarNode] = {}
    for dst_va, dst_name, src_va, ref_type in cur.fetchall():
        dst_va = int(dst_va)
        src_va = int(src_va) if src_va else None
        
        if dst_va not in globals_by_addr:
            globals_by_addr[dst_va] = GlobalVarNode(
                address_va=dst_va,
                names={dst_name} if dst_name else set(),
                readers=set(),
                writers=set(),
            )
        
        node = globals_by_addr[dst_va]
        if dst_name:
            node.names.add(dst_name)
        
        # 根据 ref_type 判断是读还是写
        if src_va and src_va in graph.nodes:
            if _is_write_ref(ref_type):
                node.writers.add(src_va)
            else:
                node.readers.add(src_va)
    
    return globals_by_addr
```

**收益：** 从 N 次查询减少到 1 次，预计提速 10-50 倍（取决于 xrefs 数量）。

### 3.2 评分计算优化

**当前问题：**
- `compute_global_var_scores()` 对每个全局变量都要遍历所有使用者，并查询每个使用者的 `analysis_info`

**优化方案：**

```python
def compute_global_var_scores_optimized(
    graph: UnifiedGraph,
    globals_by_addr: Dict[int, GlobalVarNode],
    analysis_info: Dict[int, dict],
) -> Dict[int, int]:
    """批量计算全局变量分数，减少重复查询。"""
    # 1. 收集所有使用者函数
    all_users: Set[int] = set()
    for node in globals_by_addr.values():
        all_users.update(node.readers | node.writers)
    
    # 2. 批量查询这些函数的置信度
    user_confidences: Dict[int, float] = {}
    for entry_va in all_users:
        fn = graph.nodes.get(entry_va)
        if not fn:
            continue
        best_conf = 0.0
        for fid in fn.function_ids:
            info = analysis_info.get(fid)
            if not info:
                continue
            st = (info.get("analysis_state") or "").upper()
            base = float(info.get("confidence_score") or 0) / 100.0
            if st == "LOCKED":
                base = max(base, 0.9)
            if base > best_conf:
                best_conf = base
        if best_conf > 0.0:
            user_confidences[entry_va] = best_conf
    
    # 3. 计算分数
    scores: Dict[int, int] = {}
    for addr, node in globals_by_addr.items():
        users = node.readers | node.writers
        if not users:
            continue
        
        total_score = 0.0
        for entry_va in users:
            conf = user_confidences.get(entry_va, 0.0)
            if conf <= 0.0:
                continue
            weight = 2.0 if entry_va in node.writers else 1.0
            total_score += weight * conf
        
        total_score += 0.1 * len(users)
        if total_score > 0.0:
            scores[addr] = int(total_score * 100)
    
    return scores
```

**收益：** 减少重复的 `analysis_info` 查询，预计提速 2-5 倍。

---

## Phase4: 局部变量优化

### 4.1 伪代码加载优化

**当前问题：**
- `_prepare_lvar_candidate()` 中，每个函数都要单独查询 `pseudo_functions`
- `_load_ida_phase4_eligible_fids()` 一次性加载所有 IDA 函数的伪代码，但可能很多不需要处理

**优化方案：**

```python
def _load_pseudocode_batch(
    conn: sqlite3.Connection,
    function_ids: Set[int],
) -> Dict[int, Tuple[str, str]]:
    """批量加载伪代码。"""
    if not function_ids:
        return {}
    
    placeholders = ",".join("?" for _ in function_ids)
    cur = conn.cursor()
    cur.execute(
        f"""
        SELECT function_id, prototype, body
        FROM pseudo_functions
        WHERE function_id IN ({placeholders});
        """,
        tuple(function_ids),
    )
    
    result = {}
    for fid, proto, body in cur.fetchall():
        result[int(fid)] = (proto or "", body or "")
    return result
```

**收益：** 从 N 次查询减少到 1 次，预计提速 5-20 倍。

### 4.2 变量名匹配优化

**当前问题：**
- `_find_generic_lvar_names()` 使用正则表达式逐个匹配，对于大函数（>100 行）可能较慢

**优化方案：**

```python
def _find_generic_lvar_names_optimized(code: str) -> Set[str]:
    """使用单次正则匹配查找所有默认变量名。"""
    # 编译一次正则，匹配所有模式
    pattern = re.compile(
        r'\b(?:a\d+|v\d+|var_\d+|arg\d+|param\d+)\b',
        re.IGNORECASE
    )
    return set(pattern.findall(code))
```

**收益：** 从多次匹配减少到一次，预计提速 3-10 倍。

---

## Phase5: 注释注入优化

### 5.1 分块处理优化

**当前问题：**
- `run_annotation_phase()` 中，大函数需要分块处理，但分块逻辑可能不够智能
- 每个分块都要单独调用 LLM，可能可以合并相似分块

**优化方案：**

```python
def _chunk_functions_intelligently(
    functions: List[Tuple[int, int]],  # (entry_va, function_id)
    max_chunk_tokens: int,
    token_estimator: Callable[[str], int],
) -> List[List[Tuple[int, int]]]:
    """智能分块：优先合并相似大小的函数。"""
    # 1. 按函数大小排序
    sized = [(token_estimator(_get_code(fid)), entry_va, fid) 
             for entry_va, fid in functions]
    sized.sort()
    
    # 2. 贪心分组：尽量填满每个 chunk
    chunks = []
    current_chunk = []
    current_tokens = 0
    
    for tokens, entry_va, fid in sized:
        if current_tokens + tokens > max_chunk_tokens and current_chunk:
            chunks.append(current_chunk)
            current_chunk = []
            current_tokens = 0
        current_chunk.append((entry_va, fid))
        current_tokens += tokens
    
    if current_chunk:
        chunks.append(current_chunk)
    
    return chunks
```

### 5.2 IDA 同步批量优化

**当前问题：**
- Phase5 中，每个函数的注释都要单独同步到 IDA
- `ida_sync_chunk_size = 120` 是硬编码的，可能不够灵活

**优化方案：**

```python
def _sync_comments_to_ida_batch(
    ida_url: str,
    comments_by_function: Dict[int, Dict[int, str]],  # function_id -> {line_num: comment}
    chunk_size: int = 120,
) -> None:
    """批量同步注释到 IDA。"""
    # 按 chunk_size 分组
    items = list(comments_by_function.items())
    for i in range(0, len(items), chunk_size):
        chunk = items[i:i + chunk_size]
        # 构建批量请求
        batch_request = {
            "method": "batch_set_comments",
            "params": {
                "comments": [
                    {"function_id": fid, "line_comments": line_comments}
                    for fid, line_comments in chunk
                ]
            }
        }
        # 发送到 IDA
        requests.post(f"{ida_url}/api", json=batch_request)
```

**收益：** 减少 HTTP 请求次数，预计提速 2-5 倍（取决于网络延迟）。

---

## Phase6: 导出阶段优化

（如果 Phase6 存在，请补充具体实现细节以便分析）

---

## 跨阶段通用优化

### 通用优化 1: 数据库连接池

**当前问题：**
- 每个阶段都创建新的数据库连接，没有复用
- SQLite 的 `WAL` 模式已启用，但可能可以进一步优化

**优化方案：**

```python
class DatabasePool:
    """数据库连接池（对于多线程场景）。"""
    def __init__(self, db_path: Path, max_connections: int = 5):
        self.db_path = db_path
        self.pool: queue.Queue = queue.Queue(maxsize=max_connections)
        for _ in range(max_connections):
            conn = sqlite3.connect(str(db_path))
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            self.pool.put(conn)
    
    def get_connection(self) -> sqlite3.Connection:
        return self.pool.get()
    
    def return_connection(self, conn: sqlite3.Connection):
        self.pool.put(conn)
```

### 通用优化 2: 分析信息缓存

**当前问题：**
- `load_analysis_info()` 每次都要查询整个 `analysis_status` 表
- 在 Phase1 中，`analysis_info` 会频繁更新，但其他阶段可能只需要读取

**优化方案：**

```python
class AnalysisInfoCache:
    """带版本号的分析信息缓存。"""
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.cache: Dict[int, dict] = {}
        self.version = 0
        self._refresh()
    
    def _refresh(self):
        """刷新缓存。"""
        cur = self.conn.cursor()
        cur.execute("SELECT function_id, analysis_state, confidence_score, ... FROM analysis_status;")
        self.cache = {int(row[0]): {...} for row in cur.fetchall()}
        self.version += 1
    
    def get(self, function_id: int) -> dict:
        return self.cache.get(function_id, {})
    
    def invalidate(self, function_ids: Set[int]):
        """失效特定函数的缓存。"""
        for fid in function_ids:
            self.cache.pop(fid, None)
```

### 通用优化 3: LLM 请求批处理与重试

**当前问题：**
- 每个阶段都可能遇到 API 限流（429 错误）
- 当前的重试逻辑可能不够智能

**优化方案：**

```python
class LLMRequestBatcher:
    """智能批处理与重试。"""
    def __init__(self, max_batch_size: int = 10, retry_delays: List[float] = [1, 2, 5, 10]):
        self.max_batch_size = max_batch_size
        self.retry_delays = retry_delays
        self.request_queue: queue.Queue = queue.Queue()
    
    def submit(self, request: Dict[str, Any], callback: Callable):
        """提交请求。"""
        self.request_queue.put((request, callback))
    
    def process_batch(self):
        """处理一批请求。"""
        batch = []
        while len(batch) < self.max_batch_size and not self.request_queue.empty():
            batch.append(self.request_queue.get())
        
        if not batch:
            return
        
        # 尝试发送
        for delay in self.retry_delays:
            try:
                results = self._send_batch([req for req, _ in batch])
                for (req, callback), result in zip(batch, results):
                    callback(result)
                return
            except requests.HTTPError as e:
                if e.response.status_code == 429:
                    time.sleep(delay)
                    continue
                raise
```

---

## 优先级建议

### 高优先级（立即实施）

1. **Phase1 数据库批量更新**（方案 1.3）
   - 实现简单，收益明显
   - 预计提速 5-10 倍

2. **Phase1 增量评分传播**（方案 1.1）
   - 算法改进，显著减少计算量
   - 预计提速 10-20 倍

3. **Phase2 数据库查询缓存**（方案 2.2）
   - 实现简单，收益明显
   - 预计提速 50-100 倍（对于频繁调用）

### 中优先级（近期实施）

4. **Phase3 全局变量图构建优化**（方案 3.1）
   - 减少数据库查询
   - 预计提速 10-50 倍

5. **Phase4 伪代码批量加载**（方案 4.1）
   - 减少数据库查询
   - 预计提速 5-20 倍

6. **Phase1 堆排序优化**（方案 1.2）
   - 减少堆操作开销
   - 预计提速 15-30%

### 低优先级（长期优化）

7. **Phase2 调用链遍历优化**（方案 2.1）
   - 需要重构较多代码
   - 预计减少 20-40% LLM 调用

8. **通用优化：数据库连接池**（通用优化 1）
   - 对于多线程场景才有明显收益
   - 单线程场景收益有限

---

## 实施建议

1. **分阶段实施**：先实施高优先级优化，验证效果后再继续
2. **性能测试**：每个优化都要在真实二进制文件上测试，记录前后对比
3. **向后兼容**：保持现有 API 不变，内部实现优化
4. **配置化**：将优化参数（如批处理大小、缓存大小）暴露到 `config.yaml`

---

## 参考实现

具体的优化实现可以参考：
- `tools/Semantics_Alignment/kp/kp_scoring.py` - 评分算法
- `tools/Semantics_Alignment/breadth/pipeline.py` - Phase1 主循环
- `tools/Semantics_Alignment/breadth/phases/phase2_validation.py` - Phase2 实现
- `tools/Semantics_Alignment/breadth/phases/phase3_globals.py` - Phase3 实现
