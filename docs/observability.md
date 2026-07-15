# 统一可观测与断点续跑（硬性要求）

- 所有阶段必须落盘中间结果，且可追溯到具体 `run_id`、时间戳、输入样本与参数快照。
- 每一步 LLM 处理必须记录请求上下文摘要、响应摘要、打分结果与决策原因。
- 日志保留级别默认：摘要日志常驻；原始请求/响应通过开关可选落盘。
- 每次路径选择、anchor 选择、回填裁决都必须落盘结构化日志（JSON Lines）。
- checkpoint 颗粒度：每一步 LLM 交互 + 每个阶段结束都落 checkpoint，至少包含阶段游标、已完成节点集合、失败重试计数、当前队列状态。
- 支持 `--resume` 断点续跑；恢复后不得重复破坏已确认结果（幂等写入）。
- 断点恢复冲突策略：参数变化默认拒绝恢复，除非显式使用 `--force-resume`。
- Phase7 深路径 checkpoint 在 `llm_step_progress.<goal/gen>` 保存 `path_vas`、
  `total_steps`、`completed_steps`；画像阶段在 `compare_progress.<entry_va>` 保存
  `new_profile` 与 `compare_result`，使恢复能够跳过已经成功的 API 调用。
- manifest 的 `resume_signature_payload` 是续跑兼容性的权威参数快照；旧 manifest
  若缺少 LLM 配置语义摘要，必须显式 `--force-resume`，不得猜测兼容。
- DB 写入必须事务化，失败回滚，并在日志中记录失败原因与恢复动作。

## 产物目录命名建议

- `runs/<sample>/<run_id>/artifacts/`
- `runs/<sample>/<run_id>/logs/`
- `runs/<sample>/<run_id>/checkpoints/`
- `runs/<sample>/<run_id>/reports/`
