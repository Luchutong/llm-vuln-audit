# POC 关闭确认与终审接续修复

针对 [`e06a8b4849815d2f894b420e354a6bfd`](http://127.0.0.1:5173/#run/e06a8b4849815d2f894b420e354a6bfd) 的 [POC 交接故障](poc-handoff-diagnosis-2026-11-10.md)。本次保留原运行、验证观测和冻结报告，通过关联任务接续未完成复测。

## 关闭确认

新增 [poc_context.py](../backend/audit/poc_context.py)，让上下文清理走有总截止时间的协议：

- 15 秒总窗口内，针对同一个 context ID 最多三次幂等 DELETE；状态 GET 发生瞬时失败时继续确认。连接失败后仅重建宿主自己拥有的 HTTP 连接，不重放任何 POC 作业。
- 关闭响应若明确包含本 context 的 `closed / active=0 / pending_jobs=0`，可直接完成交接，避免再发一个不必要且可能失败的 GET。DELETE 响应丢失时可由 GET 核对其已生效。
- 将“实际占用 busy”“runner 明确 unresolved”和“状态未知 unknown”分开记录。错误类型、状态码、尝试数与耗时脱敏保存；不保存令牌、异常正文或请求地址。
- 缺少计数、返回别的 context ID、负数或布尔作业数都不能授权复位。GET 的未知上下文不能替代 DELETE 的取消确认，以免延迟 CREATE 在查询后才生效；旧 runner 的未知 ID DELETE 确认会规范化零待处理作业。
- CREATE 发出前保留该 context 的所有权；清理任务被明确管理和等待，取消时不遗留孤立的 shield 请求。没有尝试创建上下文的项不再额外关闭随机 ID。
- 只有确认关闭后才清除上一 context，并开始下一次复位。真实活动或待处理作业仍然阻塞复位。

新增 `poc_context_closed`、`poc_context_close_unconfirmed` 事件及界面状态，分别显示已释放和暂未确认。已保存 verified 的实验事实不会因为清理失败被改写为未验证。

## POC 失败后的收尾

[worker.py](../backend/audit/worker.py) 在 discovery-first 的验证边界捕获 `environment_unavailable`，停止后续实验并保存 `workflow.poc_stop`，然后继续统一终审。该停止标记在同一任务暂停恢复后仍生效，不重复尝试环境故障项。

终审继续使用源码、已完成实验及原有未决状态；未使用的 POC 请求按既有政策转入终审。`required` 的完整性要求保持有效：环境故障仍使整轮 inconclusive，不能借静态 accept 把所选未完成 POC 标成成功。硬预算到期、取消和其它停止原因继续向外传播，不绕过全局闸门。此路径同时覆盖宿主队列和旧 discovery-first 调度。

持续 SDK 会话的 usage 事件保留原始 `is_error`，并补充 `terminal_reason`、`host_interrupt`、`expected_interrupt` 和 `item_published`，区分“发布后的宿主预期中断”与供应商失败。

## 验证与运行

测试使用离线模型、模拟传输或隔离 SQLite；不提交真实 runner 作业。覆盖 DELETE 已生效但响应超时、首次 GET 失败后恢复、真实占用、伪造关闭响应、未知上下文的取消保护、取消清理、两条 finding 之间的复位顺序、required 环境异常后的终审批次以及硬预算优先级。

全套后端 2492 项通过；后补两项未知上下文边界测试在最终 86 项生命周期回归中通过。前端 130 项、浏览器 27 项及生产构建通过。原始 Vite 包大小提示仍存在，不影响构建。

真实数据库副本注入 `target_reset_blocked` 后进入 review，已提交 **11** 个 final 批次，覆盖 **19** 条 finding 和 **3** 条方向，所有离线判决刻意保留 needs_evidence，不预先接受漏洞。该有界回放在确认阶段接续后停止，没有声称完成所有风险审查；完整终态收尾由两种调度模式的回归测试覆盖。见[副本回放](validation/poc-handoff-replay-2026-11-10.json)及[测试记录](validation/poc-handoff-repair-tests-2026-11-10.json)。

实际接续使用本轮未用额度作为新任务上限：**332 次模型请求 / 3937 次工具 / 5427 秒**。继承全部 28 条候选与源码证据，复用原先 verified 的首项，只选择另外 27 项复测，再统一终审；不会重新执行已确认首项来重复提权。该接续不消除原有源码方向阻塞，最终报告仍须明确这些限制。

已于北京时间 **2026-11-10 15:33:14** 启动[关联复测记录 `8a035cfcda5254238742ea8af118f869`](http://127.0.0.1:5173/#run/8a035cfcda5254238742ea8af118f869)。首个新增 POC 已保存 verified；**15:36:46** 确认其上下文 closed、活动与待处理作业均为零，随后复位，**15:37:01** 已领取下一项并绑定新的 context ID，没有重现 `target_reset_blocked`。此时累计 2 条 verified（含复用的 1 条），整轮仍在运行，不能据此宣称全部复测或终审完成。见[真实接续验证](validation/poc-handoff-live-continuation-2026-11-10.json)。
