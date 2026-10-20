import test from 'node:test';
import assert from 'node:assert/strict';
import {
  currentTraceGroups, EMPTY_TRACE_FILTERS, eventSummary, filterTrace, groupTrace,
  latestTracePage, normalizeTrace, pairToolCalls, payloadOf, scalar, traceRunState,
} from '../src/trace.ts';

const event = (id, kind, payload = {}, context = {}) => ({
  id, kind, payload, run_id: 'run-a', created_at: `2026-10-20T08:00:${String(id % 60).padStart(2, '0')}Z`, ...context,
});
const tool = (id, kind, payload = {}, context = {}) => event(id, kind, {
  tool: 'read_source', role: 'worker', worker_id: 'worker-1', task_id: 'task-1', attempt: 1,
  phase: 'task_execute', call_id: 'tool-0001', span_id: 'task_execute:tool-0001', ...payload,
}, context);

test('payload narrowing rejects arrays/null; summaries never stringify nested JSON', () => {
  for (const payload of [null, [], 'text', 5, true]) assert.deepEqual(payloadOf(event(1, 'custom', payload)), {});
  assert.equal(scalar({ dangerous: '<script>' }), '');
  const [entry] = normalizeTrace([event(1, 'custom', { queue: Array(500).fill({ data: 'x' }) })]);
  assert.equal(eventSummary(entry), '1 项已保存数据');
});

test('top-level persisted context takes precedence over older payload context', () => {
  const [entry] = normalizeTrace([tool(1, 'tool_call', { role: 'worker', task_id: 'old', attempt: 1 }, {
    actor_role: 'planner', task_id: 'new', session_id: 'session-a', plan_id: 'plan-a', planner_round: 3, attempt: 2,
  })]);
  assert.equal(entry.context.role, 'planner');
  assert.equal(entry.context.task, 'new');
  assert.equal(entry.context.session, 'session-a');
  assert.equal(entry.context.plan, 'plan-a');
  assert.equal(entry.context.round, '3');
  assert.equal(entry.context.attempt, '2');
});

test('reused tool IDs remain distinct across runs, roles, sessions, plans, tasks, workers and attempts', () => {
  const contexts = [
    [{}, {}],
    [{}, { run_id: 'run-b' }],
    [{ role: 'planner' }, {}],
    [{ session_id: 'session-a' }, {}],
    [{ plan_id: 'plan-a' }, {}],
    [{ task_id: 'task-2' }, {}],
    [{ worker_id: 'worker-2' }, {}],
    [{ attempt: 2 }, {}],
  ];
  const calls = contexts.map(([payload, context], index) => tool(index + 1, 'tool_call', { ...payload, args: { index } }, context));
  const results = contexts.map(([payload, context], index) => tool(index + 20, 'tool_result', { ...payload, status: 'ok', preview: `result-${index}` }, context));
  const spans = pairToolCalls(normalizeTrace([...calls, ...results]));
  assert.equal(spans.length, contexts.length);
  for (let index = 0; index < contexts.length; index++) {
    assert.equal(spans[index].call?.payload.args.index, index);
    assert.equal(spans[index].result?.payload.preview, `result-${index}`);
  }
  assert.equal(new Set(spans.map((span) => span.key)).size, contexts.length);
});

test('planner round markers scope legacy events that repeat invocation IDs', () => {
  const entries = normalizeTrace([
    event(1, 'planner_session_started', { session_id: 'planner-session' }),
    event(2, 'planner_round_started', { round: 1, plan_id: 'plan-1' }),
    tool(3, 'tool_call', { role: 'planner', task_id: null, worker_id: null, attempt: null, phase: 'planner_explore' }),
    tool(4, 'tool_result', { role: 'planner', task_id: null, worker_id: null, attempt: null, phase: 'planner_explore', preview: 'round-one' }),
    event(5, 'planner_round_committed', { plan_id: 'plan-1', round: 1 }),
    event(6, 'planner_round_started', { round: 2, plan_id: 'plan-2' }),
    tool(7, 'tool_call', { role: 'planner', task_id: null, worker_id: null, attempt: null, phase: 'planner_explore' }),
    tool(8, 'tool_result', { role: 'planner', task_id: null, worker_id: null, attempt: null, phase: 'planner_explore', preview: 'round-two' }),
  ]);
  const spans = pairToolCalls(entries);
  assert.equal(spans.length, 2);
  assert.equal(spans[0].context.plan, 'plan-1');
  assert.equal(spans[1].context.plan, 'plan-2');
  assert.equal(spans[0].result?.payload.preview, 'round-one');
  assert.equal(spans[1].result?.payload.preview, 'round-two');
});

test('even very old planner round markers without plan IDs isolate repeated calls', () => {
  const entries = normalizeTrace([
    event(1, 'planner_round_started', { round: 1 }),
    tool(2, 'tool_call', { role: 'planner', task_id: null }),
    tool(3, 'tool_result', { role: 'planner', task_id: null }),
    event(4, 'planner_round_started', { round: 2 }),
    tool(5, 'tool_call', { role: 'planner', task_id: null }),
    tool(6, 'tool_result', { role: 'planner', task_id: null }),
  ]);
  const spans = pairToolCalls(entries);
  assert.equal(spans.length, 2);
  assert.notEqual(spans[0].context.plan, spans[1].context.plan);
});

test('planner model request counters do not split the planning round into worker attempts', () => {
  const entries = normalizeTrace([
    event(1, 'planner_round_started', { plan_id: 'plan-1', round: 1 }),
    event(2, 'agent_phase', { role: 'planner', phase: 'planner_explore', plan_id: 'plan-1' }),
    event(3, 'model_request', { role: 'planner', attempt: 1, phase: 'planner_explore', plan_id: 'plan-1' }),
    event(4, 'model_request', { role: 'planner', attempt: 2, phase: 'planner_explore', plan_id: 'plan-1' }),
  ]);
  assert.equal(groupTrace(entries).length, 1);
  assert.ok(entries.every((entry) => entry.context.attempt === ''));
});

test('span IDs distinguish calls; repeated same-scope IDs are never overwritten', () => {
  const spans = pairToolCalls(normalizeTrace([
    tool(1, 'tool_call', { span_id: 'a' }), tool(2, 'tool_call', { span_id: 'b' }),
    tool(3, 'tool_result', { span_id: 'b', preview: 'second' }), tool(4, 'tool_result', { span_id: 'a', preview: 'first' }),
    tool(5, 'tool_call'), tool(6, 'tool_result'), tool(7, 'tool_call'), tool(8, 'tool_result'),
  ]));
  assert.equal(spans.length, 4);
  assert.equal(spans[0].result?.payload.preview, 'first');
  assert.equal(spans[1].result?.payload.preview, 'second');
  assert.equal(spans[2].call?.event.id, 5);
  assert.equal(spans[3].call?.event.id, 7);
});

test('call IDs without spans pair only in the same phase; uncorrelated history remains separate', () => {
  const spans = pairToolCalls(normalizeTrace([
    tool(1, 'tool_call', { span_id: undefined }), tool(2, 'tool_result', { span_id: undefined }),
    tool(3, 'tool_call', { span_id: undefined, phase: 'prepare' }),
    tool(4, 'tool_result', { span_id: undefined, phase: 'verdict' }),
    tool(5, 'tool_call', { span_id: undefined, call_id: undefined }),
    tool(6, 'tool_result', { span_id: undefined, call_id: undefined }),
  ]));
  assert.equal(spans.length, 5);
  assert.ok(spans[0].call && spans[0].result);
  assert.equal(spans.filter((span) => span.call && !span.result).length, 2);
  assert.equal(spans.filter((span) => span.result && !span.call).length, 2);
});

test('saved zero duration is retained, timestamp fallback and malformed timestamps are safe', () => {
  const spans = pairToolCalls(normalizeTrace([
    tool(1, 'tool_call'), tool(2, 'tool_result', { duration_ms: 0 }),
    tool(3, 'tool_call'), tool(4, 'tool_result'),
    tool(5, 'tool_call', {}, { created_at: 'invalid' }), tool(6, 'tool_result'),
  ]));
  assert.equal(spans[0].durationMs, 0);
  assert.equal(spans[1].durationMs, 1000);
  assert.equal(spans[2].durationMs, null);
});

test('filters and latest-50 paging keep tool pairs intact across the boundary', () => {
  const entries = normalizeTrace([
    tool(1, 'tool_call'),
    ...Array.from({ length: 60 }, (_, index) => event(index + 2, 'model_request', { role: 'host' })),
    tool(62, 'tool_result', { status: 'ok', preview: 'saved' }),
  ]);
  const latest = latestTracePage(entries);
  assert.equal(latest.length, 50);
  assert.equal(latest[0].event.id, 13);
  assert.equal(latestTracePage(entries, 100).length, 62);
  assert.deepEqual(latestTracePage(entries, 0), []);
  const groups = groupTrace(latest, entries);
  const toolRows = groups.flatMap((group) => group.phases.flatMap((phase) => phase.rows)).filter((row) => row.type === 'tool');
  assert.equal(toolRows.length, 1);
  assert.equal(toolRows[0].span.call.event.id, 1);
  assert.equal(toolRows[0].span.result.event.id, 62);
  const filtered = filterTrace(entries, { ...EMPTY_TRACE_FILTERS, role: 'worker', task: 'task-1', worker: 'worker-1', attempt: '1', kind: 'tool_result' });
  assert.deepEqual(filtered.map((entry) => entry.event.id), [62]);
});

test('parallel current workers expand while old attempts and finished planning remain historical', () => {
  const entries = normalizeTrace([
    tool(1, 'tool_call', { attempt: 1 }),
    event(2, 'planner_task_requeued', { task_id: 'task-1', worker_id: 'worker-1', attempt: 1 }),
    tool(3, 'tool_call', { attempt: 2 }),
    tool(4, 'tool_call', { task_id: 'task-2', worker_id: 'worker-2' }),
    event(5, 'planner_round_committed', { role: 'planner', plan_id: 'plan-1', round: 1 }),
  ]);
  const groups = groupTrace(entries);
  const current = currentTraceGroups(groups, true);
  const active = groups.filter((group) => current.has(group.key));
  assert.equal(active.length, 2);
  assert.ok(active.every((group) => group.context.role === 'worker'));
  assert.ok(!active.some((group) => group.context.task === 'task-1' && group.context.attempt === '1'));
  assert.equal(currentTraceGroups(groups, false).size, 0);
});

test('real Planner lifecycle retires queue/session placeholders when plans and workers start', () => {
  const lifecycle = [
    event(1, 'planner_run_queued', { objective: '检查上传路径安全边界' }),
    event(2, 'run_started', { mode: 'planner_v2' }),
    event(3, 'planner_session_started', { session_id: 'planner:r', max_planner_rounds: 8 }),
    event(4, 'planner_round_started', { session_id: 'planner:r', plan_id: 'plan-1', round: 1, revision: 1 }),
    event(5, 'agent_phase', { role: 'planner', session_id: 'planner:r', plan_id: 'plan-1', phase: 'planner_explore' }),
    event(6, 'tool_call', { role: 'planner', session_id: 'planner:r', plan_id: 'plan-1', phase: 'planner_explore', tool: 'project_overview', call_id: 'planner-tool-0001' }),
    event(7, 'tool_result', { role: 'planner', session_id: 'planner:r', plan_id: 'plan-1', phase: 'planner_explore', tool: 'project_overview', call_id: 'planner-tool-0001', status: 'ok' }),
    event(8, 'planner_round_committed', { plan_id: 'plan-1', round: 1, revision: 1, goal_state: 'continue' }),
    event(9, 'planner_task_started', { task_id: 'task-a', task_key: 'upload-path', worker_id: 'local:r:0', attempt: 1 }),
    event(10, 'planner_task_completed', { task_id: 'task-a', task_key: 'upload-path', worker_id: 'local:r:0', attempt: 1 }),
    event(11, 'planner_round_started', { session_id: 'planner:r', plan_id: 'plan-2', round: 2, revision: 2 }),
  ];
  const current = (count) => {
    const groups = groupTrace(normalizeTrace(lifecycle.slice(0, count)));
    const keys = currentTraceGroups(groups, true);
    return groups.filter((group) => keys.has(group.key));
  };
  assert.equal(normalizeTrace(lifecycle)[0].context.role, 'host');
  assert.deepEqual(current(1), []);
  const session = current(3);
  assert.equal(session.length, 1);
  assert.equal(session[0].context.session, 'planner:r');
  assert.equal(session[0].context.plan, '');
  const firstRound = current(7);
  assert.equal(firstRound.length, 1);
  assert.equal(firstRound[0].context.plan, 'plan-1');
  assert.equal(firstRound[0].context.session, 'planner:r');
  assert.ok(!firstRound.some((group) => group.entries.some((entry) => entry.event.kind === 'planner_session_started')));
  const worker = current(9);
  assert.equal(worker.length, 1);
  assert.equal(worker[0].context.role, 'worker');
  assert.equal(worker[0].context.task, 'task-a');
  const secondRound = current(11);
  assert.equal(secondRound.length, 1);
  assert.equal(secondRound[0].context.plan, 'plan-2');
  assert.equal(secondRound[0].context.round, '2');
  assert.equal(currentTraceGroups(groupTrace(normalizeTrace(lifecycle)), false).size, 0);
});

test('queued projections retain explicit top-level roles but never become active executions', () => {
  const entries = normalizeTrace([
    event(1, 'planner_run_queued', { role: 'worker' }, { actor_role: 'planner' }),
    event(2, 'planner_run_queued', {}, { actor_role: 'worker', run_id: 'run-b' }),
  ]);
  assert.equal(entries[0].context.role, 'planner');
  assert.equal(entries[1].context.role, 'worker');
  assert.equal(currentTraceGroups(groupTrace(entries), true).size, 0);
});

test('two recon invocations in one Planner round isolate reset spans, steps and lifecycle', () => {
  const recon = (id, kind, payload = {}) => event(id, kind, {
    role: 'recon', session_id: 'planner:r', plan_id: 'plan-1', ...payload,
  });
  const source = [
    event(1, 'planner_session_started', { session_id: 'planner:r' }),
    event(2, 'planner_round_started', { session_id: 'planner:r', plan_id: 'plan-1', round: 1 }),
    recon(3, 'recon_started', { round: 1, question: '定位路由定义' }),
    recon(4, 'recon_phase', { phase: 'recon_explore' }),
    recon(5, 'model_request', { phase: 'recon_explore', attempt: 1 }),
    recon(6, 'tool_call', { phase: 'recon_explore', call_id: 'recon-tool-0001', span_id: 'recon_explore:recon-tool-0001', tool: 'read_source' }),
    recon(7, 'tool_result', { phase: 'recon_explore', call_id: 'recon-tool-0001', span_id: 'recon_explore:recon-tool-0001', preview: 'first reconnaissance' }),
    recon(8, 'agent_code', { phase: 'recon_explore', step: 1, code: "print(read_source('routes.py'))", logs: 'first output', is_final: true }),
    recon(9, 'recon_terminal', { reason: 'completed' }),
    recon(10, 'recon_started', { round: 1, question: '检查存储配置' }),
    recon(11, 'model_request', { phase: 'recon_explore', attempt: 1 }),
    recon(12, 'tool_call', { phase: 'recon_explore', call_id: 'recon-tool-0001', span_id: 'recon_explore:recon-tool-0001', tool: 'read_source' }),
    recon(13, 'tool_result', { phase: 'recon_explore', call_id: 'recon-tool-0001', span_id: 'recon_explore:recon-tool-0001', preview: 'second reconnaissance' }),
    recon(14, 'agent_code', { phase: 'recon_explore', step: 1, code: "print(read_source('settings.py'))", logs: 'second output' }),
  ];
  const entries = normalizeTrace(source);
  const reconEntries = entries.filter((entry) => entry.context.role === 'recon');
  assert.ok(reconEntries.every((entry) => entry.context.attempt === ''));
  assert.ok(reconEntries.every((entry) => entry.context.round === '1'));
  const spans = pairToolCalls(entries);
  assert.equal(spans.length, 2);
  assert.equal(spans[0].result.payload.preview, 'first reconnaissance');
  assert.equal(spans[1].result.payload.preview, 'second reconnaissance');
  assert.notEqual(spans[0].context.invocation, spans[1].context.invocation);
  const groups = groupTrace(entries);
  const reconnaissance = groups.filter((group) => group.context.role === 'recon');
  assert.equal(reconnaissance.length, 2);
  assert.equal(reconnaissance[0].finished, true);
  assert.equal(reconnaissance[1].finished, false);
  const current = currentTraceGroups(groups, true);
  assert.ok(!current.has(reconnaissance[0].key));
  assert.ok(current.has(reconnaissance[1].key));
});

test('phase replay cannot join a new result to a dangling invocation from an earlier phase entry', () => {
  const entries = normalizeTrace([
    tool(1, 'agent_phase', { phase: 'explore' }),
    tool(2, 'tool_call', { phase: 'explore', span_id: 'explore:tool-0001' }),
    tool(3, 'agent_phase', { phase: 'verdict' }),
    tool(4, 'agent_phase', { phase: 'explore' }),
    tool(5, 'tool_call', { phase: 'explore', span_id: 'explore:tool-0001' }),
    tool(6, 'tool_result', { phase: 'explore', span_id: 'explore:tool-0001', preview: 'new phase output' }),
  ]);
  const spans = pairToolCalls(entries);
  assert.equal(spans.length, 2);
  assert.equal(spans[0].result, undefined);
  assert.equal(spans[1].result.event.id, 6);
  assert.equal(groupTrace(entries)[0].phases.length, 3);
});

test('code actions preserve saved code/log/error and phase final does not settle the audit', () => {
  const code = 'print("源码观察")\n'.repeat(500);
  const logs = '观察结果\n'.repeat(1000);
  const payload = { phase: 'task_execute', step: 1, code, logs, code_bytes: 24000, truncated: true, is_final: true, error: '可复核的解释器错误', usage: { requests: 2, tool_calls: 3 } };
  const entries = normalizeTrace([tool(1, 'agent_code', payload), tool(2, 'agent_code', { ...payload, error: null, step: 1 })]);
  const groups = groupTrace(entries);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].finished, false);
  const rows = groups[0].phases[0].rows;
  assert.equal(rows.length, 2);
  assert.notEqual(rows[0].key, rows[1].key);
  assert.equal(rows[0].entry.payload.code, code);
  assert.equal(rows[0].entry.payload.logs, logs);
  assert.equal(rows[0].entry.payload.error, '可复核的解释器错误');
  assert.match(eventSummary(entries[0]), /服务端已截断/);
  assert.match(eventSummary(entries[0]), /执行报错/);
  assert.match(eventSummary(entries[1]), /本阶段已提交/);
  assert.equal(traceRunState(entries, 'running'), 'running');
  assert.equal(pairToolCalls(entries).length, 0);
});

test('pause/resume remains reversible and historical terminal records stay collapsed', () => {
  const paused = normalizeTrace([event(1, 'run_started'), event(2, 'run_paused')]);
  assert.equal(traceRunState(paused), 'paused');
  assert.equal(traceRunState(paused, 'paused'), 'paused');
  const resumed = normalizeTrace([...paused.map((entry) => entry.event), event(3, 'run_resumed')]);
  assert.equal(traceRunState(resumed), 'running');
  assert.equal(traceRunState(resumed, 'running'), 'running');
  for (const status of ['completed', 'inconclusive', 'unreachable', 'cancelled']) {
    assert.equal(traceRunState(resumed, status), 'terminal');
  }
  assert.equal(traceRunState(normalizeTrace([event(4, 'run_completed')])), 'terminal');
  assert.equal(traceRunState(normalizeTrace([event(5, 'goal_inconclusive')])), 'terminal');
});

test('coverage, pinned reuse and budget withdrawal summaries remain bounded and distinguish navigation', () => {
  const entries = normalizeTrace([
    event(1, 'planner_coverage_prepared', { coverage: { files_read: 8, files_total: 100, read_paths: Array(500).fill('source.py') } }),
    event(2, 'planner_investigation_reused', { topic: '读取项目布局'.repeat(100), investigation_id: 'pin-1', pinned_round: 1, round: 2 }),
    event(3, 'planner_tools_withdrawn', { reason: 'budget', usage: { tool_calls: 4 }, phase: 'planner_decision' }),
    event(4, 'recon_brief_prepared', { brief: { reading_plan: Array(100).fill({ path: 'source.py' }) } }),
  ]);
  assert.match(eventSummary(entries[0]), /8 \/ 100.*导航统计/);
  assert.match(eventSummary(entries[1]), /未重跑/);
  assert.ok(eventSummary(entries[1]).length < 130);
  assert.equal(eventSummary(entries[2]), 'budget');
  assert.match(eventSummary(entries[3]), /导航线索/);
  assert.ok(entries.every((entry) => !eventSummary(entry).includes('{')));
});

test('explicit execution IDs isolate clipped recon history without relying on its start marker', () => {
  const recon = (id, kind, invocation, preview) => tool(id, kind, {
    role: 'recon', task_id: null, worker_id: null, attempt: null,
    session_id: 'planner-session', plan_id: 'plan-a', phase: 'recon_explore',
    agent_invocation_id: invocation, request_index: 1, preview,
  });
  const entries = normalizeTrace([
    recon(1, 'tool_call', 'recon-one'), recon(2, 'tool_call', 'recon-two'),
    recon(3, 'tool_result', 'recon-two', 'second'), recon(4, 'tool_result', 'recon-one', 'first'),
  ]);
  const spans = pairToolCalls(entries);
  assert.equal(spans.length, 2);
  assert.equal(spans[0].result.payload.preview, 'first');
  assert.equal(spans[1].result.payload.preview, 'second');
  assert.equal(spans[0].context.invocationId, 'recon-one');
  assert.notEqual(spans[0].key, spans[1].key);
});

test('model request ordinals remain separate from worker attempts and repeated span IDs', () => {
  const source = [
    tool(1, 'model_request', { agent_invocation_id: 'worker-run', request_index: 8, attempt: 3 }),
    tool(2, 'tool_call', { agent_invocation_id: 'worker-run', request_index: 8, attempt: 3 }),
    tool(3, 'model_request', { agent_invocation_id: 'worker-run', request_index: 9, attempt: 3 }),
    tool(4, 'tool_call', { agent_invocation_id: 'worker-run', request_index: 9, attempt: 3 }),
    tool(5, 'tool_result', { agent_invocation_id: 'worker-run', request_index: 9, attempt: 3, preview: 'new step' }),
  ];
  const entries = normalizeTrace(source);
  assert.equal(entries[0].context.attempt, '3');
  assert.equal(entries[0].context.requestIndex, '8');
  assert.equal(groupTrace(entries).length, 1);
  const spans = pairToolCalls(entries);
  assert.equal(spans.length, 2);
  assert.equal(spans[0].result, undefined);
  assert.equal(spans[1].result.payload.preview, 'new step');
});

test('old worker logs infer model steps without treating the task retry as a request ordinal', () => {
  const entries = normalizeTrace([
    tool(1, 'model_request', { attempt: 3 }), tool(2, 'tool_call', { attempt: 3 }),
    tool(3, 'tool_result', { attempt: 3 }), tool(4, 'model_request', { attempt: 3 }),
    tool(5, 'tool_call', { attempt: 3 }), tool(6, 'tool_result', { attempt: 3 }),
  ]);
  assert.ok(entries.every((entry) => entry.context.attempt === '3'));
  assert.deepEqual(entries.map((entry) => entry.context.requestIndex), ['1', '1', '1', '2', '2', '2']);
  assert.equal(pairToolCalls(entries).length, 2);
});

test('duplicate persisted frames never duplicate a tool row or public progress paragraph', () => {
  const progress = tool(1, 'audit_progress', { message: '正在核对上传入口与文件名处理。', agent_invocation_id: 'worker-run', request_index: 1 });
  const call = tool(2, 'tool_call', { agent_invocation_id: 'worker-run', request_index: 1 });
  const result = tool(3, 'tool_result', { agent_invocation_id: 'worker-run', request_index: 1 });
  const entries = normalizeTrace([progress, call, progress, result, call, result]);
  assert.equal(entries.length, 3);
  assert.equal(pairToolCalls(entries).length, 1);
  assert.equal(eventSummary(entries[0]), '正在核对上传入口与文件名处理。');
  assert.equal(normalizeTrace([progress, { ...progress, run_id: 'another-run' }]).length, 2);
});
