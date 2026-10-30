import test from 'node:test';
import assert from 'node:assert/strict';
import { diagnosticGroups, diagnosticIncidents, toolOutcome, verificationExecution, verificationJobOutcome } from '../src/diagnostics.ts';

test('completed jobs with insufficient citations do not claim the vulnerability failed to trigger', () => {
  assert.equal(verificationExecution({ execution_status: 'not_triggered', status: 'inconclusive' }), '执行完成，尚无确定验证结论');
  for (const status of ['verified', 'rejected', 'inconclusive']) {
    assert.equal(verificationExecution({ execution_status: 'success', status }), '作业执行成功');
  }
});

test('successful jobs with an interrupted conclusion keep execution and verification separate', () => {
  assert.equal(verificationExecution({ execution_status: 'conclusion_error', status: 'inconclusive' }), '已有成功作业，验证结论阶段未完成');
});

test('SDK execution failures stay distinct from valid negative experiments, including old records', () => {
  const label = '验证实验因模型或运行时异常中断，已保存作业，结论仍未决';
  assert.equal(verificationExecution({ execution_status: 'execution_error', status: 'inconclusive' }), label);
  assert.equal(verificationExecution({ execution_status: 'not_triggered', status: 'inconclusive',
    agent: { usage: { execute_reason: 'sdk_api_error' } } }), label);
  assert.equal(verificationExecution({ execution_status: 'success', status: 'verified',
    agent: { usage: { execute_reason: 'sdk_api_error' } } }), '作业执行成功');
});
import { projectActivity, groupCompletedTools } from '../src/activity.ts';

const event = (id, kind, payload = {}) => ({ id, kind, run_id: 'run-a', created_at: `2026-10-23T15:00:${String(id % 60).padStart(2, '0')}Z`,
  payload: { role: 'worker', task_id: 'task-a', attempt: 1, agent_invocation_id: 'worker-a', request_index: 1, phase: 'task_execute', ...payload } });

test('queue heartbeats collapse per finding while individual publications remain visible', () => {
  const items = projectActivity([
    event(1, 'poc_queue_item_started', { role: 'poc', finding_id: 'f1', remaining: 2 }),
    event(2, 'poc_queue_heartbeat', { role: 'poc', finding_id: 'f1', elapsed_seconds: 20 }),
    event(3, 'poc_queue_heartbeat', { role: 'poc', finding_id: 'f1', elapsed_seconds: 700, soft_limit_exceeded: true }),
    event(4, 'poc_queue_item_published', { role: 'poc', finding_id: 'f1', status: 'verified' }),
    event(5, 'poc_queue_item_started', { role: 'poc', finding_id: 'f2', remaining: 1 }),
    event(6, 'poc_queue_heartbeat', { role: 'poc', finding_id: 'f2', elapsed_seconds: 3 }),
  ], null).filter(item => item.type === 'message');
  assert.equal(items.filter(item => item.kind === 'poc_queue_heartbeat').length, 2);
  assert.match(items.find(item => item.entry.event.id === 3).secondary, /验证继续.*不代表漏洞不成立/);
  assert.match(items.find(item => item.kind === 'poc_queue_item_published').text, /已验证.*已入库/);
});

test('POC gateway errors show their HTTP status and failure category in the public activity', () => {
  const items = projectActivity([event(1, 'poc_gateway_error', { role: 'poc', http_status: 429,
    code: 'upstream_rejected', provider_error_code: 'AccountQuotaExceeded' })], null);
  const warning = items.find(item => item.type === 'message' && item.title === 'POC 模型请求异常');
  assert.ok(warning);
  assert.match(warning.text, /HTTP 429/);
  assert.match(warning.text, /AccountQuotaExceeded/);
});

test('POC stream failures explain timeout versus interrupted generation without unknown placeholders', () => {
  for (const [code, label] of [['stream_request_timeout', '单请求时限'], ['stream_idle_timeout', '没有新数据'],
    ['stream_incomplete', '提前断开'], ['stream_timeout', '旧记录']]) {
    const items = projectActivity([event(1, 'poc_gateway_error', { role: 'poc', http_status: 200,
      code, provider_error_code: 'unknown', elapsed_seconds: 180, received_bytes: 234 })], null);
    const warning = items.find(item => item.type === 'message' && item.title === 'POC 模型请求异常');
    assert.ok(warning);
    assert.ok(warning.text.includes(label));
    assert.doesNotMatch(warning.text, /unknown/);
    assert.match(warning.secondary, /180\.0 秒/);
    assert.match(warning.secondary, /234 字节/);
    assert.match(warning.secondary, /HTTP 200 仅表示/);
  }
});

test('JSON validation rejection and its retry count once and recover after a committed planner decision', () => {
  const planner = (id, kind, payload = {}) => event(id, kind, { role: 'planner', phase: 'planner_publish',
    agent_invocation_id: 'planner-json', task_id: undefined, ...payload });
  const incidents = diagnosticIncidents([
    planner(1, 'model_response', { response_format: 'json' }),
    planner(2, 'agent_output_rejected', { error_code: 'invalid_output', hint: '任务路径不在冻结快照内' }),
    planner(3, 'model_retry'),
    planner(4, 'model_response', { request_index: 2, response_format: 'json' }),
    planner(5, 'planner_agent_terminal', { request_index: 2, reason: 'completed' }),
  ]);
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0].requestIndex, '1');
  assert.equal(incidents[0].recovery.event.id, 5);
  assert.deepEqual(diagnosticGroups(incidents).map(({ errors, recovered }) => ({ errors, recovered })), [{ errors: 1, recovered: 1 }]);
});

test('request diagnostics merge nested tool/interpreter errors, duplicate frames and host summaries', () => {
  const events = [event(1, 'model_request'), event(2, 'tool_result', { tool: 'read_source', status: 'invalid_arguments',
    error_code: 'invalid_arguments', error: 'start must be an integer', args: { path: 'src/file.php', start: true } }),
    event(3, 'agent_code', { error: 'tool call failed' }), event(4, 'agent_execution_error', { error_code: 'invalid_arguments' }),
    event(5, 'agent_error_summary', { errors: 3 }), event(6, 'agent_code', { request_index: 2, code: 'print("ok")' })];
  const incidents = diagnosticIncidents([...events, events[1], events[2]]);
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0].entries.length, 3);
  assert.equal(incidents[0].recovery.event.id, 6);
  assert.deepEqual(diagnosticGroups(incidents).map(({ errors, recovered }) => ({ errors, recovered })), [{ errors: 1, recovered: 1 }]);
});

test('successful tools alone and successful code from another invocation do not imply recovery', () => {
  const incidents = diagnosticIncidents([event(1, 'agent_parse_error', { category: 'incomplete_code' }),
    event(2, 'tool_result', { status: 'ok', tool: 'read_source' }),
    event(3, 'agent_code', { request_index: 2, agent_invocation_id: 'worker-b' }),
    event(4, 'agent_code', { request_index: 3, role: 'poc', phase: 'poc_execute' })]);
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0].recovery, undefined);
});

test('recovery can cross phases within one invocation but cannot hide an error in the successful action request', () => {
  const incidents = diagnosticIncidents([event(1, 'agent_parse_error', { category: 'no_code_block' }),
    event(2, 'tool_result', { request_index: 2, phase: 'poc_conclude', status: 'error', error_code: 'internal_error' }),
    event(3, 'agent_code', { request_index: 2, phase: 'poc_conclude' }),
    event(4, 'agent_code', { request_index: 3, phase: 'poc_conclude', is_final: true })]);
  assert.equal(incidents.length, 2);
  assert.deepEqual(incidents.map((incident) => incident.recovery.event.id), [4, 4]);
  assert.deepEqual(diagnosticGroups(incidents).map((group) => group.phase), ['task_execute', 'poc_conclude']);
});

test('a late execution error for an action prevents premature recovery from that same action', () => {
  const incidents = diagnosticIncidents([event(1, 'agent_parse_error'),
    event(2, 'agent_code', { request_index: 2 }),
    event(3, 'agent_execution_error', { request_index: 2, error_code: 'invalid_arguments' })]);
  assert.equal(incidents.length, 2);
  assert.ok(incidents.every((incident) => !incident.recovery));
});

test('transient model retries count once per request and a successful final terminal counts as recovery', () => {
  const incidents = diagnosticIncidents([event(1, 'model_retry', { reason: 'timeout' }), event(2, 'model_retry', { reason: 'timeout' }),
    event(3, 'agent_code'), event(4, 'agent_parse_error', { request_index: 2 }),
    event(5, 'agent_terminal', { request_index: 2, reason: 'completed' })]);
  assert.equal(incidents.length, 2);
  assert.deepEqual(incidents.map((incident) => incident.recovery.event.id), [3, 5]);
});

test('legacy task attempts remain separate and missing request identifiers never merge unrelated events', () => {
  const old = (id, kind, payload = {}) => event(id, kind, { agent_invocation_id: undefined, request_index: undefined, ...payload });
  const incidents = diagnosticIncidents([old(1, 'model_request'), old(2, 'agent_parse_error'), old(3, 'model_request', { attempt: 2 }),
    old(4, 'agent_code', { attempt: 2 }), old(5, 'model_request'), old(6, 'agent_code')]);
  assert.equal(incidents.length, 1);
  assert.equal(incidents[0].recovery.event.id, 6);
  assert.equal(diagnosticIncidents([old(7, 'agent_parse_error'), old(8, 'agent_parse_error')]).length, 2);
});

test('script failures and timeout retain call success but are never grouped as successful operations', () => {
  for (const result of [{ exit_code: 2, execution_status: 'failed' }, { timed_out: true, execution_status: 'timeout' }]) {
    const payload = { status: 'ok', ...result };
    const outcome = toolOutcome(payload);
    assert.equal(outcome.failed, false);
    assert.equal(outcome.callText, '调用完成');
    assert.equal(outcome.executionFailed, true);
    const activities = projectActivity([event(1, 'tool_call', { tool: 'run_poc', span_id: 'a' }),
      event(2, 'tool_result', { tool: 'run_poc', span_id: 'a', ...payload })], { run: { status: 'completed' } });
    assert.equal(activities[0].status, 'warning');
    assert.equal(groupCompletedTools(activities)[0].type, 'tool');
    assert.equal(diagnosticIncidents([event(2, 'tool_result', payload)]).length, 0);
  }
});

test('cached errors preserve errors and HTTP status is separate from script exit code', () => {
  const cached = toolOutcome({ status: 'error', error_code: 'path_not_found', cached: true, error: 'missing', hint: 'use list_tree' });
  assert.equal(cached.failed, true); assert.equal(cached.cached, true); assert.equal(cached.callText, '路径不存在'); assert.equal(cached.hint, 'use list_tree');
  const http = toolOutcome({ status: 'ok', exit_code: 0, http_status: 403 });
  assert.equal(http.executionFailed, false); assert.equal(http.httpStatus, 403);
  assert.equal(toolOutcome({ status: 'cancelled', error: 'paused' }).failed, false);
  assert.equal(toolOutcome({ status: 'duplicate' }).cached, true);
  assert.equal(toolOutcome(undefined), null);
});

test('verification job and precondition summaries do not conflate execution with the verdict', () => {
  assert.equal(verificationExecution({ execution_status: 'environment_mismatch', status: 'inconclusive' }), '实验前提不符');
  assert.equal(verificationExecution({}), '历史记录未保存执行状态');
  const script = verificationJobOutcome({ kind: 'script', exit_code: 1, result: { stderr: 'login failed' } });
  assert.equal(script.executionFailed, true); assert.match(script.executionText, /退出码 1/);
  const http = verificationJobOutcome({ kind: 'http', result: { status: 401, timed_out: false } });
  assert.equal(http.httpStatus, 401); assert.equal(http.executionFailed, false);
  const precondition = verificationJobOutcome({ kind: 'script', status: 'precondition_failed', result: { precondition: { ok: false } } });
  assert.equal(precondition.executionText, '实验前提不符'); assert.equal(precondition.executionFailed, true);
  assert.equal(precondition.failed, false);
});
