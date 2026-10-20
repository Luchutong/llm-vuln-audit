import test from 'node:test';
import assert from 'node:assert/strict';
import { projectActivity, groupCompletedTools, activityPage } from '../src/activity.ts';

const event = (id, kind, payload = {}) => ({
  id, run_id: 'run-a', kind, created_at: `2026-10-20T08:00:${String(id % 60).padStart(2, '0')}Z`,
  payload: { role: 'worker', task_id: 'task-a', task_key: 'internal-task-key', worker_id: 'internal-worker-id',
    attempt: 1, phase: 'task_execute', agent_invocation_id: 'execution-a', request_index: 1, ...payload },
});
const tool = (id, kind, payload = {}) => event(id, kind, {
  tool: 'read_source', call_id: 'internal-call-id', span_id: 'internal-span-id',
  args: { path: 'src/upload.php', start: 12, end: 28 }, ...payload,
});
const detail = (status = 'running') => ({
  run: { id: 'run-a', status, created_at: '2026-10-20T08:00:00Z', snapshot_name: 'project.zip',
    task_spec: { objective: '寻找上传写入路径中的漏洞', success_criteria: '必须引用原始源码证据' },
    usage: { requests: 2, tool_calls: 4 } },
  tasks: [
    { id: 'task-a', task_key: 'internal-task-key', title: '上传写入方向', state: status === 'running' ? 'running' : 'completed', attempts: 1 },
    { id: 'task-b', task_key: 'another-internal-key', title: '认证校验方向', state: status === 'running' ? 'running' : 'completed', attempts: 2 },
  ],
  findings: [], metrics: {}, attributions: [],
});
const messages = (items) => items.filter((item) => item.type === 'message');
const tools = (items) => items.filter((item) => item.type === 'tool');
const textOf = (items) => messages(items).map((item) => `${item.text} ${item.secondary || ''}`).join('\n');

test('progress and interleaved tool calls retain chronological order while results update their original rows', () => {
  const start = [
    event(1, 'audit_progress', { message: '先核对上传入口的文件名处理。' }),
    tool(2, 'tool_call'),
    event(3, 'audit_progress', { task_id: 'task-b', agent_invocation_id: 'execution-b', message: '同时核对入口的认证检查。' }),
    tool(4, 'tool_call', { task_id: 'task-b', agent_invocation_id: 'execution-b' }),
  ];
  const before = projectActivity(start, detail());
  const after = projectActivity([...start,
    tool(5, 'tool_result', { task_id: 'task-b', agent_invocation_id: 'execution-b', status: 'ok', preview: 'auth result' }),
    tool(6, 'tool_result', { status: 'ok', preview: 'upload result' }),
  ], detail());
  assert.deepEqual(after.map((item) => item.order), [1, 2, 3, 4]);
  assert.deepEqual(tools(before).map((item) => item.key), tools(after).map((item) => item.key));
  assert.deepEqual(tools(after).map((item) => item.span.result.payload.preview), ['upload result', 'auth result']);
  assert.ok(tools(after).every((item) => item.status === 'success'));
});

test('default display labels describe actual tools and human task names without technical identifiers', () => {
  const items = projectActivity([tool(1, 'tool_call')], detail());
  const item = tools(items)[0];
  assert.equal(item.taskTitle, '上传写入方向');
  assert.match(`${item.label} ${item.subject}`, /读取/);
  assert.match(`${item.label} ${item.subject}`, /upload\.php/);
  const visible = `${item.actor} ${item.taskTitle} ${item.label} ${item.subject}`;
  assert.doesNotMatch(visible, /internal-task-key|internal-worker-id|internal-call-id|internal-span-id|execution-a/);
});

test('formal assessments replace completion fallbacks without repeating their conclusion', () => {
  const items = projectActivity([
    event(1, 'task_assessment', { outcome: 'no_evidence', summary: '该分支有明确的扩展名限制。', rationale: '只有白名单后缀能够到达写入操作。' }),
    event(2, 'planner_task_completed', { summary: '该分支有明确的扩展名限制。' }),
  ], detail('completed'));
  const text = textOf(items);
  assert.equal(text.split('该分支有明确的扩展名限制。').length - 1, 1);
  assert.match(text, /只有白名单后缀能够到达写入操作/);
  const old = projectActivity([event(2, 'planner_task_completed', { summary: '历史任务只保存了完成摘要。' })], detail('completed'));
  assert.match(textOf(old), /历史任务只保存了完成摘要/);
});

test('Planner decisions surface their basis and next action exactly once', () => {
  const context = { role: 'planner', task_id: null, worker_id: null, attempt: null, session_id: 'planner-session', plan_id: 'plan-1' };
  const items = projectActivity([
    event(1, 'planner_assessment', { ...context, basis_summary: '上传入口直接调用写入模块。', next_action: '分别核验路径处理和入口认证。' }),
    event(2, 'planner_round_committed', { ...context, basis_summary: '上传入口直接调用写入模块。', next_action: '分别核验路径处理和入口认证。' }),
  ], detail('completed'));
  assert.equal(textOf(items).split('上传入口直接调用写入模块。').length - 1, 1);
  assert.match(textOf(items), /分别核验路径处理和入口认证/);
});

test('waiting states belong to each execution and disappear when it produces public activity or ends', () => {
  const a = event(1, 'model_request');
  const b = event(2, 'model_request', { task_id: 'task-b', agent_invocation_id: 'execution-b' });
  assert.equal(projectActivity([a, b], detail()).filter((item) => item.type === 'waiting').length, 2);
  const produced = projectActivity([a, b, event(3, 'audit_progress', { message: '正在检查路径参数校验。' })], detail());
  assert.equal(produced.filter((item) => item.type === 'waiting').length, 1);
  for (const status of ['completed', 'cancelled', 'paused', 'inconclusive']) {
    assert.equal(projectActivity([a, b], detail(status)).filter((item) => item.type === 'waiting').length, 0);
  }
});

test('completed history folds in place while failures and explicitly opened tools stay visible', () => {
  const source = [];
  for (let index = 0; index < 3; index++) {
    source.push(tool(index * 2 + 1, 'tool_call', { call_id: `call-${index}`, span_id: `span-${index}` }));
    source.push(tool(index * 2 + 2, 'tool_result', { call_id: `call-${index}`, span_id: `span-${index}`, status: 'ok' }));
  }
  source.push(tool(7, 'tool_call', { call_id: 'failed', span_id: 'failed' }));
  source.push(tool(8, 'tool_result', { call_id: 'failed', span_id: 'failed', status: 'error', error: '读取失败' }));
  const items = projectActivity(source, detail('completed'));
  const grouped = groupCompletedTools(items);
  assert.equal(grouped[0].type, 'tool-group');
  assert.equal(grouped[0].tools.length, 3);
  assert.equal(grouped.at(-1).type, 'tool');
  assert.equal(grouped.at(-1).status, 'error');
  const openedKey = tools(items)[0].key;
  const protectedItems = groupCompletedTools(items, new Set([openedKey]));
  assert.equal(protectedItems[0].key, openedKey);
  assert.equal(protectedItems[0].type, 'tool');
});

test('public projection omits model internals and deduplicates replayed events', () => {
  const progress = event(1, 'audit_progress', { message: '正在检查上传路径。' });
  const items = projectActivity([
    progress, progress,
    event(2, 'agent_code', { code: 'PRIVATE_CODE_MARKER', logs: 'PRIVATE_LOG_MARKER' }),
    event(3, 'planner_situational_prepared', { findings: ['PRIVATE_CONTEXT_MARKER'] }),
    tool(4, 'tool_call'),
  ], detail());
  assert.equal(messages(items).filter((item) => item.text.includes('正在检查上传路径。')).length, 1);
  assert.doesNotMatch(textOf(items), /PRIVATE_CODE_MARKER|PRIVATE_LOG_MARKER|PRIVATE_CONTEXT_MARKER/);
});

test('a parse error is a format message, never a code action or a leaked reply', () => {
  const items = projectActivity([
    event(1, 'model_request'),
    event(2, 'model_response', { output_chars: 120, output_bytes: 120, output_tokens: 40, max_output_tokens: 4096 }),
    event(3, 'agent_parse_error', {
      phase: 'poc_conclude', step: 1, request_index: 2, category: 'no_code_block',
      hint: 'HOST_PARSE_HINT', text: 'PRIVATE_MODEL_PROSE_MARKER',
    }),
  ], detail());
  const message = messages(items).find((item) => item.title === '输出格式错误');
  assert.ok(message, textOf(items));
  assert.equal(message.tone, 'warning');
  assert.match(message.text, /第 1 步回复没有可解析的代码块/);
  assert.match(message.secondary || '', /不是代码执行失败/);
  assert.equal(items.filter((item) => item.type === 'tool').length, 0);
  assert.doesNotMatch(textOf(items), /HOST_PARSE_HINT|PRIVATE_MODEL_PROSE_MARKER/);
});

test('an early POC execution stop and a failed conclusion are shown to the reader', () => {
  const items = projectActivity([
    event(1, 'poc_execution_finished', { role: 'poc', phase: 'poc_execute', reason: 'budget', jobs: 7, scripts: 7 }),
    event(2, 'poc_conclusion_failed', {
      role: 'poc', phase: 'poc_conclude', reason: 'invalid_output',
      message: '结论阶段结束，但没有提交可校验的 final_answer',
    }),
  ], detail('completed'));
  const text = textOf(items);
  assert.match(text, /执行阶段以 budget 结束/);
  assert.match(text, /7 次 runner 作业/);
  assert.ok(messages(items).some((item) => item.title === '结论生成失败'));
  assert.match(text, /没有提交可校验的 final_answer/);
});

test('pagination retains a long-running older tool alongside the latest public activity', () => {
  const events = [tool(1, 'tool_call')];
  for (let index = 2; index < 70; index++) {
    events.push(event(index, 'audit_progress', { task_id: 'task-b', agent_invocation_id: 'execution-b', request_index: index,
      message: `正在核对第 ${index} 个已读取的调用点。` }));
  }
  const items = projectActivity(events, detail());
  const visible = activityPage(groupCompletedTools(items), 50);
  assert.ok(visible.some((item) => item.type === 'tool' && item.order === 1 && item.status === 'running'));
  assert.equal(visible.at(-1).order, 69);
  assert.ok(visible.length <= 51);
});

test('orphaned results stay traceable and invalid arguments never fabricate a source location', () => {
  const items = projectActivity([tool(1, 'tool_result', { args: undefined, status: 'error', error: '源文件缺失', preview: '实际返回片段' })], detail('completed'));
  const item = tools(items)[0];
  assert.equal(item.status, 'error');
  assert.equal(item.span.call, undefined);
  assert.equal(item.span.result.payload.preview, '实际返回片段');
  assert.doesNotMatch(`${item.label} ${item.subject}`, /undefined|null|NaN|\[object Object\]/);
});

test('all tools in the current model step remain unfolded until the next request begins', () => {
  const source = [event(1, 'model_request'),
    tool(2, 'tool_call', { span_id: 'first', call_id: 'first' }),
    tool(3, 'tool_result', { span_id: 'first', call_id: 'first', status: 'ok' }),
    tool(4, 'tool_call', { span_id: 'second', call_id: 'second' }),
    tool(5, 'tool_result', { span_id: 'second', call_id: 'second', status: 'ok' }),
  ];
  const active = projectActivity(source, detail());
  assert.ok(tools(active).every((item) => item.current));
  assert.equal(groupCompletedTools(active).filter((item) => item.type === 'tool-group').length, 0);
  const continued = projectActivity([...source, event(6, 'model_request', { request_index: 2 })], detail());
  assert.ok(tools(continued).every((item) => !item.current));
  assert.equal(groupCompletedTools(continued).filter((item) => item.type === 'tool-group').length, 1);
});

test('search titles retain the actual query when the call also narrows a source directory', () => {
  const [item] = tools(projectActivity([tool(1, 'tool_call', {
    tool: 'search_code', args: { query: 'move_uploaded_file', path: 'src/upload' },
  })], detail()));
  assert.match(`${item.label} ${item.subject}`, /move_uploaded_file/);
  assert.doesNotMatch(`${item.label} ${item.subject}`, /undefined|\[object Object\]/);
});

test('a full saved assessment stays available instead of being reduced to an event-title preview', () => {
  const summary = '已读取的路径检查有明确的边界，但仍需核对另一条写入路径。'.repeat(80);
  const rationale = '依照原始源码逐项核对入口与写入位置。'.repeat(70);
  const items = projectActivity([event(1, 'task_assessment', { summary, rationale, outcome: 'continue' })], detail('completed'));
  assert.ok(textOf(items).includes(summary));
  assert.ok(textOf(items).includes(rationale));
});

test('old tool failures and current-step tools remain accessible across history pagination', () => {
  const events = [
    tool(1, 'tool_call', { span_id: 'failed', call_id: 'failed' }),
    tool(2, 'tool_result', { span_id: 'failed', call_id: 'failed', status: 'error', error: '无法读取相关文件' }),
    tool(3, 'tool_call', { span_id: 'current', call_id: 'current' }),
    tool(4, 'tool_result', { span_id: 'current', call_id: 'current', status: 'ok' }),
  ];
  for (let index = 5; index < 70; index++) events.push(event(index, 'audit_progress', {
    task_id: 'task-b', agent_invocation_id: 'execution-b', request_index: index,
    message: `正在核对第 ${index} 个已读取的调用点。`,
  }));
  const visible = activityPage(groupCompletedTools(projectActivity(events, detail())), 50);
  assert.ok(visible.some((item) => item.type === 'tool' && item.order === 1 && item.status === 'error'));
  assert.ok(visible.some((item) => item.type === 'tool' && item.order === 3 && item.current));
});

test('default-ended source reads never display zero or invalid line ranges', () => {
  for (const end of [0, -1, undefined, {}, 'invalid']) {
    const [item] = tools(projectActivity([tool(1, 'tool_call', { args: { path: 'src/upload.php', start: 12, end } })], detail()));
    assert.match(item.subject, /upload\.php:12$/);
  }
});
