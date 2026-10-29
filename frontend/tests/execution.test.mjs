import test from 'node:test';
import assert from 'node:assert/strict';
import { ApiError, api } from '../src/api.ts';
import { activeExecutionCount, contextLine, DEFAULT_RUN_LIMITS, FULL_RUN_LIMITS, frozenPocMode, draftRunLimits, draftWorkflowAllocation, executionPhase, executionSummary, formatBytes, pocReason, stopReason, workflowFacts, workflowLimitsIssue, workflowStopLabel, WORKFLOW_STAGE_LABELS } from '../src/execution.ts';
import { projectActivity } from '../src/activity.ts';

test('drafts copy only the frozen limits and never previous consumption', () => {
  const seed = { run_limits: { responses: 111, tools: 555, seconds: 999 }, execution_summary: { run_usage: { responses: 100, tools: 500, seconds: 900 } } };
  const limits = draftRunLimits(seed);
  assert.deepEqual(limits, seed.run_limits);
  limits.responses = 1;
  assert.equal(seed.run_limits.responses, 111);
  assert.deepEqual(draftRunLimits({}), DEFAULT_RUN_LIMITS);
  assert.deepEqual(draftRunLimits(undefined), FULL_RUN_LIMITS);
  assert.deepEqual(draftRunLimits(undefined, { run_budget_limits: { defaults: seed.run_limits } }, 'goal'), seed.run_limits);
  assert.deepEqual(draftRunLimits(undefined, null, 'goal'), DEFAULT_RUN_LIMITS);
  assert.deepEqual(draftRunLimits(undefined, { run_budget_limits: { profiles: { coverage_review: seed.run_limits } } }), seed.run_limits);
});

test('execution summary handles current and legacy run projections and explains budget stops', () => {
  const summary = { stop_reason: { code: 'run_budget_exhausted', dimension: 'responses' } };
  assert.equal(executionSummary({ run: { execution_summary: summary } }), summary);
  assert.equal(executionSummary({ execution_summary: summary, run: {} }), summary);
  assert.equal(executionSummary({ run: {} }), null);
  assert.match(stopReason(summary), /整次审计预算已耗尽.*模型请求/);
  assert.equal(stopReason({ stop_reason: { code: 'x', message: '已保存阶段结果' } }), '已保存阶段结果');
  assert.equal(activeExecutionCount({ active_executions: [{ role: 'worker' }, { role: 'planner' }] }), 2);
  assert.equal(activeExecutionCount({ active_executions: 0 }), 0);
  assert.equal(executionPhase('ended'), '执行结束');
});

test('structured API errors preserve readiness detail and show its message', async () => {
  const previous = globalThis.fetch;
  const detail = { code: 'poc_not_ready', reason: 'runner_unavailable', message: '隔离环境暂不可用', checked_at: '2026-10-23' };
  try {
    globalThis.fetch = async () => new Response(JSON.stringify({ detail }), { status: 409 });
    await assert.rejects(api('/runs'), (error) => error instanceof ApiError && error.status === 409 && error.message === detail.message && assert.deepEqual(error.detail, detail) === undefined);
  } finally { globalThis.fetch = previous; }
});

test('POC off and unavailable environment are neutral lifecycle information', () => {
  assert.match(pocReason('off'), /关闭自动验证/);
  const events = ['poc_disabled', 'poc_verification_skipped', 'poc_verification_unavailable', 'poc_verification_recorded'].map((kind, index) => ({ id: index + 1, run_id: 'one', unit_id: null, kind, created_at: '', payload: { reason: 'runner_unavailable', status: 'environment_unavailable', summary: '未执行验证' } }));
  const items = projectActivity(events, { run: { status: 'inconclusive' } });
  assert.equal(items.length, events.length);
  assert.ok(items.every((item) => item.tone === 'neutral'));
});

test('contextLine reports the peak against the byte ceiling, never as a token count', () => {
  assert.equal(contextLine(undefined), '');
  assert.equal(contextLine({}), '');
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(393216), '384.0 KiB');
  assert.equal(formatBytes(null), '—');
  const line = contextLine({ history_bytes: 393216, peak_request_bytes: 300000, compactions: 2,
    summary_requests: 3, limit_hits: 0 });
  assert.match(line, /上下文峰值 293\.0 KiB \/ 上限 384\.0 KiB/);
  assert.match(line, /触发压缩 2 次/);
  assert.match(line, /摘要请求 3 次/);
  assert.doesNotMatch(line, /达到上限/);
  assert.match(contextLine({ history_bytes: 65536, limit_hits: 1 }), /达到上限 1 次/);
});

test('discovery-first previews match frozen allocation ratios and preserve the final review', () => {
  assert.deepEqual(draftWorkflowAllocation(256, 'auto'), { discovery: 180, poc: 64, review: 12 });
  assert.deepEqual(draftWorkflowAllocation(256, 'required'), { discovery: 180, poc: 64, review: 12 });
  assert.deepEqual(draftWorkflowAllocation(256, 'off'), { discovery: 244, poc: 0, review: 12 });
  for (const total of [1, 2, 3, 24, 63, 128, 255, 4096]) {
    for (const mode of ['off', 'auto']) {
      const allocation = draftWorkflowAllocation(total, mode);
      assert.equal(Object.values(allocation).reduce((a, b) => a + b, 0), total);
      assert.ok(allocation.discovery >= 1);
      assert.ok(allocation.review >= 0);
    }
  }
});

test('workflow facts preserve actual host counters and tolerate legacy absence', () => {
  const facts = { workflow: { stage: 'poc', limits: { discovery: 150, poc: 94, review: 12 }, transferred: 30 },
    directions: { unsettled_total: 4 }, verification: { pending: 2, reviewed: 1 } };
  assert.equal(workflowFacts({ run: { final_summary: { execution: facts } } }), facts);
  const live = { ...facts, verification: { pending: 1, reviewed: 2 } };
  assert.equal(workflowFacts({ execution_summary: live, run: { final_summary: { execution: facts } } }), live);
  assert.equal(workflowFacts({ run: {} }), null);
  assert.equal(WORKFLOW_STAGE_LABELS.review, '验证复核与收束');
});

test('workflow stop reasons support persisted structured administrative facts and older strings', () => {
  assert.equal(workflowStopLabel(), '');
  assert.equal(workflowStopLabel({ state: 'inconclusive', basis: '源码阶段额度已到，未决方向已保留。', code: 'stage_budget_exhausted' }), '源码阶段额度已到，未决方向已保留。');
  assert.equal(workflowStopLabel({ code: 'stage_budget_exhausted' }), '源码阶段额度已耗尽');
  assert.equal(workflowStopLabel('settled'), '源码阶段已结算');
});

test('stage quotas are validated client-side before the request reaches the host', () => {
  const automatic = draftWorkflowAllocation(400, 'auto');
  assert.equal(workflowLimitsIssue(automatic, 400, 'auto'), null);
  assert.deepEqual(automatic, { discovery: 281, poc: 100, review: 19 });
  assert.match(workflowLimitsIssue({ discovery: 300, poc: 60, review: 41 }, 400, 'auto'), /超过整次模型请求上限/);
  assert.match(workflowLimitsIssue({ discovery: 320, poc: 10, review: 20 }, 400, 'off'), /POC 配额必须为 0/);
  assert.match(workflowLimitsIssue({ discovery: 0, poc: 0, review: 19 }, 400, 'off'), /至少保留 1 次/);
  assert.match(workflowLimitsIssue({ discovery: 300, poc: 0, review: 0 }, 400, 'off'), /至少保留 1 次/);
  // A remainder below the ceiling is legal: the host adds it to discovery when frozen.
  assert.equal(workflowLimitsIssue({ discovery: 100, poc: 20, review: 10 }, 400, 'auto'), null);
});


test('clones preserve their frozen POC mode without accepting unknown policy values', () => {
  assert.equal(frozenPocMode({ poc_mode: 'auto' }), 'auto');
  assert.equal(frozenPocMode({ poc_policy: { mode: 'required' } }), 'required');
  assert.equal(frozenPocMode({ poc_mode: 'off', poc_policy: { mode: 'required' } }), 'off');
  assert.equal(frozenPocMode({ poc_policy: { mode: 'unknown' } }), 'off');
  assert.equal(frozenPocMode(), 'off');
});
