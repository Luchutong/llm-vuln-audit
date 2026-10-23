import test from 'node:test';
import assert from 'node:assert/strict';
import { ApiError, api } from '../src/api.ts';
import { activeExecutionCount, DEFAULT_RUN_LIMITS, draftRunLimits, executionPhase, executionSummary, pocReason, stopReason } from '../src/execution.ts';
import { projectActivity } from '../src/activity.ts';

test('drafts copy only the frozen limits and never previous consumption', () => {
  const seed = { run_limits: { responses: 111, tools: 555, seconds: 999 }, execution_summary: { run_usage: { responses: 100, tools: 500, seconds: 900 } } };
  const limits = draftRunLimits(seed);
  assert.deepEqual(limits, seed.run_limits);
  limits.responses = 1;
  assert.equal(seed.run_limits.responses, 111);
  assert.deepEqual(draftRunLimits({}), DEFAULT_RUN_LIMITS);
  assert.deepEqual(draftRunLimits(undefined, { run_budget_limits: { defaults: seed.run_limits } }), seed.run_limits);
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
