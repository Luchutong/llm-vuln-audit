import test from 'node:test';
import assert from 'node:assert/strict';
import { draftTask, frozenTaskPolicy, taskForStart, taskWithPolicy } from '../src/taskDraft.ts';

test('new interactive audits default to explicit full coverage review', () => {
  const task = draftTask();
  assert.equal(task.completion_policy, 'coverage_review');
  assert.equal(task.stop_on_achieved, false);
  assert.equal(task.baseline_policy, 'fresh');
  assert.equal(task.workflow_policy, 'discovery_first');
  const submitted = taskForStart(task, '检查完整项目中的漏洞风险');
  assert.equal(submitted.completion_policy, 'coverage_review');
  assert.equal(submitted.workflow_policy, 'discovery_first');
  assert.equal(submitted.stop_on_achieved, false);
  assert.equal('success_criteria' in submitted, false);
});

test('legacy task copies preserve goal closure and explicit switching controls stop behavior', () => {
  const historical = draftTask({ objective: '查找任意文件读取漏洞', stop_on_achieved: true });
  assert.equal(historical.completion_policy, 'goal');
  assert.equal(historical.stop_on_achieved, true);
  assert.equal(historical.baseline_policy, 'inherit');
  assert.equal(historical.workflow_policy, 'legacy');
  const full = taskWithPolicy(historical, 'coverage_review');
  assert.equal(full.stop_on_achieved, false);
  assert.equal(full.baseline_policy, 'fresh');
  assert.equal(full.workflow_policy, 'discovery_first');
  assert.equal(full.objective, historical.objective);
  const quick = taskWithPolicy(full, 'goal');
  assert.equal(quick.completion_policy, 'goal');
  assert.equal(quick.stop_on_achieved, true);
  assert.equal(quick.baseline_policy, 'inherit');
  assert.equal(quick.workflow_policy, 'legacy');
});

test('full audits can explicitly inherit the ledger without changing the completion policy', () => {
  const payload = taskForStart({ ...draftTask(), baseline_policy: 'inherit' }, '审查全部第一方源码入口');
  assert.equal(payload.baseline_policy, 'inherit');
  assert.equal(payload.completion_policy, 'coverage_review');
  assert.equal(payload.stop_on_achieved, false);
});

test('mode is never inferred from objective words or a scenario shortcut', () => {
  const quick = taskWithPolicy(draftTask(), 'goal');
  const payload = taskForStart({ ...quick, scenario: 'sqli' }, '审查全部源码，确定所有漏洞', '\n重点审计范围：src/a.php:1-8');
  assert.equal(payload.completion_policy, 'goal');
  assert.equal(payload.scenario, 'sqli');
  assert.ok(payload.objective.endsWith('src/a.php:1-8'));
});

test('full coverage always submits stop false even for an inconsistent historical draft', () => {
  const payload = taskForStart({ ...draftTask(), stop_on_achieved: true, success_criteria: '找到至少一处风险' }, '审查全部第一方源码入口');
  assert.equal(payload.stop_on_achieved, false);
  assert.equal('success_criteria' in payload, false);
});

test('run policy labels reflect the frozen fields and distinguish historical defaults', () => {
  const full = frozenTaskPolicy({ completion_policy: 'coverage_review', baseline_policy: 'fresh' });
  assert.equal(full.mode, '全量覆盖复核');
  assert.match(full.baseline, /空白漏洞基线/);
  assert.match(full.baselineDescription, /未继承历史漏洞结论/);
  const legacy = frozenTaskPolicy({});
  assert.equal(legacy.mode, '快速目标审计（旧记录默认）');
  assert.equal(legacy.baseline, '继承项目已有漏洞（旧记录默认）');
  const explicit = frozenTaskPolicy({ completion_policy: 'goal', baseline_policy: 'inherit' });
  assert.equal(explicit.mode, '快速目标审计');
  assert.equal(explicit.baseline, '继承项目已有漏洞');
});

test('copied historical full audits do not silently adopt the new workflow', () => {
  const historical = draftTask({ completion_policy: 'coverage_review', baseline_policy: 'fresh' });
  assert.equal(historical.workflow_policy, 'legacy');
  assert.equal(taskForStart(historical, '重放旧任务').workflow_policy, 'legacy');
  assert.equal(taskWithPolicy(historical, 'coverage_review').workflow_policy, 'discovery_first');
  assert.equal(frozenTaskPolicy({}).workflow, '共享预算调度（旧政策）');
});

test('a cloned run never carries its frozen stage quotas into the next request', () => {
  const clone = draftTask({ completion_policy: 'coverage_review', workflow_policy: 'discovery_first',
    workflow_limits: { discovery: 281, poc: 100, review: 19 } });
  const payload = taskForStart(clone, '继续复核未覆盖的源码方向');
  assert.equal('workflow_limits' in payload, false);
  // The settings panel decides the new split, including for a legacy-mode clone.
  assert.equal('workflow_limits' in taskForStart(taskWithPolicy(clone, 'goal'), '快速复核入口'), false);
});
