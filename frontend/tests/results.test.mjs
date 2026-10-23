import test from 'node:test';
import assert from 'node:assert/strict';
import { activeVulnerabilityFindings, isVulnerabilityFinding, sourceObservations, vulnerabilityFindings } from '../src/results.ts';

const finding = (id, kind = 'vulnerability', severity = 'medium', extra = {}) => ({
  id, finding_kind: kind, category: 'task_goal', severity, validation_state: 'candidate', disposition: 'open', ...extra,
});

test('explicit vulnerability classification retains real low risk and excludes neutral source facts', () => {
  for (const severity of ['low', 'medium', 'high', 'critical']) assert.equal(isVulnerabilityFinding(finding('risk', 'vulnerability', severity)), true);
  for (const kind of ['source_observation', 'data_flow', 'security_boundary', 'configuration', 'other']) {
    assert.equal(isVulnerabilityFinding(finding('fact', kind, 'high')), false);
  }
  for (const severity of ['none', 'informational', 'unknown', '', null]) assert.equal(isVulnerabilityFinding(finding('ungraded', 'vulnerability', severity)), true);
});

test('only legacy fixed vulnerability categories are inferred without an explicit kind', () => {
  for (const category of ['sqli', 'xss_r', 'command_injection']) assert.equal(isVulnerabilityFinding(finding('legacy', '', 'high', { category })), true);
  assert.equal(isVulnerabilityFinding(finding('unknown', '', 'high')), false);
  assert.equal(isVulnerabilityFinding(finding('override', 'source_observation', 'high', { category: 'sqli' })), false);
});

test('old mixed responses split without dropping source facts, human records or revisions', () => {
  const observation = finding('fact', 'data_flow', 'informational', { verdict: 'confirmed', verifications: [{ notes: '人工复核原文' }], revision: 2 });
  const withdrawn = finding('withdrawn', 'vulnerability', 'high', { disposition: 'retracted' });
  const low = finding('low', 'vulnerability', 'low');
  const detail = { findings: [low, observation, withdrawn] };
  assert.deepEqual(vulnerabilityFindings(detail), [low, withdrawn]);
  assert.deepEqual(activeVulnerabilityFindings(detail), [low]);
  assert.deepEqual(sourceObservations(detail), [observation]);
  assert.equal(sourceObservations(detail)[0], observation);
});

test('new explicit observation projection wins over its legacy raw row and is deduplicated', () => {
  const raw = finding('fact', 'data_flow', 'informational');
  const projected = { ...raw, validation_state: 'observation', attempt: 3 };
  assert.deepEqual(sourceObservations({ findings: [raw], source_observations: [projected] }), [projected]);
});
