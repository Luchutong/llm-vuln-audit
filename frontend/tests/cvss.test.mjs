import test from 'node:test';
import assert from 'node:assert/strict';
import { ratingLabel, CVSS_METRICS, CVSS_VALUES } from '../src/cvss.ts';
import { isVulnerabilityFinding } from '../src/results.ts';

test('CVSS display distinguishes zero, unscored and legacy ratings',()=>{
  assert.equal(ratingLabel({cvss:{base_score:0,severity:'none'}}),'无基础影响 · 0.0');
  assert.equal(ratingLabel({cvss:{base_score:7.5,severity:'high'}}),'高危 · 7.5');
  assert.equal(ratingLabel({cvss:null,cvss_assessment:{status:'needs_information'}}),'待评分');
  assert.equal(ratingLabel({cvss:null,legacy_severity:'critical'}),'历史等级 严重 · 未量化');
  assert.equal(ratingLabel({severity:'high'}),'历史等级 高危 · 未量化');
  for(const severity of ['none','unknown']) assert.equal(isVulnerabilityFinding({finding_kind:'vulnerability',category:'task_goal',severity}),true);
  assert.equal(CVSS_METRICS.length,8);
  assert.equal(CVSS_VALUES.PR.includes('X'),false);
});
