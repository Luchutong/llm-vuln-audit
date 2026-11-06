"""Evaluator gates only: scoring criteria never enter the source auditor."""
import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location('lab30_acceptance', Path(__file__).resolve().parents[2] / 'scripts/run_lab30_e2e.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_completed_pipeline_with_22_hits_does_not_pass_the_explicit_target():
    score = dict(protocol='lab30-v2', TP=22, FN=8, D=0, U=1, FP=1)
    assert len(module.score_problems(score, module.SCORE_TARGET)) == 4
    assert module.score_problems(score, None) == []  # historical acceptance stays frozen


@pytest.mark.parametrize('key,value', [('TP', 29), ('FN', 1), ('D', 1), ('U', 1), ('FP', 1), ('protocol', 'legacy_unit_v1'), ('TP', '30')])
def test_every_score_dimension_is_required(key, value):
    score = {k: v for k, v in module.SCORE_TARGET.items() if k != 'version'}
    assert module.score_problems(score, module.SCORE_TARGET) == []
    score[key] = value
    assert module.score_problems(score, module.SCORE_TARGET)


def test_missing_score_cannot_become_success():
    assert len(module.score_problems({}, module.SCORE_TARGET)) == 6


def test_exhaustive_task_does_not_receive_scoring_criteria():
    class Client:
        def post(self, path, json):
            assert 'TP' not in str(json) and 'truth' not in str(json)
            assert json['task']['exploration_policy'] == 'exhaustive-v1'
            self.payload = json
            return type('Response', (), {'status_code': 200, 'json': lambda _: {'id': 'isolated', 'model': 'test', 'budgets': {}}})()
    client = Client()
    module.create_run(client, 'snapshot', None, '审计完整源码的所有风险', 3, 24, 64, 'off',
        task_overrides=dict(exploration_policy='exhaustive-v1', focus_scope='all', risk_coverage_policy='bounded-v2'))
    assert 'risk_obligation_set' not in client.payload['task']  # host derives it from source


def test_pending_or_legacy_acceptance_never_enters_the_strict_score_input():
    claim = dict(finding_id='current', title='独立根因', primary_location=dict(path='entry.php', line=2),
        vulnerability_type='sqli', evidence=[], poc={'script':'sensitive runtime artifact'}, http_session='private')
    entries = [dict(final_disposition='accepted', frozen_claim=claim),
               dict(final_disposition='pending', frozen_claim=claim, final_batch_review={'decision':'accept'}),
               dict(final_disposition='accepted', frozen_claim=claim, final_batch_review={'decision':'accept'})]
    records = module.accepted_score_input({'canonical_findings':entries})
    assert len(records) == 1 and records[0]['id'] == 'current'
    assert 'poc' not in records[0] and 'http_session' not in records[0]


def test_perfect_asserted_score_still_requires_complete_independent_review():
    closure = dict(status='completed', coverage=dict(complete=True), poc=dict(jobs=1, reset_between_findings=True, seed_verified=True),
        score=dict(module.SCORE_TARGET), score_target=module.SCORE_TARGET, audit_complete=False)
    assert any('独立终审' in problem for problem in module.closure_problems(closure, 0))
