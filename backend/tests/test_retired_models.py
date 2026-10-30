"""Retired models are rejected before any provider, runner or production database access."""
import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from audit import app as app_module
from audit.codemodel import AuditCodeModel
from audit.config import ModelConfig, model_unavailable_reason, sync_model_env
from audit.worker import AuditWorker
from tests.test_host_queue import hosted, add_claim  # noqa: F401
from tests.test_review_closure import state  # noqa: F401
from tests.test_run_continuations import finish, request


@pytest.mark.parametrize('name', ['ark-code-latest', ' ARK-CODE-LATEST '])
def test_retired_model_is_rejected_at_client_and_frozen_run_resolution(name):
    config = ModelConfig(model=name, base_url='https://offline.invalid', api_key='offline')
    assert model_unavailable_reason(name)
    with pytest.raises(ValueError, match='已停用'):
        AuditCodeModel(config, gate=None, max_tokens=100)
    worker = SimpleNamespace(settings=SimpleNamespace(model=ModelConfig(model='current-model')))
    with pytest.raises(RuntimeError, match='已停用'):
        AuditWorker._model_for_run(worker, {'model': name})
    with pytest.raises(RuntimeError, match='已停用'):
        AuditWorker._model_for_run(worker, {'model': 'old-label', 'model_profile': {'model': name}})


def test_retired_profile_cannot_be_activated_queued_or_exported(tmp_path):
    def forbidden(*args, **kwargs):
        raise AssertionError('Retired model must fail before accessing dependencies')
    state = SimpleNamespace(settings=SimpleNamespace(model=ModelConfig(model='ark-code-latest')),
                            store=SimpleNamespace(select_model_profile=forbidden))
    with pytest.raises(HTTPException) as error:
        app_module._activate_profile(state, {'model': 'ark-code-latest'})
    assert error.value.status_code == 409
    with pytest.raises(HTTPException) as error:
        asyncio.run(app_module.create_audit_run(state, None))
    assert error.value.status_code == 409
    path = tmp_path / '.env'
    path.write_text('LLM_MODEL=working-model\n')
    with pytest.raises(ValueError, match='已停用'):
        sync_model_env(path, ModelConfig(model='ark-code-latest', base_url='https://offline.invalid', api_key='offline'))
    assert path.read_text() == 'LLM_MODEL=working-model\n'


def test_old_facts_survive_but_continuation_must_use_an_available_model(hosted):
    store, _, run = hosted
    add_claim(store, run, 1)
    store._write('UPDATE runs SET model=?, model_profile=? WHERE id=?',
                 ('ark-code-latest', '{}', run['id']))
    finish(store, run)
    before = store.frozen_report(run['id'])['input_json']
    with pytest.raises(ValueError, match='已停用'):
        store.create_continuation(run['id'], request(mode='review', model_profile_id='original'))
    assert len(store.list_runs()) == 1
    child = store.create_continuation(run['id'], request(mode='review'),
        model_profile=dict(profile_id='current-profile', model='deepseek-flash', base_url='https://offline.invalid'))
    assert child['model'] == 'deepseek-flash'
    assert store.get_run(run['id'])['model'] == 'ark-code-latest'
    assert store.frozen_report(run['id'])['input_json'] == before
