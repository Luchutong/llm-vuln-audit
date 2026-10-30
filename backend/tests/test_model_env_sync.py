"""Explicit export uses temporary files only; no credentials or production env are read."""
import os

import pytest

from audit.config import ModelConfig, load_env_file, sync_model_env


def test_env_export_round_trips_quotes_preserves_other_settings_and_removes_duplicates(tmp_path, monkeypatch):
    monkeypatch.setattr(os, 'environ', {})
    path = tmp_path / '.env'
    untouched = '# runner settings\nPOC_CLAUDE_MODEL=independent-model\nPOC_RUNNER_TOKEN=offline-token\n'
    path.write_text(untouched + 'LLM_MODEL=old\nexport LLM_MODEL=duplicate\nLLM_API_KEY=old')
    model = ModelConfig(model='new-model', base_url='https://example.invalid/v1',
                        api_key='offline key\'"$`\\value', thinking='enabled')
    sync_model_env(path, model)
    result = path.read_text()
    assert result.startswith(untouched)
    assert result.count('LLM_MODEL=') == 1
    assert path.stat().st_mode & 0o777 == 0o600
    for key in ('LLM_MODEL', 'LLM_BASE_URL', 'LLM_API_KEY', 'LLM_THINKING'):
        monkeypatch.delenv(key, raising=False)
    load_env_file(path)
    assert ModelConfig.from_environ() == model
    monkeypatch.setenv('LLM_MODEL', 'explicit-process-override')
    load_env_file(path)
    assert os.environ['LLM_MODEL'] == 'explicit-process-override'


def test_failed_atomic_export_preserves_original_and_cleans_temporary_file(tmp_path, monkeypatch):
    path = tmp_path / '.env'
    path.write_text('LLM_MODEL=original\n')
    def failed(*args):
        raise OSError('offline failure')
    monkeypatch.setattr('audit.config.os.replace', failed)
    with pytest.raises(OSError):
        sync_model_env(path, ModelConfig(model='new', base_url='https://example.invalid', api_key='offline'))
    assert path.read_text() == 'LLM_MODEL=original\n'
    assert list(tmp_path.iterdir()) == [path]


def test_invalid_export_cannot_modify_env_file(tmp_path):
    path = tmp_path / '.env'
    path.write_text('LLM_MODEL=original\n')
    with pytest.raises(ValueError):
        sync_model_env(path, ModelConfig(model='bad\nINJECT=1', base_url='https://example.invalid', api_key='offline'))
    assert path.read_text() == 'LLM_MODEL=original\n'
