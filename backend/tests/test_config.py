from audit.config import ModelConfig


def test_deepseek_api_key_enables_official_defaults():
    config = ModelConfig.from_environ({"DEEPSEEK_API_KEY": "local-test-key"})

    assert config.configured
    assert config.model == "deepseek-flash"
    assert config.base_url == "https://api.deepseek.com"
    assert config.api_key == "local-test-key"


def test_explicit_model_settings_override_deepseek_defaults():
    config = ModelConfig.from_environ({
        "DEEPSEEK_API_KEY": "local-test-key",
        "LLM_MODEL": "custom-model",
        "LLM_BASE_URL": "https://provider.example/v1/",
    })

    assert config.model == "custom-model"
    assert config.base_url == "https://provider.example/v1"


def test_explicit_api_key_takes_precedence_over_provider_alias():
    config = ModelConfig.from_environ({
        "DEEPSEEK_API_KEY": "deepseek-test-key",
        "LLM_API_KEY": "explicit-test-key",
    })

    assert config.api_key == "explicit-test-key"


def test_deepseek_defaults_are_not_used_without_its_key():
    config = ModelConfig.from_environ({})

    assert not config.configured
    assert config.model == ""
    assert config.base_url == ""
