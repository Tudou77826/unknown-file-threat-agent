from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from threat_agent.bootstrap.settings import (
    AppSettings,
    ModelSettings,
    build_chat_model,
    format_effective_settings,
)


def test_settings_precedence_and_path_resolution(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "THREAT_AGENT_MODE=deterministic\n"
        "THREAT_AGENT_DEFAULT_TENANT=from-file\n"
        "JUDGMENT_MAX_ITERATIONS=12\n"
        "DEMO_DATA_PROFILE=l1\n",
        encoding="utf-8",
    )
    settings = AppSettings.load(
        env_file=env_file,
        environ={"THREAT_AGENT_DEFAULT_TENANT": "from-process"},
        cli_overrides={"THREAT_AGENT_DEFAULT_TENANT": "from-cli"},
    )
    assert settings.application.default_tenant == "from-cli"
    assert settings.application.mode == "deterministic"
    assert settings.judgment_budget.max_iterations == 12
    assert settings.demo.data_profile == "l1"
    assert settings.application.default_case_dir.is_absolute()


def test_settings_reject_invalid_limits(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "EVIDENCE_QUERY_DEFAULT_LIMIT=100\nEVIDENCE_QUERY_MAX_LIMIT=10\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="cannot exceed"):
        AppSettings.load(env_file=env_file, environ={})


def test_llm_mode_requires_both_model_configurations(tmp_path: Path):
    settings = AppSettings.load(env_file=tmp_path / "missing.env", environ={})
    with pytest.raises(RuntimeError, match="judgment"):
        settings.require_models()


def test_settings_reject_non_positive_budget(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text("JUDGMENT_MAX_ITERATIONS=0\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        AppSettings.load(env_file=env_file, environ={})


def test_effective_settings_summary_marks_overrides_and_masks_keys(tmp_path: Path):
    settings = AppSettings.load(
        env_file=tmp_path / "missing.env",
        environ={
            "THREAT_AGENT_API_KEY": "sk-secret-value",
            "JUDGMENT_MODEL_NAME": "some-model",
            "JUDGMENT_MODEL_TIMEOUT_SECONDS": "90",
        },
    )
    summary = format_effective_settings(settings)
    # Overridden values carry the marker; untouched defaults do not.
    assert "judgment=some-model*" in summary
    assert "judgment=90s*" in summary
    assert "iterations=30" in summary and "iterations=30*" not in summary
    assert "lookback=24h" in summary and "lookback=24h*" not in summary
    # The API key itself never appears, only its state.
    assert "sk-secret-value" not in summary
    assert "key=<set>*" in summary


def test_disable_proxy_defaults_off_and_inherits_to_report(tmp_path: Path):
    settings = AppSettings.load(env_file=tmp_path / "missing.env", environ={})
    assert settings.judgment_model.disable_proxy is False
    assert settings.response_model.disable_proxy is False
    assert settings.report_model.disable_proxy is False


def test_disable_proxy_global_flag_applies_to_all_roles(tmp_path: Path):
    settings = AppSettings.load(
        env_file=tmp_path / "missing.env",
        environ={"MODEL_DISABLE_PROXY": "true"},
    )
    assert settings.judgment_model.disable_proxy is True
    assert settings.response_model.disable_proxy is True
    assert settings.report_model.disable_proxy is True


def test_build_chat_model_bypasses_proxy_env_when_disabled():
    settings = ModelSettings(
        api_key=SecretStr("sk-test"),
        model_name="test-model",
        disable_proxy=True,
    )
    chat = build_chat_model(settings)
    assert isinstance(chat.http_client, httpx.Client)
    assert chat.http_client._trust_env is False
    assert isinstance(chat.http_async_client, httpx.AsyncClient)
    assert chat.http_async_client._trust_env is False


def test_build_chat_model_keeps_default_clients_without_disable_proxy():
    settings = ModelSettings(
        api_key=SecretStr("sk-test"),
        model_name="test-model",
    )
    chat = build_chat_model(settings)
    assert chat.http_client is None
    assert chat.http_async_client is None
