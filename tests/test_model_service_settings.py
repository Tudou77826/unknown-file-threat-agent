"""Model-service settings page gates: the .env writer preserves unrelated
content and syncs per-role model names, the surface validates input, and the
settings page renders the editable form (Feature 17 extension)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from threat_agent.bootstrap.settings import ModelSettings, build_chat_model
from threat_agent.bootstrap.settings_store import ModelServiceConfig, ModelServiceSettingsStore
from threat_agent.bootstrap.workbench_bindings import ModelServiceSettingsSurface
from threat_agent.presentation import InMemoryCaseReadStore
from threat_agent.presentation.api.routes import create_app


def _write_env(tmp_path: Path, content: str) -> Path:
    path = tmp_path / ".env"
    path.write_text(content, encoding="utf-8")
    return path


def _config(**overrides) -> ModelServiceConfig:
    payload = dict(
        provider="anthropic",
        base_url="https://gw.example.com:9443",
        model_name="m-new",
        context_window_tokens=128000,
        disable_tls_verify=True,
        disable_proxy=False,
    )
    payload.update(overrides)
    return ModelServiceConfig(**payload)


def test_save_updates_owned_keys_in_place_and_preserves_content(tmp_path):
    env = _write_env(tmp_path, (
        "# 配置原则：只写差异。\n"
        "# ── 模型服务 ──\n"
        "THREAT_AGENT_API_KEY=sk-secret\n"
        "THREAT_AGENT_API_BASE=https://old.example.com/v1\n"
        "JUDGMENT_MODEL_NAME=m-old\n"
        "RESPONSE_MODEL_NAME=m-old\n"
        "MODEL_NAME=m-old\n"
        "KNOWLEDGE_ADAPTER=attack\n"
    ))
    store = ModelServiceSettingsStore(env)
    store.save(_config())

    text = env.read_text(encoding="utf-8")
    lines = text.splitlines()
    assert lines[0] == "# 配置原则：只写差异。"
    assert "THREAT_AGENT_API_KEY=sk-secret" in lines  # 未提供的 key 原样保留
    assert "KNOWLEDGE_ADAPTER=attack" in lines
    assert "THREAT_AGENT_API_BASE=https://gw.example.com:9443" in lines
    assert "MODEL_NAME=m-new" in lines
    # 按角色覆盖被同步，防止旧值遮蔽新模型名
    assert "JUDGMENT_MODEL_NAME=m-new" in lines
    assert "RESPONSE_MODEL_NAME=m-new" in lines
    assert "MODEL_DISABLE_TLS_VERIFY=true" in lines
    assert "MODEL_DISABLE_PROXY=false" in lines

    saved = store.read()
    assert saved is not None
    assert saved.model_name == "m-new"
    assert saved.provider == "anthropic"
    assert saved.disable_tls_verify is True


def test_save_appends_missing_keys_and_read_roundtrip(tmp_path):
    env = _write_env(tmp_path, "# 空配置\n")
    store = ModelServiceSettingsStore(env)
    assert store.read() is None

    store.save(_config(provider="openai", base_url="https://api.x.com/v1", disable_tls_verify=False))
    values = dict(
        line.split("=", 1)
        for line in env.read_text(encoding="utf-8").splitlines()
        if "=" in line and not line.startswith("#")
    )
    assert values["THREAT_AGENT_API_BASE"] == "https://api.x.com/v1"
    assert values["THREAT_AGENT_MODEL_PROVIDER"] == "openai"
    assert "THREAT_AGENT_API_KEY" not in values  # 未提供不写入
    assert store.read() is not None


def test_api_key_written_only_when_provided(tmp_path):
    env = _write_env(tmp_path, "THREAT_AGENT_API_KEY=sk-old\n")
    store = ModelServiceSettingsStore(env)
    store.save(_config())
    assert "THREAT_AGENT_API_KEY=sk-old" in env.read_text(encoding="utf-8")
    store.save(_config(api_key="sk-new"))
    assert "THREAT_AGENT_API_KEY=sk-new" in env.read_text(encoding="utf-8")


def test_save_removes_duplicate_keys_so_saved_value_applies(tmp_path):
    # .env 后者生效语义：旧文件可能有重复键（先 A 后 B，实际生效 B）。
    # 保存 C 后必须删掉重复行，否则 C 写在第一处会被后面的 B 遮蔽。
    env = _write_env(tmp_path, (
        "THREAT_AGENT_API_BASE=https://old-a.example.com\n"
        "MODEL_NAME=m-a\n"
        "THREAT_AGENT_API_BASE=https://old-b.example.com\n"
        "MODEL_NAME=m-b\n"
    ))
    store = ModelServiceSettingsStore(env)
    store.save(_config(provider="openai", base_url="https://new.example.com/v1",
                       model_name="m-new", disable_tls_verify=False))

    text = env.read_text(encoding="utf-8")
    assert text.count("THREAT_AGENT_API_BASE=") == 1
    assert text.count("MODEL_NAME=") == 1
    assert "https://new.example.com/v1" in text
    assert "old-b.example.com" not in text and "old-a.example.com" not in text
    saved = store.read()
    assert saved is not None and saved.base_url == "https://new.example.com/v1"


def test_validation_rejects_bad_provider_and_url(tmp_path):
    store = ModelServiceSettingsStore(_write_env(tmp_path, ""))
    import pytest

    with pytest.raises(Exception):
        _config(provider="gemini")
    with pytest.raises(Exception):
        _config(base_url="ftp://nope")
    with pytest.raises(Exception):
        _config(model_name="  ")


def test_tls_verify_flag_reaches_the_http_client():
    from pydantic import SecretStr

    settings = ModelSettings(
        api_key=SecretStr("dummy"),
        model_name="m",
        disable_tls_verify=True,
        disable_proxy=True,
    )
    model = build_chat_model(settings)
    async_client = getattr(model, "http_async_client", None)
    assert async_client is not None, "禁用代理或 TLS 校验时必须注入自定义 http 客户端"


# ---------------------------------------------------------------------------
# surface + routes + page
# ---------------------------------------------------------------------------

class _Surface(ModelServiceSettingsSurface):
    def __init__(self, tmp_path: Path, settings):
        from threat_agent.bootstrap.settings_store import ModelServiceSettingsStore

        self._settings = settings
        self._store = ModelServiceSettingsStore(tmp_path / ".env")


def _client(tmp_path: Path):
    from threat_agent.bootstrap.settings import AppSettings

    settings = AppSettings.load()
    surface = _Surface(tmp_path, settings)
    app = create_app(
        InMemoryCaseReadStore(),
        settings_overview={"items": [], "knowledge_adapter": "attack"},
        model_service_settings=surface,
    )
    return TestClient(app), surface


def test_settings_page_renders_editable_form(tmp_path):
    client, _surface = _client(tmp_path)
    html = client.get("/workbench/settings").text
    for fragment in ("ms-provider", "ms-base-url", "ms-model", "ms-ctx", "ms-tls", "ms-proxy", "ms-save", "ms-key"):
        assert fragment in html, fragment
    assert "重启服务后生效" in html


def test_post_saves_and_reports_restart_required(tmp_path):
    client, _surface = _client(tmp_path)
    response = client.post("/api/settings/model-service", json={
        "provider": "openai",
        "base_url": "https://api.new.com/v1",
        "model_name": "m2",
        "context_window_tokens": 64000,
        "disable_tls_verify": True,
        "disable_proxy": False,
    })
    assert response.status_code == 200
    body = response.json()
    assert body["saved"] is True and body["restart_required"] is True
    assert body["values"]["model_name"] == "m2"

    # 保存后再读页面：表单预填新值
    html = client.get("/workbench/settings").text
    assert "value='https://api.new.com/v1'" in html
    assert "value='m2'" in html
    assert "已保存的配置与当前运行值不同" in html  # 保存值 ≠ 运行值 → 提示重启生效


def test_post_invalid_url_returns_error(tmp_path):
    client, _surface = _client(tmp_path)
    response = client.post("/api/settings/model-service", json={
        "provider": "openai",
        "base_url": "not-a-url",
        "model_name": "m",
        "context_window_tokens": 64000,
    })
    assert response.status_code == 422
