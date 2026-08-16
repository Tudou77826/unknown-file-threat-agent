from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping, Literal

from dotenv import dotenv_values
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, ConfigDict, Field, SecretStr


PROJECT_ROOT = Path(__file__).resolve().parents[3]


class FrozenSettings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class ApplicationSettings(FrozenSettings):
    environment: Literal["development", "demo", "production"] = "development"
    mode: Literal["deterministic", "llm", "deepagents"] = "llm"
    default_tenant: str = "default"
    default_run_id: str = "primary"
    default_case_dir: Path = PROJECT_ROOT / "cases" / "c2_malicious"
    output_dir: Path | None = None
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    investigation_lookback_hours: float = Field(default=24.0, gt=0, le=24 * 30)


class CheckpointSettings(FrozenSettings):
    backend: Literal["memory", "sqlite"] = "memory"
    path: Path | None = None


class GraphSettings(FrozenSettings):
    recursion_limit: int = Field(default=1000, ge=10, le=10000)


class JudgmentBudgetSettings(FrozenSettings):
    max_iterations: int = Field(default=30, ge=1, le=500)
    max_tool_calls: int = Field(default=60, ge=1, le=1000)
    max_repair_actions: int = Field(default=8, ge=0, le=100)
    max_report_rejudgments: int = Field(default=2, ge=0, le=20)


class ResponseBudgetSettings(FrozenSettings):
    max_iterations: int = Field(default=3, ge=1, le=20)


class EvidenceQuerySettings(FrozenSettings):
    default_limit: int = Field(default=1000, ge=1, le=5000)
    max_limit: int = Field(default=5000, ge=1, le=5000)


class ModelSettings(FrozenSettings):
    api_key: SecretStr | None = None
    base_url: str = "https://api.siliconflow.cn/v1"
    model_name: str | None = None
    max_tokens: int = Field(default=512, ge=1, le=32768)
    context_window_tokens: int = Field(default=100000, ge=1024, le=1000000)
    timeout_seconds: float = Field(default=240, gt=0, le=1800)
    max_retries: int = Field(default=2, ge=0, le=10)
    temperature: float = Field(default=0, ge=0, le=2)


class DemoSettings(FrozenSettings):
    data_store_path: Path = PROJECT_ROOT / "outputs" / "demo-reference.sqlite"
    runtime_store_path: Path = PROJECT_ROOT / "outputs" / "investigation-runtime.sqlite"
    dataset_version: str = "2026.08.1"
    data_profile: str = "l3-attribution-and-assets"
    random_seed: int = 20260811


class PresentationSettings(FrozenSettings):
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)


class AppSettings(FrozenSettings):
    application: ApplicationSettings
    checkpoint: CheckpointSettings
    graph: GraphSettings
    judgment_budget: JudgmentBudgetSettings
    response_budget: ResponseBudgetSettings
    evidence_query: EvidenceQuerySettings
    judgment_model: ModelSettings
    response_model: ModelSettings
    report_model: ModelSettings
    demo: DemoSettings
    presentation: PresentationSettings

    @classmethod
    def load(
        cls,
        *,
        cli_overrides: Mapping[str, Any] | None = None,
        environ: Mapping[str, str] | None = None,
        env_file: Path | None = None,
    ) -> "AppSettings":
        """Load settings with CLI > process environment > root .env precedence."""

        values: dict[str, Any] = {
            key: value
            for key, value in dotenv_values(env_file or PROJECT_ROOT / ".env").items()
            if value is not None
        }
        values.update(dict(environ if environ is not None else os.environ))
        values.update({key: value for key, value in (cli_overrides or {}).items() if value is not None})

        def get(name: str, default: Any = None, *legacy: str) -> Any:
            for key in (name, *legacy):
                if key in values and values[key] not in (None, ""):
                    return values[key]
            return default

        def path(name: str, default: Path | None = None) -> Path | None:
            raw = get(name, default)
            if raw in (None, ""):
                return None
            resolved = Path(str(raw))
            return resolved if resolved.is_absolute() else PROJECT_ROOT / resolved

        common_api_key = get("THREAT_AGENT_API_KEY", None, "SILICONFLOW_API_KEY")
        common_base_url = get("THREAT_AGENT_API_BASE", "https://api.siliconflow.cn/v1")
        common_model_name = get("MODEL_NAME")
        common_context_window = get("MODEL_CONTEXT_WINDOW_TOKENS", 100000)

        def model(role: str) -> ModelSettings:
            prefix = role.upper()
            return ModelSettings(
                api_key=get(f"{prefix}_MODEL_API_KEY", common_api_key),
                base_url=get(f"{prefix}_MODEL_API_BASE", common_base_url),
                model_name=get(f"{prefix}_MODEL_NAME", common_model_name),
                max_tokens=get(f"{prefix}_MODEL_MAX_TOKENS", 512),
                context_window_tokens=get(
                    f"{prefix}_MODEL_CONTEXT_WINDOW_TOKENS", common_context_window
                ),
                timeout_seconds=get(
                    f"{prefix}_MODEL_TIMEOUT_SECONDS",
                    get(f"{prefix}_MODEL_TIMEOUT", 240),
                ),
                max_retries=get(f"{prefix}_MODEL_MAX_RETRIES", 2),
                temperature=get(f"{prefix}_MODEL_TEMPERATURE", 0),
            )

        judgment_model = model("judgment")
        response_model = model("response")
        # Report generation reuses the judgment model identity, but is a heavy
        # single-shot JSON output that deserves its own (larger) timeout and
        # token budget. Only identity fields inherit from judgment.
        report_model = ModelSettings(
            api_key=judgment_model.api_key,
            base_url=judgment_model.base_url,
            model_name=judgment_model.model_name,
            max_tokens=get("REPORT_MODEL_MAX_TOKENS", 8192),
            context_window_tokens=get(
                "REPORT_MODEL_CONTEXT_WINDOW_TOKENS", common_context_window
            ),
            timeout_seconds=get(
                "REPORT_MODEL_TIMEOUT_SECONDS",
                get("REPORT_MODEL_TIMEOUT", 300),
            ),
            max_retries=get("REPORT_MODEL_MAX_RETRIES", judgment_model.max_retries),
            temperature=get("REPORT_MODEL_TEMPERATURE", 0),
        )

        settings = cls(
            application=ApplicationSettings(
                environment=get("THREAT_AGENT_ENV", "development"),
                mode=get("THREAT_AGENT_MODE", "llm"),
                default_tenant=get("THREAT_AGENT_DEFAULT_TENANT", "default"),
                default_run_id=get("THREAT_AGENT_DEFAULT_RUN_ID", "primary"),
                default_case_dir=path(
                    "THREAT_AGENT_DEFAULT_CASE_DIR", PROJECT_ROOT / "cases" / "c2_malicious"
                ),
                output_dir=path("THREAT_AGENT_OUTPUT_DIR"),
                log_level=get("THREAT_AGENT_LOG_LEVEL", "INFO"),
                investigation_lookback_hours=get("INVESTIGATION_LOOKBACK_HOURS", 24.0),
            ),
            checkpoint=CheckpointSettings(
                backend=get("THREAT_AGENT_CHECKPOINT_BACKEND", "memory"),
                path=path("THREAT_AGENT_CHECKPOINT_PATH"),
            ),
            graph=GraphSettings(
                recursion_limit=get("THREAT_AGENT_GRAPH_RECURSION_LIMIT", 1000)
            ),
            judgment_budget=JudgmentBudgetSettings(
                max_iterations=get("JUDGMENT_MAX_ITERATIONS", 30),
                max_tool_calls=get("JUDGMENT_MAX_TOOL_CALLS", 60),
                max_repair_actions=get("JUDGMENT_MAX_REPAIR_ACTIONS", 8),
                max_report_rejudgments=get(
                    "JUDGMENT_MAX_REPORT_REJUDGMENTS",
                    get("JUDGMENT_MAX_VERDICT_REPAIRS", 2),
                ),
            ),
            response_budget=ResponseBudgetSettings(
                max_iterations=get("RESPONSE_MAX_ITERATIONS", 3)
            ),
            evidence_query=EvidenceQuerySettings(
                default_limit=get("EVIDENCE_QUERY_DEFAULT_LIMIT", 1000),
                max_limit=get("EVIDENCE_QUERY_MAX_LIMIT", 5000),
            ),
            judgment_model=judgment_model,
            response_model=response_model,
            report_model=report_model,
            demo=DemoSettings(
                data_store_path=path(
                    "DEMO_DATA_STORE_PATH", PROJECT_ROOT / "outputs" / "demo-reference.sqlite"
                ),
                runtime_store_path=path(
                    "DEMO_RUNTIME_STORE_PATH", PROJECT_ROOT / "outputs" / "investigation-runtime.sqlite"
                ),
                dataset_version=get("DEMO_DATASET_VERSION", "2026.08.1"),
                data_profile=get("DEMO_DATA_PROFILE", "l3-attribution-and-assets"),
                random_seed=get("DEMO_RANDOM_SEED", 20260811),
            ),
            presentation=PresentationSettings(
                host=get("THREAT_AGENT_API_HOST", "127.0.0.1"),
                port=get("THREAT_AGENT_API_PORT", 8000),
            ),
        )
        if settings.evidence_query.default_limit > settings.evidence_query.max_limit:
            raise ValueError("EVIDENCE_QUERY_DEFAULT_LIMIT cannot exceed EVIDENCE_QUERY_MAX_LIMIT")
        if settings.checkpoint.backend == "sqlite" and settings.checkpoint.path is None:
            raise ValueError("SQLite checkpoint backend requires THREAT_AGENT_CHECKPOINT_PATH")
        return settings

    def require_models(self) -> None:
        for role, model in (
            ("judgment", self.judgment_model),
            ("response", self.response_model),
        ):
            if model.api_key is None or not model.base_url or not model.model_name:
                raise RuntimeError(f"LLM mode requires API key, base URL and model name for {role}")


def build_chat_model(settings: ModelSettings):
    if settings.api_key is None or not settings.model_name:
        raise RuntimeError("Chat model configuration is incomplete")
    return ChatOpenAI(
        model=settings.model_name,
        api_key=settings.api_key.get_secret_value(),
        base_url=settings.base_url,
        temperature=settings.temperature,
        max_tokens=settings.max_tokens,
        timeout=settings.timeout_seconds,
        max_retries=settings.max_retries,
    )


def build_judgment_model(settings: AppSettings | None = None):
    loaded = settings or AppSettings.load()
    return build_chat_model(loaded.judgment_model)


def build_response_model(settings: AppSettings | None = None):
    loaded = settings or AppSettings.load()
    return build_chat_model(loaded.response_model)


def build_report_model(settings: AppSettings | None = None):
    loaded = settings or AppSettings.load()
    return build_chat_model(loaded.report_model)
