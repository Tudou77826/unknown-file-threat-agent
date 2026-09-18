"""Model-service settings store (management plane, Feature 17 extension).

Reads and updates the model-service block of the root ``.env`` file so the
workbench settings page can edit base URL / model identity / context window /
proxy and TLS switches without hand-editing files. The writer preserves the
existing file line-for-line (comments, ordering, unrelated keys) and only
rewrites the keys it owns; missing keys are appended under a marked section.

Validation is deliberately stricter than the raw loader: values written here
must produce a usable chat model on the next service restart.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from pydantic import Field, field_validator

from ..shared import StrictModel

# Keys this store owns, in the order they are appended when absent.
# Per-role model names are synced with MODEL_NAME so stale overrides cannot
# shadow a changed common model after restart.
_BASE_KEYS = (
    "THREAT_AGENT_MODEL_PROVIDER",
    "THREAT_AGENT_API_BASE",
    "MODEL_NAME",
    "MODEL_CONTEXT_WINDOW_TOKENS",
    "MODEL_DISABLE_TLS_VERIFY",
    "MODEL_DISABLE_PROXY",
)
_SYNC_WITH_MODEL_NAME = ("JUDGMENT_MODEL_NAME", "RESPONSE_MODEL_NAME")
_API_KEY = "THREAT_AGENT_API_KEY"

_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")

_MARK_START = "# ── 模型服务（运行工作台写入） ──"


class ModelServiceConfig(StrictModel):
    """Fields editable on the workbench settings page."""

    provider: str = Field(default="openai")
    base_url: str = Field(min_length=1)
    model_name: str = Field(min_length=1)
    context_window_tokens: int = Field(ge=1024, le=1000000)
    disable_proxy: bool = False
    disable_tls_verify: bool = False
    # write-only: 不回显；留空表示保持现有密钥
    api_key: str | None = Field(default=None)

    @field_validator("provider")
    @classmethod
    def _provider_known(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in ("openai", "anthropic"):
            raise ValueError("provider 只支持 openai 或 anthropic")
        return value

    @field_validator("base_url")
    @classmethod
    def _base_url_is_http(cls, value: str) -> str:
        value = value.strip()
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"base_url 必须是 http(s) 地址：{value}")
        return value.rstrip("/")

    @field_validator("model_name")
    @classmethod
    def _model_name_clean(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("模型 ID 不能为空")
        return value


class ModelServiceSettingsStore:
    """Line-preserving ``.env`` reader/writer for the model-service block."""

    def __init__(self, env_path: Path):
        self.env_path = Path(env_path)

    # -- read ----------------------------------------------------------------

    def read(self) -> ModelServiceConfig | None:
        """Saved values (what will apply on restart); None before first save."""

        values = self._read_values()
        if "THREAT_AGENT_API_BASE" not in values and "MODEL_NAME" not in values:
            return None
        def flag(key: str) -> bool:
            return str(values.get(key, "")).strip().lower() in ("1", "true", "yes", "on")
        return ModelServiceConfig(
            provider=str(values.get("THREAT_AGENT_MODEL_PROVIDER", "openai")).strip().lower(),
            base_url=str(values.get("THREAT_AGENT_API_BASE", "")).strip(),
            model_name=str(values.get("MODEL_NAME", "")).strip(),
            context_window_tokens=int(str(values.get("MODEL_CONTEXT_WINDOW_TOKENS", 100000))),
            disable_tls_verify=flag("MODEL_DISABLE_TLS_VERIFY"),
            disable_proxy=flag("MODEL_DISABLE_PROXY"),
        )

    def _read_values(self) -> dict[str, str]:
        values: dict[str, str] = {}
        if not self.env_path.exists():
            return values
        for line in self.env_path.read_text(encoding="utf-8").splitlines():
            match = _LINE.match(line)
            if match:
                values[match.group(1)] = match.group(2).strip().strip("'\"")
        return values

    # -- write ---------------------------------------------------------------

    def save(self, config: ModelServiceConfig) -> None:
        """Update owned keys in place, append the missing ones; the API key is
        written only when a new value is supplied (never echoed back)."""

        updates: dict[str, str] = {
            "THREAT_AGENT_MODEL_PROVIDER": config.provider,
            "THREAT_AGENT_API_BASE": config.base_url,
            "MODEL_NAME": config.model_name,
            "MODEL_CONTEXT_WINDOW_TOKENS": str(config.context_window_tokens),
            "MODEL_DISABLE_TLS_VERIFY": "true" if config.disable_tls_verify else "false",
            "MODEL_DISABLE_PROXY": "true" if config.disable_proxy else "false",
        }
        if config.api_key:
            updates[_API_KEY] = config.api_key.strip()
        existing_values = self._read_values()
        # 同步按角色覆盖的模型名，防止旧值在重启后遮蔽新的 MODEL_NAME
        for key in _SYNC_WITH_MODEL_NAME:
            if key in existing_values:
                updates[key] = config.model_name

        lines = (
            self.env_path.read_text(encoding="utf-8").splitlines()
            if self.env_path.exists()
            else ["# 配置原则：只写与代码默认值的差异，其余省略。"]
        )
        pending = dict(updates)
        owned = set(updates)
        written: list[str] = []
        seen_owned: set[str] = set()
        for line in lines:
            match = _LINE.match(line)
            key = match.group(1) if match else None
            if key in owned:
                if key in seen_owned:
                    # 重复键遵循"后者生效"语义：只保留第一处（本次写入值），
                    # 删除后续重复行，避免保存值被旧行遮蔽。
                    continue
                if key in pending:
                    written.append(f"{key}={pending.pop(key)}")
                else:  # 同步键：文件里没有对应覆盖时只需去重，不新增
                    written.append(line)
                seen_owned.add(key)
            else:
                written.append(line)
        if pending:
            if written and written[-1].strip():
                written.append("")
            written.append(_MARK_START)
            for key in _BASE_KEYS:
                if key in pending:
                    written.append(f"{key}={pending.pop(key)}")
            if _API_KEY in pending:
                written.append(f"{_API_KEY}={pending.pop(_API_KEY)}")
        self.env_path.write_text("\n".join(written) + "\n", encoding="utf-8")
