"""Replay bundle: directory convention, canonical event contract, projection.

The replay directory is the loadable unit consumed by the AI-side pipeline:

    <case_dir>/
      case.json            # TestCase
      replay/
        input.json         # canonical File record (legacy ``cases/`` format)
        events/*.jsonl     # canonical events (legacy ``cases/`` format)
        coverage.json      # optional
        artifacts/         # optional binaries, git-stored, size-limited

The canonical event shape mirrors what
``threat_agent.data_foundation`` ingests today (``event_id``, ``event_type``,
``domain``, ``observed_at``, ``host_id``, ``subject_refs``, ``data``) — kept
as a dict contract here so this package stays standalone; tests on the
outside align both sides.

Raw telemetry → canonical projection is contract-only at Step 01: Step 02
converters implement :class:`RawTelemetryProjector` against the ten probe
categories (see telemetry-scope.md) plus the environment-baseline extras.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Protocol

from pydantic import Field, field_validator

from ._base import StrictModel
from .case_model import TestCase

PLACEHOLDER_PATTERN = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")
CANONICAL_EVENT_REQUIRED_KEYS = (
    "event_id",
    "event_type",
    "domain",
    "observed_at",
    "host_id",
    "subject_refs",
    "data",
)

# Probe-aligned raw telemetry kinds (telemetry-scope.md §对齐的探针采集范围).
RAW_TELEMETRY_KINDS = frozenset(
    {
        "process",  # §1 进程（含可执行文件 Hash —— 判定锚点唯一来源）
        "file",  # §2 文件事件（无内容 Hash/大小/读取/重命名）
        "network",  # §3 网络四元组（无字节数/DNS）
        "syscall",  # §4 关键 syscall
        "authentication",  # §5 登录认证
        "account_change",  # §6 账号管理（Canonical 模型暂无对应事件族，仅记录）
        "command",  # §7 命令执行
        "file_transfer",  # §8 文件传输
        "audit_log",  # §9 auditd 规则触发
        "port",  # §10 端口与端口→进程映射
        # 探针范围之外的自建补充（环境基线，反证数据来源）：
        "baseline_package_inventory",
        "baseline_approved_endpoints",
        "baseline_listening_ports",
    }
)

BASELINE_SOURCE_KINDS = {
    "package_inventory": "baseline_package_inventory",
    "approved_endpoints": "baseline_approved_endpoints",
    "listening_ports": "baseline_listening_ports",
}


class RawTelemetryEnvelope(StrictModel):
    """One raw record captured by the self-built collector. Step 02
    converters receive these and emit canonical events."""

    kind: str  # one of RAW_TELEMETRY_KINDS
    collector: str = Field(min_length=1, description="采集器标识与版本")
    captured_at: str = Field(min_length=1)
    host_id: str = Field(min_length=1)
    payload: dict[str, Any]

    @field_validator("kind")
    @classmethod
    def _kind_in_scope(cls, value: str) -> str:
        if value not in RAW_TELEMETRY_KINDS:
            raise ValueError(
                f"unknown telemetry kind {value!r}; must be one of the "
                f"probe-aligned kinds (telemetry-scope.md)"
            )
        return value


class RawTelemetryProjector(Protocol):
    """Projection contract: raw probe-aligned telemetry → canonical events."""

    def project(self, envelope: RawTelemetryEnvelope) -> list[dict[str, Any]]: ...


def validate_canonical_event(event: dict[str, Any]) -> None:
    """Gate every event entering a replay: the shape the AI-side ingestion
    path (ReferenceEventParser) requires. Raises ``ValueError`` on violation."""

    missing = [key for key in CANONICAL_EVENT_REQUIRED_KEYS if key not in event]
    if missing:
        raise ValueError(f"canonical event missing keys {missing}: {event!r}")
    if not isinstance(event["subject_refs"], list):
        raise ValueError("subject_refs must be a list")
    if not isinstance(event["data"], dict):
        raise ValueError("data must be an object")


class ReplayBundle:
    """Loaded (unsubstituted) replay payloads for one case."""

    def __init__(
        self,
        case: TestCase,
        input_record: dict[str, Any],
        events: list[dict[str, Any]],
        event_file_names: list[str],
        coverage: dict[str, Any] | None,
    ) -> None:
        self.case = case
        self.input_record = input_record
        self.events = events
        self.event_file_names = event_file_names
        self.coverage = coverage

    @classmethod
    def load(cls, case_dir: Path) -> "ReplayBundle":
        case = TestCase.model_validate(
            json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        )
        _check_truth_is_literal(case)
        replay_dir = case_dir / "replay"
        input_record = json.loads(
            (replay_dir / "input.json").read_text(encoding="utf-8")
        )
        event_paths = sorted((replay_dir / "events").glob("*.jsonl"))
        declared = list(case.telemetry.event_files)
        actual = [path.name for path in event_paths]
        if sorted(declared) != actual:
            raise ValueError(
                f"telemetry inventory mismatch for {case.case_id}: "
                f"declared {sorted(declared)} vs actual {actual}"
            )
        events: list[dict[str, Any]] = []
        for path in event_paths:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    events.append(json.loads(line))
        for event in events:
            validate_canonical_event(event)
        _check_environment_baseline(case, events)
        _check_anchor(case, input_record)
        coverage_path = replay_dir / "coverage.json"
        coverage = (
            json.loads(coverage_path.read_text(encoding="utf-8"))
            if coverage_path.exists()
            else None
        )
        return cls(case, input_record, events, actual, coverage)


def _check_anchor(case: TestCase, input_record: dict[str, Any]) -> None:
    input_hash = str(input_record.get("File_hash") or input_record.get("file_hash") or "")
    if input_hash != case.judgment_target.file_hash:
        raise ValueError(
            f"judgment target hash mismatch for {case.case_id}: "
            f"case.json {case.judgment_target.file_hash} vs input.json {input_hash}"
        )
    input_path = str(input_record.get("File_path") or input_record.get("file_path") or "")
    if input_path != case.judgment_target.file_path:
        raise ValueError(
            f"judgment target path mismatch for {case.case_id}: "
            f"case.json {case.judgment_target.file_path} vs input.json {input_path}"
        )
    input_type = str(input_record.get("File_type") or input_record.get("file_type") or "")
    if input_type != case.judgment_target.file_type:
        raise ValueError(
            f"judgment target type mismatch for {case.case_id}: "
            f"case.json {case.judgment_target.file_type} vs input.json {input_type}"
        )


def _check_truth_is_literal(case: TestCase) -> None:
    """Ground truth is shared verbatim across variants, so placeholders can
    never resolve there — any ``{{name}}`` in GT is an authoring error."""

    leftover = find_unresolved_placeholders(case.ground_truth.model_dump())
    if leftover:
        raise ValueError(
            f"case {case.case_id} ground truth contains placeholders {leftover}; "
            f"ground truth must be literal"
        )


def _check_environment_baseline(case: TestCase, events: list[dict[str, Any]]) -> None:
    present = {str(event.get("source_system")) for event in events}
    missing = [
        source
        for source in case.telemetry.environment_baseline_sources
        if source not in present
    ]
    if missing:
        raise ValueError(
            f"case {case.case_id} declares baseline sources absent from replay: {missing}"
        )


def substitute(value: Any, parameters: dict[str, str]) -> Any:
    """Recursively replace ``{{name}}`` placeholders in strings/dicts/lists."""

    def replace(text: str) -> str:
        def _sub(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in parameters:
                raise ValueError(f"placeholder {name!r} has no value")
            return parameters[name]

        return PLACEHOLDER_PATTERN.sub(_sub, text)

    if isinstance(value, str):
        return replace(value)
    if isinstance(value, dict):
        return {key: substitute(item, parameters) for key, item in value.items()}
    if isinstance(value, list):
        return [substitute(item, parameters) for item in value]
    return value


def find_unresolved_placeholders(value: Any) -> list[str]:
    """Names still present as ``{{name}}`` after substitution."""

    found: list[str] = []

    def walk(item: Any) -> None:
        if isinstance(item, str):
            found.extend(PLACEHOLDER_PATTERN.findall(item))
        elif isinstance(item, dict):
            for child in item.values():
                walk(child)
        elif isinstance(item, list):
            for child in item:
                walk(child)

    walk(value)
    return sorted(set(found))
