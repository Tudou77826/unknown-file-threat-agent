"""TestCase schema — the standardized exam question for capability validation.

Field set follows design.md §3.1 plus the review rulings: every case anchors
one judgment-target file, ground truth is two-layered (behavioral ATT&CK
outcome vs. file-level judgment), and rule-side expectations carry the
acceptance-receipt requirement that gates miss-counting.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from ._base import StrictModel

CASE_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*$")
VARIANT_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class FileJudgment(str, Enum):
    """File-level ground truth. ``abused`` covers legitimate binaries whose
    malicious use is the attack (LOLBin-style); the AI side must argue from
    context, not from the file itself."""

    malicious = "malicious"
    benign = "benign"
    abused = "abused"


class RiskLevel(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    none = "none"


class BehavioralGroundTruth(StrictModel):
    technique_achieved: bool
    basis: str = Field(min_length=1, description="行为级依据：剧本是否达成及其证据")


class FileGroundTruth(StrictModel):
    judgment: FileJudgment
    basis: str = Field(min_length=1, description="文件级判定依据")


class GroundTruth(StrictModel):
    """Double-layer ground truth: behavioral (technique outcome) is what the
    rule side is scored against; file judgment is what the AI side is scored
    against. Variants derived from a case share this object verbatim."""

    behavior: BehavioralGroundTruth
    file: FileGroundTruth
    source: str = Field(min_length=1, description="GT 来源与确认方式（人工确认/剧本推导）")


class JudgmentTarget(StrictModel):
    """The single file the AI verdict anchors on. ``file_hash`` must equal the
    replay input record's ``File_hash`` — enforced at load time."""

    file_path: str = Field(min_length=1)
    file_hash: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    file_type: str = Field(min_length=1)


class ExpectedRuleResult(StrictModel):
    expected_hit: bool | None = Field(
        default=None, description="预期规则检出；None 表示不设预期（观察值）"
    )
    note: str | None = None
    requires_acceptance_receipt: bool = Field(
        default=True,
        description="漏检统计前提：仅「已受理且处理完成且无告警」计为漏检",
    )


class ExpectedAiResult(StrictModel):
    verdict: Literal["malicious", "benign"] | None = None
    # 期望的判定等级（六档）。复核裁决后逐案落盘；与 verdict 必须同侧。
    verdict_level: str | None = Field(default=None)
    risk_level: RiskLevel | None = None
    note: str | None = None

    @field_validator("verdict_level")
    @classmethod
    def _level_in_scale(cls, value):
        # 独立包：六级判定本地定义（与 contracts.VerdictLevel 语义对齐，抽包纪律）
        allowed = {"benign", "likely_benign", "insufficient_evidence",
                   "suspicious", "likely_malicious", "confirmed_malicious"}
        if value is not None and value not in allowed:
            raise ValueError(f"verdict_level 必须是六级判定之一: {sorted(allowed)}")
        return value


class TelemetryInventory(StrictModel):
    """Declared replay contents. The loader cross-checks both lists against
    the replay directory: missing files or undeclared files fail the load."""

    event_files: list[str] = Field(min_length=1)
    environment_baseline_sources: list[str] = Field(
        default_factory=list,
        description="环境基线来源（如 rpm-inventory、cmdb-baseline），replay 内须存在对应 source_system 的事件",
    )


class CaseProvenance(StrictModel):
    origin: Literal["hand-written", "attack-run", "autonomous-attack"]
    environment: str | None = Field(default=None, description="产出该 Case 的环境标识")
    collector: str | None = Field(default=None, description="采集器标识与版本")
    created: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    notes: str | None = None


class VariantSpec(StrictModel):
    variant_id: str = Field(min_length=1, pattern=r"^[a-z0-9][a-z0-9-]*$")
    description: str | None = None
    parameters: dict[str, str] = Field(min_length=1)

    @field_validator("parameters")
    @classmethod
    def _no_empty_values(cls, value: dict[str, str]) -> dict[str, str]:
        empty = [key for key, item in value.items() if not item]
        if empty:
            raise ValueError(f"variant parameters must be non-empty: {empty}")
        return value


class ParameterSpec(StrictModel):
    """Scenario-level parameterization: ``{{name}}`` placeholders in replay
    payloads are substituted with defaults (base view) or variant overrides.
    Orthogonal to demo data profiles (l0–l3), which crop data availability."""

    defaults: dict[str, str] = Field(default_factory=dict)
    variants: list[VariantSpec] = Field(default_factory=list)

    @field_validator("defaults")
    @classmethod
    def _defaults_non_empty(cls, value: dict[str, str]) -> dict[str, str]:
        empty = [key for key, item in value.items() if not item]
        if empty:
            raise ValueError(f"parameter defaults must be non-empty: {empty}")
        return value


class TestCase(StrictModel):
    schema_version: str = Field(default="1.0", pattern=r"^\d+\.\d+$")
    case_id: str = Field(pattern=CASE_ID_PATTERN.pattern)
    attack_tags: list[str] = Field(
        min_length=1, description="ATT&CK Technique / Tactic 标签（T-ID 优先）"
    )
    scenario: str = Field(min_length=1)
    judgment_target: JudgmentTarget
    ground_truth: GroundTruth
    expected_rule: ExpectedRuleResult
    expected_ai: ExpectedAiResult
    key_evidence: list[str] = Field(min_length=1)
    risk_level: RiskLevel
    recommended_action: str = Field(min_length=1)
    telemetry: TelemetryInventory
    provenance: CaseProvenance
    parameters: ParameterSpec = Field(default_factory=ParameterSpec)

    def variant_case_id(self, variant_id: str) -> str:
        if not VARIANT_ID_PATTERN.match(variant_id):
            raise ValueError(f"invalid variant id: {variant_id!r}")
        return f"{self.case_id}~{variant_id}"

    def variant_ids(self) -> list[str]:
        return [spec.variant_id for spec in self.parameters.variants]

    @model_validator(mode="after")
    def _expected_level_same_side_as_verdict(self) -> "TestCase":
        level = self.expected_ai.verdict_level
        verdict = self.expected_ai.verdict
        if level is not None and verdict is not None:
            malicious_side = {"suspicious", "likely_malicious", "confirmed_malicious"}
            if (verdict == "malicious") != (level in malicious_side):
                raise ValueError(
                    f"expected_ai.verdict={verdict} 与 verdict_level={level} 不同侧"
                )
        return self

    @model_validator(mode="after")
    def _expected_ai_consistent_with_truth(self) -> "TestCase":
        """The AI is scored against the file-level truth: an expectation
        that contradicts the ground truth is an authoring error, not a
        meaningful test."""

        if self.expected_ai.verdict is not None:
            implied = "malicious" if self.ground_truth.file.judgment in (
                FileJudgment.malicious,
                FileJudgment.abused,
            ) else "benign"
            if self.expected_ai.verdict != implied:
                raise ValueError(
                    f"expected_ai.verdict={self.expected_ai.verdict} contradicts "
                    f"ground_truth.file.judgment={self.ground_truth.file.judgment.value} "
                    f"(implies {implied})"
                )
        return self
