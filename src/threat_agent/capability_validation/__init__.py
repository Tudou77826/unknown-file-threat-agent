"""Feature 19 Step 01 — case & replay contracts for capability validation.

Standalone package (architecture gate): no imports from other threat_agent
subpackages; alignment with the data-foundation ingestion path is enforced
by tests on the outside.
"""

from .case_model import (
    BehavioralGroundTruth,
    CaseProvenance,
    ExpectedAiResult,
    ExpectedRuleResult,
    FileGroundTruth,
    FileJudgment,
    GroundTruth,
    JudgmentTarget,
    ParameterSpec,
    RiskLevel,
    TestCase,
    TelemetryInventory,
    VariantSpec,
)
from .derivation import (
    DerivationResult,
    DerivedCase,
    derive_variant,
    materialize_default,
)
from .projection_auditd import AuditDProjector, parse_auditd_lines
from .replay import (
    BASELINE_SOURCE_KINDS,
    RAW_TELEMETRY_KINDS,
    ReplayBundle,
    RawTelemetryEnvelope,
    RawTelemetryProjector,
    find_unresolved_placeholders,
    substitute,
    validate_canonical_event,
)
from .suite import (
    MAX_ARTIFACT_BYTES,
    CaseEntry,
    LoadedCase,
    SuiteManifest,
    ValidationSuiteRepository,
    digest_case_directory,
)

__all__ = [
    "AuditDProjector",
    "BASELINE_SOURCE_KINDS",
    "BehavioralGroundTruth",
    "CaseEntry",
    "CaseProvenance",
    "DerivedCase",
    "DerivationResult",
    "ExpectedAiResult",
    "ExpectedRuleResult",
    "FileGroundTruth",
    "FileJudgment",
    "GroundTruth",
    "JudgmentTarget",
    "LoadedCase",
    "MAX_ARTIFACT_BYTES",
    "ParameterSpec",
    "RAW_TELEMETRY_KINDS",
    "ReplayBundle",
    "RawTelemetryEnvelope",
    "RawTelemetryProjector",
    "RiskLevel",
    "SuiteManifest",
    "TestCase",
    "TelemetryInventory",
    "ValidationSuiteRepository",
    "VariantSpec",
    "derive_variant",
    "digest_case_directory",
    "find_unresolved_placeholders",
    "materialize_default",
    "parse_auditd_lines",
    "substitute",
    "validate_canonical_event",
]
