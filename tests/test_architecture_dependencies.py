from __future__ import annotations

import ast
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "src" / "threat_agent"


def _absolute_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    package = ["threat_agent", *path.relative_to(PACKAGE_ROOT).parent.parts]
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                imports.add(node.module)
            elif node.level > 0:
                base = package[: len(package) - (node.level - 1)]
                suffix = node.module.split(".") if node.module else []
                imports.add(".".join([*base, *suffix]))
    return imports


def _assert_does_not_import(package: str, forbidden: set[str]) -> None:
    violations: list[str] = []
    for path in (PACKAGE_ROOT / package).rglob("*.py"):
        for imported in _absolute_imports(path):
            if any(
                imported == f"threat_agent.{name}"
                or imported.startswith(f"threat_agent.{name}.")
                for name in forbidden
            ):
                violations.append(f"{path.relative_to(PACKAGE_ROOT)} -> {imported}")
    assert not violations, "Invalid architecture dependencies:\n" + "\n".join(violations)


def test_contracts_and_shared_have_no_feature_dependencies():
    features = {
        "bootstrap",
        "case_management",
        "data_foundation",
        "judgment",
        "knowledge",
        "presentation",
        "response_advisory",
    }
    _assert_does_not_import("contracts", features)
    _assert_does_not_import("shared", features)


def test_data_foundation_does_not_depend_on_workflow_modules():
    _assert_does_not_import(
        "data_foundation",
        {"bootstrap", "case_management", "judgment", "knowledge", "presentation", "response_advisory"},
    )


def test_judgment_does_not_depend_on_case_management():
    # The boundary port is a Python Protocol: judgment defines and consumes it,
    # concrete policies live in case_management and are injected by bootstrap.
    _assert_does_not_import("judgment", {"case_management"})


def test_presentation_only_consumes_stable_contracts():
    _assert_does_not_import(
        "presentation",
        {"bootstrap", "case_management", "data_foundation", "judgment", "knowledge", "response_advisory"},
    )


def test_package_root_contains_no_business_modules():
    assert sorted(path.name for path in PACKAGE_ROOT.glob("*.py")) == ["__init__.py"]


def test_only_bootstrap_reads_process_environment():
    violations: list[str] = []
    for path in PACKAGE_ROOT.rglob("*.py"):
        if "bootstrap" in path.relative_to(PACKAGE_ROOT).parts:
            continue
        text = path.read_text(encoding="utf-8")
        if "os.getenv" in text or "os.environ" in text or "load_dotenv" in text:
            violations.append(str(path.relative_to(PACKAGE_ROOT)))
    assert not violations, "Environment access outside bootstrap: " + ", ".join(violations)


def test_active_runtime_has_no_cross_host_scope_paths():
    """Feature 13: cross-host expansion and scope approval are deleted, not dormant."""

    forbidden_tokens = [
        "request_scope_expansion",
        "ScopeRequest",
        "ScopeExpansion",
        "awaiting_scope_approval",
        "apply_scope_decision",
        "resume_scope",
        "approve_scope",
        "scope_approval_mode",
        "max_scope_expansions",
    ]
    violations: list[str] = []
    for path in PACKAGE_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        hits = [token for token in forbidden_tokens if token in text]
        if hits:
            violations.append(f"{path.relative_to(PACKAGE_ROOT)}: {', '.join(hits)}")
    assert not violations, "Cross-host scope paths remain in the active runtime:\n" + "\n".join(violations)


def test_formal_report_is_only_constructed_by_the_publisher():
    """Feature 14: InvestigationReport construction is publisher-exclusive."""

    allowed_paths = {
        ("judgment", "application", "reporting.py"),
    }
    violations: list[str] = []
    for path in PACKAGE_ROOT.rglob("*.py"):
        if "InvestigationReport(" not in path.read_text(encoding="utf-8"):
            continue
        parts = path.relative_to(PACKAGE_ROOT).parts
        if parts in allowed_paths or path.parent.name == "contracts":
            continue
        violations.append(str(path.relative_to(PACKAGE_ROOT)))
    assert not violations, "InvestigationReport constructed outside the publisher:\n" + "\n".join(violations)


def test_no_silent_reference_filtering_or_legacy_repair_paths():
    forbidden_tokens = [
        "_sanitize_report",
        "发布校验已自动修复",
        "report_version +=",
        "max_verdict_repairs",
    ]
    violations: list[str] = []
    for path in PACKAGE_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        hits = [token for token in forbidden_tokens if token in text]
        if hits:
            violations.append(f"{path.relative_to(PACKAGE_ROOT)}: {', '.join(hits)}")
    assert not violations, "Legacy silent-repair paths remain:\n" + "\n".join(violations)


def test_validator_and_gate_stay_deterministic_and_framework_free():
    for name in ("report_validation.py", "evidence_gate.py", "report_draft.py"):
        path = PACKAGE_ROOT / "judgment" / "application" / name
        imports = _absolute_imports(path)
        for forbidden in (
            "threat_agent.bootstrap",
            "threat_agent.case_management",
            "threat_agent.data_foundation",
            "langchain_core",
            "langchain_openai",
        ):
            assert not any(
                imported == forbidden or imported.startswith(forbidden + ".")
                for imported in imports
            ), f"{name} must not import {forbidden}"
        assert "invoke_llm" not in path.read_text(encoding="utf-8")


def test_fallback_assembly_and_publication_status_flow_through_contracts():
    # Fallback field assembly lives only in the fallback builder.
    for path in PACKAGE_ROOT.rglob("*.py"):
        if "report_grounding_failed" in path.read_text(encoding="utf-8"):
            assert path.relative_to(PACKAGE_ROOT).as_posix() in {
                "judgment/application/reporting.py",
            }, f"fallback assembly leaked into {path}"
    # Presentation surfaces the contract field instead of parsing text.
    page = (PACKAGE_ROOT / "presentation" / "api" / "demo_page.py").read_text(encoding="utf-8")
    assert "publication_status" in page


def test_online_demo_path_uses_formal_investigation_api_and_activity_tools():
    page = (PACKAGE_ROOT / "presentation" / "api" / "demo_page.py").read_text(
        encoding="utf-8"
    )
    routes = (PACKAGE_ROOT / "presentation" / "api" / "routes.py").read_text(
        encoding="utf-8"
    )
    bootstrap = (PACKAGE_ROOT / "bootstrap" / "demo.py").read_text(encoding="utf-8")
    assert "POST /api/demo" not in routes
    assert '@app.post("/api/demo/' not in routes
    assert "fetch('/api/investigations'" in page
    assert "fetch(`/api/investigations/${" in page
    assert "datasetId.includes" not in page
    assert "InvestigationToolGateway(" in bootstrap
    assert "StructuredDataToolPlanner(" in bootstrap
