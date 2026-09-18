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
        "observability",
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


_KNOWLEDGE_INTERNALS = ("threat_agent.knowledge.adapters", "threat_agent.knowledge.ports")


def _assert_imports_not_starting_with(package: str, forbidden_prefixes: tuple[str, ...]) -> None:
    violations: list[str] = []
    for path in (PACKAGE_ROOT / package).rglob("*.py"):
        for imported in _absolute_imports(path):
            if any(imported.startswith(prefix) for prefix in forbidden_prefixes):
                violations.append(f"{path.relative_to(PACKAGE_ROOT)} -> {imported}")
    assert not violations, "Invalid architecture dependencies:\n" + "\n".join(violations)


def test_business_modules_consume_knowledge_capability_only():
    # Agent-side modules see the capability layer's scenario services only.
    # The supplier-shaped port and every adapter stay implementation details
    # of the knowledge package (target design sections 3 and 5).
    for package in ("judgment", "response_advisory", "case_management", "presentation"):
        _assert_imports_not_starting_with(package, _KNOWLEDGE_INTERNALS)


def test_only_the_framework_entry_binds_execution_context():
    # Authorization is bound once at the framework entry and inherited; business
    # modules read the context but must never bind, fill or override it.
    allowed_paths = {
        ("shared", "execution.py"),
        ("case_management", "application", "graph.py"),
        ("bootstrap", "middleware_runtime.py"),
    }
    allowed_files = {
        PACKAGE_ROOT.joinpath(*parts) for parts in allowed_paths
    }
    violations: list[str] = []
    for path in PACKAGE_ROOT.rglob("*.py"):
        if "bind_execution_context(" not in path.read_text(encoding="utf-8"):
            continue
        if path in allowed_files:
            continue
        violations.append(str(path.relative_to(PACKAGE_ROOT)))
    assert not violations, "bind_execution_context used outside the framework entry:\n" + "\n".join(
        violations
    )


def test_judgment_gateway_consumes_the_aggregate_data_port_only():
    gateway = (
        PACKAGE_ROOT / "judgment" / "adapters" / "investigation_tools.py"
    ).read_text(encoding="utf-8")
    assert "InvestigationDataPort" in gateway
    assert "SQLiteActivityStore" not in gateway
    assert "SQLiteActivityQueryAdapter" not in gateway


def test_agent_middleware_is_self_contained():
    # Feature 15: the middleware package must stay extractable as a standalone
    # distribution — no threat_agent imports at all, not even shared. Imports
    # of the package itself (relative imports) are fine.
    violations: list[str] = []
    for path in (PACKAGE_ROOT / "agent_middleware").rglob("*.py"):
        for imported in _absolute_imports(path):
            if imported == "threat_agent" or imported.startswith("threat_agent."):
                if imported == "threat_agent.agent_middleware" or imported.startswith(
                    "threat_agent.agent_middleware."
                ):
                    continue
                violations.append(f"{path.relative_to(PACKAGE_ROOT)} -> {imported}")
    assert not violations, "agent_middleware must not import threat_agent:\n" + "\n".join(
        violations
    )


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
    page = (PACKAGE_ROOT / "presentation" / "api" / "pages.py").read_text(encoding="utf-8")
    assert "publication_status" in page


def test_run_rows_are_written_only_by_the_run_service():
    """Feature 17 rule 5: run-row writes are owned by the run service; the
    store adapter owns storage mechanics. Any other module migrating run state
    would fork the lifecycle state machine."""

    allowed = {
        "case_management/application/run_service.py",
        "case_management/adapters/runtime_store.py",
    }
    violations: list[str] = []
    for path in PACKAGE_ROOT.rglob("*.py"):
        relative = path.relative_to(PACKAGE_ROOT).as_posix()
        if relative in allowed:
            continue
        text = path.read_text(encoding="utf-8")
        if ".create_run(" in text or ".update_run(" in text:
            violations.append(relative)
    assert not violations, "run-row writes outside the run service:\n" + "\n".join(violations)


def test_online_demo_path_uses_formal_investigation_api_and_activity_tools():
    """The demo playbook was retired (Feature 17): the legacy walkthrough route
    must stay gone, and the formal runtime must remain the only path wired in
    bootstrap's executor."""

    routes = (PACKAGE_ROOT / "presentation" / "api" / "routes.py").read_text(encoding="utf-8")
    bootstrap = (PACKAGE_ROOT / "bootstrap" / "demo.py").read_text(encoding="utf-8")
    judgment_exports = (PACKAGE_ROOT / "judgment" / "__init__.py").read_text(encoding="utf-8")

    assert "/demo/" not in routes
    assert "render_demo_page" not in routes
    assert "InvestigationToolGateway(" in bootstrap
    assert "SQLiteInvestigationDataAdapter(" in bootstrap
    assert "MiddlewareJudgmentRunner(" in bootstrap
    assert "JudgmentGraph(" not in bootstrap
    assert "JudgmentGraph" not in judgment_exports
    assert "StructuredDataToolPlanner" not in judgment_exports


def test_knowledge_stays_a_leaf_module():
    """Feature 18: corpus suppliers and routing are leaf adapters over the
    supplier port. They must never grow dependencies on business, workflow or
    bootstrap modules; bootstrap is the only place that assembles them."""

    _assert_does_not_import(
        "knowledge",
        {
            "bootstrap",
            "case_management",
            "data_foundation",
            "judgment",
            "observability",
            "presentation",
            "response_advisory",
        },
    )


def test_offline_tooling_is_never_imported_by_the_package():
    """Feature 18: scripts/ (corpus building, ops helpers) may depend on the
    package, never the other way around."""

    violations: list[str] = []
    for path in PACKAGE_ROOT.rglob("*.py"):
        for imported in _absolute_imports(path):
            if imported == "scripts" or imported.startswith("scripts."):
                violations.append(f"{path.relative_to(PACKAGE_ROOT)} -> {imported}")
    assert not violations, "package imports offline tooling:\n" + "\n".join(violations)


def test_agent_eval_is_a_standalone_kernel():
    """Feature 16: the eval kernel stays extractable — like agent_middleware
    it must not import any threat_agent module outside its own package."""

    violations: list[str] = []
    for path in (PACKAGE_ROOT / "agent_eval").rglob("*.py"):
        for imported in _absolute_imports(path):
            if imported == "threat_agent" or imported.startswith("threat_agent."):
                if imported == "threat_agent.agent_eval" or imported.startswith(
                    "threat_agent.agent_eval."
                ):
                    continue
                violations.append(f"{path.relative_to(PACKAGE_ROOT)} -> {imported}")
    assert not violations, "agent_eval must not import threat_agent business modules:\n" + "\n".join(
        violations
    )
