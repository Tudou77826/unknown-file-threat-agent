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
