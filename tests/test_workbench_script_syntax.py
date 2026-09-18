"""Syntax gate for the workbench's inline page scripts.

The workbench renders pages as server-side strings containing hand-written
inline JavaScript. Twice now a quoting slip produced a page whose script
failed to parse, which made every control on that page silently dead while
the HTTP status stayed 200 — invisible to API-level tests.

This gate parses every inline script of every workbench page with Node, so a
broken page fails the suite instead of shipping.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from threat_agent.presentation import InMemoryCaseReadStore
from threat_agent.presentation.api import pages
from threat_agent.presentation.api.routes import create_app

NODE = shutil.which("node")

# Pages that render without any injected service (pure presentation).
STATIC_PAGES = {
    "/workbench/events": pages.render_events,
    "/workbench/audit": pages.render_audit,
    "/workbench/data": lambda: pages.render_data_browser(
        [
            {"activity_type": "process", "count": 3, "first": "2026-04-23T03:17:13Z", "last": "2026-04-23T04:00:00Z"},
            {"activity_type": "network", "count": 2, "first": "2026-04-23T03:17:13Z", "last": "2026-04-23T04:00:00Z"},
        ]
    ),
    "/workbench/compare": lambda: pages.render_compare("run-a", "run-b"),
    "/workbench/settings": lambda: pages.render_settings(
        {"items": [("研判模型", "m")], "knowledge_adapter": "reference"}
    ),
    "/workbench/approvals": lambda: pages.render_approvals(0),
    "/workbench": lambda: pages.render_workbench(0),
    "/workbench/knowledge": lambda: pages.render_knowledge(
        "reference",
        "standard",
        {"supplier_id": "s", "profile": "standard", "categories": []},
        {"total": 0, "by_status": {}, "by_category": {}, "recent": []},
    ),
    "/workbench/cases": pages.render_cases,
    "/workbench/events/ref:x": lambda: pages.render_event_detail(
        event_id="ref:x",
        detail={"payload": {"File_path": "/tmp/x"}, "source": "s"},
        fields_html="<p>f</p>",
        sources_html="<p>s</p>",
        runs_html="",
        launch_html="<p>l</p>",
    ),
}

_SCRIPT = re.compile(r"<script>(.*?)</script>", re.S)


def _assert_scripts_parse(path: str, html: str) -> None:
    scripts = _SCRIPT.findall(html)
    assert scripts, f"{path} rendered no inline scripts"
    for index, code in enumerate(scripts):
        if not code.strip():
            continue
        with tempfile.NamedTemporaryFile(
            "w", suffix=".js", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(code)
            target = Path(handle.name)
        try:
            result = subprocess.run(
                [NODE, "--check", str(target)],
                capture_output=True, text=True, timeout=30,
            )
        finally:
            target.unlink(missing_ok=True)
        assert result.returncode == 0, (
            f"{path} script#{index + 1} failed to parse:\n{result.stderr.strip()[:600]}"
        )


def test_node_is_available_for_the_syntax_gate():
    """The gate must fail loudly, not skip, when it cannot run: a silent skip
    means a broken page ships green. CI installs Node for exactly this."""

    assert NODE is not None, (
        "node is required for the workbench script syntax gate; "
        "install Node in CI rather than letting this gate become a no-op"
    )


def test_static_workbench_pages_have_parseable_inline_scripts():
    for path, render in STATIC_PAGES.items():
        _assert_scripts_parse(path, render())


def test_run_page_inline_scripts_parse():
    """The run page is rendered by routes (needs a stubbed run service)."""

    class _Runs:
        def list_runs(self):
            return []

        def get_trajectory(self, run_id):
            from threat_agent.contracts import TrajectoryReadModel

            return TrajectoryReadModel(run_id=run_id, case_id="case-1")

        def get_investigation(self, run_id):
            from threat_agent.contracts import InvestigationRun, InvestigationRunReadModel

            return InvestigationRunReadModel(
                run=InvestigationRun(
                    tenant_id="default", case_id="case-1", run_id=run_id,
                    source_identity="test", status="completed", stage="published",
                    graph_thread_id="t/c/r",
                ),
                reference_dataset_id="ds", profile_id="l3-attribution-and-assets",
            )

        def knowledge_stats(self):
            return {}

    client = TestClient(create_app(InMemoryCaseReadStore(), None, _Runs()))
    response = client.get("/workbench/runs/run-1")
    assert response.status_code == 200
    _assert_scripts_parse("/workbench/runs/{id}", response.text)


def _handler_failures(path: str, html: str) -> list[str]:
    declared = {
        name: signature
        for name, signature in re.findall(r"function\s+(\w+)\s*\(([^)]*)\)", html)
    }
    failures: list[str] = []
    for attr, name, args in re.findall(r"""(on\w+)=["'](\w+)\(([^"']*)\)["']""", html):
        if name not in declared:
            # A handler pointing at a function that does not exist is a dead
            # control, which is exactly the class of bug this gate exists for.
            failures.append(f"{path}: {attr} calls undefined {name}()")
            continue
        params = [p for p in (declared[name] or "").split(",") if p.strip()]
        # Inline handlers may receive the implicit event object as arg 0.
        supplied = [a for a in args.split(",") if a.strip()]
        if len(supplied) != len(params):
            failures.append(
                f"{path}: {attr}={name}({args}) supplies {len(supplied)} args but "
                f"{name} declares {len(params)}"
            )
    return failures


def test_inline_handlers_reference_declared_functions():
    """Catch signature drift and dangling handlers across every page."""

    failures: list[str] = []
    for path, render in STATIC_PAGES.items():
        failures += _handler_failures(path, render())

    class _Runs:
        def list_runs(self):
            return []

        def get_trajectory(self, run_id):
            from threat_agent.contracts import TrajectoryReadModel

            return TrajectoryReadModel(run_id=run_id, case_id="case-1")

        def get_investigation(self, run_id):
            from threat_agent.contracts import InvestigationRun, InvestigationRunReadModel

            return InvestigationRunReadModel(
                run=InvestigationRun(
                    tenant_id="default", case_id="case-1", run_id=run_id,
                    source_identity="test", status="completed", stage="published",
                    graph_thread_id="t/c/r",
                ),
                reference_dataset_id="ds", profile_id="l3-attribution-and-assets",
            )

        def knowledge_stats(self):
            return {}

    client = TestClient(create_app(InMemoryCaseReadStore(), None, _Runs()))
    failures += _handler_failures("/workbench/runs/{id}", client.get("/workbench/runs/run-1").text)

    assert not failures, "broken inline handlers: " + "; ".join(failures)


# ------------------------------------------------------- interpreter compat

def _lowest_available_interpreter() -> list[str] | None:
    """A pre-3.12 interpreter command, if this machine has one.

    PEP 701 relaxed f-string tokenizing in 3.12, so the *only* authoritative
    check for the supported interpreters is to parse with one of them:
    ``ast.parse(feature_version=...)`` runs the 3.12+ tokenizer and silently
    accepts the very constructs that break 3.10/3.11.
    """

    candidates = [
        ["py", "-3.11"], ["py", "-3.10"], ["python3.11"], ["python3.10"],
    ]
    for command in candidates:
        try:
            result = subprocess.run(
                [*command, "-c", "import sys; print(sys.version_info[0], sys.version_info[1])"],
                capture_output=True, text=True, timeout=20,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode != 0:
            continue
        parts = result.stdout.strip().split()
        if len(parts) != 2 or not all(part.isdigit() for part in parts):
            continue
        major, minor = int(parts[0]), int(parts[1])
        # 3.10/3.11 enforce the pre-PEP-701 f-string rules we care about.
        if (major, minor) < (3, 12):
            return command
    return None


def test_sources_parse_on_the_minimum_supported_interpreter():
    """pyproject declares requires-python >= 3.10 and CI pins 3.11.

    Parses src/ and tests/ with a real pre-3.12 interpreter when one is
    available. When none is installed, the check is *delegated* to CI — and we
    assert the CI configuration actually pins a supported version, so the gate
    is never silently absent.
    """

    root = Path(__file__).resolve().parents[1]
    interpreter = _lowest_available_interpreter()

    if interpreter is None:
        ci = root / ".github" / "workflows" / "ci.yml"
        assert ci.exists(), (
            "no pre-3.12 interpreter locally and no CI workflow pinning one: "
            "the minimum-version guarantee is unenforced"
        )
        text = ci.read_text(encoding="utf-8")
        assert "python-version" in text, "CI must pin an interpreter version"
        pinned = re.findall(r'python-version:\s*["\']([0-9.]+)["\']', text)
        assert pinned, "CI python-version must be a literal version"
        for version in pinned:
            assert not version.startswith("3.1") or version.startswith(
                ("3.10", "3.11")
            ), f"CI pins {version}, which no longer exercises the 3.10/3.11 ruleset"
        return

    script = (
        "import ast,pathlib,sys;"
        "bad=[];"
        "\nfor p in list(pathlib.Path('src').rglob('*.py'))+list(pathlib.Path('tests').rglob('*.py')):"
        "\n    try: ast.parse(p.read_text(encoding='utf-8'), filename=str(p))"
        "\n    except SyntaxError as e: bad.append(f'{p}:{e.lineno} {e.msg}')"
        "\nprint(chr(10).join(bad))"
        "\nsys.exit(1 if bad else 0)"
    )
    result = subprocess.run(
        [*interpreter, "-c", script],
        cwd=str(root), capture_output=True, text=True, timeout=120,
    )
    assert result.returncode == 0, (
        f"sources must parse on {' '.join(interpreter)}:\n{result.stdout.strip()}"
    )


# ------------------------------------------- shared-constant scope rule


def test_shared_constant_maps_are_script_global():
    """A shared lookup map must be declared at the script's top level.

    Regression: the events page declared its severity colour map with `const`
    inside an async loader; the renderer defined beside it then threw
    ReferenceError, so the queue rendered empty while every other gate — syntax
    checks, API checks, unit tests — stayed green.
    """

    declaration = re.compile(r"^(?P<indent>\s*)(?:const|let|var)\s+(?P<name>[A-Z][A-Z0-9_]{2,})\s*=")
    failures: list[str] = []

    for path, render in STATIC_PAGES.items():
        for block in _SCRIPT.findall(render()):
            for line in block.splitlines():
                match = declaration.match(line)
                if match and match.group("indent"):
                    failures.append(
                        f"{path}: shared map {match.group('name')} is declared inside "
                        f"a function (indent={len(match.group('indent'))}); "
                        "other functions cannot see it"
                    )

    assert not failures, "block-scoped shared constants: " + "; ".join(failures)
