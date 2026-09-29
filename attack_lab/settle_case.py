"""Settle a field bundle into a validation_cases entry (Step 02 pipeline).

Input: one collector bundle (``collect.sh`` output scp'd back) plus the
playbook's ``case.json`` draft. Output: a loadable
``<suite>/<case-id>/`` directory — canonical replay events projected from
the auditd window, judgment-target hash anchored from the workspace digest
manifest, environment-baseline counter evidence from the collector
sidecars, and the suite manifest digests refreshed.

The produced ``case.json`` keeps the draft's ground truth and expected
results verbatim — human review happens *before* ``refresh_digests``
commits the case into the pinned suite (attack-catalog.md 纪律).

Usage:
    python settle_case.py --source attack_lab/playbooks/malicious/t1105-ingress-tool \
        --bundle bundles/t1105-ingress-tool.bundle --host-id lab-vm-01 \
        --suite validation_cases
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threat_agent.capability_validation import (  # noqa: E402
    AuditDProjector,
    TestCase,
    ValidationSuiteRepository,
    parse_auditd_lines,
)

FILE_DOMAINS = {
    "process": "process.jsonl",
    "network": "network.jsonl",
    "file": "file.jsonl",
    "persistence": "persistence.jsonl",
    "counter": "counter_evidence.jsonl",
    "other": "other.jsonl",
}


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _load_window(bundle: Path) -> tuple[int, int]:
    start_ms, end_ms = (bundle / "window.txt").read_text(encoding="utf-8").split()
    return int(start_ms), int(end_ms)


def _filter_window(lines: list[str], start_ms: int, end_ms: int) -> list[str]:
    import re

    header = re.compile(r"msg=audit\((\d+(?:\.\d+)?):\d+\)")
    kept: list[str] = []
    for line in lines:
        match = header.search(line)
        if match and start_ms <= int(float(match.group(1)) * 1000) <= end_ms:
            kept.append(line)
    return kept


def _load_path_hashes(bundle: Path, workspace_root_hint: str) -> dict[str, str]:
    """workspace_hashes.txt: '<sha256>  ./rel/path' → {abs_path: hash}.

    Keys are joined with forward slashes — bundle paths are target-side
    Linux paths and must not be mangled by the runner's OS.
    """

    root = workspace_root_hint.rstrip("/")
    hashes: dict[str, str] = {}
    manifest = bundle / "workspace_hashes.txt"
    if not manifest.exists():
        return hashes
    for line in manifest.read_text(encoding="utf-8").splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, rel = parts[0], parts[1].strip()
        rel = rel[2:] if rel.startswith("./") else rel
        hashes[f"{root}/{rel}"] = digest
    return hashes


def _load_ps_starts(bundle: Path) -> dict[int, int]:
    """ps snapshots → {pid: start_ms} for parent-relation stability.

    ``ps -eo pid,ppid,lstart,args`` lines: pid ppid, then lstart spanning
    five whitespace tokens (DAY MON DD HH:MM:SS YEAR), then args.
    """

    starts: dict[int, int] = {}
    for name in ("ps_before.txt", "ps_after.txt"):
        path = bundle / name
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            tokens = line.split(None, 8)
            if len(tokens) < 9 or not tokens[0].isdigit():
                continue
            pid = int(tokens[0])
            lstart = " ".join(tokens[3:8])
            try:
                dt = datetime.strptime(lstart, "%a %b %d %H:%M:%S %Y").replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                continue
            starts.setdefault(pid, int(dt.timestamp() * 1000))
    return starts


def _counter_evidence(
    events: list[dict],
    bundle: Path,
    host_id: str,
    observed_at: str,
) -> list[dict]:
    """Environment-baseline evidence: package ownership of the judgment
    artifacts + endpoint approval of every observed remote IP."""

    evidence: list[dict] = []
    owners: dict[str, str] = {}
    owners_file = bundle / "workspace_owners.txt"
    if owners_file.exists():
        for line in owners_file.read_text(encoding="utf-8").splitlines():
            if "\t" not in line:
                continue
            rel, owner = line.split("\t", 1)
            owners[rel.strip()] = owner.strip()
    hashes = {}
    manifest = bundle / "workspace_hashes.txt"
    if manifest.exists():
        for line in manifest.read_text(encoding="utf-8").splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2:
                rel = parts[1].strip()
                rel = rel[2:] if rel.startswith("./") else rel
                hashes[rel] = parts[0]
    for rel, digest in sorted(hashes.items()):
        owner = owners.get(rel, "NOT-OWNED")
        owned = owner not in {"NOT-OWNED", ""}
        evidence.append(
            {
                "event_id": f"baseline-package-{digest[:12]}",
                "event_type": "package_provenance",
                "domain": "reputation",
                "source_system": "rpm-inventory",
                "observed_at": observed_at,
                "host_id": host_id,
                "subject_refs": [f"file:{host_id}:{digest}"],
                "data": {
                    "package": owner if owned else None,
                    "owns_file": owned,
                    "signature_valid": owned,
                    "repository_trusted": owned,
                },
            }
        )
    approved = {
        line.strip()
        for line in (bundle / "approved_endpoints.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }
    for ip in sorted(
        {
            event["data"]["remote_ip"]
            for event in events
            if event.get("event_type") == "network_connection"
        }
    ):
        evidence.append(
            {
                "event_id": f"baseline-endpoint-{ip.replace(':', '-')}",
                "event_type": "approved_endpoint",
                "domain": "reputation",
                "source_system": "cmdb-baseline",
                "observed_at": observed_at,
                "host_id": host_id,
                "subject_refs": [f"endpoint:{ip}"],
                "data": {"remote_ip": ip, "approved": ip in approved},
            }
        )
    return evidence


def _domain_file(event: dict) -> str:
    if event["event_type"] == "package_provenance" or event["event_type"] == "approved_endpoint":
        return FILE_DOMAINS["counter"]
    if event["domain"] == "persistence":
        return FILE_DOMAINS["persistence"]
    return FILE_DOMAINS.get(event["domain"], FILE_DOMAINS["other"])


def settle(*, source: Path, bundle: Path, host_id: str, suite_root: Path, workspace_root_hint: str | None = None) -> Path:
    draft = TestCase.model_validate(
        json.loads((source / "case.json").read_text(encoding="utf-8"))
    )
    start_ms, end_ms = _load_window(bundle)
    lines = (bundle / "audit.log").read_text(encoding="utf-8", errors="replace").splitlines()
    window_lines = _filter_window(lines, start_ms, end_ms)
    envelopes = parse_auditd_lines(window_lines, host_id=host_id)

    workspace_root = f"{(workspace_root_hint or '/opt/secval-lab/cases').rstrip('/')}/{draft.case_id}"
    path_hashes = _load_path_hashes(bundle, workspace_root)
    starts = _load_ps_starts(bundle)
    projector = AuditDProjector(host_id=host_id)
    events = projector.project_batch(envelopes, path_hashes=path_hashes, process_starts=starts)
    from datetime import datetime, timezone as _tz
    observed_at = (
        datetime.fromtimestamp(end_ms / 1000, tz=_tz.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
    events.extend(_counter_evidence(events, bundle, host_id, observed_at))

    case_dir = suite_root / draft.case_id
    replay_dir = case_dir / "replay"
    events_dir = replay_dir / "events"
    events_dir.mkdir(parents=True, exist_ok=True)

    grouped: dict[str, list[dict]] = {}
    for event in events:
        grouped.setdefault(_domain_file(event), []).append(event)
    for name, items in sorted(grouped.items()):
        (events_dir / name).write_text(
            "\n".join(json.dumps(item, ensure_ascii=False) for item in items) + "\n",
            encoding="utf-8",
        )

    artifact_rel = str(draft.judgment_target.file_path).replace(workspace_root + "/", "")
    digest = path_hashes.get(draft.judgment_target.file_path) or path_hashes.get(artifact_rel)
    if not digest:
        raise SystemExit(
            f"judgment target {draft.judgment_target.file_path} not found in workspace "
            f"digest manifest — the playbook must drop it under the case workspace"
        )

    payload = draft.model_dump()
    payload["judgment_target"]["file_hash"] = digest
    payload["telemetry"] = {
        "event_files": sorted(name for name in grouped),
        "environment_baseline_sources": ["rpm-inventory", "cmdb-baseline"],
    }
    payload["provenance"] = {
        **payload["provenance"],
        "origin": "attack-run",
        "environment": host_id,
        "collector": "auditd-collector/1 + collect.sh/1",
        "notes": (
            (payload["provenance"].get("notes") or "")
            + " | settle_case.py 生成：GT 与预期结果为剧本草案，人工复核后方可入正式套件"
        ).strip(" |"),
    }
    input_record = {
        "File_id": f"file-record-{draft.case_id}",
        "File_hash": digest,
        "File_path": draft.judgment_target.file_path,
        "File_type": draft.judgment_target.file_type,
        "source": host_id,
        "Detail": json.dumps({"context": [], "feature": {"hash": digest}}, ensure_ascii=False),
    }
    (replay_dir / "input.json").write_text(
        json.dumps(input_record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (case_dir / "case.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    manifest = suite_root / "manifest.json"
    if manifest.exists():
        data = json.loads(manifest.read_text(encoding="utf-8"))
        if not any(entry["case_id"] == draft.case_id for entry in data["cases"]):
            data["cases"].append({"case_id": draft.case_id, "directory": draft.case_id})
        manifest.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    repo = ValidationSuiteRepository(suite_root)
    repo.refresh_digests()
    _, loaded = repo.load()
    settled = next(item for item in loaded if item.case.case_id == draft.case_id)
    print(
        f"settled {settled.case_ref}: {len(events)} events, "
        f"{len(grouped)} files, judgment {digest[:12]} — review GT then refresh digests"
    )
    return case_dir


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="playbook dir with case.json draft")
    parser.add_argument("--bundle", type=Path, required=True, help="collect.sh bundle dir")
    parser.add_argument("--host-id", required=True)
    parser.add_argument("--suite", type=Path, default=Path("validation_cases"))
    parser.add_argument("--workspace-root", default="/opt/secval-lab/cases")
    args = parser.parse_args()
    settle(
        source=args.source,
        bundle=args.bundle,
        host_id=args.host_id,
        suite_root=args.suite,
        workspace_root_hint=args.workspace_root,
    )


if __name__ == "__main__":
    main()
