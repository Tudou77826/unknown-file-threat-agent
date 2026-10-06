"""Feature 19 Step 02 (desk stage) gates: auditd projection contract and the
settle pipeline end-to-end. The synthetic bundle mirrors what collect.sh
produces on the target; the settle test proves a field bundle becomes a
loadable validation_cases entry before any real target exists.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

from threat_agent.capability_validation import (
    AuditDProjector,
    RawTelemetryEnvelope,
    parse_auditd_lines,
)
from threat_agent.capability_validation.replay import validate_canonical_event

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = PROJECT_ROOT / "attack_lab" / "playbooks" / "malicious" / "t1105-ingress-tool-transfer"
HOST = "lab-vm-01"
WS = "/opt/secval-lab/cases/t1105-ingress-tool-transfer"
HASH = "ab" * 32

AUDIT_LOG = "\n".join(
    [
        # file create: cp drops payload.elf (O_WRONLY|O_CREAT|O_TRUNC = 0x241)
        'type=SYSCALL msg=audit(1760000000.050:100): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffd0001 a2=241 items=1 ppid=900 pid=1000 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="cp" exe="/usr/bin/cp" key="secval"',
        'type=PATH msg=audit(1760000000.050:100): item=0 name="' + WS + '/payload.elf" inode=601 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=CREATE',
        # execve of the payload (child of bash 900)
        'type=SYSCALL msg=audit(1760000000.100:101): arch=c000003e syscall=59 success=yes exit=0 a0=7f001 a1=7f002 a2=0 items=2 ppid=900 pid=1001 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="payload.elf" exe="' + WS + '/payload.elf" key="secval"',
        'type=EXECVE msg=audit(1760000000.100:101): argc=3 a0="' + WS + '/payload.elf" a1="127.0.0.1" a2="8443"',
        'type=PATH msg=audit(1760000000.100:101): item=0 name="' + WS + '/payload.elf" inode=601 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL',
        # connect to 127.0.0.1:8443 (sockaddr 0200 20FB 7F000001)
        'type=SYSCALL msg=audit(1760000000.300:102): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=020020FB7F000001 a2=10 items=0 ppid=900 pid=1001 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=1 comm="payload.elf" exe="' + WS + '/payload.elf" key="secval"',
        # shell command (hex-encoded "cat /etc/shadow")
        "type=USER_CMD msg=audit(1760000000.400:103): pid=1200 uid=0 auid=0 msg='cwd=\"/root\" cmd=636174202F6574632F736861646F77 terminal=pts0 res=success'",
        # outside the capture window — must be dropped
        'type=SYSCALL msg=audit(1759999999.000:90): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=2 comm="early" exe="/usr/bin/early"',
    ]
)


def test_parse_auditd_classifies_probe_kinds_and_window():
    lines = AUDIT_LOG.splitlines()
    # window excludes the 1759999999.000 record when filtered by settle;
    # parse itself keeps it — classification check only.
    envelopes = parse_auditd_lines(lines, host_id=HOST)
    kinds = [envelope.kind for envelope in envelopes]
    assert kinds.count("process") == 2  # early + payload exec
    assert kinds.count("file") == 1
    assert kinds.count("network") == 1
    assert kinds.count("command") == 1
    net = next(e for e in envelopes if e.kind == "network")
    assert net.payload["remote_ip"] == "127.0.0.1"
    assert net.payload["remote_port"] == 8443
    cmd = next(e for e in envelopes if e.kind == "command")
    assert cmd.payload["cmd"] == "cat /etc/shadow"
    proc = next(e for e in envelopes if e.kind == "process" and e.payload["pid"] == 1001)
    assert proc.payload["args"] == [f"{WS}/payload.elf", "127.0.0.1", "8443"]
    assert proc.payload["ppid"] == 900


def test_projector_batch_anchors_hash_and_derives_relations():
    envelopes = [e for e in parse_auditd_lines(AUDIT_LOG.splitlines(), host_id=HOST) if e.payload.get("pid") != 2]
    projector = AuditDProjector(host_id=HOST)
    events = projector.project_batch(
        envelopes,
        path_hashes={f"{WS}/payload.elf": HASH},
        process_starts={900: 1759999000000, 1000: 1760000000050},
    )
    by_type = {}
    for event in events:
        validate_canonical_event(event)
        by_type.setdefault(event["event_type"], []).append(event)
    exec_event = by_type["process_exec"][-1]
    assert exec_event["data"]["file_ref"] == f"file:{HOST}:{HASH}"
    assert exec_event["data"]["cmdline"].endswith("payload.elf 127.0.0.1 8443")
    assert by_type["process_parent_relation"], "parent chain from ppid must be derived"
    file_event = by_type["file_event"][0]
    assert file_event["data"]["operation"] == "create"
    assert file_event["data"]["file_ref"] == f"file:{HOST}:{HASH}"
    assert file_event["data"]["acting_process_ref"].startswith(f"process:{HOST}:1000:")
    net = by_type["network_connection"][0]
    assert net["subject_refs"][1] == "endpoint:127.0.0.1:8443"


def test_projector_derives_systemd_events_from_unit_writes():
    log = "\n".join(
        [
            'type=SYSCALL msg=audit(1760000001.000:200): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffd0002 a2=241 items=1 ppid=900 pid=1100 comm="bash" exe="/usr/bin/bash" key="secval"',
            'type=PATH msg=audit(1760000001.000:200): item=0 name="/etc/systemd/system/secval-demo.service" inode=602 dev=fd:00 mode=0100644 ouid=0 ogid=0 nametype=CREATE',
        ]
    )
    events = AuditDProjector(host_id=HOST).project_batch(
        parse_auditd_lines(log.splitlines(), host_id=HOST)
    )
    assert events and events[0]["event_type"] == "systemd_event"
    assert events[0]["domain"] == "persistence"
    assert events[0]["data"]["unit"] == "secval-demo.service"
    assert events[0]["data"]["action"] == "unit_write"


def test_file_event_ingests_as_file_activity(tmp_path: Path):
    from threat_agent.contracts import DatasetManifest
    from threat_agent.data_foundation.adapters.activity_store import SQLiteActivityStore
    from threat_agent.data_foundation.adapters.parsers import ReferenceEventParser
    from threat_agent.data_foundation.application.ingestion import BatchIngestionService

    event = {
        "event_id": "f1",
        "event_type": "file_event",
        "domain": "file",
        "source_system": "auditd-collector/1",
        "observed_at": "2026-09-29T00:00:00Z",
        "host_id": HOST,
        "subject_refs": [f"file:{HOST}:{HASH}"],
        "data": {
            "file_ref": f"file:{HOST}:{HASH}",
            "path": f"{WS}/payload.elf",
            "operation": "create",
            "acting_process_ref": f"process:{HOST}:1000:1760000000050",
        },
    }
    store = SQLiteActivityStore(tmp_path / "a.sqlite")
    parser = ReferenceEventParser()
    try:
        BatchIngestionService(store, parser).ingest_payloads(
            DatasetManifest(
                tenant_id="default",
                source_identity="step02-test",
                dataset_id="d",
                dataset_version="1",
                batch_id="b",
                source_system="t",
                connector_version="t/1",
                parser_name=parser.name,
                parser_version=parser.version,
                expected_record_count=1,
            ),
            [event],
        )
        assert store.count_activities("default") >= 1
        assert store.count_quarantined("default", "b") == 0
    finally:
        store.close()


def _build_bundle(bundle: Path) -> None:
    bundle.mkdir(parents=True)
    (bundle / "window.txt").write_text("1760000000000\n1760000001000\n", encoding="utf-8")
    # settle filters the audit window: the early exec (1759999999) drops out.
    (bundle / "audit.log").write_text(AUDIT_LOG + "\n", encoding="utf-8")
    (bundle / "workspace_hashes.txt").write_text(
        f"{HASH}  ./payload.elf\n", encoding="utf-8"
    )
    (bundle / "workspace_files.txt").write_text("payload.elf\n", encoding="utf-8")
    (bundle / "workspace_owners.txt").write_text("payload.elf\tNOT-OWNED\n", encoding="utf-8")
    (bundle / "approved_endpoints.txt").write_text("# cmdb export\n10.0.0.5\n", encoding="utf-8")
    (bundle / "rpm_inventory.txt").write_text("bash-5.2\n", encoding="utf-8")
    ps_row = (
        f"  1001    900 {'Mon Sep 29 10:00:00 2025'.replace('10:00:00', '09:46:40')} {WS}/payload.elf\n"
    )
    (bundle / "ps_before.txt").write_text(
        "    PID   PPID                                          LSTART COMMAND\n"
        + f"   900      1 Mon Sep 29 09:40:00 2025 /usr/bin/bash\n{ps_row}",
        encoding="utf-8",
    )
    (bundle / "ps_after.txt").write_text(
        "    PID   PPID                                          LSTART COMMAND\n" + ps_row,
        encoding="utf-8",
    )


def _load_settle():
    spec = importlib.util.spec_from_file_location(
        "settle_case", PROJECT_ROOT / "attack_lab" / "settle_case.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_denied_syscalls_produce_no_phantom_events():
    """The collector rules capture EACCES/EPERM-denied operations; a denied
    create/connect must not become replay evidence."""

    log = [
        'type=SYSCALL msg=audit(1760000000.050:100): arch=c000003e syscall=257 success=no exit=-13 a0=ffffff9c a1=7ffd0001 a2=241 items=1 ppid=900 pid=1000 comm="curl" exe="/usr/bin/curl" key="secval"',
        'type=PATH msg=audit(1760000000.050:100): item=0 name="/etc/shadow.new" nametype=CREATE',
        'type=SYSCALL msg=audit(1760000000.300:101): arch=c000003e syscall=42 success=no exit=-111 a0=3 a1=020020FB7F000001 a2=10 ppid=900 pid=1001 comm="x" exe="/usr/bin/x" key="secval"',
        'type=SYSCALL msg=audit(1760000000.400:102): arch=c000003e syscall=59 success=no exit=-13 a0=1 items=0 ppid=900 pid=1002 comm="denied" exe="/usr/bin/denied" key="secval"',
    ]
    envelopes = parse_auditd_lines(log, host_id=HOST)
    assert envelopes == []
    assert AuditDProjector(host_id=HOST).project_batch(envelopes) == []


def test_rename_keeps_both_paths_by_nametype():
    """Two PATH records in one event must not collapse — rename relies on
    DELETE (old) + CREATE (new); order-independent."""

    log = [
        'type=SYSCALL msg=audit(1760000000.100:200): arch=c000003e syscall=82 success=yes exit=0 items=2 ppid=900 pid=1100 comm="mv" exe="/usr/bin/mv" key="secval"',
        'type=PATH msg=audit(1760000000.100:200): item=0 name="/ws/old.bin" nametype=DELETE',
        'type=PATH msg=audit(1760000000.100:200): item=1 name="/ws/new.bin" nametype=CREATE',
        # reversed record order — same event, must classify identically
        'type=SYSCALL msg=audit(1760000000.200:201): arch=c000003e syscall=82 success=yes exit=0 items=2 ppid=900 pid=1101 comm="mv" exe="/usr/bin/mv" key="secval"',
        'type=PATH msg=audit(1760000000.200:201): item=0 name="/ws/new2.bin" nametype=CREATE',
        'type=PATH msg=audit(1760000000.200:201): item=1 name="/ws/old2.bin" nametype=DELETE',
    ]
    envelopes = parse_auditd_lines(log, host_id=HOST)
    files = [e for e in envelopes if e.kind == "file"]
    assert len(files) == 2
    assert {f.payload["op"] for f in files} == {"rename"}
    assert files[0].payload["path"] == "/ws/new.bin"
    assert files[0].payload["renamed_from"] == "/ws/old.bin"
    assert files[1].payload["path"] == "/ws/new2.bin"
    assert files[1].payload["renamed_from"] == "/ws/old2.bin"


def test_expected_ai_contradicting_truth_is_rejected():
    payload = json.loads((PLAYBOOK / "case.json").read_text(encoding="utf-8"))
    from threat_agent.capability_validation import TestCase as TestCaseModel

    TestCaseModel.model_validate(payload)  # draft is consistent
    payload["expected_ai"]["verdict"] = "benign"  # GT says malicious
    with pytest.raises(Exception, match="不同侧|contradicts"):
        TestCaseModel.model_validate(payload)


def test_settle_pipeline_end_to_end(tmp_path: Path):
    bundle = tmp_path / "bundle"
    _build_bundle(bundle)
    suite = tmp_path / "suite"
    suite.mkdir()
    shutil.copytree(PROJECT_ROOT / "validation_cases", suite, dirs_exist_ok=True)
    manifest = json.loads((suite / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["cases"]:
        entry["content_digest"] = None  # unpinned copies for this test
    (suite / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    settle = _load_settle()
    settle.settle(
        source=PLAYBOOK, bundle=bundle, host_id=HOST, suite_root=suite,
        workspace_root_hint="/opt/secval-lab/cases",
    )

    case_dir = suite / "t1105-ingress-tool-transfer"
    assert (case_dir / "case.json").exists()
    assert (case_dir / "replay" / "input.json").exists()
    settled = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
    assert settled["judgment_target"]["file_hash"] == HASH  # anchored from workspace manifest
    assert settled["provenance"]["origin"] == "attack-run"
    assert sorted(settled["telemetry"]["event_files"]) == [
        "counter_evidence.jsonl", "file.jsonl", "network.jsonl", "other.jsonl", "process.jsonl",
    ]
    input_record = json.loads((case_dir / "replay" / "input.json").read_text(encoding="utf-8"))
    assert input_record["File_hash"] == HASH

    events = [
        json.loads(line)
        for name in settled["telemetry"]["event_files"]
        for line in (case_dir / "replay" / "events" / name).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    types = {event["event_type"] for event in events}
    assert {"process_exec", "file_event", "network_connection", "shell_command"} <= types
    assert "early" not in json.dumps(events)  # out-of-window record dropped
    counter = [event for event in events if event["domain"] == "reputation"]
    packages = [event for event in counter if event["event_type"] == "package_provenance"]
    endpoints = [event for event in counter if event["event_type"] == "approved_endpoint"]
    assert packages and packages[0]["data"]["owns_file"] is False
    assert endpoints and endpoints[0]["data"] == {
        "remote_ip": "127.0.0.1", "approved": False,
    }
    # Baseline evidence is observed during the capture window — not the day
    # the bundle happened to be settled.
    assert all(
        event["observed_at"].startswith("2025-10-09") for event in counter
    ), [event["observed_at"] for event in counter]

    from threat_agent.capability_validation import ValidationSuiteRepository

    _, loaded = ValidationSuiteRepository(suite).load()  # digests were refreshed by settle
    settled_case = next(item for item in loaded if item.case.case_id == "t1105-ingress-tool-transfer")
    assert settled_case.bundle.events  # fully loadable end to end
