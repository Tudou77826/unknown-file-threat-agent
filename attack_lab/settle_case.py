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
import shutil
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


def _load_system_hashes(bundle: Path) -> dict[str, str]:
    """system_hashes.txt: '<sha256>  /abs/path' → {abs_path: hash}.

    Judgment targets on system paths (masqueraded copies, authorized_keys,
    /etc/passwd) are hashed by the collector when the playbook declares them
    in ``system_paths.txt``; settle anchors them from here as a fallback.
    """

    hashes: dict[str, str] = {}
    manifest = bundle / "system_hashes.txt"
    if not manifest.exists():
        return hashes
    for line in manifest.read_text(encoding="utf-8").splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            hashes[parts[1].strip()] = parts[0]
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
        owned = (
            owner not in {"NOT-OWNED", ""}
            and "not owned" not in owner
            and not owner.startswith("file ")
        )
        # 真话原则（2026-09-30 复核裁决）：只报告实际做过的检查——包归属查询；
        # 签名与仓库信任从未检查，一律 unknown（None），不得作为恶意证据。
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
                    "signature_valid": None,
                    "repository_trusted": None,
                },
            }
        )
        # 部署台账在实验室环境不可查询（内部迁移后才有该工具）。按真话原则
        # 显式给出"查询不可用、结论未知"，AI 不得从"没有记录"推断"未授权"。
        evidence.append(
            {
                "event_id": f"baseline-registry-{digest[:12]}",
                "event_type": "deployment_registry_lookup",
                "domain": "reputation",
                "source_system": "deploy-registry",
                "observed_at": observed_at,
                "host_id": host_id,
                "subject_refs": [f"file:{host_id}:{digest}"],
                "data": {
                    "registry_available": False,
                    "registered": None,
                },
            }
        )
    baseline_lines = [
        line.strip()
        for line in (bundle / "approved_endpoints.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    has_baseline = bool(baseline_lines)  # 空清单 = 批准情况未知，不得判"未批准"
    approved = set(baseline_lines)
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
                "data": {
                    "remote_ip": ip,
                    "approved": (ip in approved) if has_baseline else None,
                },
            }
        )
    return evidence


def _domain_file(event: dict) -> str:
    if event["event_type"] == "package_provenance" or event["event_type"] == "approved_endpoint":
        return FILE_DOMAINS["counter"]
    if event["domain"] == "persistence":
        return FILE_DOMAINS["persistence"]
    return FILE_DOMAINS.get(event["domain"], FILE_DOMAINS["other"])


# ── 2026-10-10 复核整改：消答案泄露 + 证据回填 ──────────────────────────────
# 复核裁决：进程命令行携带 playbooks/malicious|benign 路径等于泄露答案——
# 模型读目录名即可答对，准确率失去含义。回放中的部署路径一律重写为中性
# run/ 前缀（采集端同步改造，重采不再带出）。
_CAMP_PATH_RULES = (
    ("/opt/secval-lab/playbooks/malicious/", "/opt/secval-lab/run/"),
    ("/opt/secval-lab/playbooks/benign/", "/opt/secval-lab/run/"),
)


def _sanitize_leaked_paths(value):
    """Recursively rewrite camp-bearing playbook paths in an event structure."""
    if isinstance(value, str):
        for old, new in _CAMP_PATH_RULES:
            if old in value:
                value = value.replace(old, new)
        return value
    if isinstance(value, list):
        return [_sanitize_leaked_paths(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize_leaked_paths(item) for key, item in value.items()}
    return value


_TEXT_SUFFIXES = {
    ".txt", ".json", ".yaml", ".yml", ".pub", ".md", ".cfg", ".conf",
    ".list", ".sh", ".py", ".service", ".cron",
}
_MAX_CONTENT_BYTES = 4096


def _workspace_evidence_events(bundle: Path, host_id: str, workspace_root: str, observed_at: str) -> list[dict]:
    """复核整改：把工作区里"采到了但没进回放"的两类证据补进回放——

    1. 文本类文件的内容（部署清单/ansible 文件/轮转策略/公钥）：此前只有
       文件名事件，内容 AI 不可查，良性案的判定依据形同虚设；
    2. ``*-evidence.txt`` 里的 stat 快照（mtime/ctime/birth）：时间戳回拨案
       的唯一定性证据，Modify 早于 Birth 的时间线矛盾必须在回放里可见。
    """

    import tarfile

    events: list[dict] = []
    tar_path = bundle / "workspace.tar.gz"
    if not tar_path.exists():
        return events
    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isfile() or member.size > _MAX_CONTENT_BYTES:
                continue
            name = member.name[2:] if member.name.startswith("./") else member.name
            suffix = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
            if suffix not in _TEXT_SUFFIXES:
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            try:
                content = handle.read().decode("utf-8")
            except UnicodeDecodeError:
                continue
            abs_path = f"{workspace_root}/{name}"
            if name.endswith("-evidence.txt") and content.lstrip().startswith("File:"):
                # stat 的对象是快照内 File: 行指向的文件（如 payload.elf），
                # 不是证据文件自身——事件必须锚定被测文件。
                subject_rel = ""
                first = content.splitlines()[0].split("File:", 1)[-1].strip()
                if first:
                    subject_rel = first[2:] if first.startswith("./") else first
                stat_fields: dict[str, str] = {}
                for line in content.splitlines():
                    if ":" not in line:
                        continue
                    key, _, raw = line.strip().partition(":")
                    key = key.strip().rstrip("0123456789 ") or key.strip()
                    value = raw.strip()
                    if not value:
                        continue
                    if key in {"Modify", "Change", "Birth", "Access"} and not key.startswith("Access:"):
                        stat_fields[f"{key.lower()}_time"] = value
                    elif key == "Uid":
                        stat_fields["owner_uid"] = value.split("/")[0].strip()
                if stat_fields:
                    stat_subject = (
                        f"{workspace_root}/{subject_rel}" if subject_rel else abs_path
                    )
                    events.append({
                        "event_id": f"file-stat-{name}",
                        "event_type": "file_stat_snapshot",
                        "domain": "file",
                        "source_system": "stat-snapshot/1",
                        "observed_at": observed_at,
                        "host_id": host_id,
                        "subject_refs": [f"file:{host_id}:{stat_subject}"],
                        "data": {"path": stat_subject, **stat_fields},
                    })
            events.append({
                "event_id": f"file-content-{name}",
                "event_type": "file_content",
                "domain": "file",
                "source_system": "file-reader/1",
                "observed_at": observed_at,
                "host_id": host_id,
                "subject_refs": [f"file:{host_id}:{abs_path}"],
                "data": {"path": abs_path, "size": member.size, "content": content},
            })
    return events


def settle(*, source: Path, bundle: Path, host_id: str, suite_root: Path, workspace_root_hint: str | None = None) -> Path:
    draft = TestCase.model_validate(
        json.loads((source / "case.json").read_text(encoding="utf-8"))
    )
    start_ms, end_ms = _load_window(bundle)
    lines = (bundle / "audit.log").read_text(encoding="utf-8", errors="replace").splitlines()
    window_lines = _filter_window(lines, start_ms, end_ms)
    envelopes = parse_auditd_lines(window_lines, host_id=host_id)
    envelopes.extend(_parse_conn_poll(bundle, host_id))
    envelopes = _scope_to_case(envelopes, draft.case_id, workspace_root_hint)

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
    events.extend(_workspace_evidence_events(bundle, host_id, workspace_root, observed_at))
    # 文件事件补内容哈希关联：/etc/passwd 这类系统路径的写入事件此前不带
    # 哈希，调查目标与事件无法凭哈希对上（复核意见：t1136）。
    all_hashes = {**_load_system_hashes(bundle), **path_hashes}
    for event in events:
        if event.get("event_type") != "file_event":
            continue
        path = str(event.get("data", {}).get("path", ""))
        digest = all_hashes.get(path)
        if digest:
            event["data"]["content_sha256"] = digest
            event["subject_refs"] = [
                *event.get("subject_refs", []),
                f"file:{host_id}:{digest}",
            ]
    events = [_sanitize_leaked_paths(event) for event in events]

    case_dir = suite_root / draft.case_id
    replay_dir = case_dir / "replay"
    events_dir = replay_dir / "events"
    if events_dir.exists():
        for stale in events_dir.glob("*.jsonl"):
            stale.unlink()  # 上次沉淀的残留会让清单校验失配
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
    digest = (
        path_hashes.get(draft.judgment_target.file_path)
        or path_hashes.get(artifact_rel)
        or _load_system_hashes(bundle).get(draft.judgment_target.file_path)
    )
    if not digest:
        raise SystemExit(
            f"judgment target {draft.judgment_target.file_path} not found in workspace "
            f"or system digest manifests — the playbook must drop it under the case "
            f"workspace or declare it in system_paths.txt"
        )

    payload = draft.model_dump()
    payload["judgment_target"]["file_hash"] = digest
    # 基线来源按实际证据条件化：无网络事件的案例没有端点可核验，
    # 不得声明 cmdb-baseline（声明了会被套件校验拒绝）。
    has_network = any(e.get("event_type") == "network_connection" for e in events)
    baseline_sources = ["rpm-inventory"] + (["cmdb-baseline"] if has_network else [])
    payload["telemetry"] = {
        "event_files": sorted(name for name in grouped),
        "environment_baseline_sources": baseline_sources,
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

    def _rollback() -> None:
        # 失败不留半成品：清掉本案例目录与清单条目，避免毒倒后续整套装载
        if manifest.exists():
            data = json.loads(manifest.read_text(encoding="utf-8"))
            data["cases"] = [e for e in data["cases"] if e["case_id"] != draft.case_id]
            manifest.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        if case_dir.exists():
            shutil.rmtree(case_dir, ignore_errors=True)

    try:
        repo = ValidationSuiteRepository(suite_root)
        repo.refresh_digests()
        _, loaded = repo.load()
        settled = next(item for item in loaded if item.case.case_id == draft.case_id)
    except Exception:
        _rollback()
        raise
    print(
        f"settled {settled.case_ref}: {len(events)} events, "
        f"{len(grouped)} files, judgment {digest[:12]} — review GT then refresh digests"
    )
    return case_dir


def _parse_conn_poll(bundle: Path, host_id: str):
    """conn_poll.log: repeated (timestamp, ss -tnp) blocks → network
    envelopes. auditd's connect leaves only the sockaddr pointer; the
    remote 4-tuple comes from this poller. De-duplicated per (pid, remote)."""

    import re as _re
    from threat_agent.capability_validation import RawTelemetryEnvelope

    path = bundle / "conn_poll.log"
    if not path.exists():
        return []
    envelopes = []
    seen: dict[tuple, dict] = {}
    ts_ms = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.isdigit():
            ts_ms = int(line)
            continue
        match = _re.search(
            r"(\S+):(\d+)\s+users:\(\(\"([^\"]+)\",pid=(\d+)", line
        )
        if not match or not ts_ms:
            continue
        peer_ip = match.group(1).strip("[]").split("%")[0]
        peer_port = int(match.group(2))
        comm = match.group(3)
        pid = int(match.group(4))
        key = (pid, peer_ip, peer_port)
        # 复核整改：按 (pid,远端) 去重会把周期回连压成一条，丢掉"多次外连"
        # 这半个事实（python 回连案的定性依据）。聚合保留观测次数与首末时间。
        if key in seen:
            seen[key]["count"] += 1
            seen[key]["last_ms"] = ts_ms
            continue
        seen[key] = {"count": 1, "first_ms": ts_ms, "last_ms": ts_ms}
        captured = (
            datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        envelopes.append(
            RawTelemetryEnvelope(
                kind="network",
                collector="ss-poller/1",
                captured_at=captured,
                host_id=host_id,
                payload={
                    "pid": pid, "ppid": 0, "uid": "", "euid": "",
                    "exe": "", "comm": comm,
                    "remote_ip": peer_ip, "remote_port": peer_port, "protocol": "tcp",
                    "_poll_meta": seen[key],
                },
            )
        )
    return envelopes


def _scope_to_case(envelopes, case_id, root_hint):
    """The audit rules see the whole host (aegis/panel churn included); the
    replay should carry the case's own activity: workspace paths, /etc
    persistence writes, and the process closure of the case's pids."""

    root = f"{(root_hint or '/opt/secval-lab/cases').rstrip('/')}/{case_id}"
    case_pids = set()
    for envelope in envelopes:
        exe = str(envelope.payload.get("exe", ""))
        if exe.startswith(root + "/"):
            case_pids.add(int(envelope.payload.get("pid", 0)))
    # seed from file envelopes: processes that touched case-relevant files
    # belong to the case even when their exe is a system interpreter
    # (python3 beacon.py / bash pipe). Paths mirror audit-rules §2 watches.
    kept_paths = (
        root + "/", "/etc/", "/usr/local/sbin/", "/usr/local/bin/",
        "/root/.ssh/", "/var/log/secval-demo/", "/var/backups/secval-demo/",
    )
    for envelope in envelopes:
        if envelope.kind != "file":
            continue
        path = str(envelope.payload.get("path", ""))
        if path.startswith(kept_paths):
            case_pids.add(int(envelope.payload.get("pid", 0) or 0))
    # closure both ways over the pid graph: ancestors AND descendants of case
    # processes are case processes (payloads exec under the playbook's tree).
    # The graph includes pids that appear only as a ppid (intermediate bash
    # wrappers often have no surviving envelope of their own).
    children: dict[int, set[int]] = {}
    parent_of: dict[int, int] = {}
    for envelope in envelopes:
        payload = envelope.payload
        if "pid" not in payload:
            continue
        pid, ppid = int(payload["pid"]), int(payload.get("ppid", 0) or 0)
        if ppid:
            children.setdefault(ppid, set()).add(pid)
            parent_of[pid] = ppid
    frontier = list(case_pids)
    while frontier:
        current = frontier.pop()
        for child in children.get(current, ()):
            if child not in case_pids:
                case_pids.add(child)
                frontier.append(child)
        parent = parent_of.get(current)
        if parent and parent not in case_pids:
            case_pids.add(parent)
            frontier.append(parent)
    kept = []
    for envelope in envelopes:
        payload = envelope.payload
        pid = int(payload.get("pid", 0) or 0)
        if envelope.kind == "process" and pid in case_pids:
            kept.append(envelope)
            continue
        if envelope.kind == "file":
            path = str(payload.get("path", ""))
            if path.startswith(kept_paths):
                kept.append(envelope)
                continue
        if envelope.kind == "network" and pid in case_pids:
            kept.append(envelope)
            continue
        if envelope.kind in {"command", "authentication"}:
            kept.append(envelope)
    return kept


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
