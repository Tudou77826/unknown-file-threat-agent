"""auditd → RawTelemetryEnvelope → canonical events (Step 02 converter).

Two stages, per the Step 01 contract:

1. :func:`parse_auditd_lines` turns raw ``/var/log/audit/audit.log`` lines
   into probe-scoped :class:`RawTelemetryEnvelope` records (kinds follow
   telemetry-scope.md; §1–§5/§7/§9 map to auditd, §10 comes from the ss
   snapshot, baselines from the collector sidecars).
2. :class:`AuditDProjector` projects envelopes into the canonical event
   shape the AI-side pipeline ingests. ``project`` is stateless per
   envelope; ``project_batch`` additionally stabilizes process identity
   (first-exec timestamp per pid) and derives parent relations, so use it
   when projecting a full capture window.

Known limits (documented, accepted for PoC): auditd carries no file hash —
the hash anchor is attached by ``settle_case`` from the collector's
workspace digest manifest; DNS and byte counts are out of probe scope.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable

from ._base import StrictModel
from .replay import RAW_TELEMETRY_KINDS, RawTelemetryEnvelope, validate_canonical_event

AUDIT_HEADER = re.compile(r"^type=(\S+)\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s*(.*)$")
FIELD = re.compile(r'(\w+)=((?:"[^"]*")|\S+)')
HEX_ARG = re.compile(r"^[0-9A-Fa-f]+$")

SYSCALL_NAMES = {
    "2": "open",
    "85": "creat",
    "87": "unlink",
    "257": "openat",
    "263": "unlinkat",
    "42": "connect",
    "59": "execve",
    "322": "execveat",
    "82": "rename",
    "264": "renameat",
    "316": "renameat2",
    "105": "setuid",
    "106": "setgid",
    "165": "mount",
}
FILE_SYSCALLS = {"open", "creat", "unlink", "openat", "unlinkat", "rename", "renameat", "renameat2"}
OPEN_WRITE_FLAGS = 0x3  # O_WRONLY | O_RDWR
OPEN_CREAT_FLAG = 0x40


def _iso(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _fields(text: str) -> dict[str, str]:
    return {key: value.strip('"') for key, value in FIELD.findall(text)}


def _decode_arg(value: str) -> str:
    """auditd quotes simple args (``a0="ls"``) and hex-encodes exotic ones."""

    if value.startswith('"') and value.endswith('"'):
        return value[1:-1]
    if HEX_ARG.match(value) and len(value) % 2 == 0 and len(value) >= 2:
        try:
            return bytes.fromhex(value).decode("utf-8", "replace")
        except ValueError:
            return value
    return value


def _parse_sockaddr(hex_addr: str) -> tuple[str, int, str] | None:
    """a1= hex sockaddr → (ip, port, protocol); AF_INET/AF_INET6 only."""

    try:
        raw = bytes.fromhex(hex_addr)
    except ValueError:
        return None
    if len(raw) < 8:
        return None
    family = int.from_bytes(raw[0:2], "little")
    port = int.from_bytes(raw[2:4], "big")
    if family == 2 and len(raw) >= 8:
        return ".".join(str(b) for b in raw[4:8]), port, "tcp"
    if family == 10 and len(raw) >= 24:
        return "ipv6:" + ":".join(f"{int.from_bytes(raw[i:i+2], 'big'):x}" for i in range(8, 24, 2)), port, "tcp6"
    return None


def parse_auditd_lines(lines: Iterable[str], *, host_id: str, collector: str = "auditd-collector/1") -> list[RawTelemetryEnvelope]:
    """Group audit records by (timestamp, serial) and classify into probe kinds."""

    # rtype → list of field dicts: one audit event may carry several records
    # of the same type (rename yields two PATH entries — keep them all).
    groups: dict[tuple[str, str], dict[str, list[dict[str, str]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    raws: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
    order: list[tuple[str, str]] = []
    for line in lines:
        match = AUDIT_HEADER.match(line.strip())
        if not match:
            continue
        rtype, ts, serial, rest = match.groups()
        key = (ts, serial)
        if key not in groups:
            order.append(key)
        groups[key][rtype].append(_fields(rest))
        raws.setdefault(key, {})[rtype] = rest

    envelopes: list[RawTelemetryEnvelope] = []
    for key in order:
        records = groups[key]
        ts_ms = int(float(key[0]) * 1000)
        envelope = _classify(records, raws.get(key, {}), ts_ms, host_id, collector)
        if envelope is not None:
            envelopes.append(envelope)
    return envelopes


def _classify(
    records: dict[str, list[dict[str, str]]],
    raws: dict[str, str],
    ts_ms: int,
    host_id: str,
    collector: str,
) -> RawTelemetryEnvelope | None:
    base = {"captured_at": _iso(ts_ms), "host_id": host_id}
    syscall_records = records.get("SYSCALL", [])
    if not syscall_records:
        return _classify_user_record(records, raws, base, host_id, collector)
    syscall = syscall_records[0]
    if syscall.get("success") != "yes":
        # The collector rules capture EACCES/EPERM-denied operations too;
        # denied syscalls must not become phantom create/connect evidence.
        return None
    call = SYSCALL_NAMES.get(syscall.get("syscall", ""), "")
    pid = int(syscall.get("pid", "0") or 0)
    common = {
        **base,
        "pid": pid,
        "ppid": int(syscall.get("ppid", "0") or 0),
        "uid": syscall.get("uid", ""),
        "euid": syscall.get("euid", ""),
        "exe": syscall.get("exe", "").strip('"'),
        "comm": syscall.get("comm", "").strip('"'),
    }
    if call == "execve":
        # Args must come from the raw line: quoted values are literal,
        # unquoted are hex — field stripping would lose that distinction.
        raw_execve = raws.get("EXECVE", "")
        args: list[str] = []
        for index, quoted, plain in re.findall(r'a(\d+)=(?:"([^"]*)"|(\S+))', raw_execve):
            args.append(quoted if quoted else _decode_arg(plain))
        return RawTelemetryEnvelope(
            kind="process", collector=collector, payload={**common, "args": args}, **base
        )
    if call in FILE_SYSCALLS:
        paths = records.get("PATH", [])
        cwd_records = records.get("CWD", [])
        cwd = cwd_records[0].get("cwd", "").strip('"') if cwd_records else ""
        # Relative PATH names resolve against the event CWD（AT_FDCWD 场景，
        # bash/cp/curl 全属此类）；CWD 缺失时退回 PARENT 项。注意不能用 PARENT
        # 优先——含子目录的相对名（webroot/shell.php）会被拼成 webroot/webroot/…。
        parent = next((p for p in paths if p.get("nametype") == "PARENT"), None)
        prefix = cwd or (parent.get("name", "").strip('"') if parent else "")

        def _resolve(item: dict[str, str]) -> str:
            name = item.get("name", "").strip('"')
            if name.startswith("/") or not name:
                return name
            return f"{prefix.rstrip('/')}/{name}" if prefix else name

        file_items = [p for p in paths if p.get("nametype") != "PARENT"]
        if call in {"rename", "renameat", "renameat2"}:
            old = next((p for p in file_items if p.get("nametype") == "DELETE"), None)
            new = next((p for p in file_items if p.get("nametype") == "CREATE"), None)
            if old and new:
                payload = {
                    **common,
                    "op": "rename",
                    "path": _resolve(new),
                    "renamed_from": _resolve(old),
                }
                return RawTelemetryEnvelope(kind="file", collector=collector, payload=payload, **base)
            return None  # incomplete rename trace
        target = file_items[0] if file_items else ({} if not parent else {})
        nametype = target.get("nametype", "NORMAL")
        path = _resolve(target)
        if not path:
            return None
        flags = int(syscall.get("a2", "0") or "0", 16) if call in {"open", "openat"} else 0
        if nametype == "CREATE" or flags & OPEN_CREAT_FLAG:
            payload = {**common, "op": "create", "path": path}
        elif nametype == "DELETE":
            payload = {**common, "op": "delete", "path": path}
        elif flags & OPEN_WRITE_FLAGS and nametype == "NORMAL":
            payload = {**common, "op": "write", "path": path}
        else:
            return None  # reads are out of probe scope
        return RawTelemetryEnvelope(kind="file", collector=collector, payload=payload, **base)
    if call == "connect":
        parsed = _parse_sockaddr(syscall.get("a1", ""))
        if parsed is None:
            return None
        ip, port, protocol = parsed
        return RawTelemetryEnvelope(
            kind="network",
            collector=collector,
            payload={**common, "remote_ip": ip, "remote_port": port, "protocol": protocol},
            **base,
        )
    if call in {"setuid", "setgid", "mount"}:
        return RawTelemetryEnvelope(
            kind="syscall",
            collector=collector,
            payload={**common, "syscall": call, "result": syscall.get("success", "")},
            **base,
        )
    return None


def _classify_user_record(
    records: dict[str, list[dict[str, str]]],
    raws: dict[str, str],
    base: dict[str, str],
    host_id: str,
    collector: str,
) -> RawTelemetryEnvelope | None:
    if "USER_CMD" in records:
        fields = records["USER_CMD"][0]
        message = raws.get("USER_CMD", "")
        cmd_match = re.search(r"cmd=(?:\"([^\"]*)\"|([0-9A-Fa-f]+))", message)
        cwd_match = re.search(r"cwd=\"([^\"]*)\"", message)
        command = _decode_arg(cmd_match.group(1) or cmd_match.group(2)) if cmd_match else ""
        return RawTelemetryEnvelope(
            kind="command",
            collector=collector,
            payload={
                **base,
                "user": fields.get("auid", ""),
                "cmd": command,
                "cwd": cwd_match.group(1) if cwd_match else "",
                "result": "success" if "res=success" in message else "failure",
            },
            **base,
        )
    if "USER_LOGIN" in records:
        fields = records["USER_LOGIN"][0]
        message = raws.get("USER_LOGIN", "")
        acct = re.search(r'acct="?([^" ]+)"?', message)
        addr = re.search(r"addr=([0-9.]+)", message)
        return RawTelemetryEnvelope(
            kind="authentication",
            collector=collector,
            payload={
                **base,
                "user": acct.group(1) if acct else "",
                "source_ip": addr.group(1) if addr else "",
                "result": "success" if "res=success" in message else "failure",
                "service": fields.get("exe", "").strip('"'),
            },
            **base,
        )
    if "USER_ACCT" in records:
        # PAM 账号阶段记录：su/sudo 切换账号的会话证据（UID0 隐藏账号案的关键
        # 一环——账号不仅被创建，还被真实使用）。归入 authentication。
        message = raws.get("USER_ACCT", "")
        acct = re.search(r'acct="?([^" ]+)"?', message)
        op = re.search(r"op=([^ ]+)", message)
        return RawTelemetryEnvelope(
            kind="authentication",
            collector=collector,
            payload={
                **base,
                "user": acct.group(1) if acct else "",
                "source_ip": "",
                "result": "success" if "res=success" in message else "failure",
                "service": op.group(1) if op else "PAM:accounting",
            },
            **base,
        )
    return None


class AuditDProjector:
    """Projects auditd-derived envelopes into canonical replay events."""

    def __init__(self, *, host_id: str) -> None:
        self.host_id = host_id
        self._starts: dict[int, int] = {}
        self._path_hashes: dict[str, str] = {}

    def project(self, envelope: RawTelemetryEnvelope) -> list[dict[str, Any]]:
        handlers = {
            "process": self._process_exec,
            "file": self._file_event,
            "network": self._network,
            "syscall": self._syscall,
            "command": self._command,
            "authentication": self._authentication,
        }
        handler = handlers.get(envelope.kind)
        return handler(envelope) if handler else []

    def project_batch(
        self,
        envelopes: list[RawTelemetryEnvelope],
        *,
        path_hashes: dict[str, str] | None = None,
        process_starts: dict[int, int] | None = None,
    ) -> list[dict[str, Any]]:
        """Stabilize process identity first, then project; also derives
        parent relations from the ``ppid`` chains observed in the window.

        ``path_hashes``: workspace path → sha256 (judgment anchor source).
        ``process_starts``: pid → process start ms (from the ps snapshots);
        falls back to the pid's first exec time in the window.
        """

        starts: dict[int, int] = dict(process_starts or {})
        for envelope in envelopes:
            if envelope.kind == "process":
                pid = int(envelope.payload["pid"])
                starts.setdefault(pid, _payload_ms(envelope))
        self._starts = starts
        self._path_hashes = dict(path_hashes or {})
        events: list[dict[str, Any]] = []
        seen_pairs: set[tuple[str, str]] = set()
        for envelope in envelopes:
            if envelope.kind == "process":
                pid = int(envelope.payload["pid"])
                ppid = int(envelope.payload.get("ppid", 0) or 0)
                if ppid and ppid != pid and ppid in starts:
                    parent = self._process_ref(ppid, starts[ppid])
                    child = self._process_ref(pid, starts[pid])
                    if (parent, child) not in seen_pairs:
                        seen_pairs.add((parent, child))
                        events.append(self._parent_relation(parent, child, envelope))
            events.extend(self.project(envelope))
        self._starts = {}
        self._path_hashes = {}
        return events

    # -- handlers -------------------------------------------------------

    def _process_ref(self, pid: int, start_ms: int) -> str:
        return f"process:{self.host_id}:{pid}:{start_ms}"

    def _process_exec(self, envelope: RawTelemetryEnvelope) -> list[dict[str, Any]]:
        payload = envelope.payload
        pid = int(payload["pid"])
        start_ms = self._starts.get(pid, _payload_ms(envelope))
        ref = self._process_ref(pid, start_ms)
        exe = payload.get("exe", "")
        args = list(payload.get("args", []))
        digest = self._path_hashes.get(exe)
        data: dict[str, Any] = {
            "process_ref": ref,
            "executable": exe,
            "cmdline": " ".join([exe, *args[1:]]) if args else exe,
            # uid+euid 双值承载提权语义（setuid 案：uid=65534/euid=0）；
            # 只留 euid 会丢掉"非特权用户执行"这半个事实。
            "uid": str(payload.get("uid", "")),
            "euid": str(payload.get("euid", "")),
        }
        subjects = [ref]
        if digest:
            data["file_ref"] = f"file:{self.host_id}:{digest}"
            subjects.append(data["file_ref"])
        return [_event("process_exec", "process", envelope, subjects, data)]

    def _parent_relation(self, parent_ref: str, child_ref: str, envelope: RawTelemetryEnvelope) -> dict[str, Any]:
        return _event(
            "process_parent_relation",
            "process",
            envelope,
            [parent_ref, child_ref],
            {"parent_ref": parent_ref, "child_ref": child_ref},
        )

    def _file_event(self, envelope: RawTelemetryEnvelope) -> list[dict[str, Any]]:
        payload = envelope.payload
        path = payload.get("path", "")
        digest = self._path_hashes.get(path)
        pid = int(payload.get("pid", 0))
        start_ms = self._starts.get(pid, _payload_ms(envelope))
        acting = self._process_ref(pid, start_ms)
        operation = str(payload.get("op", "create"))
        data: dict[str, Any] = {
            "path": path,
            "operation": operation,
            "acting_process_ref": acting,
            "acting_executable": payload.get("exe", ""),
        }
        if payload.get("renamed_from"):
            data["renamed_from"] = payload["renamed_from"]
        subjects = [f"host:{self.host_id}"]
        domain = "file"
        if digest:
            data["file_ref"] = f"file:{self.host_id}:{digest}"
            subjects.append(data["file_ref"])
        if path.startswith("/etc/systemd/system/"):
            unit = path.rsplit("/", 1)[-1]
            data = {
                "action": "unit_write",
                "unit": unit,
                "unit_path": path,
                "exec_file_ref": data.get("file_ref"),
            }
            subjects = [data.get("exec_file_ref") or f"host:{self.host_id}", f"persistence:{unit}"]
            domain = "persistence"
            return [_event("systemd_event", domain, envelope, subjects, data)]
        if "/cron" in path and path.startswith("/etc/"):
            domain = "persistence"
        return [_event("file_event", domain, envelope, subjects, data)]

    def _network(self, envelope: RawTelemetryEnvelope) -> list[dict[str, Any]]:
        payload = envelope.payload
        pid = int(payload.get("pid", 0))
        start_ms = self._starts.get(pid, _payload_ms(envelope))
        ref = self._process_ref(pid, start_ms)
        endpoint = f"endpoint:{payload['remote_ip']}:{payload['remote_port']}"
        data: dict[str, Any] = {
            "process_ref": ref,
            "remote_ip": payload["remote_ip"],
            "remote_port": int(payload["remote_port"]),
            "protocol": payload.get("protocol", "tcp"),
        }
        # 轮询器聚合元数据（settle_case）：同一四元组的观测次数与首末时间，
        # 承载"周期性多次外连"的证据（回连类案例的定性依据）。
        meta = payload.get("_poll_meta")
        if isinstance(meta, dict):
            data["observed_count"] = int(meta.get("count", 1))
            for key in ("first_ms", "last_ms"):
                if meta.get(key):
                    data[key] = int(meta[key])
        return [
            _event(
                "network_connection",
                "network",
                envelope,
                [ref, endpoint],
                data,
            )
        ]

    def _syscall(self, envelope: RawTelemetryEnvelope) -> list[dict[str, Any]]:
        payload = envelope.payload
        return [
            _event(
                str(payload.get("syscall", "syscall")),
                "syscall",
                envelope,
                [f"host:{self.host_id}"],
                {"call": payload.get("syscall"), "result": payload.get("result"), "executable": payload.get("exe", "")},
            )
        ]

    def _command(self, envelope: RawTelemetryEnvelope) -> list[dict[str, Any]]:
        payload = envelope.payload
        return [
            _event(
                "shell_command",
                "command",
                envelope,
                [f"host:{self.host_id}", f"user:{payload.get('user', '')}"],
                {"user": payload.get("user", ""), "cmd": payload.get("cmd", ""), "cwd": payload.get("cwd", "")},
            )
        ]

    def _authentication(self, envelope: RawTelemetryEnvelope) -> list[dict[str, Any]]:
        payload = envelope.payload
        subjects = [f"host:{self.host_id}", f"user:{payload.get('user', '')}"]
        if payload.get("source_ip"):
            subjects.append(f"endpoint:{payload['source_ip']}:0")
        return [
            _event(
                "login_event",
                "authentication",
                envelope,
                subjects,
                {
                    "user": payload.get("user", ""),
                    "source_ip": payload.get("source_ip", ""),
                    "result": payload.get("result", ""),
                    "service": payload.get("service", ""),
                },
            )
        ]


def _payload_ms(envelope: RawTelemetryEnvelope) -> int:
    stamp = envelope.captured_at
    parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    return int(parsed.timestamp() * 1000)


def _event(
    event_type: str,
    domain: str,
    envelope: RawTelemetryEnvelope,
    subject_refs: list[str],
    data: dict[str, Any],
) -> dict[str, Any]:
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "type": event_type,
                "kind": envelope.kind,
                "ts": envelope.captured_at,
                "host": envelope.host_id,
                "subjects": subject_refs,
                "data": data,
            },
            sort_keys=True,
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()[:16]
    event = {
        "event_id": f"{event_type}-{fingerprint}",
        "event_type": event_type,
        "domain": domain,
        "source_system": envelope.collector,
        "observed_at": envelope.captured_at,
        "host_id": envelope.host_id,
        "subject_refs": subject_refs,
        "data": data,
    }
    validate_canonical_event(event)
    return event
