# Field Mapping

## T_FILE_DETAILS to case_context

| Source field | Normalized field | Meaning |
| --- | --- | --- |
| `fileHash` | `file.sha256` | Unknown file SHA256 |
| `md5` | `file.md5` | Unknown file MD5 |
| `filePath` | `file.path` | Full path on host |
| `fileType` | `file.type` | ELF, script, archive, etc. |
| `fileSize` | `file.size` | File size |
| `fileMode` | `file.mode` | File permission |
| `Status` | `file.status` / `file.detection_result` | `3` means unknown |
| `HOFS_PATH` | `file.hofs_path` | Stored sample path |
| `Source` | `host.source` | First-level asset ID |
| `Sub_Asset` | `host.sub_asset` | Node ID |
| `POD_ID` | `host.pod_id` | Pod ID |
| `CONTAINER_ID` | `host.container_id` | Container ID |
| `CONTAINER_NAME` | `host.container_name` | Container name |
| `Process_NAME` | `trigger_process.name` | Trigger process name |
| `PID` | `trigger_process.pid` | Trigger process PID |
| `PPID` | `trigger_process.ppid` | Parent PID |
| `UID/GID/EUID/EGID` | `trigger_process.*` | Runtime identity |
| `PROCESS_CREATE_TIME` | `trigger_process.create_time` | Trigger process start time |
| `REALTIME_TYPE` | `trigger_process.realtime_type` | `0` file landing, `1` process startup |
| `DETAIL` | `process_chain` | Process chain JSON |
| `hashlist` | `hashlist` | Hashes in related process chain |

## DETAIL to process_chain

`DETAIL.context[]` is treated as the target process context.

`DETAIL.context[].tree[]` is treated as ancestors of the target process.

The MVP reverses `tree[]` before appending the target, so this:

```text
tree: [bash, sshd], context: kinsing
```

becomes:

```text
sshd -> bash -> kinsing
```

## T_PROCESS_CHAIN_HASH to process_chain

Rows are joined to process-chain nodes by:

1. `pid`
2. `processName`

If both match, `hash_match_confidence=high`.

If only `pid` matches, `hash_match_confidence=medium`.

## T_abnormal_event_TO_REPORT_OS to abnormal_events

The MVP preserves event IDs, IPs, ports, event times, attack phase, confidence,
times, duration, evidence JSON, detail JSON/text, user context, pod/host context,
and `sundries`.

| Source field | Normalized field | Meaning |
| --- | --- | --- |
| `event_id` | `abnormal_events[].event_id` | Original event ID |
| `evidence` | `abnormal_events[].evidence` | Forensic JSON: file and process context |
| `src_ip/dest_ip` | `abnormal_events[].src_ip/dest_ip` | Network context |
| `attacker_ip/onthreat_ip` | `abnormal_events[].attacker_ip/onthreat_ip` | Attack-related IPs |
| `src_port/dest_port` | `abnormal_events[].src_port/dest_port` | Network ports |
| `occur_time` | `abnormal_events[].occur_time` | Event occurrence time |
| `recent_time` | `abnormal_events[].recent_time` | Recent event time |
| `detect_time` | `abnormal_events[].detect_time` | Detection time |
| `report_time` | `abnormal_events[].report_time` | Report time |
| `attack_phase` | `abnormal_events[].attack_phase` | Attack-chain phase |
| `attack_status` | `abnormal_events[].attack_status` | Attack status |
| `confidence` | `abnormal_events[].confidence` | Upstream confidence |
| `times` | `abnormal_events[].times` | Event count |
| `duration` | `abnormal_events[].duration` | Event duration |
| `detail` | `abnormal_events[].detail` | Process-chain and file-detail JSON/text |
| `pod_id/host_id` | `abnormal_events[].pod_id/host_id` | Container/host context |
| `user_name` | `abnormal_events[].user_name` | User context |
| `visitor_ip` | `abnormal_events[].visitor_ip` | Visitor IP |
| `login_account` | `abnormal_events[].login_account` | Login account |
| `sundries` | `abnormal_events[].sundries` | User config or engine detection JSON |

Later versions should correlate by host, container, process, and time window.
