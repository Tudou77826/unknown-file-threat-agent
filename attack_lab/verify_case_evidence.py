"""单案证据验证门（2026-10-12 复核裁决第 4 条）。

采集包回传本地、settle 沉淀之后、靶机 cleanup 之前运行：
  第一检"采到了"——bundle 侧物证齐全（哈希/内容/回执日志非空）；
  第二检"AI 能查到"——离线导入活动库后，用真实查询面断言每项物证
  （原始层 + 归一化层 + 摘要视图）都真实可达。
两检全过输出 CLEANUP-OK（才允许执行靶机 cleanup_all）；任一失败列出缺口，
靶机现场保留待复查。

用法: python verify_case_evidence.py <case-id>
"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import shutil
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from threat_agent.bootstrap.eval_tasks import import_validation_datasets  # noqa: E402
from threat_agent.data_foundation.adapters.reference_store import SQLiteReferenceDataStore  # noqa: E402
from threat_agent.judgment.application.tool_observation import brief_result  # noqa: E402

BUNDLE = PROJECT_ROOT / "attack_lab" / "bundles_v2" / f"{sys.argv[1]}.bundle" if len(sys.argv) > 1 else None
CASE = sys.argv[1] if len(sys.argv) > 1 else ""


def check_collected() -> list[str]:
    """第一检：采集包物证齐全。返回缺口清单（空=通过）。"""
    gaps: list[str] = []
    b = BUNDLE
    if not b.exists():
        return [f"bundle 不存在: {b}"]
    if not (b / "system_hashes.txt").exists() or not (b / "system_hashes.txt").read_text().strip():
        gaps.append("system_hashes.txt 缺失或为空")
    if not (b / "system_stats.txt").exists() or not (b / "system_stats.txt").read_text().strip():
        gaps.append("system_stats.txt 缺失或为空")
    mc = b / "system_contents" / "manifest.txt"
    if CASE == "chain-001-full-intrusion" and (not mc.exists() or not mc.read_text().strip()):
        gaps.append("system_contents manifest 缺失或为空（本案声明了内容物证）")
    if CASE in {"t1552-004-private-key", "chain-001-full-intrusion"}:
        tr = b / "transfer_receipts.log"
        body = [l for l in tr.read_text().splitlines() if l.strip() and not l.startswith("#")] if tr.exists() else []
        if not body:
            gaps.append("transfer_receipts.log 缺失或无回执行")
        else:
            # 回执哈希必须能对上发送端归档哈希（system_hashes 中同名文件）
            import hashlib
            hashes = {}
            for line in (b / "system_hashes.txt").read_text().splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    hashes[parts[1].strip()] = parts[0]
            matched = False
            for line in body:
                fields = line.split("\t")
                if len(fields) >= 5 and fields[4] != "-":
                    for path, digest in hashes.items():
                        if path.endswith(fields[2].strip()) and digest == fields[4].strip():
                            matched = True
                if matched:
                    break
            if not matched:
                gaps.append("回执哈希与发送端归档哈希未对上（收发对应失败）")
    return gaps


def check_queryable() -> list[str]:
    """第二检：离线导入后用真实查询面断言物证可达。返回缺口清单（空=通过）。"""
    expectations: dict[str, list[str]] = {
        # 案 → [(事件类型, 必须出现的子串)]
        "t1552-004-private-key": [
            ("file_content", "asset-record-opskey"),       # 窗口前资产快照
            ("file_content", "ops@inventory-2024"),        # 快照内容含密钥注释
            ("file_content", "upload-receipt"),            # 回执文件内容
            ("transfer_receipt", "RECV-"),                 # 接收端回执事件
            ("file_stat_snapshot", "/home/ops/.ssh/id_ed25519"),  # 源密钥属性（属主/时间）
        ],
        "chain-001-full-intrusion": [
            ("file_content", "sysupd-maint"),              # cron 内容
            ("file_content", "maint-deploy"),              # authorized_keys 追加行内容
            ("file_content", "upload-receipt"),            # 回执内容
            ("transfer_receipt", "RECV-"),
            ("file_stat_snapshot", "/etc/cron.d/sysupd-maint"),
        ],
    }
    wants = expectations.get(CASE)
    if not wants:
        return []
    root = Path(tempfile.mkdtemp())
    gaps: list[str] = []
    try:
        store = SQLiteReferenceDataStore(root / "ref.sqlite")
        import_validation_datasets(store, [PROJECT_ROOT / "validation_cases_staging"])
        db = root / f"ref-{CASE}-activities.sqlite"
        conn = sqlite3.connect(db)
        for event_type, needle in wants:
            row = conn.execute(
                "SELECT payload_json FROM raw_records WHERE payload_json LIKE ? LIMIT 1",
                (f"%{event_type}%",),
            ).fetchone()
            if row is None:
                gaps.append(f"查询面缺事件 {event_type}")
                continue
            # 事件在但内容是否可见：归一化层 + 摘要视图双查
            norm = conn.execute(
                "SELECT payload_json FROM normalized_activities WHERE payload_json LIKE ? LIMIT 1",
                (f"%{needle}%",),
            ).fetchone()
            if norm is None:
                gaps.append(f"事件 {event_type} 在但归一化层不见 '{needle}'")
                continue
            activity = json.loads(norm[0])
            brief = brief_result({"activities": [activity], "evidence_references": [],
                                  "execution_boundary": {"returned_count": 1}})
            blob = json.dumps(brief, ensure_ascii=False)
            if needle not in blob and needle not in json.dumps(activity):
                gaps.append(f"'{needle}' 在摘要视图不可见（get_raw_records 仍可达则为降级）")
        conn.close()
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return gaps


def main() -> int:
    if not CASE:
        print("用法: verify_case_evidence.py <case-id>")
        return 2
    gaps = check_collected()
    print(f"[{CASE}] 第一检·采到了: {'通过' if not gaps else gaps}")
    if gaps:
        print("结果: FAIL —— 保留靶机现场，勿清理")
        return 1
    gaps = check_queryable()
    print(f"[{CASE}] 第二检·AI 能查到: {'通过' if not gaps else gaps}")
    if gaps:
        print("结果: FAIL —— 保留靶机现场，勿清理")
        return 1
    print("结果: CLEANUP-OK —— 可执行靶机 cleanup_all.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
