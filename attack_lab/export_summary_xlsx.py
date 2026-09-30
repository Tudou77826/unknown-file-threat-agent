"""汇总导出：攻击构造 × 评测结果 × 过程参数 × 数据收集/使用 → Excel。

放在需求目录（仓库根 SecAgent/）的安全能力验证汇总表。
"""

from __future__ import annotations

import json
import pathlib
from collections import Counter

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

ROOT = pathlib.Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "bundles"
OUT = pathlib.Path(__import__("os").environ.get("XLSX_OUT", str(ROOT.parent / "安全能力验证-攻击构造与评测汇总-2026-09-30.xlsx")))

# ---------- 1) 攻击目录全集（attack-catalog.md + demo 数据轴） ----------
CATALOG = [
    ("恶意", "T1105+T1222.002", "外部拉取 ELF→chmod→执行回连（工具传输）", "下载的 payload.elf", "b6 镜像下载", "已构造", "已采集(干净重跑)", "已沉淀(4事件+反证)", "已评测·可疑(方向对)", "文件创建事件缺失(采集时序)"),
    ("恶意", "T1543.002", "systemd 服务持久化+回连", "后门 payload.elf", "b1 vendor agent", "已有(c2-malicious-elf)", "—(手写即正式)", "已入库(手写)", "已评测·确认恶意✓", "证据链完整对照样本"),
    ("恶意", "T1053.003", "cron 定时任务持久化", "载荷 payload.elf", "b4 运维 cron", "已构造", "已采集(风暴期)", "已沉淀(4事件)", "已评测·可疑(方向对)", "cron 写入事件缺失"),
    ("恶意", "T1505.003", "Web Shell 写入+HTTP 触发", "webroot/shell.php", "—", "已构造", "已采集(风暴期)", "待重沉淀", "未评测", "草案路径已修正(webroot)"),
    ("恶意", "T1574.006", "LD_PRELOAD 劫持合法程序", "libpreload.so", "b5 编译产物", "已构造", "已采集(风暴期)", "待重沉淀", "未评测", ""),
    ("恶意", "T1547.006", "内核模块 insmod 加载", "rootkit.ko", "—", "已构造(可跳过)", "未采(无内核头)", "未沉淀", "未评测", "需靶机装 kernel-headers"),
    ("恶意", "T1486", "勒索加密蜜罐目录(演练后恢复)", "cryptor.elf", "b2 管理员备份", "已构造", "已采集(风暴期)", "待重沉淀", "未评测", ""),
    ("恶意", "T1037.004", "rc.local 启动项持久化", "payload.elf", "—", "已构造", "已采集", "已沉淀(4事件)", "已评测·可疑(方向对)", "rc.local 写入事件缺失"),
    ("恶意", "T1005+T1560.001", "敏感目录聚合归档(外传准备)", "staging.tar.gz", "b2 管理员备份", "已构造(引用bug已修)", "待重采", "未沉淀", "未评测", "shadow 样例 $6 引用已修"),
    ("恶意", "T1219", "远控隧道部署+出站长连", "tunnel.elf", "b1 vendor agent", "已构造", "已采集(风暴期)", "待重沉淀", "未评测", ""),
    ("恶意", "T1567.002", "归档上传外部存储(外传)", "exfil.tar.gz", "—", "已构造", "已采集(风暴期)", "待重沉淀", "未评测", ""),
    ("良性", "baseline", "vendor 监控代理随 systemd 运行回连批准端点", "monitor-agent", "—", "已有(c2-benign-baseline)", "—(手写即正式)", "已入库(手写)", "已评测·倾向良性✓", "零误报对照"),
    ("良性", "baseline", "管理员 tar 备份应用目录", "backup.tar.gz", "↔恶意07/09", "已构造", "已采集(风暴期)", "待重沉淀", "未评测", ""),
    ("良性", "baseline", "运维部署并执行内部工具脚本", "ops-tool.sh", "↔恶意01", "已构造", "已采集(风暴期)", "待重沉淀", "未评测", ""),
    ("良性", "baseline", "运维 cron 日志清理任务", "logclean.sh", "↔恶意03", "已构造", "已采集(风暴期)", "待重沉淀", "未评测", ""),
    ("良性", "baseline", "开发者编译并运行演示程序", "demo.elf", "↔恶意05", "已构造", "已采集(风暴期)", "待重沉淀", "未评测", ""),
    ("良性", "baseline", "从内部批准镜像下载工具并执行", "mirror-tool", "↔恶意01/11", "已构造(curl重试已修)", "待重采", "未沉淀", "未评测", ""),
]
DEMO_ROWS = [
    ("恶意·数据轴", "T1543.002+T1071.001", "C2 后门 × L0-L3 数据层级对比(4案例+L3诱导)", "sysupd", "同族良性", "demo_data 基准", "—", "已入库", "已评测·梯度✓", "L0可疑→L3确认恶意"),
    ("良性·数据轴", "baseline", "vendor 代理 × L0-L3(4案例)+L3诱导(2案例)", "monitor-agent", "—", "demo_data 基准", "—", "已入库", "已评测·稳定✓", "全档倾向良性+边界免疫"),
]



# 已入选 PoC 的 12 条（T-ID -> 状态描述）
SELECTED = {
    "T1105": ("已构造·已采集·已评测", "工具传输(配 chmod T1222.002)；靶场证据缺口致置信保守"),
    "T1222.002": ("随 T1105 剧本", "chmod 赋权环节"),
    "T1543.002": ("已构造·已评测✓", "systemd 持久化；c2-malicious-elf 证据链完整精确命中；另有独立剧本待重采"),
    "T1053.003": ("已构造·已评测", "cron 持久化；cron 写入事件缺失(采集缺口)"),
    "T1505.003": ("已构造·已采集待重沉淀", "Web Shell；草案路径已修正"),
    "T1574.006": ("已构造·已采集待重沉淀", "LD_PRELOAD 劫持"),
    "T1547.006": ("已构造·待重采", "内核模块；需靶机 kernel-headers"),
    "T1486": ("已构造·已采集待重沉淀", "勒索加密(演练后恢复)"),
    "T1037.004": ("已构造·已评测", "rc.local 启动项；写入事件缺失(采集缺口)"),
    "T1005": ("已构造·待重采", "本地收集归档(配 T1560.001)；引用 bug 已修"),
    "T1560.001": ("随 T1005 剧本", "tar 归档环节"),
    "T1219": ("已构造·已采集待重沉淀", "远控隧道"),
    "T1567.002": ("已构造·已采集待重沉淀", "归档外传"),
}
EXCLUDED = {
    "T1055.001": "排除: 语料核验非 Linux 平台",
    "T1136.001": "排除: Canonical 无账号事件族(telemetry-scope 缺口4)",
    "T1210": "排除: 跨主机, 违反 F13 单主机边界",
}


def build_full_pool() -> list[list]:
    """全部可构造攻击 = Linux + 落文件可观测的完整技术池(ATT&CK v19.2)。"""
    import json as _json
    from collections import defaultdict as _dd

    data = _json.loads((ROOT / "downloads" / "enterprise-attack.json").read_text(encoding="utf-8"))
    objs = data["objects"]
    comps = {o["id"]: o.get("name", "") for o in objs if o.get("type") == "x-mitre-data-component"}
    an2c = _dd(set)
    for o in objs:
        if o.get("type") == "x-mitre-analytic":
            for ls in o.get("x_mitre_log_source_references", []):
                if ls.get("x_mitre_data_component_ref") in comps:
                    an2c[o["id"]].add(comps[ls["x_mitre_data_component_ref"]])
    ds2an = {o["id"]: o.get("x_mitre_analytic_refs", []) for o in objs if o.get("type") == "x-mitre-detection-strategy"}
    t2ds = _dd(list)
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "detects":
            t2ds[o["target_ref"]].append(o["source_ref"])

    def file_observable(t):
        for ds in t2ds.get(t["id"], []):
            for an in ds2an.get(ds, []):
                if any("file" in c.lower() for c in an2c.get(an, set())):
                    return True
        return False

    rows = []
    for t in objs:
        if t.get("type") != "attack-pattern" or t.get("revoked") or t.get("x_mitre_deprecated"):
            continue
        if not any("Linux" in p for p in t.get("x_mitre_platforms", [])):
            continue
        if not file_observable(t):
            continue
        tid = t["external_references"][0]["external_id"]
        tactics = ", ".join(sorted({k["phase_name"] for k in t.get("kill_chain_phases", [])}))
        if tid in SELECTED:
            status, note = SELECTED[tid]
            rows.append([tid, t["name"], tactics, status, note])
        elif tid in EXCLUDED:
            rows.append([tid, t["name"], tactics, "排除", EXCLUDED[tid]])
        else:
            rows.append([tid, t["name"], tactics, "可构造备选池", "满足 Linux+落盘约束, 未入 PoC(仅需 10-20 条)"])
    rows.sort(key=lambda r: (0 if "已" in r[3] or r[3] == "排除" else 1, r[0]))
    return rows


def load_axis(dirname: str) -> list[dict]:
    rep = json.loads((ROOT / "outputs/eval" / dirname / "report.json").read_text(encoding="utf-8"))
    rows = []
    for case in rep["cases"]:
        run = case["runs"][0]
        d = ROOT / "outputs/eval" / dirname / "runs" / f"{case['case_id']}_bf21a9e8fbc5_1" / "artifacts"
        j = json.loads((d / "judgment.json").read_text(encoding="utf-8")) if (d / "judgment.json").exists() else {}
        m = run.get("metrics_raw") or {}
        scores = run.get("scores") or {}
        vm = scores.get("verdict_match", {})
        rows.append({
            "case": case["case_id"],
            "tags": ",".join(case.get("tags", [])),
            "verdict": j.get("verdict", {}).get("level", "-"),
            "passed": (case.get("pass_at_k") or {}).get("all_epochs_passed"),
            "dist": (vm.get("dimensions") or {}).get("distance"),
            "pub": j.get("publication_status", "-"),
            "evidence": len(j.get("evidence_refs", [])),
            "mins": round(m.get("duration_seconds", 0) / 60, 1),
            "model_calls": int(m.get("model_calls", 0)),
            "tool_calls": int(m.get("tool_calls", 0)),
            "tokens_k": int(m.get("total_tokens", 0) / 1000),
        })
    return rows


def demo_collect_use() -> list[list]:
    rows = []
    for cid in ("c2_malicious", "c2_benign"):
        counts: Counter = Counter()
        for f in (ROOT / "cases" / cid / "events").glob("*.jsonl"):
            counts[f.stem] = sum(1 for line in f.read_text(encoding="utf-8").splitlines() if line.strip())
        rows.append([
            "数据完整度轴(demo)", cid,
            "固定剧本全量事件: process/network/persistence/counter_evidence 四类 jsonl",
            json.dumps(dict(counts), ensure_ascii=False), "-",
            "按 profile 的 visible_sources 过滤消费(L0 仅告警 → L3 全量+反证)",
        ])
    return rows


def field_collect_use() -> list[list]:
    rows = []
    for cid in ("t1105-ingress-tool-transfer", "t1053-003-cron-persistence", "t1037-004-rc-local"):
        b = BUNDLE / f"{cid}.bundle"
        if not b.exists():
            continue
        audit_lines = sum(1 for _ in open(b / "audit.log", encoding="utf-8", errors="replace"))
        poll = b / "conn_poll.log"
        poll_lines = sum(1 for _ in open(poll, encoding="utf-8", errors="replace")) if poll.exists() else 0
        wf = b / "workspace_files.txt"
        ws_files = sum(1 for line in open(wf, encoding="utf-8")) if wf.exists() else 0
        rd = ROOT / "validation_cases_staging" / cid / "replay" / "events"
        settled: Counter = Counter()
        if rd.exists():
            for f in rd.glob("*.jsonl"):
                for line in f.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        settled[json.loads(line)["event_type"]] += 1
        rows.append([
            "技术覆盖轴(靶场)", cid,
            "auditd(进程/文件/网络/提权/USER_*) + ss 轮询四元组 + ps 谱系 + rpm 清单/包归属 + 批准端点基线 + 工件哈希",
            json.dumps({"audit切片行": audit_lines, "网络轮询行": poll_lines, "工作区工件": ws_files,
                        "快照": "ps×2/ss×2/rpm/owners/endpoints"}, ensure_ascii=False),
            json.dumps(dict(settled), ensure_ascii=False),
            f"沉淀后 {sum(settled.values())} 事件进 replay 被评测消费(执行+回连+双反证)；文件/持久化事件缺失=已知采集缺口",
        ])
    return rows


# ---------- 写工作簿 ----------
wb = Workbook()
HDR_FILL = PatternFill("solid", fgColor="1F3A5F")
HDR_FONT = Font(bold=True, color="FFFFFF", size=11)
OK_FILL = PatternFill("solid", fgColor="E8F5E9")
WARN_FILL = PatternFill("solid", fgColor="FFF8E1")
THIN = Border(*[Side(style="thin", color="D0D0D0")] * 4)


def fill_sheet(ws, headers, rows, widths, color_col=None):
    ws.append(headers)
    for c in range(1, len(headers) + 1):
        cell = ws.cell(1, c)
        cell.fill = HDR_FILL
        cell.font = HDR_FONT
        cell.alignment = Alignment(horizontal="center", vertical="center")
    for r in rows:
        ws.append(r)
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    for row in ws.iter_rows(min_row=2):
        for cell in row:
            cell.border = THIN
            cell.alignment = Alignment(vertical="top", wrap_text=True)
        if color_col:
            v = str(row[color_col - 1].value or "")
            if "✓" in v:
                row[color_col - 1].fill = OK_FILL
            elif any(k in v for k in ("可疑", "待", "未", "缺失")):
                row[color_col - 1].fill = WARN_FILL
    ws.freeze_panes = "A2"


ws0 = wb.active
ws0.title = "可构造攻击全集"
pool = build_full_pool()
rows0 = [[i + 1, *r] for i, r in enumerate(pool)]
fill_sheet(ws0, ["序号", "ATT&CK", "技术名称", "战术", "状态", "说明/理由"],
           rows0, [5, 12, 34, 26, 20, 44], color_col=5)

ws1 = wb.create_sheet("PoC选择目录")
rows1 = [[i + 1, *c] for i, c in enumerate(CATALOG)]
rows1 += [[len(CATALOG) + i + 1, *d] for i, d in enumerate(DEMO_ROWS)]
fill_sheet(ws1, ["序号", "类别", "ATT&CK", "场景", "判定对象", "良性对照", "构造状态", "靶场采集", "沉淀入库", "评测状态", "备注"],
           rows1, [5, 11, 18, 34, 18, 14, 17, 14, 16, 18, 26], color_col=10)

ws2 = wb.create_sheet("评测结果明细")
rows2 = []
for r in load_axis("baseline"):
    rows2.append(["数据完整度轴", r["case"], r["tags"],
                  "confirmed_malicious" if "malicious" in r["case"] else "benign",
                  r["verdict"], r["pub"], "通过" if r["passed"] else "未过",
                  r["dist"] if r["dist"] is not None else "-",
                  r["mins"], r["model_calls"], r["tool_calls"], r["tokens_k"], r["evidence"]])
for r in load_axis("validation-baseline"):
    expected = "benign" if "benign" in r["case"] else "confirmed_malicious"
    rows2.append(["技术覆盖轴", r["case"], r["tags"], expected,
                  r["verdict"], r["pub"], "通过" if r["passed"] else "未过",
                  r["dist"] if r["dist"] is not None else "-",
                  r["mins"], r["model_calls"], r["tool_calls"], r["tokens_k"], r["evidence"]])
fill_sheet(ws2, ["评测轴", "案例", "标签", "期望判定", "实际判定", "发布状态", "结论", "等级距离", "耗时(分)", "模型调用", "工具调用", "tokens(k)", "证据引用数"],
           rows2, [13, 30, 30, 18, 18, 10, 8, 9, 9, 9, 9, 10, 11], color_col=7)

ws3 = wb.create_sheet("数据收集与使用")
rows3 = demo_collect_use() + field_collect_use()
rows3.append(["技术覆盖轴(靶场·待重采)", "其余8案例(t1219/t1486/t1543/t1567/t1574/bb2-bb5)+t1005/bb6",
              "同上采集器(修复版: 切片 flush 等待+多卷读取+hold 监听)",
              "风暴期 bundle 已下载待重跑", "待沉淀", "重采后补齐文件/持久化事件再评测"])
fill_sheet(ws3, ["评测轴", "案例/组", "采集了什么", "采集量(原始)", "沉淀后(进入replay)", "实际被消费/缺口"],
           rows3, [20, 30, 44, 30, 26, 38])

ws4 = wb.create_sheet("指标汇总")
rows4 = [
    ["数据完整度轴·方向正确率", "10/10 恶意/良性零判反", "100%"],
    ["数据完整度轴·降级纪律", "L0/L1 无确认级结论", "100%"],
    ["数据完整度轴·边界免疫", "2 个跨主机诱导案例零采信", "100%"],
    ["数据完整度轴·接地发布", "10/10 grounded", "100%"],
    ["数据完整度轴·单案成本", "均值 21 分钟 / 9.5 模型调用 / 17 工具调用 / 26万 tokens", "—"],
    ["技术覆盖轴·检出方向", "3/3 靶场恶意案例落恶意侧, 良性零误报", "100%"],
    ["技术覆盖轴·置信等级", "3 靶场案例=可疑(期望确认) — 根因: replay 缺持久化/文件事件(采集缺口), AI 证据纪律正确", "保守但正确"],
    ["技术覆盖轴·对照", "手写 c2-malicious-elf 证据链完整→精确确认恶意", "✓"],
    ["技术覆盖轴·单案成本", "均值 18 分钟 / 9.4 模型调用 / 18 工具调用 / 22万 tokens", "—"],
    ["模型与运行环境", "glm-5.3-flash · middleware 运行时 · 真实调查管线(研判→接地→处置)", "—"],
    ["待办", "靶场 11 案例重采(修复版采集器)→复跑技术覆盖轴→18 案例完整基线", "—"],
]
fill_sheet(ws4, ["指标", "数值/说明", "达成"], rows4, [30, 66, 12])

wb.save(OUT)
print("saved:", OUT)
