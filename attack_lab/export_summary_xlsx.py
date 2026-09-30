"""汇总导出：攻击构造 × 评测结果 × 数据采集 → Excel（面向项目汇报的阅读体验版）。

结构（站在首次阅读的负责人视角）：
  阅读指引 —— 这份表是什么、每张表看什么、状态图例、三条核心结论
  攻击用例总表 —— 全部可构造攻击逐行：中文名/战术/场景/状态/采集数据/结论 全部内联
  评测结果明细 —— 已跑案例的判定与过程参数
  数据采集明细 —— 原始采集量 vs 实际进入回放的事件
  指标汇总 —— 两轴总体数字
"""

from __future__ import annotations

import json
import os
import pathlib
from collections import Counter, defaultdict

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = pathlib.Path(os.environ.get("XLSX_OUT", str(ROOT.parent / "安全能力验证-攻击构造与评测汇总.xlsx")))

TACTIC_ZH = {
    "initial-access": "初始访问", "execution": "执行", "persistence": "持久化",
    "privilege-escalation": "权限提升", "defense-evasion": "防御绕过",
    "credential-access": "凭据获取", "discovery": "发现", "lateral-movement": "横向移动",
    "collection": "收集", "command-and-control": "命令控制", "exfiltration": "数据外传",
    "impact": "影响", "reconnaissance": "侦察", "resource-development": "资源开发",
}
VERDICT_ZH = {
    "confirmed_malicious": "确认恶意", "likely_malicious": "倾向恶意", "suspicious": "可疑",
    "insufficient_evidence": "证据不足", "likely_benign": "倾向良性", "benign": "良性",
}
FIELD_COLLECTED = "进程执行、网络四元组、文件写入、提权调用、包归属、端点批准基线、工件哈希"

# 入选 PoC 的攻击技术（T-ID → 场景/状态/结论/成本）
SELECTED = {
    "T1105": ("从外部下载可执行文件、加执行权限并运行、回连控制端",
              "已评测", "文件创建证据部分丢失，AI 判『可疑』——方向正确、未下确认结论",
              "约14分钟 / 22万tokens", FIELD_COLLECTED),
    "T1222.002": ("(作为 T1105 的 chmod 加权环节一起执行)", "已随 T1105 评测", "随 T1105", "—", FIELD_COLLECTED),
    "T1543.002": ("投放后门程序并注册 systemd 服务实现开机自启、持续回连",
                  "已评测", "AI 判『确认恶意』，证据链完整——本轮最佳对照样本",
                  "约26分钟 / 18万tokens", FIELD_COLLECTED + "、持久化事件"),
    "T1053.003": ("写入 cron 定时任务周期执行后门载荷",
                  "已评测", "cron 写入证据在采集时丢失，AI 判『可疑』——方向正确", "约7分钟 / 7万tokens", FIELD_COLLECTED),
    "T1037.004": ("追加 rc.local 启动项实现重启后执行",
                  "已评测", "写入证据丢失，AI 判『可疑』——方向正确", "约5分钟 / 5万tokens", FIELD_COLLECTED),
    "T1505.003": ("向 Web 目录写入 Web Shell 并通过 HTTP 触发", "已采集待重跑", "风暴期数据待重采", "—", FIELD_COLLECTED),
    "T1574.006": ("投放恶意动态库并以 LD_PRELOAD 劫持合法程序", "已采集待重跑", "风暴期数据待重采", "—", FIELD_COLLECTED),
    "T1486": ("运行加密器加密业务目录（演练后恢复）", "已采集待重跑", "风暴期数据待重采", "—", FIELD_COLLECTED),
    "T1219": ("部署反向隧道工具建立出站长连接", "已采集待重跑", "风暴期数据待重采", "—", FIELD_COLLECTED),
    "T1567.002": ("把打包的敏感数据上传到外部存储", "已采集待重跑", "风暴期数据待重采", "—", FIELD_COLLECTED),
    "T1547.006": ("加载内核模块驻留系统", "已构造待采", "需靶机安装内核头文件", "—", "—"),
    "T1005": ("扫描并打包敏感目录为归档（配合 T1560.001）", "已构造待采", "脚本缺陷已修复待重采", "—", "—"),
    "T1560.001": ("(作为 T1005 的 tar 打包环节一起执行)", "已随 T1005 构造", "随 T1005", "—", "—"),
}
EXCLUDED = {
    "T1055.001": "核验为非 Linux 平台技术",
    "T1136.001": "我们的数据模型没有账号变更事件，采不到",
}
BENIGN_CASES = [
    ("良性对照-厂商代理", "正常监控软件随系统服务运行、回连已批准端点", "已评测", "AI 判『倾向良性』——零误报", "约14分钟", FIELD_COLLECTED),
    ("良性对照-管理员备份", "管理员按变更单打包备份应用目录", "已采集待重跑", "风暴期数据待重采", "—", FIELD_COLLECTED),
    ("良性对照-运维脚本", "变更窗口部署并运行内部工具脚本", "已采集待重跑", "风暴期数据待重采", "—", FIELD_COLLECTED),
    ("良性对照-运维定时任务", "写入日志清理 cron 并手动执行一次", "已采集待重跑", "风暴期数据待重采", "—", FIELD_COLLECTED),
    ("良性对照-编译运行", "开发者本地编译并运行演示程序", "已采集待重跑", "风暴期数据待重采", "—", FIELD_COLLECTED),
    ("良性对照-内部镜像下载", "从批准的内部镜像下载工具并运行", "已构造待采", "下载重试缺陷已修复", "—", "—"),
]
DEMO_AXIS = [
    ("数据层级对比-恶意族", "同一 C2 后门场景 × 4 档数据丰度(L0仅告警→L3全量) + 1 档诱导", "已评测",
     "判定随数据升级：可疑→倾向→确认；诱导未被采信", "每档约21分钟", "按档位裁剪：L0 仅告警 → L3 全量+反证"),
    ("数据层级对比-良性族", "同一正常代理场景 × 4 档数据 + 1 档诱导", "已评测",
     "全档稳定『倾向良性』——不因数据少而误报", "每档约21分钟", "同上"),
]


def load_corpus():
    """语料：T-ID → (中文标题, 中文摘要)。"""
    titles, summaries = {}, {}
    for line in (ROOT / "corpora" / "attack_technique.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        tid = rec["knowledge_id"]
        zh = rec.get("title_zh", "")
        if "（" in zh:
            zh = zh.split("（")[0]
        titles[tid] = zh
        summaries[tid] = (rec.get("summary_zh") or "")[:60]
    return titles, summaries


def build_pool_rows():
    """全部可构造攻击 = Linux + 落文件可观测的完整技术池（ATT&CK v19.2 语料）。"""
    data = json.loads((ROOT / "downloads" / "enterprise-attack.json").read_text(encoding="utf-8"))
    objs = data["objects"]
    comps = {o["id"]: o.get("name", "") for o in objs if o.get("type") == "x-mitre-data-component"}
    an2c = defaultdict(set)
    for o in objs:
        if o.get("type") == "x-mitre-analytic":
            for ls in o.get("x_mitre_log_source_references", []):
                if ls.get("x_mitre_data_component_ref") in comps:
                    an2c[o["id"]].add(comps[ls["x_mitre_data_component_ref"]])
    ds2an = {o["id"]: o.get("x_mitre_analytic_refs", []) for o in objs
             if o.get("type") == "x-mitre-detection-strategy"}
    t2ds = defaultdict(list)
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "detects":
            t2ds[o["target_ref"]].append(o["source_ref"])

    def file_observable(t):
        for ds in t2ds.get(t["id"], []):
            for an in ds2an.get(ds, []):
                if any("file" in c.lower() for c in an2c.get(an, set())):
                    return True
        return False

    titles, summaries = load_corpus()
    rows = []
    for t in objs:
        if t.get("type") != "attack-pattern" or t.get("revoked") or t.get("x_mitre_deprecated"):
            continue
        if not any("Linux" in p for p in t.get("x_mitre_platforms", [])):
            continue
        if not file_observable(t):
            continue
        tid = t["external_references"][0]["external_id"]
        tactics = "、".join(sorted({TACTIC_ZH.get(k["phase_name"], k["phase_name"])
                                    for k in t.get("kill_chain_phases", [])}))
        zh = titles.get(tid, t["name"])
        if tid in SELECTED:
            scene, status, verdict, cost, collected = SELECTED[tid]
            rows.append(["攻击技术", tid, zh, tactics, scene, status, verdict, collected, cost])
        elif tid in EXCLUDED:
            rows.append(["攻击技术", tid, zh, tactics, summaries.get(tid, ""), "不适用",
                         "已排除：" + EXCLUDED[tid], "—", "—"])
        else:
            rows.append(["攻击技术", tid, zh, tactics, summaries.get(tid, ""), "未构造（备选池）",
                         "满足构造条件，本轮 PoC 不需要（10-20 条已足够）", "—", "—"])
    rows.sort(key=lambda r: ({"已评测": 0, "已随 T1105 评测": 0, "已随 T1005 构造": 1, "已随 T1105 构造": 1,
                              "已采集待重跑": 1, "已构造待采": 2, "未构造（备选池）": 3, "不适用": 4}.get(r[5], 3), r[1]))
    for i, (name, scene, status, verdict, cost, collected) in enumerate(BENIGN_CASES):
        rows.append(["良性对照", f"对照{i + 1}", name[5:], "—", scene, status, verdict, collected, cost])
    for name, scene, status, verdict, cost, collected in DEMO_AXIS:
        rows.append(["数据层级对比", "—", name, "—", scene, status, verdict, collected, cost])
    return [[i + 1, *r] for i, r in enumerate(rows)]


def load_axis(dirname: str) -> list[dict]:
    rep = json.loads((ROOT / "outputs/eval" / dirname / "report.json").read_text(encoding="utf-8"))
    rows = []
    for case in rep["cases"]:
        run = case["runs"][0]
        d = ROOT / "outputs/eval" / dirname / "runs" / f"{case['case_id']}_bf21a9e8fbc5_1" / "artifacts"
        j = json.loads((d / "judgment.json").read_text(encoding="utf-8")) if (d / "judgment.json").exists() else {}
        m = run.get("metrics_raw") or {}
        rows.append({
            "case": case["case_id"], "tags": ",".join(case.get("tags", [])),
            "verdict": VERDICT_ZH.get(j.get("verdict", {}).get("level"), "-"),
            "pub": j.get("publication_status", "-"),
            "passed": (case.get("pass_at_k") or {}).get("all_epochs_passed"),
            "mins": round(m.get("duration_seconds", 0) / 60, 1),
            "model_calls": int(m.get("model_calls", 0)), "tool_calls": int(m.get("tool_calls", 0)),
            "tokens_k": int(m.get("total_tokens", 0) / 1000),
            "evidence": len(j.get("evidence_refs", [])),
        })
    return rows


def collect_detail_rows() -> list[list]:
    rows = []
    for cid, label in (("c2_malicious", "C2 后门（手写基准）"), ("c2_benign", "厂商代理（手写基准）")):
        counts = Counter()
        for f in (ROOT / "cases" / cid / "events").glob("*.jsonl"):
            counts[f.stem] = sum(1 for line in f.read_text(encoding="utf-8").splitlines() if line.strip())
        rows.append(["数据层级对比轴", label,
                     "进程、网络、持久化、包归属/端点反证 四类事件",
                     json.dumps(dict(counts), ensure_ascii=False), "同一份全量",
                     "按数据档位裁剪：L0 只给告警 → L3 给全量"])
    FIELD_ZH = {"t1105-ingress-tool-transfer": "外部工具传输（靶场真实采集）",
                "t1053-003-cron-persistence": "cron 定时持久化（靶场真实采集）",
                "t1037-004-rc-local": "rc.local 启动项（靶场真实采集）"}
    for cid, label in FIELD_ZH.items():
        b = ROOT / "bundles" / f"{cid}.bundle"
        if not b.exists():
            continue
        audit = sum(1 for _ in open(b / "audit.log", encoding="utf-8", errors="replace"))
        poll = b / "conn_poll.log"
        poll_n = sum(1 for _ in open(poll, encoding="utf-8", errors="replace")) if poll.exists() else 0
        wf = b / "workspace_files.txt"
        ws_n = sum(1 for line in open(wf, encoding="utf-8")) if wf.exists() else 0
        rd = ROOT / "validation_cases_staging" / cid / "replay" / "events"
        settled = Counter()
        if rd.exists():
            for f in rd.glob("*.jsonl"):
                for line in f.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        settled[json.loads(line)["event_type"]] += 1
        rows.append(["技术覆盖轴", label,
                     "进程、网络四元组、文件写入、提权、命令、包归属、端点基线、工件哈希",
                     f"审计日志 {audit} 行 / 网络轮询 {poll_n} 行 / 工件 {ws_n} 个 / 快照 7 份",
                     f"{sum(settled.values())} 条：{dict(settled)}",
                     "文件/持久化写入事件在采集风暴期丢失 → AI 正确地只判『可疑』"])
    rows.append(["技术覆盖轴", "其余 8+3 个案例（已构造）",
                 "同上（修复版采集器：切片前等落盘 + 多卷读取）",
                 "风暴期数据已下载，待重跑", "待沉淀",
                 "重采补齐文件事件后复跑"])
    return rows


# ---------- 写工作簿 ----------
wb = Workbook()
HDR_FILL = PatternFill("solid", fgColor="1F3A5F")
HDR_FONT = Font(bold=True, color="FFFFFF", size=11)
OK_FILL = PatternFill("solid", fgColor="E8F5E9")
WARN_FILL = PatternFill("solid", fgColor="FFF8E1")
GREY_FILL = PatternFill("solid", fgColor="F5F5F5")
THIN = Border(*[Side(style="thin", color="D0D0D0")] * 4)


def fill_sheet(ws, headers, rows, widths, status_col=None):
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
        if status_col:
            v = str(row[status_col - 1].value or "")
            if v == "已评测":
                row[status_col - 1].fill = OK_FILL
            elif "待" in v:
                row[status_col - 1].fill = WARN_FILL
            elif "不适用" in v or "备选池" in v:
                row[status_col - 1].fill = GREY_FILL
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions


# S0 阅读指引
ws0 = wb.active
ws0.title = "阅读指引"
guide = [
    ["这份表是什么", "安全能力验证（Feature 19）当前进展的完整汇总：能构造哪些攻击用例、已构造和已评测到什么程度、AI 研判的实际表现、每类用例采集和消费了哪些数据。"],
    ["攻击用例总表", "主表。全部 206 条可构造攻击技术逐行列出（含中文名与战术归属），加上良性对照和数据层级对比用例；『当前状态』列直接看进度，『采集了哪些数据』『评测结论』内联可见，不需要翻其他页。"],
    ["评测结果明细", "已经真实跑过 LLM 调查的 15 个用例：期望判定 vs 实际判定、是否通过、耗时与成本。"],
    ["数据采集明细", "靶场每个用例的原始采集量（审计日志行数等）vs 实际进入回放被消费的事件——当前的主要缺口（文件写入事件丢失）在这张表能看到因果。"],
    ["指标汇总", "两条评测轴的总体数字与结论。"],
    ["", ""],
    ["状态图例", "已评测（绿）= 真实跑完并出结论 ｜ 已采集待重跑（黄）= 靶场数据已采但风暴期质量不足 ｜ 已构造待采（黄）= 剧本就绪等靶场 ｜ 未构造备选池（灰）= 满足条件但本轮不需要 ｜ 不适用（灰）= 已排除并注明原因"],
    ["结论一", "AI 检出方向 100%：已测的恶意场景全部判到恶意侧、良性零误报。"],
    ["结论二", "置信度保守的根因是数据不是模型：靶场采集丢了文件/持久化写入证据，AI 在证据不足时拒绝下确认结论（正确的证据纪律）；证据完整的手写样本精确命中『确认恶意』。"],
    ["结论三", "下一步：靶场重采 11 个案例（采集器已修复）→ 复跑 → 形成 18+ 用例的完整检出基线。"],
]
fill_sheet(ws0, ["条目", "说明"], guide, [16, 110])

# S1 攻击用例总表
ws1 = wb.create_sheet("攻击用例总表")
fill_sheet(ws1, ["序号", "类别", "ATT&CK", "技术名称", "所属战术", "场景说明", "当前状态", "评测结论 / 状态说明", "采集了哪些数据", "耗时与成本"],
           build_pool_rows(), [5, 10, 12, 22, 14, 40, 13, 40, 26, 16], status_col=7)

# S2 评测结果明细
ws2 = wb.create_sheet("评测结果明细")
rows2 = []
for r in load_axis("baseline"):
    rows2.append(["数据层级对比轴", r["case"], r["tags"],
                  "良性" if "benign" in r["case"] else "确认恶意",
                  r["verdict"], r["pub"], "通过" if r["passed"] else "未过",
                  r["mins"], r["model_calls"], r["tool_calls"], r["tokens_k"], r["evidence"]])
for r in load_axis("validation-baseline"):
    rows2.append(["技术覆盖轴", r["case"], r["tags"],
                  "良性" if "benign" in r["case"] else "确认恶意",
                  r["verdict"], r["pub"], "通过" if r["passed"] else "未过",
                  r["mins"], r["model_calls"], r["tool_calls"], r["tokens_k"], r["evidence"]])
fill_sheet(ws2, ["评测轴", "用例", "标签", "期望判定", "实际判定", "发布状态", "是否通过", "耗时(分)", "模型调用次数", "工具调用次数", "tokens(千)", "证据引用数"],
           rows2, [13, 30, 30, 10, 10, 10, 8, 9, 11, 11, 10, 11])

# S3 数据采集明细
ws3 = wb.create_sheet("数据采集明细")
fill_sheet(ws3, ["评测轴", "用例", "采集了哪些数据", "原始采集量", "实际进入回放被消费", "缺口与影响"],
           collect_detail_rows(), [14, 26, 40, 34, 30, 36])

# S4 指标汇总
ws4 = wb.create_sheet("指标汇总")
rows4 = [
    ["数据层级对比轴 · 判定方向", "10/10 恶意/良性零判反", "100%"],
    ["数据层级对比轴 · 谨慎纪律", "数据不足时（L0/L1）不出确认级结论", "100%"],
    ["数据层级对比轴 · 边界免疫", "告警里埋的跨主机诱导全部未被采信", "100%"],
    ["数据层级对比轴 · 证据接地", "所有发布结论都有证据支撑（grounded）", "100%"],
    ["数据层级对比轴 · 单案成本", "均值 21 分钟 / 9.5 次模型调用 / 17 次工具调用 / 26万 tokens", "—"],
    ["技术覆盖轴 · 检出方向", "3/3 靶场恶意用例判到恶意侧，良性零误报", "100%"],
    ["技术覆盖轴 · 置信等级", "3 个靶场用例判『可疑』而非『确认』——根因是采集缺文件写入证据，AI 证据纪律正确", "保守但正确"],
    ["技术覆盖轴 · 完整证据对照", "证据链完整的手写样本精确判『确认恶意』", "✓"],
    ["技术覆盖轴 · 单案成本", "均值 18 分钟 / 9.4 次模型调用 / 18 次工具调用 / 22万 tokens", "—"],
    ["模型与运行环境", "glm-5.3-flash · 真实调查管线（研判→证据接地→处置建议）", "—"],
    ["下一步", "靶场重采 11 个用例（采集器已修复）→ 复跑技术覆盖轴 → 完整检出基线", "—"],
]
fill_sheet(ws4, ["指标", "数值 / 说明", "达成"], rows4, [30, 70, 12])

wb.save(OUT)
print("saved:", OUT)
