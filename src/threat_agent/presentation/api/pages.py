"""Feature 17 workbench pages: design system, shared JS base, all templates.

Self-contained (no CDN, works air-gapped). Templates use __PLACEHOLDER__
tokens; routes.py substitutes rendered fragments. Shared JS provides
toast/confirm-modal/safeFetch/i18n/relative-time so no page relies on native
browser dialogs or naked fetch calls.
"""

from __future__ import annotations

import html as _html
import json as _json

VERDICT_ZH = {
    "confirmed_malicious": "确认恶意",
    "likely_malicious": "高度疑似恶意",
    "suspicious": "存在可疑行为",
    "insufficient_evidence": "证据不足",
    "likely_benign": "倾向良性",
    "benign": "确认良性",
}

VERDICT_PILL = {
    "confirmed_malicious": "bad",
    "likely_malicious": "bad",
    "suspicious": "warn",
    "insufficient_evidence": "muted",
    "likely_benign": "ok",
    "benign": "ok",
}

STATUS_ZH = {
    "queued": "排队中", "running": "调查中", "awaiting_approval": "待审批",
    "completed": "已完成", "failed": "失败",
}
STATUS_PILL = {
    "queued": "info", "running": "warn", "awaiting_approval": "violet",
    "completed": "ok", "failed": "bad",
}

ACTION_ZH = {
    "run_created": "创建运行", "run_completed": "运行完成", "run_failed": "运行失败",
    "run_interrupted": "运行中断", "run_replayed": "运行重放", "tool_invoked": "工具调用",
    "knowledge_consulted": "知识咨询", "report_published": "报告发布",
    "approval_requested": "请求审批", "approval_decided": "审批决策",
    "debug_resumed": "调试重放",
    "demo_approval_decided": "审批决策",
}

ACTION_TYPES_ZH = {
    "isolate_host": "隔离受影响主机", "preserve_evidence": "保全调查证据",
    "block_endpoint": "阻断恶意端点", "terminate_process": "终止恶意进程",
    "remove_persistence": "移除持久化配置", "monitor": "加强监控",
    "collect_more_data": "补充取证后再研判",
    "manual_review": "转人工复核",
    "re_run_analysis": "重新运行分析",
}

# --------------------------------------------------------------- display map
# Single translation gate: templates and API payloads must never render raw
# model/enum values. Everything user-visible goes through these maps.

PROFILE_ZH = {
    "l0-alert-only": "仅告警核实（L0）",
    "l1-process-context": "进程上下文（L1）",
    "l2-behavior-telemetry": "行为遥测（L2）",
    "l3-attribution-and-assets": "溯源与资产（L3）",
}

DATASET_ZH = {
    "c2-malicious-reference": "C2 恶意样本（演练）",
    "c2-benign-reference": "C2 良性对照（演练）",
}

STAGE_ZH = {
    "queued": "排队中", "initializing": "接入", "investigating": "调查中",
    "judgment": "研判", "reporting": "报告", "approval": "待审批",
    "response_advisory": "处置建议", "publishing": "发布", "published": "已发布",
    "advised": "已处置", "intake": "接入", "plan": "规划", "execute": "执行",
    "gate": "证据门", "compose": "报告", "advise": "处置", "done": "完成",
}

TOOL_ZH = {
    "query_process_activities": "进程与命令",
    "query_network_activities": "网络连接",
    "query_socket_activities": "网络收发",
    "query_file_activities": "文件变更",
    "query_service_activities": "系统服务",
    "query_package_activities": "软件包来源",
    "query_asset_activities": "资产基线",
    "query_extension_activities": "扩展记录",
    "explore_entity": "实体关联探索",
    "get_raw_records": "原始记录",
    "calculate_activity_metrics": "活动统计",
    "lookup_attack_technique": "查询攻击技术库",
    "consult_judgment_experience": "查询研判经验",
    "interpret_telemetry_field": "解析遥测字段",
}

KIND_ZH = {
    "run": "启动", "graph": "编排", "thinking": "推理", "decision": "决策",
    "tool": "查询", "tool_error": "查询被拒", "context": "上下文",
    "model_input": "模型输入", "model_output": "模型输出",
    "validation": "发布校验", "repair": "重新研判", "report": "报告",
    "verdict": "结论", "response": "处置建议", "approval": "审批",
    "knowledge": "知识检索", "result": "结果", "complete": "完成",
    "round": "调查轮次", "gate": "预算与门槛", "error": "错误",
}

KNOWLEDGE_STATUS_ZH = {
    "available": "已命中", "empty": "无结果", "not_configured": "未配置",
    "permission_denied": "无权限", "timeout": "超时", "degraded": "降级", "error": "异常",
}

APPROVAL_CLASS_ZH = {
    "security_lead": "需安全负责人审批",
    "isolation_required": "需审批后隔离",
    "business_owner": "需业务负责人确认",
    "operator": "需运维执行确认",
    "recommended": "建议执行",
    "none": "无需审批",
}

DENY_REASON_ZH = {
    "reference_not_authorized": "引用了本次未授权的数据",
    "host_out_of_scope": "主机超出授权范围",
    "time_out_of_scope": "时间超出授权窗口",
    "budget_exhausted": "调查预算耗尽",
    "tool_not_allowed": "该工具不在此场景授权",
}

PUBLICATION_ZH = {
    "grounded": "证据充分发布",
    "fallback": "证据不足兜底",
}

PLAN_STATUS_ZH = {
    "recommended": "建议执行",
    "approval_required": "需人工审批",
    "insufficient_context": "上下文不足",
    "rejected": "未批准",
}


def profile_zh(profile_id: str) -> str:
    if not profile_id:
        return "—"
    return PROFILE_ZH.get(profile_id, profile_id)


def dataset_zh(dataset_id: str) -> str:
    if not dataset_id or dataset_id == "alert_json":
        return "手工告警"
    return DATASET_ZH.get(dataset_id, dataset_id)


def stage_zh(stage: str) -> str:
    return STAGE_ZH.get(stage, stage or "—")


def tool_zh(tool: str) -> str:
    if not tool or tool == "—":
        return "—"
    return TOOL_ZH.get(tool, tool)


def kind_zh(kind: str) -> str:
    return KIND_ZH.get(kind, kind)


RESOURCE_ZH = {
    "investigation_run": "调查任务",
    "tool": "数据查询",
    "knowledge": "知识检索",
    "report": "研判报告",
    "response_plan": "处置方案",
    "checkpoint": "回溯点",
    "approval": "审批决策",
    "audit": "审计记录",
}

SOURCE_CATEGORY_ZH = {
    "analyst_judgment_experience": "研判经验库",
    "attack_technique": "攻击技术库",
    "telemetry_field_manual": "遥测字段手册",
    "response_playbook": "处置手册",
    "org_sop": "组织处置规程",
    "responder_experience": "响应经验库",
    "historical_case": "历史案件",
}


def resource_zh(value: str) -> str:
    return RESOURCE_ZH.get(value, value)


# 咨询入口 → 面板标题；baseline 是固定基线节点，其余是按需知识工具。
KNOWLEDGE_ENTRY_ZH = {
    "baseline": "基线检索（研判指引）",
}


_KNOWLEDGE_STATUS_PILL = {
    "available": "ok", "degraded": "warn", "timeout": "warn",
    "error": "bad", "permission_denied": "bad",
}


def knowledge_card_html(item) -> str:
    """知识面板卡片：哪个入口、状态、命中了哪些条目。

    事件明细带 items（knowledge_id/version/title，不含正文）时列出命中
    条目；旧运行的明细没有 items，回退到翻译后的消息行，不编造内容。
    """

    detail = getattr(item, "detail", None) or {}
    entry = str(detail.get("entry") or detail.get("tool_name") or "")
    if entry in KNOWLEDGE_ENTRY_ZH:
        label = KNOWLEDGE_ENTRY_ZH[entry]
    elif entry:
        label = tool_zh(entry)
    else:
        label = "知识咨询"
    status = str(detail.get("status") or "")
    status_label = KNOWLEDGE_STATUS_ZH.get(status, status or "未知")
    status_pill = _KNOWLEDGE_STATUS_PILL.get(status, "muted")
    hit_items = [
        hit for hit in (detail.get("items") or [])
        if isinstance(hit, dict) and hit.get("knowledge_id")
    ]
    parts = [
        "<div class='know'><div class='know-head'><b>" + _html.escape(label) + "</b> "
        f"<span class='pill {status_pill}'>{_html.escape(status_label)}</span>"
        + (f" <span class='muted'>命中 {len(hit_items)} 条</span>" if hit_items else "")
        + "</div>"
    ]
    if hit_items:
        for hit in hit_items[:6]:
            parts.append(
                "<div class='know-item'><span class='mono'>"
                + _html.escape(str(hit.get("knowledge_id") or "")) + "</span> "
                + _html.escape(str(hit.get("title") or "")) + "</div>"
            )
        if len(hit_items) > 6:
            parts.append(f"<div class='know-item muted'>… 共 {len(hit_items)} 条</div>")
    else:
        summary = str(getattr(item, "summary", "") or "")
        parts.append(
            "<div class='muted'>" + _html.escape(translate_knowledge_message(summary)) + "</div>"
        )
    for note in (detail.get("limitations") or [])[:2]:
        parts.append("<div class='know-note'>" + _html.escape(str(note)) + "</div>")
    parts.append("</div>")
    return "".join(parts)


def translate_knowledge_message(message: str) -> str:
    """Turn '知识咨询 lookup_attack_technique 完成: available' into a human
    sentence. Unknown shapes are returned unchanged (never fabricate)."""

    if not message:
        return message
    text = message
    for tool, label in TOOL_ZH.items():
        text = text.replace(tool, label)
    for status, label in KNOWLEDGE_STATUS_ZH.items():
        text = text.replace(status, label)
    for token in ("知识咨询", "知识检索："):
        text = text.replace(token, "")
    text = text.replace("完成:", " ").replace("完成：", " ")
    text = text.replace("基线知识检索", "基线检索")
    return " ".join(text.split())


# Legacy/internal strings that predate the display gate and are already
# persisted in the audit ledger: translated at display time so old records read
# the same as new ones.
LEGACY_TEXT_ZH = {
    "framework-middleware": "",
    "persistent-demo-run-service": "",
    "demo_approval_decided": "审批决策",
    "reference-demo-policy": "内置策略",
    "InterfaceError": "数据存储访问冲突",
    "DataAccessError": "数据引用无效",
    "APITimeoutError": "模型服务超时",
    "APIConnectionError": "模型服务连接失败",
    "演示策略不批准执行高影响处置": "内置策略未批准高影响处置",
}

for _tool, _label in TOOL_ZH.items():
    LEGACY_TEXT_ZH[_tool] = _label
for _status, _label in KNOWLEDGE_STATUS_ZH.items():
    LEGACY_TEXT_ZH[_status] = _label


def display_summary(text: str) -> str:
    """Final scrubbing pass for any operator-visible summary string."""

    if not text:
        return text
    out = text
    for raw, label in LEGACY_TEXT_ZH.items():
        out = out.replace(raw, label)
    out = out.replace("（）", "").replace("()", "")
    return " ".join(out.split())


def approval_class_zh(value) -> str:
    if not value:
        return "按策略执行"
    return APPROVAL_CLASS_ZH.get(str(value), str(value))


def approval_card_html(pending, inline: bool = False) -> str:
    """Shared four-state approval decision card: rendered on the approval desk
    and inline inside the live investigation view (no page jump)."""

    run_id = _html.escape(pending.run_id)
    plan = pending.plan or {}
    actions = plan.get("actions") or []
    action_html = "".join(
        "<div class='action-item'><b>"
        + _html.escape(ACTION_TYPES_ZH.get(a.get("action_type"), a.get("action_type") or "动作"))
        + "</b> <span class='pill info'>"
        + _html.escape(approval_class_zh(a.get("approval_class")))
        + "</span><br>" + _html.escape(a.get("rationale") or "")
        + "<br><span class='muted'>业务影响："
        + _html.escape(a.get("expected_impact") or "待评估") + "</span></div>"
        for a in actions
    ) or "<p class='muted'>该处置方案未包含具体动作</p>"
    plan_json = _html.escape(_json.dumps(plan, ensure_ascii=False))
    # Inline use sits inside the live investigation column: keep the decision
    # surface but drop the outer card chrome so it reads as part of the stream.
    card_class = "approval-card inline" if inline else "card approval-card"
    actions_json = _html.escape(_json.dumps(actions, ensure_ascii=False, indent=1))
    return (
        f"<div class='{card_class}' id='approval-{run_id}'>"
        "<h2>等待你的审批 <span class='hint'>处置动作由你确认后进入执行队列；本系统不自动执行生产动作</span></h2>"
        f"<p class='muted' style='margin:0 0 8px'>案件 <span class='mono'>{_html.escape(pending.case_id)}</span></p>"
        + action_html
        + f"<textarea id='planbase-{run_id}' style='display:none'>{plan_json}</textarea>"
        + "<details style='margin-top:10px'><summary class='muted'>调整处置动作（高级）</summary>"
        + f"<textarea id='plan-{run_id}'>{actions_json}</textarea></details>"
        + "<div style='display:flex;gap:8px;margin-top:12px;align-items:center;flex-wrap:wrap'>"
        + f"<input id='by-{run_id}' placeholder='审批人' style='width:130px' value='值班分析师'>"
        + f"<input id='cm-{run_id}' placeholder='驳回意见（驳回必填）' style='flex:1;min-width:180px'>"
        + f"<button class='btn' onclick=\"decideApproval('{run_id}','accept')\">批准执行</button>"
        + f"<button class='btn ghost' onclick=\"decideApproval('{run_id}','edit')\">调整后批准</button>"
        + f"<button class='btn warn' onclick=\"decideApproval('{run_id}','respond')\">驳回</button>"
        + f"<button class='btn ghost' onclick=\"decideApproval('{run_id}','ignore')\" "
        "title='放弃本次处置方案并关闭该调查'>搁置</button></div>"
        + "<p class='muted' style='margin:8px 0 0;font-size:11.5px'>"
        "批准＝按方案执行 · 调整后批准＝修改动作后执行 · 驳回＝说明理由退回 · 搁置＝放弃本方案并关闭调查</p>"
        + "</div>"
    )


CSS = """
:root{
  --bg:#f5f6fa;--surface:#ffffff;--ink:#0f172a;--muted:#64748b;--line:#e8eaf0;
  --accent:#0f766e;--accent-soft:#ccfbf1;--sidebar:#0a161c;--sidebar-ink:#c4d4d2;
  --grad:linear-gradient(135deg,#0d9488 0%,#0f766e 100%);
  --ok:#16a34a;--ok-soft:#dcfce7;--warn:#d97706;--warn-soft:#fef3c7;
  --bad:#dc2626;--bad-soft:#fee2e2;--info:#0e7490;--info-soft:#cffafe;
  --violet:#7c3aed;--violet-soft:#ede9fe;
  --r-sm:8px;--r-md:12px;--r-lg:16px;--r-xs:6px;--radius:14px;
  --shadow:0 1px 2px rgba(15,23,42,.05),0 10px 30px rgba(15,23,42,.06);
  --shadow-lift:0 4px 12px rgba(13,148,136,.14),0 18px 44px rgba(15,23,42,.10);
}
*{box-sizing:border-box}html,body{margin:0;height:100%}
body{font:13.5px/1.65 "MiSans","PingFang SC","Microsoft YaHei UI",system-ui,sans-serif;background:var(--bg);color:var(--ink);display:flex}
a{color:var(--accent);text-decoration:none}a:hover{color:#0f766e;text-decoration:underline}
:focus-visible{outline:2px solid #2dd4bf;outline-offset:1px;border-radius:var(--r-xs)}
.sidebar{width:222px;flex:0 0 222px;background:linear-gradient(180deg,#0a161c 0%,#0d2430 100%);color:var(--sidebar-ink);display:flex;flex-direction:column;position:sticky;top:0;height:100vh}
.brand{padding:18px 18px 14px;border-bottom:1px solid rgba(255,255,255,.06);display:flex;align-items:center;gap:11px}
.logo-chip{width:36px;height:36px;flex:0 0 36px;border-radius:var(--r-md);background:var(--grad);display:flex;align-items:center;justify-content:center;box-shadow:0 4px 14px rgba(13,148,136,.45)}
.logo-chip svg{width:19px;height:19px}
.brand .name{line-height:1.25}
.brand b{font-size:14.5px;color:#fff;letter-spacing:.02em;display:block}
.brand span{font-size:9.5px;color:#7ca39d;letter-spacing:.12em}
.nav{padding:10px 10px;flex:1}
.nav .sep{padding:14px 10px 4px;font-size:10px;letter-spacing:.14em;color:#5f7d78}
.nav a{display:flex;align-items:center;gap:10px;padding:9px 12px;margin:2px 0;color:var(--sidebar-ink);font-size:13px;border-radius:var(--r-sm);transition:background .15s,color .15s}
.nav a:hover{background:rgba(255,255,255,.06);color:#fff}
.nav a.active{background:linear-gradient(135deg,rgba(13,148,136,.32),rgba(8,145,178,.16));color:#fff;font-weight:600;box-shadow:inset 0 0 0 1px rgba(45,212,191,.35)}
.nav a .ico{width:17px;height:17px;display:flex;align-items:center;justify-content:center;color:#84a8a3}
.nav a.active .ico,.nav a:hover .ico{color:#99f6e4}
.nav a .ico svg{width:16px;height:16px}
.nav a .count{margin-left:auto;background:linear-gradient(135deg,#f43f5e,#ef4444);color:#fff;border-radius:999px;font-size:10px;padding:1px 7px;font-weight:700}
.nav a.soon{opacity:.45}
.nav a.soon::after{content:"Soon";margin-left:auto;font-size:9px;color:#648a84;border:1px solid #24413e;border-radius:var(--r-xs);padding:0 4px}
.foot{padding:12px 18px;border-top:1px solid rgba(255,255,255,.06);font-size:11px;color:#5f7d78}
.main{flex:1;min-width:0;display:flex;flex-direction:column}
.topbar{display:flex;justify-content:space-between;align-items:center;padding:13px 28px;background:rgba(255,255,255,.82);backdrop-filter:blur(10px);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
.topbar h1{font-size:17px;margin:0;font-weight:700;letter-spacing:-.01em}
.topbar .sub{font-size:12px;color:var(--muted)}
.content{padding:20px 28px 60px;flex:1}
.hero{border-radius:16px;background:linear-gradient(120deg,#0f766e 0%,#0d9488 55%,#0891b2 100%);color:#fff;padding:20px 24px;margin-bottom:18px;box-shadow:0 12px 34px rgba(13,148,136,.32);display:flex;justify-content:space-between;align-items:center;gap:18px;flex-wrap:wrap}
.hero h2{margin:0 0 4px;font-size:18px;font-weight:700;letter-spacing:-.01em}
.hero p{margin:0;font-size:12.5px;opacity:.88}
.hero .chips{display:flex;gap:8px;flex-wrap:wrap}
.hero .chip{background:rgba(255,255,255,.16);border:1px solid rgba(255,255,255,.28);color:#fff;border-radius:999px;padding:6px 14px;font-size:12px;font-weight:600;cursor:pointer;transition:background .15s}
.hero .chip:hover{background:rgba(255,255,255,.30)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:16px 18px;margin-bottom:16px;transition:box-shadow .2s}
.card:hover{box-shadow:var(--shadow-lift)}
.card h2{font-size:14px;margin:0 0 10px;font-weight:600;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.card h2 .hint{font-weight:400;font-size:11px;color:var(--muted)}
.grid{display:grid;gap:14px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:16px}
.kpi{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:14px 16px;box-shadow:var(--shadow)}
.kpi .top{display:flex;align-items:center;gap:10px}
.kpi .chip-ico{width:36px;height:36px;flex:0 0 36px;border-radius:var(--r-sm);display:flex;align-items:center;justify-content:center}
.kpi .chip-ico.indigo{background:var(--accent-soft);color:var(--accent)}
.kpi .chip-ico.green{background:var(--ok-soft);color:var(--ok)}
.kpi .chip-ico.red{background:var(--bad-soft);color:var(--bad)}
.kpi .chip-ico.violet{background:var(--violet-soft);color:var(--violet)}
.kpi .chip-ico svg{width:17px;height:17px}
.kpi small{color:var(--muted);font-size:11px}
.kpi b{font-size:21px;font-weight:800;display:block;line-height:1.3}
.pill{display:inline-flex;align-items:center;gap:5px;padding:2px 10px;border-radius:999px;font-size:11.5px;font-weight:700;white-space:nowrap}
td .pill{vertical-align:middle}
/* Table spec: primary column never wraps; ids render short with full value on hover. */
td,th{overflow-wrap:normal}
.id-short{font:11.5px/1.5 "JetBrains Mono",Consolas,monospace;color:var(--ink);white-space:nowrap}
.id-short:hover{text-decoration:underline}
.copy-btn{border:1px solid var(--line);background:var(--surface);color:var(--muted);border-radius:var(--r-xs);font-size:10px;
  padding:0 5px;cursor:pointer;margin-left:5px}
.copy-btn:hover{color:var(--accent);border-color:#99f6e4}
.token-cell{font:11.5px/1.5 "JetBrains Mono",Consolas,monospace;white-space:nowrap;color:var(--ink)}
.token-cell small{display:block;color:var(--muted);font-size:10px}
.report-link{font-size:12px}
.pill::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.pill.ok{background:var(--ok-soft);color:var(--ok)}.pill.bad{background:var(--bad-soft);color:var(--bad)}
.pill.warn{background:var(--warn-soft);color:var(--warn)}.pill.info{background:var(--info-soft);color:var(--info)}
.pill.violet{background:var(--violet-soft);color:var(--violet)}.pill.muted{background:#f3f4f6;color:var(--muted)}
.mono{font-family:"JetBrains Mono",Consolas,monospace;font-size:12px}
.muted{color:var(--muted)}
.btn{display:inline-flex;align-items:center;gap:6px;border:0;background:var(--grad);color:#fff;padding:8px 18px;border-radius:var(--r-sm);font-weight:600;font-size:13px;cursor:pointer;box-shadow:0 4px 14px rgba(13,148,136,.30);transition:transform .15s,box-shadow .15s}
.btn:hover{transform:translateY(-1px);box-shadow:0 7px 20px rgba(13,148,136,.40)}
.btn.ghost{background:var(--surface);color:var(--accent);border:1px solid #99f6e4;box-shadow:none}
.btn.small{padding:3px 11px;font-size:12px;border-radius:var(--r-xs)}
.btn.warn{background:var(--surface);color:var(--bad);border-color:var(--bad);box-shadow:none}
.btn:disabled{opacity:.5;cursor:default}
input,select,textarea{font:inherit;border:1px solid var(--line);border-radius:var(--r-sm);padding:8px 11px;background:var(--surface);width:100%;transition:border .15s,box-shadow .15s}
input:focus,select:focus,textarea:focus{outline:none;border-color:#5eead4;box-shadow:0 0 0 3px var(--accent-soft)}
textarea{font:12px/1.55 Consolas,monospace;min-height:110px}
label{font-size:12px;color:var(--muted);display:block;margin:8px 0 4px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:11px;color:var(--muted);font-weight:600;padding:8px 10px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:9px 10px;border-bottom:1px solid #f1f2f6;vertical-align:middle}
tr:hover td{background:#f2fbfa}
.banner{display:flex;align-items:center;gap:10px;border-radius:var(--radius);padding:10px 16px;margin-bottom:16px;font-weight:600;font-size:13px}
.banner.violet{background:var(--violet-soft);border:1px solid #ddd6fe;color:var(--violet)}
.banner.red{background:var(--bad-soft);border:1px solid #fecaca;color:var(--bad)}
.banner.amber{background:var(--warn-soft);border:1px solid #fde68a;color:#92400e}
.layout3{display:grid;grid-template-columns:250px minmax(0,1fr) 300px;gap:16px;align-items:start}
@media(max-width:1100px){.layout3{grid-template-columns:1fr}.kpis{grid-template-columns:repeat(2,1fr)}}
.metric{padding:7px 0;border-bottom:1px solid #f1f2f6;font-size:12px}
.metric small{color:var(--muted);display:block}.metric b{font-size:13px;word-break:break-all}
.round{position:relative;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:12px 16px;margin:0 0 12px 22px;box-shadow:var(--shadow)}
.round::before{content:"";position:absolute;left:-17px;top:18px;width:10px;height:10px;border-radius:50%;background:var(--grad);box-shadow:0 0 0 3px var(--accent-soft)}
.rounds{position:relative}
.rounds::before{content:"";position:absolute;left:6px;top:8px;bottom:8px;width:2px;background:var(--line)}
.round h3{margin:0 0 4px;font-size:13px;color:var(--accent)}
.obs{margin:0 0 8px;font-weight:600;font-size:13.5px}
details.entry{border:1px solid var(--line);border-radius:var(--r-sm);background:#fbfbfd;margin:6px 0;padding:6px 10px;font-size:12px}
details.entry summary{cursor:pointer;display:flex;gap:8px;align-items:baseline}
.tag{font:700 10px/1.6 Consolas,monospace;color:#0f766e;background:#ccfbf1;border-radius:var(--r-xs);padding:1px 7px;white-space:nowrap}
.tag.tool{background:var(--ok-soft);color:var(--ok)}.tag.tool_error{background:var(--bad-soft);color:var(--bad)}
.tag.validation{background:var(--warn-soft);color:var(--warn)}.tag.knowledge{background:#ecfdf5;color:var(--ok)}
.tag.debug{background:var(--violet-soft);color:var(--violet)}
details.entry pre{white-space:pre-wrap;overflow-wrap:anywhere;font:11px/1.55 Consolas,monospace;color:#374151;max-height:240px;overflow:auto;margin:6px 0 2px}
.refs{color:var(--muted);font-size:11px;margin-top:3px}
.evref{margin-right:8px}
.wf{height:6px;border-radius:var(--r-xs);background:var(--info-soft);margin:3px 0 2px;position:relative}
.wf i{position:absolute;left:0;top:0;height:100%;border-radius:var(--r-xs);background:linear-gradient(90deg,#0d9488,#0891b2);opacity:.8;min-width:2px}
.know{font-size:12px;border-left:3px solid var(--ok);padding:5px 9px;margin:6px 0;background:var(--surface);border-radius:0 8px 8px 0}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;margin:6px 0}
.form-grid label{display:flex;flex-direction:column;gap:5px;font-size:12px;color:var(--muted)}
.form-grid input,.form-grid select{padding:7px 10px;border:1px solid var(--line);border-radius:var(--r-sm);font-size:13px;background:#fff;color:var(--ink)}
.form-checks{display:flex;gap:18px;flex-wrap:wrap;margin:10px 0 0}
.form-checks label.chk{display:flex;align-items:center;gap:6px;font-size:13px;color:var(--ink);cursor:pointer}
.know-head{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:4px}
.know-item{padding:2px 0 2px 4px;line-height:1.5;word-break:break-all}
.know-note{padding:2px 0 2px 4px;color:var(--muted);line-height:1.4}
.livecard{border:1px solid #99f6e4;background:var(--accent-soft);padding:6px 10px;margin:6px 0;font-size:12px;border-radius:var(--r-sm);animation:fade .3s ease}
@keyframes fade{from{opacity:0;transform:translateY(4px)}}
.righttabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-bottom:10px}
.righttabs button{border:0;background:none;padding:6px 12px;font-size:12.5px;color:var(--muted);cursor:pointer;border-bottom:2px solid transparent;font-weight:600}
.righttabs button.on{color:var(--accent);border-bottom-color:var(--accent)}
.tabpane{display:none}.tabpane.on{display:block}
.cp{border:1px solid var(--line);border-radius:var(--r-sm);background:var(--surface);padding:7px 10px;margin:6px 0;font-size:11.5px}
.cp .row{display:flex;justify-content:space-between;gap:8px;align-items:center}
.cp .mono{color:var(--muted);font-size:10px}
.ev{border:1px solid var(--line);border-radius:var(--r-sm);background:#fbfbfd;padding:7px 10px;margin:7px 0;font-size:11.5px}
.ev pre{white-space:pre-wrap;overflow-wrap:anywhere;font:10.5px/1.5 Consolas,monospace;max-height:220px;overflow:auto;margin:4px 0 0}
.verdict{display:flex;align-items:center;gap:12px;margin:4px 0 8px}
.verdict .lvl{font-size:20px;font-weight:800}
.lvl.confirmed_malicious,.lvl.likely_malicious{color:var(--bad)}
.lvl.suspicious{color:var(--warn)}.lvl.insufficient_evidence{color:var(--muted)}
.lvl.likely_benign,.lvl.benign{color:var(--ok)}
.report-sec{font-size:12px;margin-top:8px}
.report-sec h4{font-size:11px;color:var(--muted);margin:10px 0 4px;font-weight:600}
.ev-item{border:1px solid var(--line);border-radius:var(--r-sm);padding:7px 10px;margin:5px 0;font-size:12px;background:#fbfbfd}
.action-item{border-left:3px solid var(--accent);border-radius:0 9px 9px 0;background:#fbfbfd;padding:7px 10px;margin:6px 0;font-size:12px}
.fallback-warn{background:var(--warn-soft);border:1px solid #fde68a;color:#92400e;border-radius:var(--r-sm);padding:8px 12px;font-size:12px;margin:6px 0}
.empty{display:flex;flex-direction:column;align-items:center;gap:8px;padding:36px 20px;text-align:center}
.empty .ico{width:46px;height:46px;border-radius:var(--r-lg);background:var(--accent-soft);color:var(--accent);
  display:flex;align-items:center;justify-content:center}
.empty .ico svg{width:22px;height:22px}
.empty b{font-size:14px}.empty p{margin:0;font-size:12.5px;color:var(--muted);max-width:460px}
.errbar{display:flex;align-items:center;gap:10px;background:var(--bad-soft);border:1px solid #fecaca;
  color:var(--bad);border-radius:var(--radius);padding:10px 14px;margin-bottom:12px;font-size:12.5px}
.skel{height:14px;border-radius:var(--r-xs);background:linear-gradient(90deg,#eef0f3 25%,#f6f7f8 37%,#eef0f3 63%);background-size:400% 100%;animation:sk 1.2s ease infinite;margin:8px 0}
@keyframes sk{0%{background-position:100% 0}100%{background-position:0 0}}
#toasts{position:fixed;right:18px;bottom:18px;z-index:99;display:flex;flex-direction:column;gap:8px}
.toast{background:#0f172a;color:#f9fafb;border-radius:var(--r-md);padding:10px 16px;font-size:13px;box-shadow:var(--shadow-lift);animation:fade .25s ease;max-width:420px}
.toast.ok{background:linear-gradient(135deg,#065f46,#059669)}.toast.bad{background:linear-gradient(135deg,#7f1d1d,#dc2626)}
#modal{position:fixed;inset:0;background:rgba(15,23,42,.45);backdrop-filter:blur(3px);z-index:98;display:none;align-items:center;justify-content:center}
#modal.on{display:flex}
#modal .box{background:var(--surface);border-radius:var(--r-lg);padding:20px 22px;max-width:460px;width:92%;box-shadow:0 24px 70px rgba(0,0,0,.32)}
#modal h3{margin:0 0 8px;font-size:15px}#modal p{margin:0 0 14px;font-size:13px;color:var(--muted)}
#modal .row{display:flex;gap:8px;justify-content:flex-end}
.pager{display:flex;gap:6px;align-items:center;margin-top:10px;font-size:12px;color:var(--muted)}
.pager button{border:1px solid var(--line);background:var(--surface);border-radius:var(--r-xs);padding:2px 9px;cursor:pointer;font-size:12px}
.pager button:disabled{opacity:.4;cursor:default}
/* ---------- report & response plan ---------- */
.verdict-hero{display:flex;justify-content:space-between;align-items:center;gap:16px;flex-wrap:wrap;
  border-radius:var(--r-md);padding:16px 18px;margin:0 0 14px;border:1px solid var(--line);
  border-left:5px solid var(--muted);background:linear-gradient(90deg,#fbfbfd,#fff)}
.verdict-hero.bad{border-left-color:var(--bad);background:linear-gradient(90deg,var(--bad-soft),#fff 70%)}
.verdict-hero.warn{border-left-color:var(--warn);background:linear-gradient(90deg,var(--warn-soft),#fff 70%)}
.verdict-hero.ok{border-left-color:var(--ok);background:linear-gradient(90deg,var(--ok-soft),#fff 70%)}
.verdict-hero .vh-label{display:block;font-size:11px;letter-spacing:.1em;color:var(--muted);margin-bottom:2px}
.verdict-hero .vh-level{font-size:26px;font-weight:800;line-height:1.15}
.vh-level.confirmed_malicious,.vh-level.likely_malicious{color:var(--bad)}
.vh-level.suspicious{color:var(--warn)}
.vh-level.likely_benign,.vh-level.benign{color:var(--ok)}
.vh-level.insufficient_evidence{color:var(--muted)}
.verdict-hero .vh-side{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.report-sec h4{font-size:12.5px;color:var(--ink);margin:18px 0 8px;display:flex;align-items:center;gap:8px}
.report-sec h4 .bar{width:3px;height:13px;border-radius:2px;background:var(--grad);display:inline-block}
.report-sec h4 .hint{font-weight:400}
.lead-text{margin:0;font-size:14px;line-height:1.85;color:#1f2937}
.stat-row{display:flex;gap:10px;flex-wrap:wrap}
.stat{flex:1 1 120px;border:1px solid var(--line);border-radius:var(--r-sm);padding:10px 12px;background:#fbfbfd}
.stat b{display:block;font-size:19px;font-weight:700;line-height:1.2}
.stat small{color:var(--muted);font-size:11px}
.limit-list{margin:10px 0 0;padding-left:16px;font-size:12.5px;color:#4b5563}
.limit-list li{margin:3px 0}
.ev-list{display:flex;flex-direction:column;gap:8px}
.ev-card{display:flex;gap:11px;border:1px solid var(--line);border-radius:var(--r-sm);padding:11px 13px;background:#fff}
.ev-card:hover{border-color:#cbd5e1}
.ev-idx{flex:0 0 22px;height:22px;border-radius:6px;background:var(--accent-soft);color:var(--accent);
  font-size:11.5px;font-weight:800;display:flex;align-items:center;justify-content:center}
.ev-card .ev-body{min-width:0;flex:1}
.ev-card .ev-text{margin:0;font-size:13px;line-height:1.7}
.ev-card .ev-refs{margin-top:6px;display:flex;gap:6px;flex-wrap:wrap}
.ev-card .ev-refs a{font:11px/1.6 "JetBrains Mono",Consolas,monospace;border:1px solid #cffafe;
  background:var(--info-soft);color:var(--info);border-radius:5px;padding:0 6px}
.plan-section{margin-top:20px;padding-top:4px;border-top:1px solid var(--line)}
.plan-list{display:flex;flex-direction:column;gap:9px}
.plan-card{border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:var(--r-sm);
  padding:12px 14px;background:#fff}
.plan-card.lead{border-left-color:var(--warn)}
.plan-head{display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.plan-idx{flex:0 0 20px;height:20px;border-radius:6px;background:var(--accent);color:#fff;font-size:11px;
  font-weight:800;display:flex;align-items:center;justify-content:center}
.plan-head b{font-size:13.5px}
.plan-why{margin:7px 0 0;font-size:12.5px;color:#374151;line-height:1.7}
.plan-impact{margin-top:7px;font-size:11.5px;color:var(--muted);display:flex;gap:6px;align-items:baseline}
.plan-impact b{color:#4b5563;font-weight:600}
.plan-foot{margin-top:11px;font-size:11.5px;color:var(--muted)}
.top-actions{display:flex;align-items:center;gap:14px}
.bell{position:relative;width:34px;height:34px;border-radius:var(--r-sm);border:1px solid var(--line);background:var(--surface);display:flex;align-items:center;justify-content:center;cursor:pointer;color:var(--muted)}
.bell:hover{color:var(--accent);border-color:#99f6e4}
.bell svg{width:16px;height:16px}
.bell .dot{position:absolute;top:-4px;right:-4px;background:linear-gradient(135deg,#f43f5e,#ef4444);color:#fff;font-size:9.5px;font-weight:700;border-radius:999px;padding:0 5px;min-width:16px;text-align:center}
.user-chip{display:flex;align-items:center;gap:8px;font-size:12.5px;font-weight:600}
.user-chip .avatar{width:30px;height:30px;border-radius:50%;background:var(--grad);color:#fff;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700}
.evcard{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden;transition:box-shadow .2s,transform .2s;display:flex;flex-direction:column}
.evcard:hover{box-shadow:var(--shadow-lift);transform:translateY(-2px)}
.evcard .sev{height:4px}
.evcard .body{padding:14px 16px;display:flex;flex-direction:column;gap:6px;flex:1}
.evcard .file{font-size:13.5px;font-weight:700;word-break:break-all}
.evcard .meta{display:flex;gap:10px;flex-wrap:wrap;font-size:11.5px;color:var(--muted)}
.evcard .foot{display:flex;justify-content:space-between;align-items:center;padding:10px 16px;border-top:1px solid var(--line);background:#fbfbfd}
.evgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(330px,1fr));gap:14px}
.field-table{width:100%;font-size:12.5px}
.field-table td{padding:6px 8px}
.field-table td:first-child{color:var(--muted);width:130px}
"""

BASE_JS = r"""
const $=id=>document.getElementById(id);
const esc=v=>{const d=document.createElement('span');d.textContent=String(v??'');return d.innerHTML};
const STATUS_ZH=__STATUS_ZH__;
const zhStatus=s=>STATUS_ZH[s]||s;
const PILL={queued:'info',running:'warn',awaiting_approval:'violet',completed:'ok',failed:'bad'};
const SEV={'confirmed_malicious':'#dc2626','likely_malicious':'#ea580c','suspicious':'#d97706',
  'likely_benign':'#0891b2','benign':'#16a34a','insufficient_evidence':'#94a3b8'};


const pill=s=>'<span class="pill '+(PILL[s]||'muted')+'">'+zhStatus(s)+'</span>';
const VZ=__VERDICT_ZH__;const VP=__VERDICT_PILL__;
const verdictPill=v=>'<span class="pill '+(VP[v]||'muted')+'">'+(VZ[v]||esc(v))+'</span>';
const AZ=__ACTION_ZH__;
const AT=__ACTION_TYPES_ZH__;
function relTime(iso){if(!iso)return '—';const t=new Date(iso);const s=(Date.now()-t.getTime())/1000;
  if(isNaN(s))return iso;if(s<60)return '刚刚';if(s<3600)return Math.floor(s/60)+' 分钟前';
  if(s<86400)return Math.floor(s/3600)+' 小时前';return Math.floor(s/86400)+' 天前';}
function absTime(iso){return (iso||'').replace('T',' ').slice(0,19)}
function fmtDur(ms){if(ms==null)return '—';if(ms<1000)return Math.round(ms)+'ms';return (ms/1000).toFixed(1)+'s'}
function toast(msg,type){const box=document.getElementById('toasts')||(function(){const b=document.createElement('div');b.id='toasts';document.body.appendChild(b);return b})();
  const t=document.createElement('div');t.className='toast '+(type||'');t.innerHTML=msg;box.appendChild(t);
  setTimeout(()=>t.remove(),type==='bad'?6000:3500);}
function confirmModal(title,body,onOk){
  let m=document.getElementById('modal');
  if(!m){m=document.createElement('div');m.id='modal';document.body.appendChild(m);}
  m.innerHTML='<div class="box"><h3>'+esc(title)+'</h3><p>'+body+'</p><div class="row">'
    +'<button class="btn ghost" id="m-cancel">取消</button><button class="btn" id="m-ok">确认</button></div></div>';
  m.classList.add('on');
  m.querySelector('#m-cancel').onclick=()=>m.classList.remove('on');
  m.querySelector('#m-ok').onclick=()=>{m.classList.remove('on');onOk();};
}
async function safeFetch(url,opts){
  try{
    const r=await fetch(url,opts);
    let data=null;try{data=await r.json()}catch(e){}
    if(!r.ok)return {ok:false,status:r.status,error:(data&&data.detail)||('HTTP '+r.status),data};
    return {ok:true,data};
  }catch(e){return {ok:false,status:0,error:String(e)}}
}
const TOOL_ZH=__TOOL_ZH__;
const KIND_ZH=__KIND_ZH__;
const KSTATUS_ZH=__KSTATUS_ZH__;
const STAGE_ZH=__STAGE_ZH__;
const kindZh=k=>KIND_ZH[k]||k;
const stageZh=s=>STAGE_ZH[s]||s||'—';
async function decideApproval(runId,decision){
  const by=document.getElementById('by-'+runId);
  const cm=document.getElementById('cm-'+runId);
  const payload={decision, decided_by:(by&&by.value)||'值班分析师'};
  const comment=cm?cm.value.trim():'';
  if(decision==='respond'&&!comment){toast('驳回必须填写意见','bad');return}
  if(comment)payload.comment=comment;
  if(decision==='edit'){
    try{
      const actions=JSON.parse(document.getElementById('plan-'+runId).value);
      const base=JSON.parse(document.getElementById('planbase-'+runId).value||'{}');
      base.actions=actions;payload.edited_plan=base;
    }catch(e){toast('调整后的动作 JSON 不合法','bad');return}
  }
  const {ok,data,error}=await safeFetch('/api/approvals/'+runId,{method:'POST',
    headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
  if(!ok){toast('决策失败：'+esc(error),'bad');return}
  const labels={accept:'已批准执行',edit:'已调整后批准',respond:'已驳回',ignore:'已搁置'};
  toast(labels[decision]||'已决策','ok');
  const card=document.getElementById('approval-'+runId);
  if(card)card.innerHTML='<h2>已决策</h2><p class="muted">'+(labels[decision]||'已决策')
    +'，处置建议已回灌调查流程。</p>';
}
function emptyState(title,body,cta){
  return '<div class="empty"><div class="ico"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
    +'stroke-width="2" stroke-linecap="round"><path d="M20 6L9 17l-5-5"/></svg></div><b>'+esc(title)+'</b>'
    +(body?'<p>'+body+'</p>':'')+(cta||'')+'</div>';}
function showError(boxId,msg,retryFn){
  const box=document.getElementById(boxId);if(!box)return;
  box.innerHTML='<div class="errbar"><span>数据加载失败：'+esc(msg)+'</span></div>';
  const bar=box.querySelector('.errbar');
  const btn=document.createElement('button');
  btn.className='btn ghost small';btn.style.marginLeft='auto';btn.textContent='重试';
  btn.onclick=()=>{box.innerHTML='';retryFn();};
  bar.appendChild(btn);
}
function shortId(v){v=String(v||'');return v.length<=14?v:v.slice(0,10)+'…'+v.slice(-3);}
function idCell(v){if(!v)return '—';v=String(v);
  return '<span class="id-short" title="'+esc(v)+'">'+esc(shortId(v))+'</span>'
    +'<button class="copy-btn" onclick="copyText(\''+esc(v)+'\',event)" title="复制完整 ID">复制</button>';}
function copyText(v,ev){if(ev)ev.stopPropagation();
  (navigator.clipboard?navigator.clipboard.writeText(v):Promise.reject()).then(()=>toast('已复制','ok'),()=>toast('复制失败','bad'));}
function tokenCell(u){if(!u||!Object.keys(u).length)return '<span class="muted">—</span>';
  const i=u.input_tokens??u.prompt_tokens??0,out=u.output_tokens??u.completion_tokens??0;
  const k=n=>n>=1000?(n/1000).toFixed(1)+'k':String(n);
  return '<span class="token-cell">'+k(i)+' / '+k(out)+'<small>输入 / 输出</small></span>';}
function pager(total,page,per,render){
  const pages=Math.max(1,Math.ceil(total/per));const p=Math.min(page,pages);
  const bar=document.createElement('div');bar.className='pager';
  bar.innerHTML='<button '+(p<=1?'disabled':'')+'>‹ 上一页</button><span>第 '+p+' / '+pages+' 页 · 共 '+total+' 条</span><button '+(p>=pages?'disabled':'')+'>下一页 ›</button>';
  const [prev,next]=bar.querySelectorAll('button');
  prev.onclick=()=>render(p-1);next.onclick=()=>render(p+1);
  return bar;
}
"""


def shell(title: str, active: str, content: str, sub: str = "", approvals_count: int | None = None) -> str:
    icons = {
        "events": '<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>',
        "data": '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
        "workbench": '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
        "cases": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
        "approvals": '<path d="M16 11l4 4-4 4M8 5L4 9l4 4"/>',
        "audit": '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
        "kb": '<path d="M4 19.5A2.5 2.5 0 016.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 014 19.5v-15A2.5 2.5 0 016.5 2z"/>',
        "eval": '<path d="M9 3h6M10 3v6l-5 8.5A2 2 0 006.7 21h10.6a2 2 0 001.7-3L14 9V3"/>',
        "skills": '<path d="M12 20h9M16.5 3.5a2.12 2.12 0 013 3L7 19l-4 1 1-4z"/>',
        "demo": '<polygon points="5 3 19 12 5 21 5 3"/>',
    }

    def svg(key):
        path = icons.get(key, icons["workbench"])
        return ('<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" '
                'stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + path + "</svg>")

    def nav_item(href, ico, label, key, count=None, soon=False):
        cls = "active" if key == active else ("soon" if soon else "")
        badge = f'<span class="count">{count}</span>' if count else ""
        return f'<a href="{href}" class="{cls}"><span class="ico">{svg(key)}</span>{label}{badge}</a>'

    approval_badge = approvals_count if (approvals_count and approvals_count > 0) else None
    nav = "".join([
        '<div class="sep">输入</div>',
        nav_item("/workbench/events", "⚡", "安全事件", "events"),
        nav_item("/workbench/data", "⛁", "数据浏览", "data"),
        '<div class="sep">调查</div>',
        nav_item("/workbench", "▦", "调查中心", "workbench"),
        nav_item("/workbench/cases", "🛡", "案件档案", "cases"),
        nav_item("/workbench/approvals", "⚖", "审批台", "approvals", count=approval_badge),
        '<div class="sep">运营</div>',
        nav_item("/workbench/audit", "☰", "审计日志", "audit"),
        nav_item("/workbench/knowledge", "◈", "知识库", "kb"),
        nav_item("#", "⚗", "评测基线", "eval", soon=True),
        nav_item("#", "✎", "调查技能", "skills", soon=True),
        '<div class="sep">其他</div>',
        nav_item("/workbench/settings", "⚙", "设置", "settings"),
    ])
    base = (
        BASE_JS
        .replace("__STATUS_ZH__", _json.dumps(STATUS_ZH, ensure_ascii=False))
        .replace("__VERDICT_ZH__", _json.dumps(VERDICT_ZH, ensure_ascii=False))
        .replace("__VERDICT_PILL__", _json.dumps(VERDICT_PILL, ensure_ascii=False))
        .replace("__ACTION_ZH__", _json.dumps(ACTION_ZH, ensure_ascii=False))
        .replace("__ACTION_TYPES_ZH__", _json.dumps(ACTION_TYPES_ZH, ensure_ascii=False))
        .replace("__TOOL_ZH__", _json.dumps(TOOL_ZH, ensure_ascii=False))
        .replace("__KIND_ZH__", _json.dumps(KIND_ZH, ensure_ascii=False))
        .replace("__KSTATUS_ZH__", _json.dumps(KNOWLEDGE_STATUS_ZH, ensure_ascii=False))
        .replace("__STAGE_ZH__", _json.dumps(STAGE_ZH, ensure_ascii=False))
    )
    # Shared JS must load BEFORE page scripts: page templates call
    # safeFetch/$/toast immediately, so late-registered consts would be in
    # their temporal dead zone and every page would silently fail to render.
    bell = ""
    if approvals_count:
        bell = ('<a class="bell" href="/workbench/approvals" title="待审批">'
                '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
                'stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/>'
                '<path d="M13.73 21a2 2 0 01-3.46 0"/></svg>'
                f'<span class="dot">{approvals_count}</span></a>')
    else:
        bell = ('<a class="bell" href="/workbench/approvals" title="通知">'
                '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" '
                'stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/>'
                '<path d="M13.73 21a2 2 0 01-3.46 0"/></svg></a>')
    return (
        '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{title}</title><style>{CSS}</style></head><body>"
        '<div id="toasts"></div>'
        + "<script>" + base + "</script>"
        + "<script>document.addEventListener('click',e=>{const m=document.getElementById('modal');"
        "if(m&&m.classList.contains('on')&&e.target===m)m.classList.remove('on')});</script>"
        + '<nav class="sidebar">'
        '<div class="brand"><div class="logo-chip"><svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>'
        '<div class="name"><b>SecAgent 工作台</b><span>UNKNOWN FILE THREAT</span></div></div>'
        f'<div class="nav">{nav}</div><div class="foot">AI 安全研判引擎 · 本机运行</div></nav>'
        '<div class="main"><div class="topbar"><h1>' + title + "</h1>"
        + (f'<div class="sub">{sub}</div>' if sub else "")
        + '<div class="top-actions">' + bell
        + '<div class="user-chip"><div class="avatar">A</div>值班分析师</div></div></div>'
        + '<div class="content">' + content
        + "</div></div></body></html>"
    )


def render_workbench(pending_count: int | None) -> str:
    body = r"""
<div class="hero">
  <div><h2 id="greet">SecAgent 安全研判引擎</h2>
  <p>从种子事件或告警发起调查 · AI 逐轮研判 · 关键决策交给你审批</p></div>
  <div class="chips">
    <a class="chip" href="/workbench/events">⚡ 查看种子事件</a>
    <a class="chip" href="/workbench/approvals">⚖ 审批台</a>
    <a class="chip" href="/workbench/knowledge">◈ 知识库</a>
  </div>
</div>
<div id="errbox"></div>
<div class="kpis" id="kpis"></div>
<div class="card"><h2>调查任务
  <span class="hint" id="refresh-hint"></span>
  <span style="margin-left:auto;display:flex;gap:8px;align-items:center">
    <input id="q" placeholder="搜索 run / 来源 / 状态" style="width:220px;padding:4px 10px" oninput="page=1;renderTable()">
    <button class="btn ghost small" id="pause" onclick="togglePause()">暂停刷新</button>
  </span></h2>
  <table><thead><tr><th>调查任务</th><th>来源 / 证据范围</th><th>状态</th><th>阶段</th><th>Token</th><th>报告</th><th style="width:150px">操作</th></tr></thead>
  <tbody id="runs"><tr><td colspan="7"><div class="skel"></div><div class="skel"></div><div class="skel"></div></td></tr></tbody></table>
  <div id="pager"></div>
  <div id="cmpbar" style="display:flex;gap:8px;align-items:center;margin-top:8px;font-size:12px"></div>
</div>
<div class="card"><h2>待办</h2><p id="approval-line" class="muted">加载中…</p></div>
<script>
let runs=[],page=1,per=8,paused=false,picked=[];
function togglePick(id,el){
  if(el.checked){if(!picked.includes(id))picked.push(id);picked=picked.slice(-2);}
  else picked=picked.filter(x=>x!==id);
  renderTable();
}
function goCompare(){
  if(picked.length!==2){toast('请勾选两次调查','bad');return}
  location.href='/workbench/compare?a='+encodeURIComponent(picked[0])+'&b='+encodeURIComponent(picked[1]);
}
function renderTable(){
  const q=($('q').value||'').toLowerCase();
  const rows=runs.filter(it=>!q||JSON.stringify(it).toLowerCase().includes(q));
  const slice=rows.slice((page-1)*per,page*per);
  $('runs').innerHTML=slice.map(it=>{
    const run=it.run;
    return '<tr><td><input type="checkbox" style="width:auto;margin-right:6px" '
      +(picked.includes(run.run_id)?'checked':'')+' onclick="togglePick(\''+run.run_id+'\',this)">'
      +'<a class="id-short" href="/workbench/runs/'+run.run_id+'">'+esc(shortId(run.run_id))+'</a>'
      +'<br><span class="muted" style="font-size:10.5px">'+relTime(run.started_at)+'</span></td>'
      +'<td>'+esc(it.source_label||'手工告警')+'<span class="muted"> · '+esc(it.profile_label||'—')+'</span></td>'
      +'<td>'+pill(run.status)+'</td><td>'+esc(it.stage_label||run.stage)+'</td>'
      +'<td>'+tokenCell(it.token_usage)+'</td>'
      +'<td>'+(run.report_id?'<a class="report-link" href="/workbench/runs/'+run.run_id+'">查看报告</a>':'<span class="muted">—</span>')+'</td>'
      +'<td>'+(run.status!=='running'&&run.status!=='queued'
        ?'<button class="btn ghost small" onclick="replay(event,\''+run.run_id+'\')">重放</button>':'')
      +(run.status==='awaiting_approval'?' <a class="btn small" href="/workbench/approvals">审批</a>':'')
      +'</td></tr>';
  }).join('')||('<tr><td colspan="7">'+emptyState('还没有调查任务',
    '到 <a href="/workbench/events">安全事件</a> 页选择一个事件发起排查，AI 会逐轮调查。')+'</td></tr>');
  $('pager').innerHTML='';$('pager').appendChild(pager(rows.length,page,per,p=>{page=p;renderTable()}));
  picked=picked.filter(id=>runs.some(r=>r.run.run_id===id));
  const cb=document.getElementById('cmpbar');
  if(cb)cb.innerHTML=picked.length===2
    ?('<span>已选 2 次调查</span> <button class="btn small" onclick="goCompare()">对比选中</button>'
      +' <button class="btn ghost small" onclick="picked=[];renderTable()">清空</button>')
    :'<span class="muted">勾选两次调查可对比结论与成本</span>';
}
async function loadRuns(){
  const {ok,data,error}=await safeFetch('/api/runs');
  if(!ok){showError('errbox',error,loadRuns);return}
  const eb=document.getElementById('errbox');if(eb)eb.innerHTML='';
  runs=data.runs||[];
  const c=k=>runs.filter(x=>x.run.status===k).length;
  $('kpis').innerHTML=
    '<div class="kpi"><small>总运行</small><b>'+runs.length+'</b></div>'+
    '<div class="kpi"><small>已完成</small><b style="color:var(--ok)">'+c('completed')+'</b></div>'+
    '<div class="kpi"><small>失败</small><b style="color:var(--bad)">'+c('failed')+'</b></div>'+
    '<div class="kpi"><small>待审批</small><b style="color:var(--violet)">'+c('awaiting_approval')+'</b></div>';
  renderTable();
  const ap=await (await fetch('/api/approvals')).json();
  const n=(ap.approvals||[]).length;
  $('approval-line').innerHTML=n?('有 <b>'+n+'</b> 项处置方案待审批 → <a href="/workbench/approvals">进入审批台</a>'):'当前没有待审批的处置方案。';
}
function replay(ev,id){
  confirmModal('重放运行','将为 <span class="mono">'+id+'</span> 产生一条新运行（当前代码与配置重跑，原运行保留）。',async()=>{
    const {ok,data,error}=await safeFetch('/api/runs/'+id+'/replay',{method:'POST'});
    if(ok){toast('已重放为 <span class="mono">'+data.run_id+'</span>','ok');loadRuns()}
    else toast('重放失败：'+esc(error),'bad');
  });
}
function togglePause(){paused=!paused;$('pause').textContent=paused?'恢复刷新':'暂停刷新';}
let lastTick=0;
setInterval(()=>{if(!paused){loadRuns();lastTick=Date.now();}},4000);
setInterval(()=>{const h=document.getElementById('refresh-hint');
  if(h&&lastTick)h.textContent='· 更新于 '+Math.round((Date.now()-lastTick)/1000)+' 秒前';},1000);
loadRuns();
</script>"""
    return shell("调查中心", "workbench", body.strip(),
                 sub="发起 · 监督 · 审批 · 调测", approvals_count=pending_count)


def render_events() -> str:
    body = r"""
<div class="card" style="margin-bottom:14px"><h2>提交新告警 <span class="hint">单条对象或 JSON 数组批量 · 调查后停在审批等待人工决策</span></h2>
  <textarea id="alert" placeholder='{"File_id":"f-1","File_hash":"&lt;sha256&gt;","File_path":"/tmp/.cache/sysupd","Sub_asset":"payment-api-prod-01"}'></textarea>
  <div style="margin-top:10px;display:flex;gap:8px">
    <button class="btn" onclick="startAlert(event)">建案并调查</button>
    <button class="btn ghost" onclick="batchAlert(event)">批量导入</button>
  </div>
</div>
<div id="errbox"></div>
<div class="kpis" id="stats"></div>
<div class="card" style="padding:10px 16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap">
  <input id="fq" placeholder="搜索文件路径、主机" style="max-width:260px" oninput="renderCards()">
  <select id="fsrc" style="width:180px" onchange="renderCards()"><option value="">全部来源</option></select>
  <select id="fstate" style="width:160px" onchange="renderCards()">
    <option value="">全部状态</option><option value="open">待处置</option>
    <option value="done">已排查</option><option value="bad">判定恶意</option>
  </select>
  <span class="muted" id="fcount" style="margin-left:auto;font-size:12px"></span>
</div>
<div class="evgrid" id="cards"><div class="card"><div class="skel"></div><div class="skel"></div></div></div>
<script>
async function startAlert(ev){
  let alert;try{alert=JSON.parse($('alert').value)}catch(e){toast('告警 JSON 不合法','bad');return}
  ev.target.disabled=true;
  const {ok,data,error}=await safeFetch('/api/intake',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({alert})});
  ev.target.disabled=false;
  if(ok){toast('已建案，正在跳转实时调查','ok');location.href='/workbench/runs/'+data.run_id;}
  else toast('失败：'+esc(error),'bad');
  load();
}
async function batchAlert(ev){
  let arr;try{arr=JSON.parse($('alert').value)}catch(e){toast('JSON 不合法','bad');return}
  if(!Array.isArray(arr)){toast('批量导入需要 JSON 数组','bad');return}
  const {ok,data,error}=await safeFetch('/api/intake/batch',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({alerts:arr})});
  if(ok)toast('批量建案 '+data.accepted+' 条'+(data.failed?'，失败 '+data.failed+' 条':''),'ok');
  else toast('失败：'+esc(error),'bad');
  load();
}
let allItems=[];
async function load(){
  const {ok,data,error}=await safeFetch('/api/events');
  if(!ok){showError('errbox',error,load);return}
  const eb=document.getElementById('errbox');if(eb)eb.innerHTML='';
  const items=data.events||[];
    allItems=items;
  const verdictOf=e=>e.verdict||'';
  // Mutually exclusive buckets that add up to the total: a run that published
  // "insufficient evidence" is a decided outcome, not an open one.
  const malicious=items.filter(e=>['confirmed_malicious','likely_malicious'].includes(verdictOf(e))).length;
  const benign=items.filter(e=>['benign','likely_benign'].includes(verdictOf(e))).length;
  const undetermined=items.filter(e=>['suspicious','insufficient_evidence'].includes(verdictOf(e))).length;
  const openCount=items.filter(e=>!verdictOf(e)).length;
  const srcs=[...new Set(items.map(e=>e.source_label||e.source))];
  document.getElementById('fsrc').innerHTML='<option value="">全部来源</option>'
    +srcs.map(x=>'<option>'+esc(x)+'</option>').join('');
  document.getElementById('stats').innerHTML=
    '<div class="kpi"><div class="top"><div class="chip-ico indigo"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></div><small>事件总量</small></div><b>'+items.length+'</b></div>'+
    '<div class="kpi"><div class="top"><div class="chip-ico violet"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/></svg></div><small>未定论</small></div><b style="color:var(--violet)">'+undetermined+'</b></div>'+
    '<div class="kpi"><div class="top"><div class="chip-ico red"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div><small>判定恶意</small></div><b style="color:var(--bad)">'+malicious+'</b></div>'+
    '<div class="kpi"><div class="top"><div class="chip-ico green"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg></div><small>判定良性</small></div><b style="color:var(--ok)">'+benign+'</b></div>'
    +'<div class="kpi"><div class="top"><div class="chip-ico indigo"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/></svg></div><small>待排查</small></div><b>'+openCount+'</b></div>';
  renderCards();
}
function renderCards(){
  const items=allItems||[];
  const q=(document.getElementById('fq').value||'').toLowerCase();
  const src=document.getElementById('fsrc').value;
  const st=document.getElementById('fstate').value;
  const rows=items.filter(e=>{
    if(q&&!((e.file_path||'')+(e.host||'')).toLowerCase().includes(q))return false;
    if(src&&(e.source_label||e.source)!==src)return false;
    if(st==='open'&&e.verdict)return false;
    if(st==='done'&&!e.verdict)return false;
    if(st==='bad'&&!['confirmed_malicious','likely_malicious'].includes(e.verdict||''))return false;
    return true;
  });
  const fc=document.getElementById('fcount');
  if(fc)fc.textContent='显示 '+rows.length+' / '+items.length+' 个事件';
  document.getElementById('cards').innerHTML=rows.map(e=>{
    const v=e.verdict||'';const sev=SEV[v]||'#64748b';
    const vlabel=v?(VZ[v]||v):'未定论';
    return '<div class="evcard"><div class="sev" style="background:'+sev+'"></div>'
    +'<div class="body"><div class="file">'+esc(e.file_path)+'</div>'
    +'<div class="meta"><span>主机 '+esc(e.host)+'</span><span>'+esc(e.source_label||e.source)+'</span></div>'
    +'<div class="meta">'
    +(v?'<span class="pill '+(VP[v]||'muted')+'">'+esc(vlabel)+'</span>':'<span class="pill muted">未定论</span>')
    +(e.data_sources!=null?'<span class="muted" style="font-size:11px">'+e.data_sources+' 类证据可查</span>':'')
    +'</div></div>'
    +'<div class="foot"><span class="muted" style="font-size:11px">'+(e.latest_status?'最近状态 '+zhStatus(e.latest_status):'尚未排查')+'</span>'
    +'<a class="btn small" href="/workbench/events/'+encodeURIComponent(e.event_id)+'">'+(e.verdict?'查看':'去排查')+'</a></div></div>';
  }).join('')||('<div class="card">'+emptyState('没有匹配的安全事件','换个筛选条件，或清空搜索框。')+'</div>');
}
load();
</script>"""
    return shell("安全事件", "events", body.strip(), sub="事件队列 · 从事件发起排查")


def render_event_detail(event_id: str, detail: dict, fields_html: str,
                        sources_html: str, runs_html: str, launch_html: str) -> str:
    def esc(v):
        return _html.escape("" if v is None else str(v))

    title = detail.get("title") or (detail.get("payload") or {}).get("File_path") or "安全事件"
    # "Investigated" means this case actually has runs, not merely that a
    # case id exists (the payload always carries one).
    closed = "尚未排查" not in str(detail.get("runs_html") or "尚未排查")
    badge = detail.get("badge")
    lead = detail.get("lead")


    body = (
        "<div class='grid' style='grid-template-columns:minmax(0,1.5fr) minmax(0,1fr)'>"
        "<div>"
        + "<div class='card'>"
        + ("<div style='display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap'>"
           + (f"<span class='pill violet'>{esc(badge)}</span>" if badge else "")
           + (f"<span class='pill ok'>已闭环</span>" if closed else "<span class='pill warn'>待处置</span>")
           + "</div>")
        + f"<h2 style='font-size:16px;margin:0 0 6px'>{esc(title)}</h2>"
        + (f"<p class='muted' style='margin:0 0 8px;font-size:12.5px'>{esc(lead)}</p>" if lead else "")
        + f"<div class='report-sec'><h4>告警要点</h4>{fields_html}</div>"
        + "<details style='margin-top:10px'><summary class='muted'>原始告警载荷</summary>"
        + "<pre style='white-space:pre-wrap;overflow-wrap:anywhere;font:11px/1.6 Consolas,monospace;"
        + "background:#fbfbfd;border:1px solid var(--line);border-radius:var(--r-sm);padding:10px;"
        + "max-height:280px;overflow:auto;margin-top:8px'>"
        + esc(_json.dumps(detail.get("payload") or {}, ensure_ascii=False, indent=1))
        + "</pre></details></div>"
        + ("<div class='card'><h2>该案件的调查记录</h2>" + runs_html + "</div>" if runs_html else "")
        + "</div>"
        + "<div>"
        + "<div class='card'><h2>可访问数据 <span class='hint'>发起前先看证据在哪</span></h2>" + sources_html + "</div>"
        + "<div class='card'><h2>排查行动</h2>" + launch_html + "</div>"
        + "</div></div>"
    )
    return shell("事件 · " + (esc(title)[:24] or esc(event_id)), "events", body,
                 sub=esc(detail.get("source") or ""))


def render_data_browser(sources: list) -> str:
    import html as _h
    import json as _j

    DOMAIN_ZH = {
        "process": "进程与命令", "network": "网络连接", "socket": "网络收发",
        "file": "文件变更", "service": "系统服务", "package": "软件包来源",
        "asset": "资产基线", "extension": "扩展记录",
    }
    cards = "".join(
        "<div class='card dom-card' data-t='" + _h.escape(item["activity_type"]) + "' "
        "style='margin:0;cursor:pointer' onclick='pick(this.dataset.t)'>"
        "<div style='display:flex;align-items:center;gap:10px'>"
        "<span class='pill info'>"
        + _h.escape(DOMAIN_ZH.get(item["activity_type"], item["activity_type"]))
        + "</span><b style='font-size:20px'>" + str(item["count"]) + "</b>"
        + "<span class='muted' style='font-size:11px'>条记录</span></div>"
        + "<p class='muted' style='margin:6px 0 0;font-size:11px'>"
        + _h.escape(str(item.get("first") or "—"))[:19] + " 起</p></div>"
        for item in sources
    )
    body = (
        "<div id='errbox'></div>"
        "<div class='card'><h2>可访问的安全数据 <span class='hint'>点击数据域查看记录 · 只读</span></h2>"
        "<div class='grid' style='grid-template-columns:repeat(auto-fill,minmax(210px,1fr))'>"
        + (cards or "<p class='muted'>尚未接入任何活动数据</p>") + "</div></div>"
        "<div class='card' id='detail-card' style='display:none'><h2 id='dom-title'></h2>"
        "<div style='display:flex;gap:8px;align-items:center;margin-bottom:10px'>"
        "<input id='q' placeholder='在记录中搜索…' style='max-width:320px' oninput='page=1;render()'>"
        "<span class='muted' id='meta'></span></div>"
        "<div id='records'></div><div id='pager'></div></div>"
        "<script>"
        "const __SOURCES=" + _j.dumps(sources, ensure_ascii=False).replace("</", "<" + chr(92) + "/") + ";"
        "let records=[],cur=null,page=1,per=8;"
        "const DZ=" + _j.dumps(DOMAIN_ZH, ensure_ascii=False) + ";"
        "function esc(v){const d=document.createElement('span');d.textContent=String(v??'');return d.innerHTML}"
        "function pick(t){cur=t;page=1;"
        "document.querySelectorAll('.dom-card').forEach(c=>{c.style.boxShadow=c.dataset.t===t?'var(--shadow-lift)':''});"
        "document.getElementById('detail-card').style.display='block';"
        "document.getElementById('dom-title').textContent='数据域 · '+(DZ[t]||t);loadSamples(t);}"
        "async function loadSamples(t){"
        "const {ok,data,error}=await safeFetch('/api/data/sources/'+encodeURIComponent(t));"
        "if(!ok){showError('errbox',error,()=>loadSamples(t));return}"
        "const eb=document.getElementById('errbox');if(eb)eb.innerHTML='';"
        "records=data.records||[];render();}"
        "function render(){"
        "const q=(document.getElementById('q').value||'').toLowerCase();"
        "const rows=records.filter(r=>!q||JSON.stringify(r).toLowerCase().includes(q));"
        "const slice=rows.slice((page-1)*per,page*per);"
        "document.getElementById('meta').textContent=rows.length+' 条（每页 '+per+'）';"
        "document.getElementById('records').innerHTML=slice.map(r=>{"
        "const entries=Object.entries(r).filter(([k,v])=>typeof v!=='object');"
        "return '<details class=\"ev\"><summary>记录 · '+esc(String(r.observed_at||r.event_id||r.activity_id||'')).slice(0,60)+'</summary>'"
        "+'<table class=\"field-table\">'+entries.map(([k,v])=>'<tr><td>'+esc(k)+'</td><td class=\"mono\">'+esc(String(v).slice(0,180))+'</td></tr>').join('')+'</table>'"
        "+'</details>'}).join('')||emptyState('该数据域没有匹配记录','换个搜索词试试。');"
        "const box=document.getElementById('pager');box.innerHTML='';"
        "box.appendChild(pager(rows.length,page,per,p=>{page=p;render()}));}"
        "</script>"
    )
    return shell("数据浏览", "data", body, sub="我们可访问的安全数据 · 只读")


def render_approvals(pending_count: int) -> str:
    body = r"""
<div id="errbox"></div>
<div id="list"><div class="skel"></div><div class="skel"></div></div>
<script>
async function load(){
  const {ok,data,error}=await safeFetch('/api/approvals');
  if(!ok){showError('errbox',error,load);return}
  const items=data.approvals||[];
  document.getElementById('list').innerHTML = items.length
    ? items.map(it=>it.card_html).join('')
    : '<div class="card">'+emptyState('当前没有待审批的处置方案',
        '当调查产生需要人工确认的处置动作时，会在这里等你决策，并同时在对应调查页内联显示。'
        +'<br>你可以先到 <a href="/workbench/events">安全事件</a> 页发起排查。')+'</div>';
}
load();
</script>"""
    return shell("审批台", "approvals", body.strip(),
                 sub="处置动作由你确认", approvals_count=pending_count)


def render_audit() -> str:
    body = r"""
<div id="errbox"></div>
<div class="card"><h2>审计日志 <span class="hint">全部操作留痕 · 最近 300 条</span></h2>
  <div style="display:flex;gap:8px;align-items:center;margin-bottom:10px;flex-wrap:wrap">
    <select id="action" style="width:200px"><option value="">全部动作</option></select>
    <input id="run" placeholder="按运行 ID 过滤" style="width:220px">
    <input id="q" placeholder="内容搜索" style="width:220px">
    <button class="btn small" onclick="page=1;load()">查询</button>
    <a class="btn ghost small" href="/api/audit/export.csv">导出 CSV</a>
    <span class="muted" id="count"></span>
  </div>
  <table><thead><tr><th>时间</th><th>动作</th><th>资源</th><th>运行</th><th>摘要</th></tr></thead>
  <tbody id="rows"><tr><td colspan="5"><div class="skel"></div></td></tr></tbody></table>
  <div id="pager"></div>
</div>
<script>
let items=[],page=1,per=15;
async function load(){
  const a=document.getElementById('action').value,r=document.getElementById('run').value.trim();
  const q=[];if(a)q.push('action_label='+encodeURIComponent(a));if(r)q.push('run_id='+r);
  const {ok,data,error}=await safeFetch('/api/audit'+(q.length?'?'+q.join('&'):''));
  if(!ok){showError('errbox',error,load);return}
  const eb=document.getElementById('errbox');if(eb)eb.innerHTML='';
  items=data.audit||[];
  document.getElementById('count').textContent='最近 '+items.length+' 条';
  render();
}
function render(){
  const q=(document.getElementById('q').value||'').toLowerCase();
  const rows=items.filter(e=>!q||JSON.stringify(e).toLowerCase().includes(q));
  const slice=rows.slice((page-1)*per,page*per);
  document.getElementById('rows').innerHTML=slice.map(e=>
    '<tr><td class="muted" title="'+absTime(e.created_at)+'">'+relTime(e.created_at)+'</td>'
    +'<td><span class="tag">'+esc(e.action_label||AZ[e.action]||e.action)+'</span></td>'
    +'<td>'+esc(e.resource_label||e.resource_type)+'</td>'
    +'<td><a class="id-short" href="/workbench/runs/'+e.run_id+'" title="'+esc(e.run_id)+'">'+esc(shortId(e.run_id))+'</a></td>'
    +'<td>'+esc(e.result_summary)+'</td></tr>').join('')
    ||('<tr><td colspan="5">'+emptyState('没有匹配的审计记录','换个动作筛选，或清空搜索条件。')+'</td></tr>');
  const box=document.getElementById('pager');box.innerHTML='';
  box.appendChild(pager(rows.length,page,per,p=>{page=p;render()}));
}
(async()=>{const {ok,data}=await safeFetch('/api/audit');
  if(ok){const acts=data.actions||[];
  document.getElementById('action').innerHTML='<option value="">全部动作</option>'+acts.map(a=>'<option>'+esc(a)+'</option>').join('');}})();
load();
</script>"""
    return shell("审计日志", "audit", body.strip(), sub="跨运行留痕 · query_id 贯穿")


def render_cases() -> str:
    body = r"""
<div id="list"><div class="skel"></div><div class="skel"></div></div>
<script>
async function load(){
  const {ok,data,error}=await safeFetch('/api/cases-view');
  if(!ok){toast('加载失败：'+esc(error),'bad');return}
  const items=data.cases||[];
  if(!items.length){document.getElementById('list').innerHTML='<div class="card"><p class="muted">暂无案件</p></div>';return}
  document.getElementById('list').innerHTML=items.map(c=>
    '<div class="card"><h2>案件 <span class="mono">'+esc(c.case_id)+'</span>'
    +(c.verdict?verdictPill(c.verdict):'')
    +(c.publication_status==='fallback'?' <span class="pill warn">兜底发布</span>':'')
    +'</h2><p class="muted">来源 '+esc(c.sources.join('、'))+' · '+c.runs+' 次运行 · 最新运行 <a class="mono" href="/workbench/runs/'+c.latest_run_id+'">'+c.latest_run_id+'</a>（'+esc(zhStatus(c.latest_status))+'）</p></div>'
  ).join('');
}
load();
</script>"""
    return shell("案件档案", "cases", body.strip(), sub="案件为中心 · 跨运行聚合")


def render_knowledge(adapter: str, profile: str | None, catalog: dict | None, stats: dict) -> str:
    def esc(v):
        return _html.escape("" if v is None else str(v))

    if adapter == "reference":
        config_html = (
            "<span class='pill ok'>内置参考语料</span>"
            f" <span class='muted'>档位 {esc(profile)} · 接入内网知识服务后，此处显示真实语料的目录与命中情况</span>"
        )
    elif adapter == "attack":
        count = 0
        if catalog:
            count = sum(
                len(category.get("items", []))
                for category in catalog.get("categories", [])
                if category.get("category") == "attack_technique"
            )
        config_html = (
            "<span class='pill ok'>ATT&amp;CK 真实语料</span>"
            f" <span class='muted'>{count} 条技术 · 词法检索 · 离线构建（scripts/build_attack_corpus.py）· "
            "attack_technique 源走 ATT&amp;CK，其余来源仍为参考语料</span>"
        )
    elif adapter == "null":
        config_html = "<span class='pill muted'>未配置（null）</span> <span class='muted'>运行中的知识咨询将返回 not_configured</span>"
    else:
        config_html = f"<span class='pill info'>{esc(adapter)}</span>"

    cat_html = ""
    if catalog:
        for category in catalog.get("categories", []):
            rows = "".join(
                "<tr><td class='mono'>" + esc(item["knowledge_id"]) + "</td><td>"
                + esc(item["title"]) + "</td><td class='muted'>" + esc(item["summary"])
                + "</td><td>"
                + (
                    "<span class='pill bad'>注入演练样本</span>"
                    if "poison" in str(item.get("knowledge_id") or "")
                    else ("<span class='pill warn'>租户受限</span>"
                          if item.get("restricted_to_tenant") else "—")
                )
                + "</td></tr>"
                for item in category.get("items", [])
            )
            cat_html += (
                "<div class='card'><h2>" + esc(SOURCE_CATEGORY_ZH.get(category["category"], category["category"]))
                + " <span class='hint'>" + str(len(category.get("items", []))) + " 条</span></h2>"
                + "<table><thead><tr><th>知识 ID</th><th>标题</th><th>摘要</th><th>约束</th></tr></thead><tbody>"
                + rows + "</tbody></table></div>"
            )
    else:
        cat_html = "<div class='card'><p class='muted'>当前适配器未暴露语料目录（内网 RAG 接入后自动出现）。</p></div>"

    by_status = stats.get("status_labels") or stats.get("by_status") or {}
    total = stats.get("total", 0)
    configured = adapter in ("reference", "attack")
    mismatch = configured and by_status.get("not_configured", 0) == total and total > 0
    stats_html = (
        "<div class='card'><h2>运行命中统计"
        + ("" if total else " <span class='hint'>尚无运行</span>") + "</h2>"
        + ("<div class='banner amber' style='margin-bottom:10px'>以下统计来自知识源配置生效之前的运行；"
           "发起一次新的调查即可看到 available 命中。</div>" if mismatch else "")
        + "<div class='kpis' style='grid-template-columns:repeat(3,1fr)'>"
        + "<div class='kpi'><small>咨询总数</small><b>" + str(total) + "</b></div>"
        + "<div class='kpi'><small>命中情况</small><b style='font-size:12px;font-weight:600'>"
        + "、".join(esc(k) + " " + str(v) for k, v in (stats.get("status_labels") or {}).items())
        + "</b></div>"
        + "<div class='kpi'><small>涉及知识源</small><b>" + str(len(stats.get("category_labels") or {})) + " 类</b></div></div>"
        + "<table><thead><tr><th>最近检索</th><th>结果</th></tr></thead><tbody>"
        + "".join(
            "<tr><td><a class='id-short' href='/workbench/runs/" + esc(item.get("run_id")) + "'>"
            + esc(str(item.get("run_id") or "")[:10]) + "…</a> · "
            + esc(translate_knowledge_message(item.get("message") or "")) + "</td><td>"
            + esc(item.get("status_label") or item.get("status")) + "</td></tr>"
            for item in stats.get("recent") or []
        )
        + "</tbody></table></div>"
    )
    return shell("知识库", "kb", config_html and (
        "<div class='card'><h2>知识源</h2><p>" + config_html + "</p>"
        "<p class='muted'>每次检索都记录来源与结果状态；某个知识源不可用时会如实标注，不会用空结果冒充“没有相关知识”。</p></div>"
        + stats_html + cat_html), sub="检索来源与命中情况")


def render_compare(a: str, b: str) -> str:
    body = r"""
<div class="card"><h2>调查对比 <span class="hint mono">__A__ ↔ __B__</span></h2>
<div id="errbox"></div>
<div id="cmp"><div class="skel"></div><div class="skel"></div></div></div>
<script>
const A_ID="__A__",B_ID="__B__";
async function load(){
  const [ra,rb]=await Promise.all([safeFetch('/api/runs/'+A_ID),safeFetch('/api/runs/'+B_ID)]);
  if(!ra.ok||!rb.ok){showError('errbox','运行不存在',load);return}
  const A=ra.data,B=rb.data;
  const tok=r=>{const t={};(r.events||[]).forEach(e=>{const u=e.token_usage||{};
    for(const k in u)t[k]=(t[k]||0)+u[k];});return t;};
  const rounds=r=>(r.events||[]).filter(e=>e.details&&e.details.kind==='round').length;
  const lvl=r=>{const v=r.investigation_report&&r.investigation_report.verdict;if(!v)return '<span class="pill muted">未定论</span>';
    const l=v.level&&(v.level.value||v.level)||v.level;return verdictPill(l);};
  const rows=[
    ['状态',pill(A.run.status),pill(B.run.status)],
    ['结论',lvl(A),lvl(B)],
    ['发布状态',esc((A.investigation_report||{}).publication_status||'—'),esc((B.investigation_report||{}).publication_status||'—')],
    ['调查轮次',rounds(A)+' 轮',rounds(B)+' 轮'],
    ['事件数',(A.events||[]).length,(B.events||[]).length],
    ['Token',tokenCell(tok(A)),tokenCell(tok(B))],
    ['执行摘要',esc((A.investigation_report||{}).executive_summary||'—'),esc((B.investigation_report||{}).executive_summary||'—')],
  ];
  document.getElementById('cmp').innerHTML='<table><thead><tr><th>对比项</th><th>'
    +esc(A_ID)+'</th><th>'+esc(B_ID)+'</th></tr></thead><tbody>'
    +rows.map(r=>'<tr><td class="muted">'+r[0]+'</td><td>'+r[1]+'</td><td>'+r[2]+'</td></tr>').join('')
    +'</tbody></table>';
}
load();
</script>"""
    body = body.replace("__A__", _html.escape(a)).replace("__B__", _html.escape(b))
    return shell("调查对比", "workbench", body.strip(), sub="两次调查的结论与成本差异")


def render_run(run_id: str, status: str, case_id: str, rounds_html: str,
               phases_html: str, knowledge_html: str, report_html: str,
               metrics: str, banner: str, pipeline_html: str,
               rounds_count: int = 0, events_count: int = 0,
               inline_approval: str = "", rejections_html: str = "",
               last_seq: int = 0, token_usage: dict | None = None) -> str:
    usage = token_usage or {}
    tok_in = int(usage.get("input_tokens") or usage.get("prompt_tokens") or 0)
    tok_out = int(usage.get("output_tokens") or usage.get("completion_tokens") or 0)
    body = (
        '<div style="margin-bottom:14px">' + banner + "</div>"
        + '<div class="card" style="padding:10px 18px;margin-bottom:14px"><h2>调查流程 <span class="hint" id="stage-hint">'
        + _html.escape(STATUS_ZH.get(status, status)) + "</span></h2>" + pipeline_html + "</div>"
        + '<div class="layout3">'
        + "<div>" + metrics + "</div>"
        + '<div class="rounds"><div class="card" style="padding:12px 16px"><h2>调查进展 <span class="hint" id="live-hint"></span></h2>'
        + '<div id="live"></div>' + inline_approval + rounds_html + "</div>"
        + '<div class="card" style="padding:12px 16px"><h2>阶段事件</h2>' + phases_html + "</div>"
        # The conclusion belongs at the end of the investigation, not in the
        # narrow sidebar: readers follow the stream and expect the verdict there.
        + report_html + "</div>"
        + '<div><div class="card"><div class="righttabs">'
        + '<button class="on" onclick="tab(0,this)">知识</button>'
        + '<button onclick="tab(1,this)">证据回溯</button>'
        + '<button onclick="tab(2,this)">时间旅行</button></div>'
        + '<div class="tabpane on" id="tp0">' + knowledge_html + "</div>"
        + '<div class="tabpane" id="tp1"><p class="muted">点击中栏事件里的证据引用，原始返回显示在这里。</p><div id="assoc"></div></div>'
        + '<div class="tabpane" id="tp2"><p class="hint muted" style="margin:0 0 8px">'
        + "回溯点用于调试：可从任一历史点重放本次调查，正式产物不受影响。</p>"
        + '<div id="cps" class="muted">加载中…</div></div></div>'
        + rejections_html + "</div></div>"
    )
    page = r"""
<script>
const RUN="__RUN_ID__", STATUS="__STATUS__", LAST_SEQ=__LAST_SEQ__;
let liveRounds=__SNAP_ROUNDS__, liveEvents=__SNAP_EVENTS__;
let liveTokIn=__SNAP_TOK_IN__, liveTokOut=__SNAP_TOK_OUT__;
let reloadTimer=null;
function finishPage(){
  // 终态（完成/失败/停靠审批）后整页刷新：右侧面板、轮次明细、报告与
  // 审批卡都是服务端渲染的快照，直播流只覆盖中栏事件流。
  if(reloadTimer)return;reloadTimer=setTimeout(()=>location.reload(),1500);
}
async function checkRunTerminal(){
  if(reloadTimer)return true;
  const {ok,data}=await safeFetch("/api/runs/"+RUN);
  if(!ok)return false;
  const st=((data||{}).run||{}).status;
  if(["completed","failed","awaiting_approval"].includes(st)){finishPage();return true}
  return false;
}
function fmtTok(n){return n>=1000?(n/1000).toFixed(1)+"k":""+n}
function bumpCounters(){
  const r=document.querySelector("[data-metric='rounds']"), e=document.querySelector("[data-metric='events']"), t=document.querySelector("[data-metric='tokens']");
  if(r)r.textContent=liveRounds+" / "+liveEvents;
  if(e)e.textContent=liveEvents;
  if(t)t.textContent=(liveTokIn||liveTokOut)?(fmtTok(liveTokIn)+" / "+fmtTok(liveTokOut)):"—";
}
function tab(i,btn){document.querySelectorAll('.righttabs button').forEach(b=>b.classList.remove('on'));btn.classList.add('on');
  document.querySelectorAll('.tabpane').forEach(p=>p.classList.remove('on'));document.getElementById('tp'+i).classList.add('on');}
document.addEventListener("click", e=>{
  const t=e.target;
  if(t.classList && t.classList.contains("evref")){e.preventDefault();
    document.querySelector('.righttabs button').classList.remove('on');
    document.querySelectorAll('.righttabs button')[1].classList.add('on');
    document.querySelectorAll('.tabpane').forEach(p=>p.classList.remove('on'));
    document.getElementById('tp1').classList.add('on');
    loadEvidence(t.dataset.ref);}
});
async function loadEvidence(ref){
  const box=document.getElementById("assoc");
  box.innerHTML='<p class="muted">查询 '+esc(ref)+' …</p>';
  const {ok,data,error}=await safeFetch("/api/runs/"+RUN+"/evidence/"+encodeURIComponent(ref));
  if(!ok){box.innerHTML='<p class="muted">查询失败：'+esc(error)+'</p>';return}
  box.innerHTML=(data.events||[]).map(ev=>
    '<div class="ev"><b>'+ev.event_type+'</b> · '+esc(ev.details&&ev.details.message||'')+
    '<pre>'+esc(JSON.stringify(ev.details,null,1))+'</pre></div>').join('')||'<p class="muted">无关联事件</p>';
}
if(["running","queued","awaiting_approval"].includes(STATUS)){
  document.getElementById("live-hint").textContent="· 实时";
  const NARRATIVE={round:1,thinking:1,verdict:1,report:1,response:1,approval:1,
    tool:1,tool_error:1,decision:1,run:1,graph:1,error:1,knowledge:1,complete:1};
  let techCount=0;
  // 审批停靠没有对应操作事件（只有审计与状态迁移），轮询状态兜底，
  // 让内联审批卡在停靠后 ~10s 内随整页刷新出现。
  setInterval(()=>{checkRunTerminal()},10000);
  const es=new EventSource("/api/runs/"+RUN+"/events/stream");
  es.onmessage=m=>{
    const ev=JSON.parse(m.data);
    // The initial render already contains everything up to LAST_SEQ; without
    // this the streamed copy would duplicate the snapshot.
    if(ev.sequence&&ev.sequence<=LAST_SEQ)return;
    const d=ev.details||{};
    const kind=d.kind||ev.event_type;
    liveEvents++;
    const tu=d.token_usage||{};
    liveTokIn+=tu.input_tokens||tu.prompt_tokens||0;
    liveTokOut+=tu.output_tokens||tu.completion_tokens||0;
    bumpCounters();
    if(kind==="complete"){finishPage();}
    const lane=document.getElementById("live");
    if(kind==="error"){
      const card=document.createElement("div");card.className="livecard";
      card.style.background="var(--bad-soft)";card.style.borderColor="#fecaca";
      card.innerHTML="<span class='tag error'>失败</span> "+esc(d.error_message||d.message||"")
        +(d.exception_traceback?("<pre style='white-space:pre-wrap;overflow-wrap:anywhere;font:10px/1.5 Consolas,monospace;max-height:200px;overflow:auto;margin-top:6px'>"+esc(d.exception_traceback.slice(-1200))+"</pre>"):"");
      lane.appendChild(card);
      const hint=document.getElementById("stage-hint");if(hint)hint.textContent="失败";
      finishPage();
      return;
    }
    if(kind==="round"){
      // A finished round renders exactly like its persisted counterpart so the
      // streamed timeline and the snapshot share one visual language.
      const card=document.createElement("div");
      card.className="round";card.style.marginLeft="0";
      card.innerHTML="<h3>第 "+esc(d.round||"?")+" 轮</h3><p class='obs'>"+esc(d.observation||d.message||"")+"</p>";
      lane.appendChild(card);
      liveRounds++;bumpCounters();
    } else if(NARRATIVE[kind]){
      const card=document.createElement("div");card.className="livecard";
      const dur=d.duration_ms?" <span class='muted mono' style='font-size:10px'>"+fmtDur(d.duration_ms)+"</span>":"";
      card.innerHTML="<span class='tag "+esc(kind)+"'>"+esc(kindZh(kind))+"</span> "+esc(d.message||"")+dur;
      lane.appendChild(card);
      lane.parentElement.scrollTop=lane.parentElement.scrollHeight;
    } else {
      techCount++;
      let chip=document.getElementById("tech-chip");
      if(!chip){chip=document.createElement("span");chip.id="tech-chip";chip.className="tag muted";
        chip.style.marginLeft="6px";document.getElementById("live-hint").appendChild(chip);}
      chip.textContent="· 技术事件 "+techCount+"（折叠）";
    }
    const hint=document.getElementById("stage-hint");
    if(hint&&ev.stage)hint.textContent=stageZh(ev.stage);
    const bar=document.getElementById("pipeline");
    if(bar){
      const order=bar.dataset.order.split(",");
      let map={};try{map=JSON.parse(bar.dataset.map||"{}")}catch(e){}
      const node=map[ev.stage]||ev.stage;
      const idx=order.indexOf(node);
      bar.querySelectorAll("[data-stage]").forEach(p=>{
        const i=order.indexOf(p.dataset.stage);
        p.className="pill "+(i<idx?"ok":(i===idx?"violet":"muted"));
      });
    }
  };
  es.onerror=()=>{
    document.getElementById("live-hint").textContent="· 实时流结束";
    // 终态则以整页刷新收尾；未终态（长模型调用期间流空闲超时）不 close()，
    // 浏览器原生 EventSource 自动重连续流，LAST_SEQ 去重保证不重复渲染。
    checkRunTerminal();
  };
}
async function loadCheckpoints(){
  const box=document.getElementById("cps");
  const {ok,data,error}=await safeFetch("/api/debug/runs/"+RUN+"/checkpoints");
  if(!ok){box.textContent=esc(error||"该运行暂无可回溯的检查点");return}
  const cps=(data.checkpoints||[]).slice(0,25);
  box.innerHTML=cps.map(c=>
    '<div class="cp"><div class="row"><span>第 '+c.step+' 步 · <b>'+esc(stageZh(c.node)||"完成")+'</b></span>'
    +'<span><button class="btn ghost small" data-cp="'+esc(c.checkpoint_id)+'" data-act="state">查看状态</button> '
    +'<button class="btn ghost small" data-cp="'+esc(c.checkpoint_id)+'" data-act="replay">从此重放</button></span></div>'
    +'<div id="st-'+c.checkpoint_id+'" class="muted" style="margin-top:4px;font-size:11px"></div>'
    +'<span class="mono">'+relTime(c.created_at)+'</span></div>').join('')
    ||"（本次调查没有留下回溯点）";
}
document.addEventListener("click",e=>{
  const b=e.target.closest?e.target.closest("[data-act]"):null;
  if(!b)return;
  if(b.dataset.act==="state")showState(b.dataset.cp);
  else if(b.dataset.act==="replay")resume(b.dataset.cp);
});
async function showState(cp){
  const box=document.getElementById("st-"+cp);
  box.textContent="读取中…";
  const {ok,data,error}=await safeFetch("/api/debug/runs/"+RUN+"/checkpoints/"+cp+"/state");
  if(!ok){box.textContent="状态不可读："+esc(error);return}
  const n=data.node_summaries||{};
  const next=(n.next_nodes||[]).map(stageZh).join("、")||"—";
  box.innerHTML="阶段 <b>"+esc(stageZh(n.lifecycle_status))+"</b> · 报告 "
    +(n.has_report?"已生成":"未生成")+" · 处置方案 "+(n.has_response_plan?"已生成":"未生成")
    +" · 重放将执行 <b>"+esc(next)+"</b>";
}
function resume(cp){
  confirmModal("从 checkpoint 重放","正式产物不受影响；重放事件以 <span class='tag debug'>debug</span> 标记进入事件流。",async()=>{
    const {ok,data,error}=await safeFetch("/api/debug/runs/"+RUN+"/resume",{method:"POST",headers:{'content-type':'application/json'},body:JSON.stringify({checkpoint_id:cp})});
    if(ok){toast("重放已启动，事件将实时进入本页","ok");if(STATUS==="completed")setTimeout(()=>location.reload(),1500);}
    else toast("失败："+esc(error),"bad");
  });
}
loadCheckpoints();
</script>"""
    page = (page.replace("__RUN_ID__", run_id)
                .replace("__STATUS__", status)
                .replace("__LAST_SEQ__", str(last_seq))
                .replace("__SNAP_ROUNDS__", str(rounds_count))
                .replace("__SNAP_EVENTS__", str(events_count))
                .replace("__SNAP_TOK_IN__", str(tok_in))
                .replace("__SNAP_TOK_OUT__", str(tok_out)))
    content = body.strip() + page
    return shell("调查轨迹 · " + run_id, "workbench", content,
                 sub="案件 " + case_id, approvals_count=None)



def render_settings(overview: dict, *, model_service: dict | None = None) -> str:
    def esc(v):
        return _html.escape("" if v is None else str(v))

    rows = "".join(
        f"<div class='metric'><small>{esc(label)}</small><b class='mono'>{esc(value)}</b></div>"
        for label, value in overview.get("items", [])
    )
    knowledge_label = {"reference": "内置参考语料", "attack": "ATT&CK 真实语料", "null": "未接入"}.get(
        str(overview.get("knowledge_adapter")), str(overview.get("knowledge_adapter")))

    # 模型服务配置表单：预填"已保存"值（重启后生效的值），无保存值时回落当前生效值
    ms = model_service or {}
    saved = ms.get("saved") or ms.get("effective") or {}
    effective = ms.get("effective") or {}
    f = {key: esc(saved.get(key, "")) for key in
         ("provider", "base_url", "model_name", "context_window_tokens")}
    f["context_window_tokens"] = f["context_window_tokens"] or "100000"
    chk = lambda key: " checked" if saved.get(key) else ""  # noqa: E731
    drift = ms.get("restart_required")
    drift_banner = (
        "<div class='banner amber' style='margin:0 0 12px'>已保存的配置与当前运行值不同，"
        "重启服务后生效。</div>" if drift else ""
    )
    form = (
        "<div class='card'><h2>模型服务配置 <span class='hint'>保存写入 .env · 重启服务后生效</span></h2>"
        + drift_banner
        + "<div class='form-grid'>"
        + "<label>协议格式<select id='ms-provider'>"
        + "<option value='openai'" + (" selected" if f["provider"] != "anthropic" else "") + ">OpenAI 兼容（/chat/completions）</option>"
        + "<option value='anthropic'" + (" selected" if f["provider"] == "anthropic" else "") + ">Anthropic Messages（/v1/messages）</option>"
        + "</select></label>"
        + "<label>服务地址 Base URL<input id='ms-base-url' class='mono' placeholder='https://api.example.com/v1' value='" + f["base_url"] + "'></label>"
        + "<label>模型 ID<input id='ms-model' class='mono' placeholder='model-name' value='" + f["model_name"] + "'></label>"
        + "<label>上下文窗口（tokens）<input id='ms-ctx' type='number' min='1024' max='1000000' step='1024' class='mono' value='" + f["context_window_tokens"] + "'></label>"
        + "<label>API Key（留空保持不变）<input id='ms-key' type='password' placeholder='不回显 · 留空=不修改'></label>"
        + "</div>"
        + "<div class='form-checks'>"
        + "<label class='chk'><input type='checkbox' id='ms-tls'" + chk("disable_tls_verify") + "> 禁用 TLS 证书校验（自签名证书的内网端点）</label>"
        + "<label class='chk'><input type='checkbox' id='ms-proxy'" + chk("disable_proxy") + "> 禁用系统代理（直连模型端点）</label>"
        + "</div>"
        + "<div style='display:flex;gap:10px;align-items:center;margin-top:12px'>"
        + "<button class='btn primary' id='ms-save'>保存配置</button>"
        + "<span class='muted' id='ms-msg' style='font-size:12px'></span></div>"
        + "<details class='muted' style='margin-top:10px;font-size:12px'><summary>当前生效值（重启前不变）</summary>"
        + "<div class='metric'><small>协议</small><b class='mono'>" + esc(effective.get("provider", "")) + "</b></div>"
        + "<div class='metric'><small>服务地址</small><b class='mono'>" + esc(effective.get("base_url", "")) + "</b></div>"
        + "<div class='metric'><small>模型 ID</small><b class='mono'>" + esc(effective.get("model_name", "")) + "</b></div>"
        + "<div class='metric'><small>上下文窗口</small><b class='mono'>" + esc(effective.get("context_window_tokens", "")) + "</b></div>"
        + "<div class='metric'><small>禁用 TLS 校验 / 禁用代理</small><b>"
        + ("开" if effective.get("disable_tls_verify") else "关") + " / "
        + ("开" if effective.get("disable_proxy") else "关") + "</b></div>"
        + "</details></div>"
    )

    body = (
        form
        + "<div class='card'><h2>研判模型</h2>" + rows + "</div>"
        "<div class='card'><h2>知识源</h2>"
        "<div class='metric'><small>当前状态</small><b>" + esc(knowledge_label)
        + "</b></div>"
        "<p class='muted' style='font-size:12px'>接入组织知识服务后，研判与处置会自动引用其检索结果，"
        "调查流程无需改动。</p></div>"
        "<p class='muted'>模型服务与知识源之外的部分为当前生效配置，由部署方维护。</p>"
    )
    page_script = r"""
<script>
document.addEventListener("click", async e=>{
  if(e.target.id!=="ms-save")return;
  const msg=document.getElementById("ms-msg");
  const payload={
    provider:document.getElementById("ms-provider").value,
    base_url:document.getElementById("ms-base-url").value.trim(),
    model_name:document.getElementById("ms-model").value.trim(),
    context_window_tokens:parseInt(document.getElementById("ms-ctx").value,10),
    disable_tls_verify:document.getElementById("ms-tls").checked,
    disable_proxy:document.getElementById("ms-proxy").checked
  };
  const key=document.getElementById("ms-key").value;
  if(key)payload.api_key=key;
  if(!payload.base_url){msg.textContent="服务地址不能为空";return}
  if(!payload.model_name){msg.textContent="模型 ID 不能为空";return}
  const {ok,data,error}=await safeFetch("/api/settings/model-service",{
    method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(payload)});
  if(!ok){msg.textContent="保存失败："+(error||"");return}
  if(data&&data.validation_error){msg.textContent="校验失败："+data.validation_error;return}
  msg.textContent="已保存 · 重启服务后生效";
  toast("模型服务配置已保存，重启服务后生效");
  setTimeout(()=>location.reload(),1500);
});
</script>"""
    return shell("设置", "settings", body + page_script, sub="模型服务 · 知识源 · 生效配置")
