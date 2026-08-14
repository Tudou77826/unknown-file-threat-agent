from __future__ import annotations

import html
import json

from ...contracts import DemoComparisonReadModel


SOURCE_PRESENTATION = {
    "alert": ("原始告警线索", "原始告警"),
    "edr-process": ("确认文件是否执行", "EDR 进程遥测"),
    "auditd-execve": ("追踪后续命令", "Linux 命令执行审计"),
    "edr-network": ("识别外联目标", "EDR 网络遥测"),
    "ebpf-socket": ("验证双向通信", "eBPF Socket 观测"),
    "auditd-file": ("发现关键文件变更", "Linux 文件变更审计"),
    "package-manager": ("追溯安装行为", "软件包管理记录"),
    "systemd-journal": ("确认系统服务启动", "Systemd 服务日志"),
    "rpm-inventory": ("核验软件包归属与签名", "RPM 软件清单"),
    "cmdb-baseline": ("比对批准资产基线", "CMDB 业务基线"),
}

QUESTION_PRESENTATION = {
    "role-execution": ("执行确认", "这个未知文件是否真的运行过？"),
    "role-attribution": ("进程归因", "后续行为是否由该文件产生？"),
    "role-c2-behavior": ("远控行为", "它是否外联并接收远程命令？"),
    "role-persistence": ("持久化", "它是否建立了持续驻留机制？"),
    "role-counter-evidence": ("合法性反证", "它是否可能是批准的合法软件？"),
}

DATA_REQUIREMENTS = [
    {
        "name": "主机进程与命令执行",
        "priority": "P0 · 必须",
        "sources": ["edr-process", "auditd-execve"],
        "value": "确认文件是否执行、由谁启动，以及后续命令归因",
        "collect": "进程创建/退出、父子进程关系、命令执行、执行用户与文件哈希",
        "demo": {
            "c2-malicious-reference": "提供 5 条关键事件：root 执行 sysupd、3 段父子关系，以及后门拉起 /bin/sh 执行 id 和 uname -a",
            "c2-benign-reference": "提供 4 条关键事件：systemd 启动 monitor-agent、父子关系，以及程序执行 uptime 健康检查",
        },
        "fields": "主机 ID、进程 ID、父进程 ID、可执行路径、命令行、用户、开始时间、文件哈希",
        "coverage": "重点服务器全量覆盖；事件时间误差 ≤ 5 秒；保留 ≥ 30 天",
        "freshness": "接入延迟 ≤ 5 分钟",
    },
    {
        "name": "进程网络与 Socket 行为",
        "priority": "P0 · 必须",
        "sources": ["edr-network", "ebpf-socket"],
        "value": "把外联目标、收发方向和远程命令关联到具体进程",
        "collect": "进程级网络连接、目标 IP/端口、连接频率、Socket 收发方向与字节数",
        "demo": {
            "c2-malicious-reference": "提供 6 条关键事件：4 次连接 203.0.113.50:443，以及同一 Socket 的入站 48B、出站 312B",
            "c2-benign-reference": "提供 6 条关键事件：4 次厂商端点心跳，以及监控 Socket 的入站 20B、出站 64B",
        },
        "fields": "主机 ID、进程 ID、目标 IP/端口、协议、方向、字节数、连接与收发时间",
        "coverage": "重点服务器出站连接全量覆盖；进程与连接标识可关联",
        "freshness": "接入延迟 ≤ 5 分钟",
    },
    {
        "name": "文件变更与系统服务",
        "priority": "P0 · 必须",
        "sources": ["auditd-file", "package-manager", "systemd-journal"],
        "value": "确认攻击者是否写入服务、启用自启动并形成持续驻留",
        "collect": "关键文件写入、服务配置变更、服务启用/启动和软件安装记录",
        "demo": {
            "c2-malicious-reference": "提供 3 条关键事件：写入、启用并启动 sysupd.service，执行文件指向未知程序",
            "c2-benign-reference": "提供 3 条关键事件：软件包安装并启动 vendor-monitor.service",
        },
        "fields": "主机 ID、文件路径、变更动作、服务名、服务配置、执行文件、操作者、时间",
        "coverage": "/etc、systemd、计划任务等持久化位置全量覆盖",
        "freshness": "接入延迟 ≤ 10 分钟",
    },
    {
        "name": "软件包来源与签名",
        "priority": "P1 · 重要",
        "sources": ["rpm-inventory"],
        "value": "识别文件是否属于可信软件包，避免把合法运维误判为攻击",
        "collect": "文件与软件包归属、包版本、来源仓库、签名验证和安装记录",
        "demo": {
            "c2-malicious-reference": "提供 1 条核验记录：文件不属于已安装软件包、签名无效、来源仓库不可信",
            "c2-benign-reference": "提供 1 条核验记录：归属 vendor-monitor-3.2.1，签名有效且仓库可信",
        },
        "fields": "主机 ID、文件路径/哈希、包名版本、仓库、签名状态、安装时间",
        "coverage": "生产主机每日全量清单，并保留安装变更记录",
        "freshness": "清单更新 ≤ 24 小时",
    },
    {
        "name": "资产与批准通信基线",
        "priority": "P1 · 重要",
        "sources": ["cmdb-baseline"],
        "value": "判断主机关键度、业务归属、批准端点和处置影响",
        "collect": "资产环境与关键度、业务负责人、批准通信端点、隔离策略和维护窗口",
        "demo": {
            "c2-malicious-reference": "提供生产支付资产上下文，并标记 203.0.113.50:443 为未批准端点、隔离需要双人审批",
            "c2-benign-reference": "提供测试监控资产上下文，并确认厂商端点属于批准的 vendor-monitor-cloud 服务",
        },
        "fields": "资产 ID、环境、业务系统、关键度、责任人、批准端点、隔离策略、维护窗口",
        "coverage": "纳管服务器资产 ID 可与安全遥测稳定关联",
        "freshness": "变更后 ≤ 24 小时同步",
    },
]

CASE_STORIES = {
    "c2-malicious-reference": {
        "badge": "预置攻击 · 生产环境",
        "title": "未知程序伪装成系统更新服务，在支付服务器上建立远控通道",
        "lead": "安全设备最初只发现 /tmp/.cache/sysupd 这个未知 ELF。完整事件显示，它通过 SSH 会话以 root 身份执行，随后外联、创建系统服务并执行远程命令。",
        "asset": "payment-api-prod-01",
        "asset_meta": "生产支付接口 · 核心资产",
        "risk": "攻击仍具备远程控制与重启后驻留能力",
        "scope": "当前证据仅覆盖 server-01，相关身份和横向影响尚未排查",
        "steps": [
            ("03:17", "进入主机", "SSH 会话启动 bash，为后续执行提供入口"),
            ("03:20", "恶意执行", "bash 以 root 身份运行 /tmp/.cache/sysupd"),
            ("03:21", "外联与驻留", "连接 203.0.113.50:443，同时写入并启用 sysupd.service"),
            ("03:24", "远程控制", "收到网络输入后拉起 /bin/sh，执行 id 与 uname -a"),
        ],
    },
    "c2-benign-reference": {
        "badge": "预置对照 · 测试环境",
        "title": "监控程序表现出相似行为，但完整数据证明它是批准的合法软件",
        "lead": "安全设备最初只发现 /opt/vendor/monitor-agent 这个未知 ELF。完整事件显示，它由 systemd 正常启动，只访问批准的厂商端点，并具有可信软件包来源。",
        "asset": "monitoring-test-02",
        "asset_meta": "监控验证系统 · 低关键度资产",
        "risk": "未发现恶意活动，行为与批准的监控服务一致",
        "scope": "软件签名、仓库来源与 CMDB 端点基线均已完成核验",
        "steps": [
            ("03:20", "服务启动", "systemd 启动 vendor-monitor 守护进程"),
            ("03:20", "健康检查", "程序调用 uptime 获取主机运行状态"),
            ("03:21", "监控心跳", "周期连接批准的厂商监控服务"),
            ("03:25", "身份核验", "软件包签名、可信仓库和 CMDB 基线共同完成反证"),
        ],
    },
}


def _present_sources(source_ids: list[str]) -> tuple[list[str], list[str]]:
    capabilities: list[str] = []
    technical_sources: list[str] = []
    for source_id in source_ids:
        capability, label = SOURCE_PRESENTATION.get(source_id, ("其他数据线索", source_id))
        if capability not in capabilities:
            capabilities.append(capability)
        technical_sources.append(f"{label}（{source_id}）")
    return capabilities, technical_sources


def render_demo_page(item: DemoComparisonReadModel) -> str:
    profiles = []
    for profile in item.profiles:
        capabilities, technical_sources = _present_sources(profile.readiness.available_sources)
        answerable = {question.question_id for question in profile.readiness.answerable_questions}
        questions = [
            {"id": question_id, "label": label, "question": question, "available": question_id in answerable}
            for question_id, (label, question) in QUESTION_PRESENTATION.items()
        ]
        visible_sources = set(profile.readiness.available_sources)
        data_requirements = []
        for requirement in DATA_REQUIREMENTS:
            present = visible_sources.intersection(requirement["sources"])
            status = "ready" if len(present) == len(requirement["sources"]) else "partial" if present else "missing"
            data_requirements.append({
                **requirement,
                "status": status,
                "demo_data": requirement["demo"][item.dataset_id],
                "source_labels": [SOURCE_PRESENTATION[source][1] for source in requirement["sources"]],
            })
        profiles.append({
            "profile_id": profile.profile_id,
            "level": profile.level.upper(),
            "answerable": len(profile.readiness.answerable_questions),
            "blocked": len(profile.readiness.blocked_questions),
            "capabilities": capabilities,
            "technical_sources": technical_sources,
            "questions": questions,
            "source_count": len(profile.readiness.available_sources),
            "data_requirements": data_requirements,
        })

    story = CASE_STORIES[item.dataset_id]
    story_steps = "".join(
        f'<li><time>{html.escape(at)}</time><div><b>{html.escape(title)}</b><span>{html.escape(description)}</span></div></li>'
        for at, title, description in story["steps"]
    )
    profiles_json = json.dumps(profiles, ensure_ascii=False).replace("</", "<\\/")
    dataset_json = json.dumps(item.dataset_id, ensure_ascii=False)
    notice = html.escape(item.reference_data_notice)
    return f'''<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>未知文件 AI 调查演示</title>
<style>
:root{{--paper:#f8f3e9;--surface:#fffdf8;--ink:#29251f;--muted:#756b5e;--line:#ddd2c2;--rust:#a44828;--rust-dark:#743019;--rust-soft:#f2ded2;--sage:#5f7258;--sage-soft:#e5ecdf;--amber:#b88028;--shadow:0 18px 55px rgba(77,55,31,.10)}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.65 "Microsoft YaHei UI","Noto Sans SC",sans-serif}}body:before{{content:"";position:fixed;inset:0;pointer-events:none;opacity:.42;background:radial-gradient(circle at 12% 8%,#fff 0 15%,transparent 38%),radial-gradient(circle at 88% 78%,#eadcc6 0,transparent 32%)}}button{{font:inherit}}main{{position:relative;max-width:min(1720px,100%);margin:auto;padding:28px 32px 72px}}
.mast{{display:flex;justify-content:space-between;align-items:center;padding-bottom:14px;border-bottom:1px solid var(--line);font-size:13px;color:var(--muted)}}.brand{{font:600 17px Georgia,"Songti SC",serif;color:var(--ink)}}.live-dot{{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--sage);margin-right:7px}}
.hero{{padding:38px 0 26px;display:flex;justify-content:space-between;gap:35px;align-items:end}}.kicker,.step-label{{font:800 11px monospace;letter-spacing:.13em;color:var(--rust)}}h1{{font:500 clamp(34px,4.5vw,58px)/1.12 Georgia,"Songti SC",serif;letter-spacing:-.03em;margin:9px 0 0}}.notice{{max-width:390px;color:var(--muted);font-size:12px;border-left:2px solid var(--amber);padding-left:16px}}
.page-nav{{display:grid;grid-template-columns:repeat(3,1fr);border:1px solid var(--line);background:#fffaf1;box-shadow:var(--shadow);margin-bottom:24px}}.nav-step{{border:0;border-right:1px solid var(--line);background:transparent;padding:15px 18px;text-align:left;color:var(--muted);cursor:pointer}}.nav-step:last-child{{border-right:0}}.nav-step b{{display:block;color:inherit;font-size:15px}}.nav-step span{{font:700 10px monospace}}.nav-step.active{{background:var(--rust);color:white}}.nav-step.complete:not(.active){{color:var(--sage)}}
.page{{display:none;animation:arrive .35s ease both}}.page.active{{display:block}}.panel{{background:rgba(255,253,248,.9);border:1px solid var(--line);box-shadow:var(--shadow);padding:30px}}.panel h2{{font:500 31px Georgia,"Songti SC",serif;line-height:1.25;margin:5px 0 12px}}.lead{{color:var(--muted);font-size:16px;max-width:830px}}
.situation-grid{{display:grid;grid-template-columns:1.4fr .6fr;gap:26px;margin-top:25px}}.attack-chain{{list-style:none;margin:0;padding:0;border-top:1px solid var(--line)}}.attack-chain li{{display:grid;grid-template-columns:70px 1fr;gap:18px;padding:18px 0;border-bottom:1px solid var(--line)}}.attack-chain time{{font:700 12px monospace;color:var(--rust)}}.attack-chain b,.attack-chain span{{display:block}}.attack-chain span{{color:var(--muted);font-size:13px;margin-top:3px}}.situation-card{{background:var(--rust-soft);border-top:3px solid var(--rust);padding:22px}}.situation-card small{{color:var(--muted)}}.situation-card strong{{display:block;font:500 22px Georgia,"Songti SC",serif;margin:4px 0 18px}}.risk-row{{padding:14px 0;border-top:1px solid #d9bdad}}.risk-row b{{display:block;color:var(--rust-dark)}}.next{{display:flex;justify-content:flex-end;margin-top:24px}}.primary,.secondary{{border-radius:3px;padding:12px 22px;font-weight:750;cursor:pointer}}.primary{{border:1px solid var(--rust-dark);background:var(--rust);color:#fff}}.secondary{{border:1px solid var(--line);background:#fffaf2;color:var(--rust)}}
.data-layout{{display:grid;grid-template-columns:230px 1fr;gap:28px;margin-top:25px}}.profiles{{display:grid;gap:8px}}.profile-choice{{border:1px solid var(--line);background:#fffaf2;padding:13px 15px;text-align:left;color:var(--muted);cursor:pointer}}.profile-choice strong{{font:600 20px Georgia,serif;margin-right:9px;color:var(--ink)}}.profile-choice.selected{{background:var(--rust);border-color:var(--rust);color:#fff}}.profile-choice.selected strong{{color:#fff}}.data-summary{{display:flex;align-items:end;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:17px;margin-bottom:14px}}.data-summary strong{{font:500 38px Georgia,serif;color:var(--rust)}}.data-summary small{{color:var(--muted)}}.question-grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:9px}}.question{{padding:13px;border:1px solid var(--line);background:#fffdf8;display:grid;grid-template-columns:23px 1fr;gap:9px}}.question i{{font-style:normal;color:#aaa096}}.question.available i{{color:var(--sage)}}.question b,.question span{{display:block}}.question span{{font-size:12px;color:var(--muted)}}.source-detail{{margin-top:15px;color:var(--muted);font-size:12px}}.source-detail summary{{cursor:pointer;color:var(--rust);width:max-content}}.requirement-section{{margin-top:28px;padding-top:23px;border-top:1px solid var(--line)}}.section-head{{display:flex;justify-content:space-between;gap:20px;align-items:end;margin-bottom:13px}}.section-head h3{{font:500 23px Georgia,"Songti SC",serif;margin:0}}.section-head p{{margin:0;color:var(--muted);font-size:12px;max-width:520px}}.requirement-list{{display:grid;gap:10px}}.requirement{{display:grid;grid-template-columns:155px 1fr 1.15fr 108px;gap:14px;padding:16px;border:1px solid var(--line);background:#fffdf8;align-items:start}}.requirement-name b,.requirement-name span{{display:block}}.requirement-name span{{font-size:10px;color:var(--rust);font-weight:800}}.requirement h4{{font-size:11px;margin:0 0 3px;color:var(--muted)}}.requirement p{{font-size:12px;margin:0;color:#4c443b}}.requirement-demo{{padding-left:14px;border-left:2px solid #d8c4b4}}.requirement-demo p{{color:var(--rust-dark)}}.source-badges{{display:flex;flex-wrap:wrap;gap:4px;margin-top:8px}}.source-badges span{{padding:2px 6px;background:#f3ece2;color:#776b5e;font-size:10px;border-radius:2px}}.requirement-status{{text-align:center;border-radius:999px;padding:4px 7px;font-size:11px;font-weight:800;background:#eee8de;color:#807668}}.requirement.ready .requirement-status{{background:var(--sage-soft);color:var(--sage)}}.requirement.partial .requirement-status{{background:#f4e7c9;color:#8a631e}}.requirement.missing{{border-left:3px solid var(--rust)}}.requirement.missing .requirement-status{{background:var(--rust-soft);color:var(--rust-dark)}}.engineering-detail{{grid-column:2/4;font-size:11px;color:var(--muted)}}.engineering-detail summary{{cursor:pointer;color:#88796a}}.engineering-detail div{{margin-top:5px}}.request-summary{{margin-top:10px;padding:12px 14px;background:#f7ecdf;color:#6c4935;font-size:13px}}
.ai-shell{{padding:0;overflow:hidden}}.ai-head{{padding:27px 30px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;gap:25px}}.ai-head h2{{margin:4px 0 0}}.status{{color:var(--rust);font-weight:700}}.status:before{{content:"";display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--rust);margin-right:8px;animation:pulse 1.4s infinite}}.wf{{display:flex;align-items:center;gap:10px;overflow-x:auto;padding:18px 24px;background:#faf3e8;border-bottom:1px solid var(--line)}}.wf-node{{flex:0 0 auto;display:flex;align-items:center;gap:8px;padding:9px 14px;border:1px solid #d8ccb8;border-radius:999px;background:#fffdf8;font-size:13px;color:#a09688;white-space:nowrap}}.wf-node i{{width:13px;height:13px;flex:0 0 13px;border-radius:50%;border:1px solid #b9ae9f}}.wf-node.active{{color:var(--rust);font-weight:700;border-color:var(--rust)}}.wf-node.active i{{background:var(--rust);border-color:var(--rust);box-shadow:0 0 0 5px var(--rust-soft);animation:pulse 1.4s infinite}}.wf-node.done{{color:var(--sage);border-color:#b7c4ad}}.wf-node.done i{{background:var(--sage);border-color:var(--sage)}}.wf-arrow{{color:#c4b69f;font-size:16px;flex:0 0 auto}}.wf-loop{{flex:0 0 auto;display:flex;flex-direction:column;gap:7px;border:1px dashed #c9b18d;border-radius:12px;padding:11px 13px;background:#fbf6ec}}.wf-loop.active{{border-color:var(--rust);box-shadow:0 0 0 4px var(--rust-soft)}}.wf-loop-label{{font:800 9px monospace;letter-spacing:.1em;color:#a0815a;text-align:center}}.wf-loop-body{{display:flex;align-items:center;gap:8px}}.wf-node-branch{{align-self:center;font-size:11px;padding:6px 11px}}.wf-node-stack{{flex-direction:column;align-items:stretch;gap:5px;border-radius:10px;padding:10px 12px;white-space:normal;text-align:left}}.wf-node-head{{display:flex;align-items:center;gap:7px}}.wf-node-stack em{{display:block;font-style:normal;font-size:11px;color:#8d7f6b;font-weight:400;line-height:1.45;max-width:132px}}.wf-branch{{display:flex;flex-direction:column;align-items:center;gap:3px;padding-top:5px;border-top:1px dashed #d8c4b0}}.wf-branch-note{{font-size:10px;color:#a0815a}}.wf-loop-exit{{font-size:10px;color:#a0815a;text-align:center;border-top:1px dashed #d8c4b0;padding-top:5px}}
.analysis-area{{display:grid;grid-template-columns:1fr 290px;min-height:340px}}.stream{{padding:28px;border-right:1px solid var(--line)}}.agent-state{{display:flex;gap:14px;align-items:center;padding:14px 16px;border:1px solid #e3d5c3;background:#faf3e8;border-radius:10px}}.orb{{position:relative;width:30px;height:30px;flex:0 0 30px}}.orb:before,.orb:after{{content:"";position:absolute;border-radius:50%}}.orb:before{{inset:5px;background:var(--rust);box-shadow:0 0 18px #a4482855;animation:breathe 1.5s ease-in-out infinite}}.orb:after{{inset:0;border:1px solid #c98a70;animation:orbit 2.2s linear infinite}}.thinking{{font-weight:750}}.thinking-sub{{font-size:12px;color:var(--muted)}}.events{{display:grid;gap:10px;margin-top:18px}}.event{{padding:13px 16px;background:#fffdf8;border:1px solid var(--line);border-left:3px solid var(--sage);animation:arrive .3s ease both}}.event.verdict,.event.response{{border-left-color:var(--rust)}}.event-tag{{font:800 10px monospace;color:var(--rust)}}.event-node{{display:inline-block;margin-left:8px;font-size:10px;color:#887b6a;border:1px solid #ddd2c2;border-radius:999px;padding:1px 7px}}.event-obs{{display:block;margin-top:4px;color:#5a5147;font-size:13px}}.event p{{margin:3px 0}}.quiet-note{{color:var(--muted);font-size:13px}}.dossier{{padding:28px;background:#fffaf2}}.dossier h3{{font:500 22px Georgia,"Songti SC",serif;margin:0 0 16px}}.metric{{padding:13px 0;border-top:1px solid var(--line)}}.metric small,.metric strong{{display:block}}.metric small{{color:var(--muted)}}
.outputs{{display:none;padding:0 30px 30px;background:#fffdf8}}.outputs.show{{display:block}}.output-title{{font:500 25px Georgia,"Songti SC",serif;padding:24px 0 12px;margin:0;border-top:1px solid var(--line)}}.report{{border:1px solid #d6c8b7;background:#fffaf2;padding:24px}}.judgment-report{{border-top:4px solid var(--rust)}}.response-report{{border-top:4px solid var(--sage);margin-top:20px}}.report-head{{display:flex;justify-content:space-between;gap:20px;align-items:start}}.report-kicker{{font:800 10px monospace;letter-spacing:.12em;color:var(--muted)}}.verdict{{font:500 30px Georgia,"Songti SC",serif;color:var(--rust-dark)}}.report-summary{{font-size:16px;max-width:800px}}.judgment-meta{{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:17px 0}}.judgment-meta div{{padding:11px;background:#f5eadd;border-top:2px solid #d2b39f}}.judgment-meta small,.judgment-meta strong{{display:block}}.judgment-meta small{{color:var(--muted);font-size:10px}}.report-section-title{{font-size:13px;margin:20px 0 7px}}.evidence-list,.action-list{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}}.evidence-item,.action-item{{border:1px solid var(--line);background:#fffdf8;padding:14px}}.evidence-item b,.action-item b{{display:block}}.evidence-item span,.action-item span{{display:block;color:var(--muted);font-size:12px;margin-top:5px}}.assessment-grid{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}.assessment{{padding:14px;border:1px solid var(--line);background:#fffdf8}}.assessment b{{display:block;font-size:12px}}.assessment p{{margin:5px 0 0;color:var(--muted);font-size:12px}}.statement-list{{margin-top:6px;display:grid;gap:6px}}.statement-item{{color:var(--muted);font-size:12px;line-height:1.6;padding-left:11px;border-left:2px solid #e6dccb}}.statement-empty{{color:#b7ab99;font-size:12px;font-style:italic}}.repair-traces{{margin-top:9px;font-size:11px;color:#9a8b77;border-top:1px dashed #e0d4c3;padding-top:6px}}.repair-traces summary{{cursor:pointer;color:#887a68;width:max-content}}.repair-traces .statement-item{{border-left-color:#d9c9b0;color:#9a8b77}}.response-meta{{display:flex;gap:18px;flex-wrap:wrap;color:var(--muted);font-size:13px;margin-top:8px}}.restart{{margin-top:18px}}
@keyframes orbit{{to{{transform:rotate(360deg)}}}}@keyframes breathe{{50%{{transform:scale(.65);opacity:.55}}}}@keyframes pulse{{50%{{transform:scale(1.25);opacity:.55}}}}@keyframes arrive{{from{{opacity:0;transform:translateY(7px)}}}}@media(prefers-reduced-motion:reduce){{*{{animation:none!important}}}}@media(max-width:850px){{.hero,.situation-grid,.data-layout,.analysis-area{{display:grid;grid-template-columns:1fr}}.question-grid,.evidence-list,.action-list,.judgment-meta,.assessment-grid{{grid-template-columns:1fr}}.requirement{{grid-template-columns:1fr}}.requirement-status{{width:max-content}}.stream{{border-right:0;border-bottom:1px solid var(--line)}}}}@media(max-width:560px){{main{{padding:18px 12px 45px}}.nav-step{{padding:11px 9px}}.nav-step b{{font-size:12px}}.panel{{padding:20px}}.page-nav span{{display:none}}.wf-node span{{display:none}}}}
.ai-dialogue{{margin-top:18px;border:1px solid #e1d7c8;border-radius:16px;background:#fffdf9;overflow:hidden}}.ai-dialogue summary{{cursor:pointer;list-style:none;padding:14px 16px;font-weight:700;color:#3e352c;display:flex;align-items:center;justify-content:space-between}}.ai-dialogue summary::-webkit-details-marker{{display:none}}.ai-dialogue summary::after{{content:'展开';font-size:12px;font-weight:500;color:#8b7865}}.ai-dialogue[open] summary::after{{content:'收起'}}.dialogue-note{{padding:0 16px 12px;color:#897866;font-size:12px}}.dialogue-list{{border-top:1px solid #eee5da;max-height:680px;overflow:auto;padding:14px;display:grid;gap:14px}}.dialogue-empty{{color:#9a8978;font-size:13px;padding:8px}}.dialogue-turn{{display:grid;grid-template-columns:92px minmax(0,1fr);gap:10px;align-items:start}}.dialogue-role{{font-size:11px;font-weight:800;letter-spacing:.04em;color:#806d5a;padding-top:7px}}.dialogue-bubble{{border-radius:12px;padding:11px;background:#f6f0e8;color:#423a32;font:12px/1.55 Consolas,"Microsoft YaHei",monospace;white-space:pre-wrap;overflow-wrap:anywhere;max-height:420px;overflow:auto}}.dialogue-turn.tool .dialogue-bubble{{background:#eef3ed}}.dialogue-turn.system .dialogue-bubble{{background:#f3f0eb;color:#71675d}}.dialogue-turn.error .dialogue-bubble{{background:#fff0ec;color:#8b2f1b;border:1px solid #efc2b6}}@media(max-width:720px){{.dialogue-turn{{grid-template-columns:1fr;gap:3px}}}}
</style></head><body><main>
<header class="mast"><span class="brand">未知文件调查室</span><span><i class="live-dot"></i>DeepSeek 双模型在线</span></header>
<section class="hero"><div><div class="kicker">AI INVESTIGATION WALKTHROUGH</div><h1>从一条告警，到可执行的安全决策</h1></div><div class="notice">{notice}</div></section>
<nav class="page-nav" aria-label="演示步骤"><button class="nav-step active" data-page="situation"><span>01</span><b>事件与当前态势</b></button><button class="nav-step" data-page="data"><span>02</span><b>数据与证据条件</b></button><button class="nav-step" data-page="ai"><span>03</span><b>AI 分析与输出</b></button></nav>

<section class="page active" id="page-situation"><article class="panel"><div class="step-label">01 / INCIDENT SITUATION · {html.escape(story["badge"])}</div><h2>{html.escape(story["title"])}</h2><p class="lead">{html.escape(story["lead"])}</p><div class="situation-grid"><ol class="attack-chain">{story_steps}</ol><aside class="situation-card"><small>受影响资产</small><strong>{html.escape(story["asset"])}</strong><div class="risk-row"><b>当前安全状态</b>{html.escape(story["risk"])}</div><div class="risk-row"><b>已知调查边界</b>{html.escape(story["scope"])}</div></aside></div><div class="next"><button class="primary" data-goto="data">查看哪些数据能证明这些行为 →</button></div></article></section>

<section class="page" id="page-data"><article class="panel"><div class="step-label">02 / DATA FOUNDATION</div><h2>同一起事件，数据越完整，能够回答的问题越多</h2><p class="lead">选择一个数据等级，查看本次测试实际提供了哪些数据，以及项目落地需要持续收集哪些数据。</p><div class="data-layout"><div class="profiles" id="profiles"></div><div><div class="data-summary"><div><strong id="readiness">0/5</strong><small> 个关键问题已有数据支撑</small></div><div><b id="source-count">0</b><small> 类原始数据源</small></div></div><div class="question-grid" id="question-grid"></div><details class="source-detail"><summary>查看本级数据来源</summary><div id="technical-sources"></div></details></div></div><section class="requirement-section"><div class="section-head"><div><div class="step-label">DATA REQUEST</div><h3>数据接入诉求</h3></div><p>主体说明“需要收集什么”和“本次测试提供了什么”；字段、覆盖和时效要求放在工程明细中。</p></div><div class="requirement-list" id="requirement-list"></div><div class="request-summary" id="request-summary"></div><div class="next"><button class="primary" data-goto="ai">使用当前数据启动 AI 调查 →</button></div></section></article></section>

<section class="page" id="page-ai"><article class="panel ai-shell"><div class="ai-head"><div><div class="step-label">03 / AI INVESTIGATION</div><h2>AI 调查过程与专业输出</h2></div><button class="primary" id="start">启动 AI 全流程调查</button></div><div class="wf" id="workflow"><div class="wf-node" data-node="readiness"><i></i><span>数据就绪度</span></div><div class="wf-arrow">→</div><div class="wf-node" data-node="intake"><i></i><span>告警接入</span></div><div class="wf-arrow">→</div><div class="wf-loop" id="wf-loop"><span class="wf-loop-label">调查循环 · AI 自主决策</span><div class="wf-loop-body"><div class="wf-node wf-node-stack" data-node="plan"><span class="wf-node-head"><i></i><span>规划调查</span></span><em>选工具 · 填参数 · 判断证据是否充分</em></div><div class="wf-arrow">⇄</div><div class="wf-node wf-node-stack" data-node="validate"><span class="wf-node-head"><i></i><span>校验动作</span></span><em>策略校验 · 非法动作交回 AI 修复</em></div><div class="wf-arrow">⇄</div><div class="wf-node wf-node-stack" data-node="execute"><span class="wf-node-head"><i></i><span>执行查询</span></span><em>数据工具网关查询活动数据</em></div></div><div class="wf-branch"><div class="wf-node wf-node-branch" data-node="scope"><i></i><span>范围扩展</span></div><span class="wf-branch-note">发现范围外主机 · 发起审批（demo 策略拒绝）</span></div><div class="wf-loop-exit">证据充分 或 预算耗尽 → 跳出循环 → 生成研判</div></div><div class="wf-arrow">→</div><div class="wf-node" data-node="compose"><i></i><span>生成研判</span></div><div class="wf-arrow">→</div><div class="wf-node" data-node="gate"><i></i><span>证据充分性再确认</span></div><div class="wf-arrow">→</div><div class="wf-node" data-node="advise"><i></i><span>处置建议</span></div><div class="wf-arrow">→</div><div class="wf-node" data-node="done"><i></i><span>完成</span></div></div><div class="analysis-area"><div class="stream"><div class="agent-state"><i class="orb"></i><div><div class="thinking" id="thinking">等待启动调查</div><div class="thinking-sub">下方调试视图会逐轮展示模型输入、结构化输出、工具调用与完整返回</div></div></div><div class="events" id="events"><div class="quiet-note">启动后，关键调查进展会在这里出现。</div></div></div><aside class="dossier"><h3>调查进度</h3><div class="metric"><small>当前数据等级</small><strong id="dossier-profile">—</strong></div><div class="metric"><small>已查询活动领域</small><strong id="evidence-count">0</strong></div><div class="metric"><small>当前研判</small><strong id="current-verdict">尚未形成结论</strong></div><div class="metric"><small>运行状态</small><strong class="status" id="status">尚未启动</strong></div></aside></div><div class="outputs" id="outputs"><h3 class="output-title">调查交付物</h3><section class="report judgment-report"><div class="report-kicker">INVESTIGATION REPORT / 研判报告</div><div class="report-head"><div><div class="verdict" id="report-verdict"></div><p class="report-summary" id="report-summary"></p></div><div id="report-confidence"></div></div><div class="judgment-meta"><div><small>威胁类型</small><strong id="report-threat"></strong></div><div><small>受影响资产</small><strong id="report-assets"></strong></div><div><small>查询边界</small><strong id="report-coverage"></strong></div><div><small>证据引用</small><strong id="report-ref-count"></strong></div></div><h4 class="report-section-title">关键判断依据</h4><div class="evidence-list" id="report-evidence"></div><h4 class="report-section-title">影响评估与结论边界</h4><div class="assessment-grid"><div class="assessment"><b>当前态势</b><p id="report-impact"></p></div><div class="assessment"><b>反证检查</b><p id="report-counter"></p></div><div class="assessment"><b>调查范围</b><p id="report-scope"></p></div><div class="assessment"><b>结论限制</b><p id="report-limitations"></p><details class="repair-traces" id="repair-traces"><summary>发布校验记录</summary><div id="report-repair-traces"></div></details></div></div></section><section class="report response-report"><div class="report-kicker">RESPONSE PLAN / 处置方案</div><div class="report-head"><div><div class="verdict" id="response-status"></div><p class="report-summary">处置建议由独立模型结合已发布的研判结果、资产上下文和审批约束生成；本系统不会自动执行生产处置动作。</p></div></div><div class="response-meta" id="response-meta"></div><div class="action-list" id="response-actions"></div></section><button class="secondary restart" id="restart">重新选择数据并调查</button></div></article></section>

<script>
const datasetId={dataset_json};const profileData={profiles_json};let selected=profileData[profileData.length-1];let rendered=0;const seenDomains=new Set();const wfIds=['readiness','intake','plan','validate','execute','scope','compose','gate','advise','done'];const wfLabel={{readiness:'数据就绪度',intake:'告警接入',plan:'规划调查',validate:'校验动作',execute:'执行查询',scope:'范围扩展',compose:'生成研判',gate:'证据充分性再确认',advise:'处置建议',done:'完成'}};const completedNodes=new Set();let currentNode=null;const $=id=>document.getElementById(id);const safe=v=>{{const n=document.createElement('span');n.textContent=String(v??'');return n.innerHTML}};
function showPage(name){{document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active',p.id===`page-${{name}}`));document.querySelectorAll('.nav-step').forEach(b=>b.classList.toggle('active',b.dataset.page===name));window.scrollTo({{top:document.querySelector('.page-nav').offsetTop-14,behavior:'smooth'}})}}document.querySelectorAll('[data-goto]').forEach(b=>b.onclick=()=>showPage(b.dataset.goto));document.querySelectorAll('.nav-step').forEach(b=>b.onclick=()=>showPage(b.dataset.page));
const requirementStatus={{ready:'已具备',partial:'部分具备',missing:'待客户提供'}};
function choose(p){{selected=p;document.querySelectorAll('.profile-choice').forEach(b=>b.classList.toggle('selected',b.dataset.profile===p.profile_id));$('readiness').textContent=`${{p.answerable}}/5`;$('source-count').textContent=p.source_count;$('technical-sources').textContent=p.technical_sources.length?p.technical_sources.join(' · '):'仅有原始告警，没有行为遥测';$('question-grid').replaceChildren(...p.questions.map(q=>{{const e=document.createElement('div');e.className=`question ${{q.available?'available':''}}`;e.innerHTML=`<i>${{q.available?'✓':'—'}}</i><div><b>${{safe(q.label)}}</b><span>${{safe(q.available?q.question:'缺少数据，暂时无法回答')}}</span></div>`;return e}}));$('requirement-list').replaceChildren(...p.data_requirements.map(r=>{{const e=document.createElement('article');e.className=`requirement ${{r.status}}`;e.innerHTML=`<div class="requirement-name"><span>${{safe(r.priority)}}</span><b>${{safe(r.name)}}</b><div class="source-badges">${{r.source_labels.map(s=>`<span>${{safe(s)}}</span>`).join('')}}</div></div><div><h4>需要持续收集</h4><p>${{safe(r.collect)}}</p></div><div class="requirement-demo"><h4>本次测试提供</h4><p>${{r.status==='missing'?'当前等级未提供该类数据':safe(r.demo_data)}}</p></div><div class="requirement-status">${{requirementStatus[r.status]}}</div><details class="engineering-detail"><summary>字段与接入要求</summary><div><b>最低字段：</b>${{safe(r.fields)}}<br><b>覆盖要求：</b>${{safe(r.coverage)}}<br><b>时效要求：</b>${{safe(r.freshness)}}<br><b>研判用途：</b>${{safe(r.value)}}</div></details>`;return e}}));const ready=p.data_requirements.filter(r=>r.status==='ready');const missing=p.data_requirements.filter(r=>r.status!=='ready');$('request-summary').textContent=`本次 ${{p.level}} 测试已提供 ${{ready.length}} 类完整数据${{ready.length?'：'+ready.map(r=>r.name).join('、'):''}}；仍需补充 ${{missing.length}} 类${{missing.length?'：'+missing.map(r=>r.name).join('、'):''}}。`}}
function buildChoices(){{profileData.forEach(p=>{{const b=document.createElement('button');b.className='profile-choice';b.dataset.profile=p.profile_id;b.innerHTML=`<strong>${{safe(p.level)}}</strong>${{p.answerable}} 个问题可回答`;b.onclick=()=>choose(p);$('profiles').appendChild(b)}});choose(selected)}}
function setNode(id){{if(!wfIds.includes(id))return;completedNodes.add(id);currentNode=id;document.querySelectorAll('.wf-node').forEach(el=>{{const n=el.dataset.node;const active=n===id;const done=!active&&completedNodes.has(n);el.classList.toggle('active',active);el.classList.toggle('done',done);el.classList.toggle('pending',!active&&!done)}});$('wf-loop').classList.toggle('active',['plan','validate','execute'].includes(id))}}
function addFinding(kind,label,message,obs){{const q=$('events').querySelector('.quiet-note');if(q)q.remove();const row=document.createElement('article');row.className=`event ${{kind}}`;const nodeName=wfLabel[currentNode];row.innerHTML=`<span class="event-tag">${{safe(label)}}</span>${{nodeName?`<span class="event-node">来源：${{safe(nodeName)}}</span>`:''}}<p>${{safe(message)}}</p>${{obs||''}}`;$('events').appendChild(row)}}
const activityZh={{process:'进程与命令',network:'网络连接',socket:'网络收发',file:'文件变更',service:'系统服务',package:'软件包来源',asset:'资产基线',extension:'扩展记录'}};
function normalizeEvent(e){{const d=e.details||{{}};return {{...e,kind:d.kind||e.kind||e.event_type,message:d.message||e.message||'',details:d}}}}
const dialogue=document.createElement('details');dialogue.className='ai-dialogue';dialogue.open=true;dialogue.innerHTML='<summary>模型完整对话与工具调用</summary><div class="dialogue-note">调试视图：逐轮展示 System、User、模型结构化输出、工具参数与完整返回，以及真实错误信息。API Key 不属于模型消息，不会显示。</div><div class="dialogue-list" id="dialogue-list"><div class="dialogue-empty">启动调查后，这里会实时记录完整交互。</div></div>';document.querySelector('.stream').appendChild(dialogue);
function pretty(v){{if(typeof v==='string')return v;try{{return JSON.stringify(v,null,2)}}catch(_e){{return String(v)}}}}
function appendDialogue(role,css,body){{const list=$('dialogue-list');if(list.querySelector('.dialogue-empty'))list.innerHTML='';const turn=document.createElement('div');turn.className=`dialogue-turn ${{css}}`;const roleEl=document.createElement('div');roleEl.className='dialogue-role';roleEl.textContent=role;const bubble=document.createElement('pre');bubble.className='dialogue-bubble';bubble.textContent=pretty(body);turn.append(roleEl,bubble);list.appendChild(turn);list.scrollTop=list.scrollHeight}}
function renderDialogue(raw){{const e=normalizeEvent(raw),d=e.details||{{}};if(e.kind==='model_input'){{if(d.registered_tools)appendDialogue('TOOL SCHEMAS','system',d.registered_tools);(d.messages||[]).forEach(m=>appendDialogue(String(m.role||'input').toUpperCase(),'ai',m));return}}if(e.kind==='model_output'){{const nativeOutput=d.output??{{content:d.content,tool_calls:d.tool_calls,invalid_tool_calls:d.invalid_tool_calls,response_metadata:d.response_metadata,usage_metadata:d.usage_metadata,additional_kwargs:d.additional_kwargs}};appendDialogue(d.error_type?'MODEL ERROR':'ASSISTANT',d.error_type?'error':'ai',d.error_type?{{error_type:d.error_type,error_message:d.error_message}}:nativeOutput);return}}if(e.kind==='tool'){{appendDialogue('TOOL CALL','tool',{{tool_call_id:d.tool_call_id,tool_name:d.tool_name,arguments:d.arguments}});appendDialogue('TOOL RESULT','tool',d.result??d);return}}if(e.kind==='tool_error'){{appendDialogue('TOOL ERROR','error',{{tool_call_id:d.tool_call_id,tool_name:d.tool_name,arguments:d.arguments,error_type:d.error_type,error_message:d.error_message}});return}}if(e.kind==='error'){{appendDialogue('RUN ERROR','error',{{error_type:d.error_type,error_message:d.error_message,exception_repr:d.exception_repr}});return}}if(['decision','repair','validation','report','response','verdict','tool_message'].includes(e.kind))appendDialogue(e.kind.toUpperCase(),'system',d)}}
function renderEvent(raw){{const e=normalizeEvent(raw);if(e.node)setNode(e.node);if(['run','graph'].includes(e.kind)){{$('thinking').textContent='正在理解告警、资产与数据条件';return}}if(e.kind==='tool'){{const d=e.details||{{}};const domain=d.activity_type;if(domain&&!seenDomains.has(domain)){{seenDomains.add(domain);$('evidence-count').textContent=String(seenDomains.size)}}addFinding('evidence','数据核验',domain?`已查询${{activityZh[domain]||domain}}，返回 ${{d.returned_count??'若干'}} 条活动记录。`:`已完成一项数据核验：${{d.tool_name||'调查工具'}}。`);$('thinking').textContent='正在核对活动记录与实体关联';return}}if(e.kind==='round'){{const d=e.details||{{}};addFinding('evidence',`第 ${{d.round||'?'}} 轮调查`,d.observation||`本轮执行了 ${{d.tool_names?.length||0}} 个数据工具。`);$('thinking').textContent='正在汇总本轮调查成果';return}}if(['thinking','decision','repair','validation'].includes(e.kind)){{$('thinking').textContent=e.message.includes('处置')?'研判已移交处置模型，正在评估业务影响':'AI 正在综合本次查询返回的数据';return}}if(e.kind==='verdict'){{$('thinking').textContent='研判模型已完成证据交叉验证';$('current-verdict').textContent=e.message.replace('研判结论：','');addFinding('verdict','研判形成',e.details?.summary||e.message);return}}if(e.kind==='report'){{addFinding('verdict','报告生成','正式研判报告已经通过引用与调查范围校验。');return}}if(e.kind==='response'){{$('thinking').textContent='处置模型正在检查审批约束和业务影响';addFinding('response','处置形成',`已形成 ${{e.details?.action_types?.length||0}} 项处置建议。`);return}}if(e.kind==='error')addFinding('verdict','运行异常',e.message)}}
const actionZh={{isolate_host:'隔离受影响主机',preserve_evidence:'保全调查证据',block_endpoint:'阻断恶意端点',terminate_process:'终止恶意进程',remove_persistence:'移除持久化配置',monitor:'加强监控'}};const statusZh={{recommended:'已形成处置建议',approval_required:'需要审批后执行',insufficient_context:'处置上下文不足',rejected:'未批准'}};
const threatZh={{backdoor_c2:'后门与远程控制',ransomware:'勒索软件',data_exfiltration:'数据外泄',unknown:'未知威胁'}};
function statements(items){{return (items||[]).map(x=>x.text).filter(Boolean)}}
function fillList(id, items, emptyText){{const el=$(id);const vals=(items||[]).filter(Boolean);if(!vals.length){{el.innerHTML=`<span class="statement-empty">${{safe(emptyText)}}</span>`;return}}el.innerHTML=vals.map(t=>`<div class="statement-item">${{safe(t)}}</div>`).join('')}}
function renderOutputs(job){{const report=job.investigation_report;const verdict=report?.verdict;const plan=job.response_plan;const keyEvidence=report?.key_evidence||[];$('report-verdict').textContent=VERDICT_LABELS[verdict?.level]||verdict?.level||'未形成结论';$('report-summary').textContent=report?.executive_summary||verdict?.summary||'未生成正式研判报告';$('report-threat').textContent=threatZh[verdict?.threat_type]||verdict?.threat_type||'待确认';$('report-assets').textContent=(report?.asserted_host_refs||[]).join('、')||'报告未声明';$('report-coverage').textContent=`${{report?.query_boundary_refs?.length||0}} 个查询边界`;$('report-ref-count').textContent=`${{report?.supporting_evidence_refs?.length||0}} 条证据引用`;$('report-impact').textContent='';fillList('report-impact',statements(report?.current_situation),'报告未声明');$('report-counter').textContent='';fillList('report-counter',statements(report?.counter_evidence),'报告未声明');$('report-scope').textContent='';fillList('report-scope',statements(report?.affected_scope),'报告未声明');const limits=(report?.limitations||[]);const realLimits=limits.filter(t=>!t.startsWith('发布校验已自动修复'));const repairTraces=limits.filter(t=>t.startsWith('发布校验已自动修复'));fillList('report-limitations',realLimits,'报告未声明额外限制');const trEl=$('repair-traces');if(repairTraces.length){{trEl.style.display='';fillList('report-repair-traces',repairTraces,'');}}else{{trEl.style.display='none'}}$('report-evidence').replaceChildren(...keyEvidence.map(s=>{{const e=document.createElement('div');e.className='evidence-item';e.innerHTML=`<span>${{safe(s.text)}} · 引用 ${{s.supporting_refs?.length||0}} 条证据</span>`;return e}}));$('response-status').textContent=statusZh[plan?.status]||plan?.status||'尚未生成';$('response-meta').innerHTML=`<span>建议 ${{plan?.actions?.length||0}} 项</span><span>剩余风险 ${{plan?.residual_risk?.length||0}} 项</span><span>生产动作未执行</span>`;$('response-actions').replaceChildren(...(plan?.actions||[]).map(a=>{{const e=document.createElement('div');e.className='action-item';e.innerHTML=`<b>${{safe(actionZh[a.action_type]||a.action_type)}}</b><span>${{safe(a.rationale)}}<br>业务影响：${{safe(a.expected_impact||'待评估')}}<br>审批：${{safe(a.approval_class||'按策略执行')}}</span>`;return e}}));$('outputs').classList.add('show')}}
const VERDICT_LABELS={{confirmed_malicious:'确认恶意',likely_malicious:'高度疑似恶意',suspicious:'存在可疑行为',insufficient_evidence:'证据不足',likely_benign:'倾向良性',benign:'确认良性'}};
async function poll(runId){{try{{const r=await fetch(`/api/investigations/${{encodeURIComponent(runId)}}`);if(!r.ok)throw new Error();const job=await r.json();job.events.slice(rendered).forEach(e=>{{renderEvent(e);renderDialogue(e)}});rendered=job.events.length;const status=job.run?.status;$('status').textContent={{queued:'等待运行',running:'AI 正在调查',completed:'调查完成',failed:'调查失败'}}[status]||status;if(status==='completed'){{document.querySelectorAll('.wf-node').forEach(el=>{{el.classList.add('done');el.classList.remove('active')}});$('wf-loop').classList.remove('active');$('thinking').textContent='研判报告与处置方案已生成';renderOutputs(job);return}}if(status==='failed'){{$('thinking').textContent='本次调查未完成';$('start').disabled=false;return}}setTimeout(()=>poll(runId),900)}}catch(_e){{$('status').textContent='连接中断，正在重试';setTimeout(()=>poll(runId),1600)}}}}
$('start').onclick=async()=>{{$('start').disabled=true;$('outputs').classList.remove('show');$('events').innerHTML='<div class="quiet-note">AI 正在阅读告警与资产背景…</div>';$('dialogue-list').innerHTML='<div class="dialogue-empty">AI 正在建立调查上下文…</div>';$('dossier-profile').textContent=`${{selected.level}} · ${{selected.answerable}}/5 可回答`;$('current-verdict').textContent='尚未形成结论';$('status').textContent='正在创建运行';rendered=0;seenDomains.clear();completedNodes.clear();currentNode=null;document.querySelectorAll('.wf-node').forEach(el=>el.classList.remove('active','done'));setNode('intake');try{{const r=await fetch('/api/investigations',{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify({{reference_dataset_id:datasetId,profile_id:selected.profile_id}})}});if(!r.ok)throw new Error();poll((await r.json()).run_id)}}catch(_e){{$('status').textContent='无法启动调查';$('start').disabled=false}}}};$('restart').onclick=()=>{{showPage('data');$('start').disabled=false;$('outputs').classList.remove('show')}};buildChoices();
</script></main></body></html>'''
