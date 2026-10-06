"""工程师复核裁决的三项评分修复回归测试（2026-09-30）。

① epoch 均值累积错误：两轮 0/1 应得 0.5（原实现 0.25）
② 无评分记录 / 全部 None（不适用）→ 无法评价，不算通过
③ 边界评分器无判定产物 → fail-closed（原来空断言=保持=通过）
"""

from __future__ import annotations

import json
from pathlib import Path

from threat_agent.agent_eval.core import Case, RunRecord, Score
from threat_agent.agent_eval.reporter import summarize
from threat_agent.bootstrap.eval_scorers import BoundaryInterceptionScorer

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _case() -> Case:
    return Case(case_id="c1", suite="s@1")


def _record(rid: str, status: str = "ok") -> RunRecord:
    return RunRecord(run_id=rid, case_ref="c1", config={}, status=status)


def test_dimension_mean_across_epochs_is_equal_weight():
    """① 两轮同维度 0 与 1 → 案例均值 0.5，跨案例再平均仍 0.5。"""

    scores = {
        "c1#h#1": [Score(scorer="s", dimensions={"acc": 0.0}, passed=True)],
        "c1#h#2": [Score(scorer="s", dimensions={"acc": 1.0}, passed=True)],
    }
    report = summarize([_record("c1#h#1"), _record("c1#h#2")], {"c1": _case()}, scores)
    assert report["dimensions"]["acc"] == 0.5


def test_missing_scores_is_unevaluated_not_pass():
    """② 无评分记录 → 整案无法评价（None），不算通过，通过率分母排除。"""

    report = summarize([_record("c1#h#1")], {"c1": _case()}, {})
    assert report["cases"][0]["pass_at_k"]["all_epochs_passed"] is None
    assert report["totals"]["unevaluated_cases"] == 1


def test_all_not_applicable_scores_is_unevaluated():
    """② 所有评分器均 None（不适用）→ 无法评价，不算通过。"""

    scores = {"c1#h#1": [Score(scorer="cost", dimensions={"t": 1.0}, passed=None)]}
    report = summarize([_record("c1#h#1")], {"c1": _case()}, scores)
    assert report["cases"][0]["pass_at_k"]["all_epochs_passed"] is None


def test_mixed_pass_and_unevaluated_epoch_is_unevaluated():
    """② 多 epoch 中一轮通过一轮无法评价 → 整案无法评价（不能靠缺席轮过关）。"""

    scores = {
        "c1#h#1": [Score(scorer="s", dimensions={"acc": 1.0}, passed=True)],
        "c1#h#2": [],
    }
    report = summarize([_record("c1#h#1"), _record("c1#h#2")], {"c1": _case()}, scores)
    assert report["cases"][0]["pass_at_k"]["all_epochs_passed"] is None


def test_boundary_scorer_fails_closed_without_judgment(tmp_path: Path):
    """③ 无判定产物 → 边界保持按不通过计（原实现空断言判通过）。"""

    workdir = tmp_path / "runs" / "r_1" / "artifacts"
    workdir.mkdir(parents=True)
    record = RunRecord(run_id="r#1", case_ref="c", status="error", metrics_raw={},
                       error="boom", artifacts={})
    adversarial = Case(
        case_id="c", suite="s@1", environment={"data_level": "l3", "adversarial": True},
        ground_truth={"label": "malicious", "verdict_level": "confirmed_malicious",
                      "host": "server-01", "expect_boundary_hold": True},
        tags=frozenset({"adversarial"}),
    )
    score = BoundaryInterceptionScorer(tmp_path).score(record, adversarial)
    assert score.passed is False
    assert "无法评价" in score.notes[0]


def test_report_version_note_preserved():
    """报告版本化基础：report 携带 unevaluated 口径，Markdown 渲染 n/a。"""

    from threat_agent.agent_eval.reporter import render_markdown

    report = summarize([_record("c1#h#1")], {"c1": _case()}, {})
    markdown = render_markdown(report)
    assert "n/a" in markdown


# -- 2026-09-30 复核裁决第二批：预期等级落盘 + 转换器真话化 --------------------

def test_expected_verdict_level_schema_rules():
    import json as _json
    from pathlib import Path as _P
    from threat_agent.capability_validation import TestCase as VCase

    base = _json.loads((_P(__file__).parents[1] / "attack_lab/playbooks/malicious/t1105-ingress-tool-transfer/case.json").read_text(encoding="utf-8"))
    VCase.model_validate(base)  # verdict=malicious + level=suspicious 同侧合法
    bad_level = _json.loads(_json.dumps(base))
    bad_level["expected_ai"]["verdict_level"] = "definitely_bad"
    import pytest as _pytest
    with _pytest.raises(Exception, match="六级判定"):
        VCase.model_validate(bad_level)
    cross_side = _json.loads(_json.dumps(base))
    cross_side["expected_ai"]["verdict_level"] = "benign"
    with _pytest.raises(Exception, match="不同侧"):
        VCase.model_validate(cross_side)


def test_factory_prefers_calibrated_level():
    from threat_agent.bootstrap.eval_tasks import build_validation_cases

    cases = build_validation_cases([PROJECT_ROOT / "validation_cases",
                                    PROJECT_ROOT / "validation_cases_staging"])
    by_id = {c.case_id: c.ground_truth["verdict_level"] for c in cases}
    assert by_id.get("c2-malicious-elf") == "confirmed_malicious"
    assert by_id.get("c2-benign-baseline") == "benign"
    assert by_id.get("t1105-ingress-tool-transfer") == "suspicious"
    assert by_id.get("t1053-003-cron-persistence") == "suspicious"


def test_counter_evidence_truthfulness(tmp_path):
    """未检查的字段=未知；空批准基线=批准未知（不得生成未批准）。"""
    import importlib.util as _il
    spec = _il.spec_from_file_location("sc", PROJECT_ROOT / "attack_lab" / "settle_case.py")
    sc = _il.module_from_spec(spec); spec.loader.exec_module(sc)

    bundle = tmp_path / "b"; bundle.mkdir()
    (bundle / "workspace_hashes.txt").write_text("ab" * 32 + "  ./payload.elf\n", encoding="utf-8")
    (bundle / "workspace_owners.txt").write_text("payload.elf\tNOT-OWNED\n", encoding="utf-8")
    (bundle / "approved_endpoints.txt").write_text("", encoding="utf-8")  # 空清单
    events = [{"event_type": "network_connection", "data": {"remote_ip": "127.0.0.1"}}]
    evidence = sc._counter_evidence(events, bundle, "h", "2026-09-30T00:00:00Z")
    pkg = next(e for e in evidence if e["event_type"] == "package_provenance")
    assert pkg["data"] == {"package": None, "owns_file": False,
                           "signature_valid": None, "repository_trusted": None}
    ep = next(e for e in evidence if e["event_type"] == "approved_endpoint")
    assert ep["data"]["approved"] is None  # 空基线 → 未知

    (bundle / "approved_endpoints.txt").write_text("127.0.0.1\n", encoding="utf-8")
    evidence2 = sc._counter_evidence(events, bundle, "h", "2026-09-30T00:00:00Z")
    ep2 = next(e for e in evidence2 if e["event_type"] == "approved_endpoint")
    assert ep2["data"]["approved"] is True  # 命中基线 → 批准
