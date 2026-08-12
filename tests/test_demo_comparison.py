from fastapi.testclient import TestClient

from threat_agent.bootstrap.demo import build_all_comparisons
from threat_agent.bootstrap.settings import AppSettings
from threat_agent.presentation import InMemoryCaseReadStore, InMemoryDemoComparisonStore
from threat_agent.presentation.api.routes import create_app


class FakeRunService:
    def start(self, dataset_id, profile_id):
        assert dataset_id == "c2-benign-reference"
        assert profile_id == "l3-attribution-and-assets"
        return "ai-test"

    def get(self, run_id):
        if run_id != "ai-test":
            return None
        return {
            "run_id": run_id,
            "status": "running",
            "events": [{"sequence": 1, "kind": "thinking", "message": "planning"}],
            "result": None,
            "error": None,
        }


def test_full_demo_proves_data_quality_changes_judgment(tmp_path):
    settings = AppSettings.load(
        environ={
            "THREAT_AGENT_MODE": "deterministic",
            "DEMO_DATA_STORE_PATH": str(tmp_path / "reference.sqlite"),
            "DEMO_DATASET_VERSION": "2026.08.1",
        },
        env_file=tmp_path / "missing.env",
    )
    comparisons = build_all_comparisons(settings)
    malicious = comparisons["c2-malicious-reference"]
    benign = comparisons["c2-benign-reference"]
    assert [len(item.readiness.answerable_questions) for item in malicious.profiles] == [0, 2, 4, 5]
    assert [item.case.judgment.verdict.level.value for item in malicious.profiles] == [
        "insufficient_evidence", "insufficient_evidence", "confirmed_malicious", "confirmed_malicious"
    ]
    assert [item.case.judgment.verdict.level.value for item in benign.profiles] == [
        "insufficient_evidence", "insufficient_evidence", "likely_malicious", "benign"
    ]
    assert malicious.fixed_conditions["rag_adapter"] == "null"

    app = create_app(InMemoryCaseReadStore(), InMemoryDemoComparisonStore(comparisons))
    client = TestClient(app)
    api = client.get("/api/demo/c2-benign-reference")
    assert api.status_code == 200
    assert len(api.json()["profiles"]) == 4
    page = client.get("/demo/c2-benign-reference")
    assert page.status_code == 200
    assert "从一条告警，到可执行的安全决策" in page.text
    assert "l3-attribution-and-assets" in page.text


def test_demo_page_can_start_and_observe_ai_run(tmp_path):
    settings = AppSettings.load(
        environ={
            "THREAT_AGENT_MODE": "deterministic",
            "DEMO_DATA_STORE_PATH": str(tmp_path / "reference.sqlite"),
            "DEMO_DATASET_VERSION": "2026.08.1",
        },
        env_file=tmp_path / "missing.env",
    )
    comparisons = build_all_comparisons(settings)
    client = TestClient(create_app(
        InMemoryCaseReadStore(), InMemoryDemoComparisonStore(comparisons), FakeRunService()
    ))
    started = client.post(
        "/api/demo/c2-benign-reference/runs",
        json={"profile_id": "l3-attribution-and-assets"},
    )
    assert started.status_code == 200
    observed = client.get("/api/demo/runs/ai-test")
    assert observed.status_code == 200
    assert observed.json()["events"][0]["kind"] == "thinking"
    page = client.get("/demo/c2-benign-reference")
    assert "启动 AI 全流程调查" in page.text
    assert "事件与当前态势" in page.text
    assert "数据与证据条件" in page.text
    assert "AI 分析与输出" in page.text
    assert "确认良性" in page.text
    assert "这个未知文件是否真的运行过" in page.text
    assert "确认文件是否执行" in page.text
    assert "查看本级数据来源" in page.text
    assert "表现出相似行为" in page.text
    assert "理解告警" in page.text
    assert "研判报告" in page.text
    assert "处置方案" in page.text
    assert "数据接入诉求" in page.text
    assert "需要持续收集" in page.text
    assert "本次测试提供" in page.text
    assert "最低字段" in page.text
    assert "时效要求" in page.text
    assert "影响评估与结论边界" in page.text
    assert "合法性反证" in page.text
    assert "查看结构化记录" not in page.text
