"""Report stage batching — a run's findings are reported across several
agent calls and merged, so a large run can't overflow one prompt."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from audit.config import HarnessConfig, StageConfig
from audit.runner import AgentRunError, PromptTooLongError
from audit.stages import _common, report
from audit.stages._common import StageContext


def _finding(i: int, severity: str = "high") -> SimpleNamespace:
    return SimpleNamespace(
        finding_id=f"f_{i:03d}", group_id=None, severity=severity,
        vuln_class="idor", file="app.py", line_start=1, line_end=2,
        description="d" * 40, evidence="code",
        raw_json={"finding_id": f"f_{i:03d}", "severity": severity},
        validation_json={})


@pytest.fixture(autouse=True)
def _results_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(_common, "RESULTS", tmp_path / "results")


class _DB:
    def __init__(self, n: int) -> None:
        self.reachable = [(_finding(i), {"reachable": True, "entry_points": [],
                                         "call_chain": []}) for i in range(n)]
        self.costs = 0

    def get_reachable_canonical_findings(self, run_id):
        return self.reachable

    def record_cost(self, *a):
        self.costs += 1

    def add_artifact(self, *a):
        pass


def _ctx(tmp_path: Path) -> StageContext:
    cfg = HarnessConfig(stages={"report": StageConfig(
        name="report", model="x", concurrency=1, tools=["Read"],
        max_turns=10, permission_mode="default", repair_attempts=0)})
    return StageContext(run_id="r", repo_path=tmp_path, config=cfg)


def _echo_agent(calls: list[int], fail=lambda batch: None):
    async def fake(**kw):
        batch = kw["user_input"]["ready_findings"]
        calls.append(len(batch))
        if (exc := fail(batch)) is not None:
            raise exc
        return SimpleNamespace(
            payload={"findings": [
                {"finding_id": r["finding"]["finding_id"],
                 "severity": r["finding"]["severity"]} for r in batch]},
            raw_result_message={}, artifact_path=Path("x"))
    return fake


async def test_findings_split_into_batches_and_merged(tmp_path, monkeypatch):
    calls: list[int] = []
    monkeypatch.setattr(report, "run_agent", _echo_agent(calls))
    db = _DB(25)
    out = json.loads((await report.run_report(_ctx(tmp_path), db)).read_text())
    assert calls == [10, 10, 5]
    assert [f["finding_id"] for f in out["findings"]] == [f"f_{i:03d}" for i in range(25)]
    assert out["summary"] == {"total": 25, "by_severity": {"high": 25}}


async def test_prompt_too_long_halves_batch(tmp_path, monkeypatch):
    calls: list[int] = []
    too_long = lambda b: PromptTooLongError("Prompt is too long") if len(b) > 3 else None
    monkeypatch.setattr(report, "run_agent", _echo_agent(calls, too_long))
    out = json.loads((await report.run_report(_ctx(tmp_path), _DB(10))).read_text())
    assert calls == [10, 5, 2, 3, 5, 2, 3]
    assert out["summary"]["total"] == 10


async def test_failed_batch_falls_back_without_losing_others(tmp_path, monkeypatch):
    calls: list[int] = []
    bad = lambda b: AgentRunError("schema") if b[0]["finding"]["finding_id"] == "f_010" else None
    monkeypatch.setattr(report, "run_agent", _echo_agent(calls, bad))
    out = json.loads((await report.run_report(_ctx(tmp_path), _DB(15))).read_text())
    assert out["summary"]["total"] == 15
    fallback = [f for f in out["findings"] if "recommendation" in f]
    assert [f["finding_id"] for f in fallback] == [f"f_{i:03d}" for i in range(10, 15)]


def test_batch_respects_char_budget(monkeypatch):
    monkeypatch.setattr(report, "BATCH_MAX_CHARS", 100)
    items = [({"x": "a" * 60}, None) for _ in range(4)]
    assert [len(b) for b in report._batch(items)] == [1, 1, 1, 1]
