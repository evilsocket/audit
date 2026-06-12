from __future__ import annotations

import json
from pathlib import Path

from audit.dashboard.queries import get_run_metrics, get_runs, get_stage_models
from audit.state import StateDB


def _finding(finding_id: str, severity: str = "high") -> dict:
    return {
        "finding_id": finding_id,
        "file": "app.py",
        "line_start": 1,
        "line_end": 5,
        "vuln_class": "open_redirect",
        "severity": severity,
        "description": "A test finding with enough detail to satisfy schema-like expectations.",
        "evidence_snippet": "window.location.assign(userControlledUrl)",
        "confidence": 0.9,
    }


def _task(task_id: str) -> dict:
    return {
        "task_id": task_id,
        "source": "recon",
        "attack_class": "open_redirect",
        "scope_hint": "HTTP route passes user-controlled redirect target to browser navigation.",
        "target_files": ["app.py"],
        "rationale": "User-controlled redirect handling should be reviewed.",
        "priority": 1,
    }


def test_get_runs_does_not_multiply_costs(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    db = StateDB(db_path)

    run_id = db.create_run("/tmp/repo", "r1")

    db.add_task(run_id, _task("t_one"))
    db.add_task(run_id, _task("t_two"))

    db.add_finding(run_id, "t_one", _finding("f_one", "high"))
    db.set_finding_validation(
        "f_one",
        "confirmed",
        {
            "finding_id": "f_one",
            "verdict": "confirmed",
            "rationale": "Confirmed in test.",
            "validator_confidence": 0.9,
        },
    )
    db.assign_finding_group("f_one", "g_one", True)
    db.add_trace(
        "f_one",
        {
            "finding_id": "f_one",
            "reachable": True,
            "confidence": 0.9,
            "rationale": "Reachable in test.",
        },
    )

    db.add_finding(run_id, "t_two", _finding("f_two", "medium"))
    db.set_finding_validation(
        "f_two",
        "rejected",
        {
            "finding_id": "f_two",
            "verdict": "rejected",
            "rationale": "Rejected in test.",
            "validator_confidence": 0.9,
        },
    )

    db.record_cost(
        run_id,
        "hunt",
        "t_one",
        {
            "total_cost_usd": 1.25,
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
            },
        },
    )
    db.record_cost(
        run_id,
        "validate",
        "f_one",
        {
            "total_cost_usd": 2.75,
            "usage": {
                "input_tokens": 30,
                "output_tokens": 40,
            },
        },
    )
    db.close()

    runs = get_runs(db_path)
    assert len(runs) == 1

    row = runs[0]
    assert row["run_id"] == "r1"
    assert row["task_count"] == 2
    assert row["final_validated_finding_count"] == 1
    assert row["high_count"] == 1
    assert row["medium_count"] == 0
    assert row["total_cost_usd"] == 4.0


def test_stage_models_are_read_from_jsonl_artifacts(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    db = StateDB(db_path)

    run_id = db.create_run("/tmp/repo", "r1")

    artifact = tmp_path / "results" / "r1" / "recon" / "recon.jsonl"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(
        json.dumps(
            {
                "kind": "meta",
                "stage": "recon",
                "model": "claude-opus-4-7",
            }
        )
        + "\n"
    )

    db.add_artifact(run_id, "recon", None, "jsonl", str(artifact))
    db.close()

    assert get_stage_models(db_path, run_id) == {
        "recon": "claude-opus-4-7",
    }


def test_get_run_metrics_includes_models_and_stage_order(tmp_path: Path) -> None:
    db_path = tmp_path / "state.db"
    db = StateDB(db_path)

    run_id = db.create_run("/tmp/repo", "r1")
    db.record_cost(
        run_id,
        "hunt",
        "t_one",
        {
            "total_cost_usd": 1.25,
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
            },
        },
    )

    artifact = tmp_path / "results" / "r1" / "hunt" / "t_one.jsonl"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(
        json.dumps(
            {
                "kind": "meta",
                "stage": "hunt",
                "model": "claude-sonnet-4-6",
            }
        )
        + "\n"
    )

    db.add_artifact(run_id, "hunt", "t_one", "jsonl", str(artifact))
    db.close()

    metrics = get_run_metrics(db_path, run_id)
    costs = metrics["costs"]

    assert len(costs) == 1
    assert costs[0]["stage"] == "hunt"
    assert costs[0]["stage_order"] == 2
    assert costs[0]["model"] == "claude-sonnet-4-6"
    assert costs[0]["calls"] == 1
    assert costs[0]["cost_usd"] == 1.25