from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_ROOT = REPO_ROOT / "results"


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(r) for r in rows]


def _dedupe_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    out: list[Path] = []

    for path in paths:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        out.append(path)

    return out


def artifact_path_candidates(path: str) -> list[Path]:
    """Return possible local paths for an artifact.

    Artifact paths are recorded at scan time. If state.db and results/ are later
    copied into another clone, the recorded absolute path can point to the old
    clone. When that happens, recover by preserving the suffix from results/.
    """
    raw = Path(path)
    candidates: list[Path] = []

    if raw.is_absolute():
        candidates.append(raw)
    else:
        candidates.append(REPO_ROOT / raw)
        candidates.append(raw)

    parts = raw.parts
    if "results" in parts:
        idx = parts.index("results")
        candidates.append(REPO_ROOT.joinpath(*parts[idx:]))

    return _dedupe_paths(candidates)


def read_artifact_model(path: str) -> str | None:
    """Read the model from a JSONL artifact.

    The runner writes a metadata row like:
    {"kind": "meta", "stage": "...", "model": "..."}

    If that row is unavailable, fall back to the first assistant row model in
    the same artifact. This still reflects the actual model used by the run.
    """
    fallback_model: str | None = None

    for artifact_path in artifact_path_candidates(path):
        if not artifact_path.exists() or not artifact_path.is_file():
            continue

        try:
            with artifact_path.open("r", encoding="utf-8", errors="replace") as fp:
                for idx, line in enumerate(fp):
                    if idx > 100:
                        break

                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    model = obj.get("model")
                    if obj.get("kind") == "meta" and model:
                        return str(model)

                    if fallback_model is None and model:
                        fallback_model = str(model)
        except OSError:
            continue

    return fallback_model


def get_stage_models_from_artifacts_table(db_path: Path, run_id: str) -> dict[str, set[str]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT stage, path
            FROM artifacts
            WHERE run_id = ?
              AND kind = 'jsonl'
            ORDER BY stage, ref_id, created_at
            """,
            (run_id,),
        ).fetchall()

    models_by_stage: dict[str, set[str]] = {}

    for row in rows:
        model = read_artifact_model(row["path"])
        if not model:
            continue
        models_by_stage.setdefault(row["stage"], set()).add(model)

    return models_by_stage


def get_stage_models_from_results_dir(run_id: str) -> dict[str, set[str]]:
    """Recover model usage by scanning results/<run-id>/**/*.jsonl directly."""
    run_results = RESULTS_ROOT / run_id
    if not run_results.exists():
        return {}

    models_by_stage: dict[str, set[str]] = {}

    for artifact_path in sorted(run_results.rglob("*.jsonl")):
        try:
            relative = artifact_path.relative_to(run_results)
        except ValueError:
            continue

        if not relative.parts:
            continue

        stage = relative.parts[0]
        model = read_artifact_model(str(artifact_path))
        if not model:
            continue

        models_by_stage.setdefault(stage, set()).add(model)

    return models_by_stage


def get_stage_models(db_path: Path, run_id: str) -> dict[str, str]:
    """Return stage -> model name(s) for a run.

    Uses only scan artifacts, not current config, so it reflects what actually
    ran. First tries the artifacts table. Then scans results/<run-id>/ directly.
    """
    models_by_stage = get_stage_models_from_artifacts_table(db_path, run_id)

    direct_models = get_stage_models_from_results_dir(run_id)
    for stage, models in direct_models.items():
        models_by_stage.setdefault(stage, set()).update(models)

    return {
        stage: ", ".join(sorted(models))
        for stage, models in models_by_stage.items()
    }


def get_runs(db_path: Path) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT
              r.run_id,
              r.repo_path,
              r.status,
              r.started_at,
              r.finished_at,
              COALESCE(costs.total_cost_usd, 0) AS total_cost_usd,
              COALESCE(tasks.task_count, 0) AS task_count,
              COALESCE(final_findings.final_validated_finding_count, 0) AS final_validated_finding_count,
              COALESCE(final_findings.critical_count, 0) AS critical_count,
              COALESCE(final_findings.high_count, 0) AS high_count,
              COALESCE(final_findings.medium_count, 0) AS medium_count,
              COALESCE(final_findings.low_count, 0) AS low_count,
              COALESCE(final_findings.informational_count, 0) AS informational_count
            FROM runs r
            LEFT JOIN (
              SELECT
                run_id,
                COALESCE(SUM(usd), 0) AS total_cost_usd
              FROM costs
              GROUP BY run_id
            ) costs ON costs.run_id = r.run_id
            LEFT JOIN (
              SELECT
                run_id,
                COUNT(*) AS task_count
              FROM tasks
              GROUP BY run_id
            ) tasks ON tasks.run_id = r.run_id
            LEFT JOIN (
              SELECT
                f.run_id,
                COUNT(*) AS final_validated_finding_count,
                SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_count,
                SUM(CASE WHEN f.severity = 'high' THEN 1 ELSE 0 END) AS high_count,
                SUM(CASE WHEN f.severity = 'medium' THEN 1 ELSE 0 END) AS medium_count,
                SUM(CASE WHEN f.severity = 'low' THEN 1 ELSE 0 END) AS low_count,
                SUM(CASE WHEN f.severity = 'informational' THEN 1 ELSE 0 END) AS informational_count
              FROM findings f
              JOIN traces tr ON tr.finding_id = f.finding_id
              WHERE f.validation_status = 'confirmed'
                AND f.is_canonical = 1
                AND tr.reachable = 1
              GROUP BY f.run_id
            ) final_findings ON final_findings.run_id = r.run_id
            ORDER BY r.started_at DESC
            """
        ).fetchall()

    return rows_to_dicts(rows)


def get_run(db_path: Path, run_id: str) -> dict[str, Any] | None:
    with connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT
              r.run_id,
              r.repo_path,
              r.status,
              r.started_at,
              r.finished_at,
              COALESCE(costs.total_cost_usd, 0) AS total_cost_usd
            FROM runs r
            LEFT JOIN (
              SELECT
                run_id,
                COALESCE(SUM(usd), 0) AS total_cost_usd
              FROM costs
              GROUP BY run_id
            ) costs ON costs.run_id = r.run_id
            WHERE r.run_id = ?
            """,
            (run_id,),
        ).fetchone()

    return dict(row) if row else None


def get_run_metrics(db_path: Path, run_id: str) -> dict[str, Any]:
    with connect(db_path) as conn:
        task_rows = conn.execute(
            """
            SELECT status, COUNT(*) AS count
            FROM tasks
            WHERE run_id = ?
            GROUP BY status
            """,
            (run_id,),
        ).fetchall()

        finding_rows = conn.execute(
            """
            SELECT
              COUNT(*) AS raw,
              SUM(CASE WHEN validation_status = 'confirmed' THEN 1 ELSE 0 END) AS confirmed,
              SUM(CASE WHEN is_canonical = 1 THEN 1 ELSE 0 END) AS canonical
            FROM findings
            WHERE run_id = ?
            """,
            (run_id,),
        ).fetchone()

        reachable_row = conn.execute(
            """
            SELECT COUNT(*) AS reachable
            FROM findings f
            JOIN traces tr ON tr.finding_id = f.finding_id
            WHERE f.run_id = ?
              AND f.validation_status = 'confirmed'
              AND f.is_canonical = 1
              AND tr.reachable = 1
            """,
            (run_id,),
        ).fetchone()

        cost_rows = conn.execute(
            """
            SELECT
              stage,
              CASE stage
                WHEN 'recon' THEN 1
                WHEN 'hunt' THEN 2
                WHEN 'validate' THEN 3
                WHEN 'gapfill' THEN 4
                WHEN 'dedupe' THEN 5
                WHEN 'trace' THEN 6
                WHEN 'feedback' THEN 7
                WHEN 'report' THEN 8
                ELSE 99
              END AS stage_order,
              COUNT(*) AS calls,
              COALESCE(SUM(usd), 0) AS cost_usd,
              COALESCE(SUM(input_tokens), 0) AS input_tokens,
              COALESCE(SUM(output_tokens), 0) AS output_tokens
            FROM costs
            WHERE run_id = ?
            GROUP BY stage
            ORDER BY stage_order, stage
            """,
            (run_id,),
        ).fetchall()

    tasks_by_status = {r["status"]: r["count"] for r in task_rows}
    model_by_stage = get_stage_models(db_path, run_id)

    costs = rows_to_dicts(cost_rows)
    for row in costs:
        row["model"] = model_by_stage.get(row["stage"], "")

    return {
        "tasks": tasks_by_status,
        "findings": {
            "raw": finding_rows["raw"] or 0,
            "confirmed": finding_rows["confirmed"] or 0,
            "canonical": finding_rows["canonical"] or 0,
            "reachable": reachable_row["reachable"] or 0,
        },
        "costs": costs,
    }


def get_tasks(db_path: Path, run_id: str) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT
              task_id,
              source,
              attack_class,
              priority,
              status,
              target_files,
              rationale,
              created_at,
              updated_at
            FROM tasks
            WHERE run_id = ?
            ORDER BY priority, created_at
            """,
            (run_id,),
        ).fetchall()

    out = rows_to_dicts(rows)

    for row in out:
        try:
            row["target_files"] = json.loads(row["target_files"])
        except Exception:
            row["target_files"] = [row["target_files"]]

    return out


def get_findings(db_path: Path, run_id: str) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT
              f.finding_id,
              f.task_id,
              f.file,
              f.line_start,
              f.line_end,
              f.vuln_class,
              f.severity,
              f.description,
              f.evidence,
              f.poc_succeeded,
              f.confidence,
              f.validation_status,
              f.group_id,
              f.is_canonical,
              tr.reachable,
              tr.confidence AS trace_confidence,
              tr.rationale AS trace_rationale
            FROM findings f
            LEFT JOIN traces tr ON tr.finding_id = f.finding_id
            WHERE f.run_id = ?
            ORDER BY
              CASE f.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
              END,
              f.file,
              f.line_start
            """,
            (run_id,),
        ).fetchall()

    return rows_to_dicts(rows)


def get_artifacts(db_path: Path, run_id: str) -> list[dict[str, Any]]:
    with connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT
              stage,
              ref_id,
              kind,
              path,
              created_at
            FROM artifacts
            WHERE run_id = ?
            ORDER BY stage, ref_id, kind
            """,
            (run_id,),
        ).fetchall()

    return rows_to_dicts(rows)


def get_report_path(results_root: Path, run_id: str) -> Path:
    return results_root / run_id / "report" / "report.json"