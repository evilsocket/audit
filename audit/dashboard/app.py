from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from audit.dashboard import queries


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = REPO_ROOT / "state.db"
RESULTS_ROOT = REPO_ROOT / "results"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_app(db_path: Path = DB_PATH, results_root: Path = RESULTS_ROOT) -> FastAPI:
    app = FastAPI(title="Security Audit Dashboard")

    app.mount(
        "/static",
        StaticFiles(directory=str(STATIC_DIR)),
        name="static",
    )

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    @app.get("/", response_class=HTMLResponse)
    def runs(request: Request):
        return templates.TemplateResponse(
            request=request,
            name="runs.html",
            context={
                "runs": queries.get_runs(db_path),
            },
        )

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_detail(request: Request, run_id: str):
        run = queries.get_run(db_path, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Unknown run_id")
        metrics = queries.get_run_metrics(db_path, run_id)
        return templates.TemplateResponse(
            request=request,
            name="run_detail.html",
            context={
                "run": run,
                "metrics": metrics,
            },
        )

    @app.get("/runs/{run_id}/tasks", response_class=HTMLResponse)
    def tasks(request: Request, run_id: str):
        run = queries.get_run(db_path, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Unknown run_id")
        return templates.TemplateResponse(
            request=request,
            name="tasks.html",
            context={
                "run": run,
                "tasks": queries.get_tasks(db_path, run_id),
            },
        )

    @app.get("/runs/{run_id}/findings", response_class=HTMLResponse)
    def findings(request: Request, run_id: str):
        run = queries.get_run(db_path, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Unknown run_id")
        return templates.TemplateResponse(
            request=request,
            name="findings.html",
            context={
                "run": run,
                "findings": queries.get_findings(db_path, run_id),
            },
        )

    @app.get("/runs/{run_id}/artifacts", response_class=HTMLResponse)
    def artifacts(request: Request, run_id: str):
        run = queries.get_run(db_path, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Unknown run_id")
        return templates.TemplateResponse(
            request=request,
            name="artifacts.html",
            context={
                "run": run,
                "artifacts": queries.get_artifacts(db_path, run_id),
            },
        )

    @app.get("/runs/{run_id}/report", response_class=HTMLResponse)
    def report(request: Request, run_id: str):
        run = queries.get_run(db_path, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Unknown run_id")

        report_path = queries.get_report_path(results_root, run_id)
        report = None
        if report_path.exists():
            report = json.loads(report_path.read_text())

        return templates.TemplateResponse(
            request=request,
            name="report.html",
            context={
                "run": run,
                "report": report,
                "report_path": report_path,
            },
        )

    @app.get("/api/runs")
    def api_runs():
        return {"runs": queries.get_runs(db_path)}

    @app.get("/api/runs/{run_id}")
    def api_run(run_id: str):
        run = queries.get_run(db_path, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Unknown run_id")
        return {
            "run": run,
            "metrics": queries.get_run_metrics(db_path, run_id),
            "tasks": queries.get_tasks(db_path, run_id),
            "findings": queries.get_findings(db_path, run_id),
            "artifacts": queries.get_artifacts(db_path, run_id),
        }

    @app.get("/artifacts/raw", response_class=PlainTextResponse)
    def raw_artifact(path: str):
        artifact_path = Path(path).resolve()

        allowed_roots = [
            (results_root).resolve(),
            (REPO_ROOT / "work").resolve(),
        ]

        if not any(str(artifact_path).startswith(str(root)) for root in allowed_roots):
            raise HTTPException(status_code=403, detail="Artifact path is outside allowed roots")

        if not artifact_path.exists() or not artifact_path.is_file():
            raise HTTPException(status_code=404, detail="Artifact not found")

        return artifact_path.read_text(errors="replace")

    return app


app = create_app()