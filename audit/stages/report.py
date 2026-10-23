"""Stage 8: Report — schema-validated final document."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from audit.runner import (AgentRunError, PromptTooLongError, TransientAgentError,
                          run_agent)
from audit.state import StateDB
from audit.stages._common import StageContext

log = logging.getLogger(__name__)

# One agent call can't hold a whole run's findings: a real-world run with
# 149 reachable findings produced ~1.8M chars of input. Keep each call well
# inside the context window and within what the model can rewrite in one
# output.
BATCH_MAX_FINDINGS = 10
BATCH_MAX_CHARS = 120_000


async def run_report(ctx: StageContext, db: StateDB) -> Path:
    reachable = db.get_reachable_canonical_findings(ctx.run_id)
    ready = []
    for f, trace in reachable:
        ready.append({
            "finding": f.raw_json,
            "validation": f.validation_json,
            "trace": trace,
            "variants": _group_members_excluding(db, ctx.run_id, f.group_id, f.finding_id)
                       if f.group_id else [],
        })

    sc = ctx.stage("report")
    target = {"repo_path": str(ctx.repo_path)}

    out_path = ctx.results_dir("report") / "report.json"

    if not ready:
        # No reachable findings — emit a minimal empty report without burning an agent call.
        empty = {
            "run_id": ctx.run_id,
            "target": target,
            "summary": {"total": 0, "by_severity": {}},
            "findings": [],
        }
        out_path.write_text(json.dumps(empty, indent=2))
        log.info("[%s] report: no reachable findings — wrote empty report to %s",
                 ctx.run_id, out_path)
        return out_path

    batches = _batch(list(zip(ready, reachable)))
    log.info("[%s] report: %d findings in %d batch(es)",
             ctx.run_id, len(ready), len(batches))
    findings_out: list[dict] = []
    for i, batch in enumerate(batches, 1):
        findings_out.extend(
            await _report_batch(ctx, db, sc, target, batch, f"report_agent_{i:03d}"))

    report = {
        "run_id": ctx.run_id,
        "target": target,
        "summary": _summarize(findings_out),
        "findings": findings_out,
    }
    out_path.write_text(json.dumps(report, indent=2))
    log.info("[%s] report: %d findings written to %s",
             ctx.run_id, len(findings_out), out_path)
    return out_path


def _batch(items: list[tuple[dict, tuple]]) -> list[list[tuple[dict, tuple]]]:
    """Split findings into batches small enough for one agent call — both
    the input (context window) and the output (every finding is rewritten)."""
    batches: list[list[tuple[dict, tuple]]] = []
    cur: list[tuple[dict, tuple]] = []
    cur_chars = 0
    for item in items:
        size = len(json.dumps(item[0], ensure_ascii=False))
        if cur and (len(cur) >= BATCH_MAX_FINDINGS or cur_chars + size > BATCH_MAX_CHARS):
            batches.append(cur)
            cur, cur_chars = [], 0
        cur.append(item)
        cur_chars += size
    if cur:
        batches.append(cur)
    return batches


async def _report_batch(ctx: StageContext, db: StateDB, sc, target: dict,
                        batch: list[tuple[dict, tuple]], name: str) -> list[dict]:
    """Report one batch; halve it on context overflow, fall back to the
    mechanical report for that batch on any other failure."""
    user_input = {"run_id": ctx.run_id, "target": target,
                  "ready_findings": [r for r, _ in batch], **ctx.extras()}
    try:
        result = await run_agent(
            stage="report",
            prompt_file=ctx.prompt("08-report"),
            user_input=user_input,
            schema_file=ctx.schema("report"),
            allowed_tools=sc.tools,
            model=sc.model,
            cwd=ctx.repo_path,
            add_dirs=[ctx.repo_path],
            max_turns=sc.max_turns,
            permission_mode=sc.permission_mode,
            artifact_dir=ctx.results_dir("report"),
            artifact_name=name,
            repair_attempts=max(sc.repair_attempts, 2),  # report MUST validate
        )
    except PromptTooLongError as e:
        if len(batch) > 1:
            mid = len(batch) // 2
            log.warning("[%s] report %s: prompt too long — splitting %d findings",
                        ctx.run_id, name, len(batch))
            return (await _report_batch(ctx, db, sc, target, batch[:mid], name + "a")
                    + await _report_batch(ctx, db, sc, target, batch[mid:], name + "b"))
        log.error("[%s] report %s failed: %s — using fallback for this finding",
                  ctx.run_id, name, e)
        return _build_fallback_findings([r for _, r in batch])
    except (AgentRunError, TransientAgentError) as e:
        log.error("[%s] report %s failed: %s — using fallback for %d findings",
                  ctx.run_id, name, e, len(batch))
        return _build_fallback_findings([r for _, r in batch])

    db.record_cost(ctx.run_id, "report", None, result.raw_result_message)
    db.add_artifact(ctx.run_id, "report", None, "jsonl", str(result.artifact_path))
    return result.payload.get("findings", [])


def _summarize(findings: list[dict]) -> dict:
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {"total": len(findings), "by_severity": by_sev}


def _group_members_excluding(db: StateDB, run_id: str, group_id: str,
                             exclude: str) -> list[str]:
    rows = db._conn.execute(  # type: ignore[attr-defined]
        "SELECT finding_id FROM findings WHERE run_id = ? AND group_id = ? AND finding_id != ?",
        (run_id, group_id, exclude),
    ).fetchall()
    return [r["finding_id"] for r in rows]


def _build_fallback_findings(reachable) -> list[dict]:
    findings_out = []
    for f, trace in reachable:
        findings_out.append({
            "finding_id": f.finding_id,
            "title": f"{f.vuln_class} in {f.file}",
            "severity": f.severity,
            "vuln_class": f.vuln_class,
            "file": f.file,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "description": f.description,
            "evidence": f.evidence,
            "trace": {
                "entry_points": trace.get("entry_points", []),
                "call_chain": trace.get("call_chain", []),
            },
            "recommendation": "Review the sink and add input validation / use a safe API.",
        })
    return findings_out
