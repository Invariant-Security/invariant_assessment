"""Thin FastAPI wrapper over invariant_assessment's own evaluation engine
(CHECKS/document_slug_for_os) -- exposes exactly the shape invariant_api's
routes/assess.py needs, and nothing else. No Postgres here, ever: this
service only knows "which check titles passed/failed, with what
evidence" -- turning that into a real Finding (external_id, remediation,
CIS level/scored) is invariant_api's job, which owns the database.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from invariant_assessment import CHECKS, document_slug_for_os
from invariant_assessment.facts import collect_facts
from invariant_assessment.observability import timed

app = FastAPI(title="Invariant Assessment")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


class CheckResult(BaseModel):
    titles: list[str]
    status: str
    evidence: str


class RunResponse(BaseModel):
    document: str
    results: list[CheckResult]


@app.post("/assessment/run", response_model=RunResponse)
def run_assessment(target: str) -> RunResponse:
    """One `docker exec` (collect_facts) against `target`, then every
    CHECKS entry evaluated against that single snapshot. `target` is a
    query param (not a body) since it's the only input -- matches how
    lightweight this call is meant to stay.
    """
    with timed(f"collect_facts:{target}"):
        facts = collect_facts(target)

    if not facts.os_id or not facts.os_version_id:
        raise HTTPException(422, f"could not detect OS for target {target!r}")
    document = document_slug_for_os(facts.os_id, facts.os_version_id)

    results = [
        CheckResult(
            titles=check.titles,
            status="PASS" if check.evaluate(facts) else "FAIL",
            evidence=check.evidence(facts),
        )
        for check in CHECKS
    ]
    return RunResponse(document=document, results=results)
