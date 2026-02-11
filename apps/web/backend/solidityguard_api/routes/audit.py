"""Routes for /api/audit — audit lifecycle management."""

import json
import logging
import os
import tempfile

from fastapi import APIRouter, HTTPException, Request, UploadFile, File, Form, WebSocket, WebSocketDisconnect

from solidityguard_api.routes.auth import get_current_user
from solidityguard_api.models.schemas import (
    AuditMode,
    AuditReport,
    AuditRequest,
    AuditStatus,
    AuditStatusEnum,
    Finding,
)
from solidityguard_api.services.audit_manager import audit_manager
from solidityguard_api.services.scanner import generate_report_pdf
from solidityguard_api.websocket import ws_manager

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/api/audit", response_model=AuditStatus)
async def start_audit(
    request: Request,
    files: list[UploadFile] | None = File(default=None),
    path: str | None = Form(default=None),
    mode: str = Form(default="standard"),
    tools: str = Form(default="pattern"),
):
    """Start a new audit. Requires Google OAuth authentication."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Sign in with Google to submit contracts for audit")
    # Frontend may send tools as JSON array '["pattern","slither"]' or CSV 'pattern,slither'
    try:
        tool_list = json.loads(tools) if tools.startswith("[") else [t.strip() for t in tools.split(",")]
    except (json.JSONDecodeError, TypeError):
        tool_list = [t.strip() for t in tools.split(",")]
    logger.info("Audit request: mode=%s tools=%s files=%d", mode, tool_list, len(files) if files else 0)
    audit_mode = AuditMode(mode)
    temp_dir = None

    if files:
        # Save uploaded files to a temp directory
        temp_dir = tempfile.mkdtemp(prefix="solidityguard_")
        for f in files:
            if not f.filename:
                continue
            # Sanitize: strip leading slashes / ../ to prevent path traversal
            safe_name = os.path.normpath(f.filename).lstrip(os.sep)
            if safe_name.startswith(".."):
                continue
            dest = os.path.join(temp_dir, safe_name)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            try:
                content = await f.read()
                with open(dest, "wb") as out:
                    out.write(content)
            except Exception as exc:
                logger.warning("Failed to save uploaded file %s: %s", f.filename, exc)
        target_path = temp_dir
    elif path:
        if not os.path.exists(path):
            raise HTTPException(status_code=400, detail=f"Path does not exist: {path}")
        target_path = path
    else:
        raise HTTPException(status_code=400, detail="Provide either 'files' or 'path'")

    audit_id = audit_manager.create_audit(target_path, audit_mode, tool_list, temp_dir=temp_dir)
    audit_manager.start_audit(audit_id)

    state = audit_manager.get_state(audit_id)
    return state.to_status()


@router.post("/api/audit/json", response_model=AuditStatus)
async def start_audit_json(request: AuditRequest):
    """Start a new audit via JSON body with a local path."""
    if not request.path:
        raise HTTPException(status_code=400, detail="'path' is required")
    if not os.path.exists(request.path):
        raise HTTPException(status_code=400, detail=f"Path does not exist: {request.path}")

    audit_id = audit_manager.create_audit(
        request.path, request.mode, request.tools
    )
    audit_manager.start_audit(audit_id)
    state = audit_manager.get_state(audit_id)
    return state.to_status()


@router.get("/api/audit/{audit_id}", response_model=AuditStatus)
async def get_audit_status(audit_id: str):
    state = audit_manager.get_state(audit_id)
    if not state:
        raise HTTPException(status_code=404, detail="Audit not found")
    return state.to_status()


@router.get("/api/audit/{audit_id}/findings", response_model=list[Finding])
async def get_audit_findings(
    audit_id: str,
    severity: str | None = None,
    category: str | None = None,
):
    state = audit_manager.get_state(audit_id)
    if not state:
        raise HTTPException(status_code=404, detail="Audit not found")

    findings = state.findings
    if severity:
        findings = [f for f in findings if f.severity == severity.upper()]
    if category:
        findings = [f for f in findings if f.category == category]
    return findings


@router.get("/api/audit/{audit_id}/report", response_model=AuditReport)
async def get_audit_report(audit_id: str):
    state = audit_manager.get_state(audit_id)
    if not state:
        raise HTTPException(status_code=404, detail="Audit not found")
    if state.status != AuditStatusEnum.complete:
        raise HTTPException(status_code=409, detail="Audit not yet complete")

    counts = state.to_status().findings_count
    return AuditReport(
        id=state.id,
        score=state.score,
        summary=counts,
        findings=state.findings,
        tools_used=state.tools,
        report_markdown=state.report_markdown,
        timestamp=state.started_at,
    )


@router.get("/api/audit/{audit_id}/report/pdf")
async def get_audit_report_pdf(audit_id: str):
    """Generate and download a styled PDF audit report."""
    from fastapi.responses import Response
    from pathlib import Path

    state = audit_manager.get_state(audit_id)
    if not state:
        raise HTTPException(status_code=404, detail="Audit not found")
    if state.status != AuditStatusEnum.complete:
        raise HTTPException(status_code=409, detail="Audit not yet complete")

    pdf_bytes = generate_report_pdf(
        state.findings,
        project=Path(state.target_path).name,
        tools_used=state.tools,
    )
    if not pdf_bytes:
        raise HTTPException(status_code=500, detail="PDF generation failed. weasyprint may not be installed.")

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="audit-report-{audit_id[:8]}.pdf"'},
    )


@router.websocket("/api/audit/{audit_id}/stream")
async def audit_stream(websocket: WebSocket, audit_id: str):
    state = audit_manager.get_state(audit_id)
    if not state:
        await websocket.close(code=4004, reason="Audit not found")
        return

    await ws_manager.connect(audit_id, websocket)
    try:
        while True:
            # Keep connection alive; client can send pings
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.disconnect(audit_id, websocket)
