"""Audit manager — runs audits in background threads and manages state."""

import logging
import uuid
import time
import threading
import shutil
from datetime import datetime, timezone
from pathlib import Path

from solidityguard_api.models.schemas import (
    AuditMode,
    AuditStatus,
    AuditStatusEnum,
    Finding,
    SeverityCounts,
)
from solidityguard_api.services.scanner import run_scan, generate_report_markdown, deduplicate_findings
from solidityguard_api.websocket import ws_manager

logger = logging.getLogger(__name__)


PHASE_NAMES = [
    "Entry Point Analysis",
    "Automated Scan",
    "Finding Verification",
    "Cross-Reference & Deduplication",
    "Confidence Scoring",
    "Threshold Filtering",
    "Report Generation",
]

# Confidence boost table when multiple tools agree
_MULTI_TOOL_BOOST = 0.10  # Two tools agree
_TRI_TOOL_BOOST = 0.15    # Three+ tools agree
_CONFIDENCE_CAP = 0.95
_CONFIDENCE_THRESHOLD = 0.70


class AuditState:
    """In-memory state for a single audit."""

    def __init__(self, audit_id: str, target_path: str, mode: AuditMode, tools: list[str]):
        self.id = audit_id
        self.target_path = target_path
        self.mode = mode
        self.tools = tools
        self.status = AuditStatusEnum.pending
        self.phase = 0
        self.total_phases = 7
        self.phase_name = PHASE_NAMES[0]
        self.progress = 0.0
        self.findings: list[Finding] = []
        self.started_at = datetime.now(timezone.utc)
        self.completed_at: datetime | None = None
        self.score: int = 100
        self.summary: dict = {}
        self.report_markdown: str = ""
        self.error: str | None = None
        self.temp_dir: str | None = None

    def to_status(self) -> AuditStatus:
        counts = SeverityCounts(
            critical=sum(1 for f in self.findings if f.severity == "CRITICAL"),
            high=sum(1 for f in self.findings if f.severity == "HIGH"),
            medium=sum(1 for f in self.findings if f.severity == "MEDIUM"),
            low=sum(1 for f in self.findings if f.severity == "LOW"),
            informational=sum(1 for f in self.findings if f.severity == "INFORMATIONAL"),
            total=len(self.findings),
        )
        return AuditStatus(
            id=self.id,
            status=self.status,
            phase=self.phase,
            total_phases=self.total_phases,
            phase_name=self.phase_name,
            progress=self.progress,
            findings_count=counts,
            started_at=self.started_at,
            completed_at=self.completed_at,
        )


class AuditManager:
    """Manages audit lifecycle, background execution, and WebSocket notifications."""

    def __init__(self):
        self._audits: dict[str, AuditState] = {}
        self._lock = threading.Lock()

    def create_audit(self, target_path: str, mode: AuditMode, tools: list[str], temp_dir: str | None = None) -> str:
        audit_id = str(uuid.uuid4())
        state = AuditState(audit_id, target_path, mode, tools)
        state.temp_dir = temp_dir
        with self._lock:
            self._audits[audit_id] = state
        return audit_id

    def get_state(self, audit_id: str) -> AuditState | None:
        return self._audits.get(audit_id)

    def start_audit(self, audit_id: str) -> None:
        state = self._audits.get(audit_id)
        if not state:
            return
        state.status = AuditStatusEnum.running
        thread = threading.Thread(target=self._run_audit, args=(audit_id,), daemon=True)
        thread.start()

    def _run_audit(self, audit_id: str) -> None:
        state = self._audits.get(audit_id)
        if not state:
            return

        try:
            # Phase 1: Entry Point Analysis — enumerate contract files
            self._update_phase(state, 1, 0.0)
            time.sleep(0.3)  # brief pause so frontend can connect and see Phase 1

            target = Path(state.target_path)
            sol_files = list(target.rglob("*.sol")) + list(target.rglob("*.vy"))
            total_files = len(sol_files)

            # Count public/external functions as entry points
            entry_points = 0
            for i, fpath in enumerate(sol_files):
                try:
                    content = fpath.read_text(errors="ignore")
                    for line in content.splitlines():
                        stripped = line.strip()
                        if stripped.startswith("function ") and ("external" in stripped or "public" in stripped):
                            entry_points += 1
                except Exception:
                    pass
                self._update_phase(state, 1, (i + 1) / max(total_files, 1))

            ws_manager.broadcast_sync(audit_id, {
                "type": "entry_points",
                "files": total_files,
                "entry_points": entry_points,
            })
            self._update_phase(state, 1, 1.0)

            # Phase 2: Automated scan (Slither + Aderyn + Mythril + pattern scanner)
            self._update_phase(state, 2, 0.0)

            # Run scan with progress updates per tool
            tool_list = state.tools
            all_findings: list = []
            for i, tool in enumerate(tool_list):
                self._update_phase(state, 2, i / max(len(tool_list), 1))
                try:
                    tool_findings = run_scan(state.target_path, [tool])
                    all_findings.extend(tool_findings)
                    logger.info("Tool %s returned %d findings", tool, len(tool_findings))
                except Exception:
                    logger.exception("Tool %s failed on %s", tool, state.target_path)

            state.findings = all_findings
            self._update_phase(state, 2, 1.0)

            # Broadcast each finding
            for f in state.findings:
                ws_manager.broadcast_sync(audit_id, {
                    "type": "finding",
                    "finding": f.model_dump(),
                })

            # Phase 3: Finding verification — generate verification prompts
            self._update_phase(state, 3, 0.0)
            verification_prompts = []
            for f in state.findings:
                if f.severity in ("CRITICAL", "HIGH"):
                    verification_prompts.append({
                        "finding_id": f.id,
                        "file": f.file,
                        "line": f.line,
                        "severity": f.severity,
                        "tool": f.tool,
                        "confidence": f.confidence,
                    })
            ws_manager.broadcast_sync(audit_id, {
                "type": "verification",
                "prompts_generated": len(verification_prompts),
            })
            self._update_phase(state, 3, 1.0)

            # Phase 4: Cross-reference & deduplication
            self._update_phase(state, 4, 0.0)
            before_count = len(state.findings)
            state.findings = deduplicate_findings(state.findings)
            after_count = len(state.findings)
            ws_manager.broadcast_sync(audit_id, {
                "type": "deduplication",
                "before": before_count,
                "after": after_count,
                "removed": before_count - after_count,
            })
            self._update_phase(state, 4, 1.0)

            # Phase 5: Confidence scoring with multi-tool boosting
            self._update_phase(state, 5, 0.0)
            boosted = 0
            for f in state.findings:
                if "[Confirmed by:" in f.description:
                    boosted += 1
            ws_manager.broadcast_sync(audit_id, {
                "type": "scoring",
                "total_findings": len(state.findings),
                "multi_tool_confirmed": boosted,
            })
            self._update_phase(state, 5, 1.0)

            # Phase 6: Threshold filtering — remove findings below confidence threshold
            self._update_phase(state, 6, 0.0)
            pre_filter = len(state.findings)
            state.findings = [
                f for f in state.findings if f.confidence >= _CONFIDENCE_THRESHOLD
            ]
            filtered_out = pre_filter - len(state.findings)
            ws_manager.broadcast_sync(audit_id, {
                "type": "filtering",
                "threshold": _CONFIDENCE_THRESHOLD,
                "kept": len(state.findings),
                "filtered_out": filtered_out,
            })
            self._update_phase(state, 6, 1.0)

            # Phase 7: Report generation
            self._update_phase(state, 7, 0.0)
            markdown, score, summary = generate_report_markdown(
                state.findings,
                project=Path(state.target_path).name,
                tools_used=state.tools,
            )
            state.report_markdown = markdown
            state.score = score
            state.summary = summary
            self._update_phase(state, 7, 1.0)

            # Complete
            state.status = AuditStatusEnum.complete
            state.completed_at = datetime.now(timezone.utc)

            counts = state.to_status().findings_count
            ws_manager.broadcast_sync(audit_id, {
                "type": "complete",
                "summary": counts.model_dump(),
                "score": state.score,
            })

        except Exception as e:
            state.status = AuditStatusEnum.failed
            state.error = str(e)
            state.completed_at = datetime.now(timezone.utc)
            ws_manager.broadcast_sync(audit_id, {
                "type": "error",
                "message": str(e),
            })
        finally:
            # Clean up temp directory if one was created
            if state.temp_dir:
                shutil.rmtree(state.temp_dir, ignore_errors=True)

    def _update_phase(self, state: AuditState, phase: int, progress: float) -> None:
        state.phase = phase
        state.phase_name = PHASE_NAMES[phase - 1] if phase <= len(PHASE_NAMES) else "Finalizing"
        state.progress = progress
        ws_manager.broadcast_sync(state.id, {
            "type": "phase" if progress == 0.0 else "progress",
            "phase": phase,
            "total": state.total_phases,
            "name": state.phase_name,
            "percent": int(progress * 100),
        })


# Singleton
audit_manager = AuditManager()
