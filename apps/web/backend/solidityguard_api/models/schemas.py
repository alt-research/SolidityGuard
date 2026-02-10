"""Pydantic models for the SolidityGuard API."""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class AuditMode(str, Enum):
    quick = "quick"
    standard = "standard"
    deep = "deep"


class AuditStatusEnum(str, Enum):
    pending = "pending"
    running = "running"
    complete = "complete"
    failed = "failed"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class AuditRequest(BaseModel):
    path: Optional[str] = None
    mode: AuditMode = AuditMode.standard
    tools: list[str] = Field(default_factory=lambda: ["pattern"])
    categories: Optional[list[str]] = None


class Finding(BaseModel):
    id: str
    title: str
    severity: str
    confidence: float
    file: str
    line: int
    code_snippet: str
    description: str
    remediation: str
    category: str
    swc: Optional[str] = None
    tool: str = "pattern-scanner"


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    total: int = 0


class AuditStatus(BaseModel):
    id: str
    status: AuditStatusEnum
    phase: int = 0
    total_phases: int = 7
    phase_name: str = ""
    progress: float = 0.0
    findings_count: SeverityCounts = Field(default_factory=SeverityCounts)
    started_at: datetime
    completed_at: Optional[datetime] = None


class AuditReport(BaseModel):
    id: str
    score: int
    summary: SeverityCounts
    findings: list[Finding]
    tools_used: list[str]
    report_markdown: str
    timestamp: datetime


class PatternInfo(BaseModel):
    id: str
    title: str
    severity: str
    category: str
    swc: Optional[str] = None
    description: str


class ToolStatus(BaseModel):
    name: str
    available: bool
    version: Optional[str] = None


class FuzzTestRequest(BaseModel):
    findings: list[dict]
    contracts_path: str = "."


class FuzzTestResponse(BaseModel):
    foundry_test: str
    echidna_test: str
    echidna_config: str
    summary: dict


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.1"
    timestamp: datetime
