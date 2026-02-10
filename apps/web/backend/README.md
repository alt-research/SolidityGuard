# SolidityGuard API Backend

FastAPI backend for the SolidityGuard smart contract security audit dashboard.

## Quick Start

```bash
pip install -e .
uvicorn solidityguard_api.main:app --reload
```

Server runs at http://localhost:8000

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/patterns` | List all 104 vulnerability patterns |
| `GET` | `/api/patterns/{id}` | Get pattern details |
| `GET` | `/api/tools` | Check available security tools |
| `POST` | `/api/audit` | Start audit (multipart: files + form fields) |
| `POST` | `/api/audit/json` | Start audit (JSON body with local path) |
| `GET` | `/api/audit/{id}` | Get audit status |
| `GET` | `/api/audit/{id}/findings` | Get findings (supports `?severity=` and `?category=`) |
| `GET` | `/api/audit/{id}/report` | Get markdown report |
| `WS` | `/api/audit/{id}/stream` | WebSocket stream for real-time progress |

## WebSocket Messages

```json
{"type": "phase", "phase": 2, "total": 7, "name": "Automated Scan", "percent": 0}
{"type": "progress", "phase": 2, "total": 7, "name": "Automated Scan", "percent": 100}
{"type": "finding", "finding": {"id": "ETH-001", "severity": "CRITICAL", ...}}
{"type": "complete", "summary": {"critical": 2, "high": 5, ...}, "score": 35}
{"type": "error", "message": "..."}
```
