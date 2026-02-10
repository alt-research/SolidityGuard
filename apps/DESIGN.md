# SolidityGuard Application Design

## Overview

Three application surfaces sharing a single scanner core:

1. **CLI** — `solidityguard` Python command-line tool with rich terminal UI
2. **Web** — FastAPI backend + React frontend dashboard
3. **Desktop** — Tauri app (Mac/Linux/Windows) wrapping the same React frontend

All three surfaces call the same Python scanner engine (`solidity_guard.py`).

---

## Architecture

```
                    ┌──────────────────────┐
                    │    Scanner Core       │
                    │  solidity_guard.py    │
                    │  (50+ detectors,      │
                    │   104 patterns)       │
                    └──────┬───────────────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
    ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
    │    CLI      │ │  FastAPI    │ │   Tauri     │
    │  (Click +   │ │  Backend    │ │  Desktop    │
    │   Rich)     │ │  + WebSocket│ │  (Rust)     │
    └─────────────┘ └──────┬──────┘ └──────┬──────┘
                           │               │
                    ┌──────▼──────┐        │
                    │   React     │◄───────┘
                    │  Frontend   │  (same frontend)
                    │ (Tailwind)  │
                    └─────────────┘
```

---

## 1. CLI Application (`apps/cli/`)

### Command Structure

```bash
# Main audit command
solidityguard audit ./contracts
solidityguard audit ./contracts --deep    # multi-agent mode
solidityguard audit ./contracts --quick   # fast scan only

# Individual scans
solidityguard scan ./contracts                          # all patterns
solidityguard scan ./contracts --category reentrancy    # by category
solidityguard scan ./contracts --pattern ETH-001        # specific pattern

# Report generation
solidityguard report ./findings.json --format pdf
solidityguard report ./findings.json --format markdown

# Benchmark
solidityguard benchmark                   # DeFiVulnLabs
solidityguard benchmark --paradigm        # Paradigm CTF
solidityguard benchmark --all             # combined

# Info
solidityguard patterns                    # list all 104 patterns
solidityguard patterns --category defi    # filter by category
solidityguard tools                       # check tool availability
solidityguard version
```

### Terminal UI Design (Rich)

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  SolidityGuard v1.0 — Smart Contract Security      ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

 Target: ./contracts (5 files, 1,234 lines)
 Tools:  Slither ✓  Aderyn ✓  Mythril ✗  Pattern Scanner ✓

━━━ Audit Progress ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Phase 1/7  Automated Scan        ████████████████████ 100%
 Phase 2/7  Finding Verification  ████████████░░░░░░░░  60%
 Phase 3/7  Pattern Analysis      ░░░░░░░░░░░░░░░░░░░░   0%

━━━ Findings ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 CRITICAL  2  ││████████████████████
 HIGH      5  ││██████████████████████████████████████████████████
 MEDIUM    3  ││██████████████████████████████
 LOW       4  ││████████████████████████████████████████
 INFO      2  ││████████████████████

━━━ Top Findings ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 CRITICAL  ETH-001  Single-function Reentrancy
           contracts/Vault.sol:45 │ Confidence: 95%
           State update after external call

 CRITICAL  ETH-019  Delegatecall to Untrusted Callee
           contracts/Proxy.sol:23 │ Confidence: 90%
           delegatecall with user-supplied target

 HIGH      ETH-024  Oracle Manipulation
           contracts/Lending.sol:89 │ Confidence: 85%
           getReserves() used for rate calculation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Score: 35/100 │ 16 findings │ Report: ./audit-report.md
```

### Tech Stack
- **Python 3.10+**
- **Click** — command-line argument parsing
- **Rich** — terminal formatting, progress bars, tables, syntax highlighting
- **Packaging**: `pyproject.toml` with `[project.scripts]` entry point

### File Structure
```
apps/cli/
├── pyproject.toml
├── solidityguard/
│   ├── __init__.py
│   ├── __main__.py          # python -m solidityguard
│   ├── cli.py               # Click command definitions
│   ├── ui.py                # Rich UI components (panels, tables, progress)
│   ├── scanner.py           # Wrapper around solidity_guard.scan_patterns()
│   └── config.py            # CLI configuration
└── README.md
```

---

## 2. Web Application (`apps/web/`)

### Backend (FastAPI)

#### REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/audit` | Start new audit (upload files or provide path) |
| `GET` | `/api/audit/:id` | Get audit status and summary |
| `GET` | `/api/audit/:id/findings` | Get findings list (filterable) |
| `GET` | `/api/audit/:id/report` | Get generated report (MD/PDF) |
| `DELETE` | `/api/audit/:id` | Cancel running audit |
| `GET` | `/api/patterns` | List all 104 patterns |
| `GET` | `/api/patterns/:id` | Get pattern details |
| `GET` | `/api/tools` | Check available tool status |
| `GET` | `/api/health` | Health check |

#### WebSocket

| Endpoint | Description |
|----------|-------------|
| `WS /api/audit/:id/stream` | Real-time audit progress + findings stream |

#### WebSocket Message Types

```json
{"type": "phase", "phase": 2, "total": 7, "name": "Finding Verification"}
{"type": "progress", "phase": 2, "percent": 60}
{"type": "finding", "finding": {"id": "ETH-001", "severity": "CRITICAL", ...}}
{"type": "complete", "summary": {"critical": 2, "high": 5, ...}, "score": 35}
{"type": "error", "message": "Slither not available"}
```

#### Data Models

```python
class AuditRequest:
    files: list[UploadFile] | None     # uploaded .sol files
    path: str | None                    # local path (desktop mode)
    mode: str = "standard"              # quick | standard | deep
    tools: list[str] = ["pattern"]      # pattern, slither, aderyn, mythril
    categories: list[str] | None        # filter categories (None = all)

class AuditStatus:
    id: str
    status: str                         # pending | running | complete | failed
    phase: int
    total_phases: int
    phase_name: str
    progress: float                     # 0.0 - 1.0
    findings_count: dict[str, int]      # severity -> count
    started_at: datetime
    completed_at: datetime | None

class Finding:
    id: str                             # ETH-xxx
    title: str
    severity: str                       # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: float
    file: str
    line: int
    code_snippet: str
    description: str
    remediation: str
    category: str
    swc: str | None

class AuditReport:
    id: str
    score: int                          # 0-100
    summary: dict[str, int]
    findings: list[Finding]
    tools_used: list[str]
    timestamp: datetime
```

### Frontend (React)

#### Pages

| Route | Page | Description |
|-------|------|-------------|
| `/` | Home | Upload contracts, start audit, recent history |
| `/audit/:id` | Audit Live | Real-time progress, streaming findings |
| `/audit/:id/findings` | Findings | Filterable findings dashboard |
| `/audit/:id/report` | Report | Professional report view + export |
| `/patterns` | Patterns | Browse all 104 vulnerability patterns |

#### UI Design

**Color Palette (Dark Theme)**:
- Background: `#0a0a0a` / `#111111` / `#1a1a1a`
- Surface: `#1e1e2e` / `#252536`
- Border: `#2a2a3a`
- Text Primary: `#e0e0e0`
- Text Secondary: `#888899`
- Accent (brand): `#00cc6a` (security green)
- Critical: `#ff4757`
- High: `#ff6b35`
- Medium: `#ffc048`
- Low: `#4da6ff`
- Info: `#6c6c80`

**Typography**:
- UI: Inter (sans-serif)
- Code: JetBrains Mono (monospace)
- Sizes: 12/14/16/20/24/32px scale

**Layout — Home Page**:
```
┌─────────────────────────────────────────────────────────┐
│  ◆ SolidityGuard              [Patterns] [Docs] [⚙]    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│     ┌─────────────────────────────────────────────┐     │
│     │                                             │     │
│     │     Drop Solidity files here                │     │
│     │     or click to browse                      │     │
│     │                                             │     │
│     │     ┌──────────────────────────┐            │     │
│     │     │   Start Audit            │            │     │
│     │     └──────────────────────────┘            │     │
│     │                                             │     │
│     │  Quick Scan ○  Standard ●  Deep ○           │     │
│     └─────────────────────────────────────────────┘     │
│                                                         │
│  ━━━ Recent Audits ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  │
│  ┌─────────────────────────────────────────────────┐    │
│  │ MyVault.sol    Score: 35/100   3 Critical  5h ago│    │
│  │ Token.sol      Score: 82/100   0 Critical  1d ago│    │
│  │ Bridge.sol     Score: 61/100   1 Critical  3d ago│    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

**Layout — Audit Live Page**:
```
┌─────────────────────────────────────────────────────────┐
│  ◆ SolidityGuard   ← Back          Audit #a1b2c3       │
├──────────┬──────────────────────────────────────────────┤
│          │                                              │
│ FILES    │  Phase 3 of 7: Pattern Analysis              │
│          │  ████████████████░░░░░░░░░░░░░░░░ 56%        │
│ Vault.sol│                                              │
│ Token.sol│  ┌─ Severity Distribution ────────────────┐  │
│ Proxy.sol│  │  ●● CRITICAL  ●●●●● HIGH               │  │
│ Utils.sol│  │  ●●● MEDIUM   ●●●● LOW  ●● INFO        │  │
│ Lib.sol  │  └────────────────────────────────────────┘  │
│          │                                              │
│ ──────── │  ━━━ Live Findings ━━━━━━━━━━━━━━━━━━━━━━━  │
│          │                                              │
│ TOOLS    │  ┌── CRITICAL ─────────────────────────────┐ │
│ ✓ Pattern│  │ ETH-001 Single-function Reentrancy      │ │
│ ✓ Slither│  │ Vault.sol:45  │  Confidence: 95%        │ │
│ ⟳ Aderyn │  │ msg.sender.call{value: amount}("")      │ │
│ ✗ Mythril│  │ State updated after external call        │ │
│          │  └─────────────────────────────────────────┘ │
│          │                                              │
│          │  ┌── HIGH ─────────────────────────────────┐ │
│          │  │ ETH-024 Oracle Manipulation             │ │
│          │  │ Lending.sol:89  │  Confidence: 85%      │ │
│          │  └─────────────────────────────────────────┘ │
│          │                                              │
├──────────┴──────────────────────────────────────────────┤
│ Scanning... 3 findings found │ Elapsed: 12s             │
└─────────────────────────────────────────────────────────┘
```

**Layout — Findings Page**:
```
┌─────────────────────────────────────────────────────────┐
│  ◆ SolidityGuard   ← Back   [Findings] [Report]        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Score: 35/100   │  16 findings  │  5 files scanned     │
│                                                         │
│  ┌─ Filters ──────────────────────────────────────────┐ │
│  │ Severity: [All] [Critical] [High] [Med] [Low]     │ │
│  │ Category: [All ▼]  Confidence: [≥ 0.7 ▼]          │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
│  ┌─ ETH-001 ── CRITICAL ── 95% ──────────────────────┐ │
│  │ Single-function Reentrancy                         │ │
│  │ contracts/Vault.sol:45                             │ │
│  │ ┌───────────────────────────────────────────────┐  │ │
│  │ │ 44│   (bool ok,) = msg.sender.call{value: a}  │  │ │
│  │ │ 45│   balances[msg.sender] -= amount; // ← !! │  │ │
│  │ └───────────────────────────────────────────────┘  │ │
│  │                                                    │ │
│  │ ▸ Attack Scenario                                  │ │
│  │ ▸ Remediation                                      │ │
│  └────────────────────────────────────────────────────┘ │
│                                                         │
│  ┌─ ETH-019 ── CRITICAL ── 90% ──────────────────────┐ │
│  │ Delegatecall to Untrusted Callee                   │ │
│  │ ...                                                │ │
│  └────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

#### Component Tree

```
App
├── Layout
│   ├── Navbar (logo, nav links, settings)
│   └── Footer (status bar)
├── HomePage
│   ├── FileUpload (drag-and-drop zone)
│   ├── AuditConfig (mode selector, tool toggles)
│   ├── StartButton
│   └── RecentAudits (list of past audits)
├── AuditPage
│   ├── ProgressPanel (phase bars, elapsed time)
│   ├── SeverityChart (donut/bar chart)
│   ├── FindingsStream (live findings feed)
│   └── FileSidebar (file tree + tool status)
├── FindingsPage
│   ├── ScoreBanner (security score, summary stats)
│   ├── FilterBar (severity, category, confidence)
│   └── FindingsList
│       └── FindingCard (expandable)
│           ├── CodeSnippet (syntax-highlighted)
│           ├── AttackScenario (collapsible)
│           └── Remediation (collapsible with code)
├── ReportPage
│   ├── ReportPreview (rendered markdown)
│   └── ExportButtons (PDF, Markdown, JSON)
└── PatternsPage
    ├── PatternSearch (search + category filter)
    └── PatternGrid (104 pattern cards)
```

### Tech Stack (Frontend)
- **React 19** + TypeScript
- **Vite** — build tool
- **Tailwind CSS 4** — styling
- **React Router** — client-side routing
- **Lucide React** — icons
- **Monaco Editor** or **Prism.js** — code syntax highlighting
- **Recharts** — severity distribution charts

### File Structure
```
apps/web/
├── backend/
│   ├── pyproject.toml
│   ├── solidityguard_api/
│   │   ├── __init__.py
│   │   ├── main.py               # FastAPI app, CORS, startup
│   │   ├── routes/
│   │   │   ├── audit.py          # /api/audit endpoints
│   │   │   ├── patterns.py       # /api/patterns endpoints
│   │   │   └── tools.py          # /api/tools endpoints
│   │   ├── models/
│   │   │   ├── audit.py          # Pydantic models
│   │   │   └── finding.py        # Finding model
│   │   ├── services/
│   │   │   ├── scanner.py        # Scanner service (wraps solidity_guard)
│   │   │   └── audit_manager.py  # Manages audit lifecycle + WebSocket
│   │   └── websocket.py          # WebSocket handler
│   └── README.md
└── frontend/
    ├── package.json
    ├── tsconfig.json
    ├── vite.config.ts
    ├── tailwind.config.ts
    ├── index.html
    ├── public/
    │   └── favicon.svg
    └── src/
        ├── main.tsx
        ├── App.tsx
        ├── index.css              # Tailwind + custom theme
        ├── lib/
        │   ├── api.ts             # API client
        │   ├── ws.ts              # WebSocket client
        │   └── types.ts           # TypeScript types
        ├── components/
        │   ├── Layout.tsx         # Navbar + footer
        │   ├── FileUpload.tsx     # Drag-and-drop upload
        │   ├── AuditConfig.tsx    # Mode + tool selector
        │   ├── ProgressPanel.tsx  # Phase progress bars
        │   ├── SeverityChart.tsx  # Donut chart
        │   ├── FindingCard.tsx    # Expandable finding
        │   ├── CodeSnippet.tsx    # Syntax-highlighted code
        │   ├── FilterBar.tsx      # Severity/category filters
        │   ├── ScoreBanner.tsx    # Security score display
        │   └── PatternCard.tsx    # Pattern info card
        └── pages/
            ├── Home.tsx
            ├── Audit.tsx
            ├── Findings.tsx
            ├── Report.tsx
            └── Patterns.tsx
```

---

## 3. Desktop Application (`apps/desktop/`)

### Approach

**Tauri v2** wraps the same React frontend with native capabilities:
- Native file system access (no upload needed — direct path selection)
- System tray with audit status
- Native file dialogs
- Cross-platform: macOS (.dmg), Linux (.AppImage/.deb), Windows (.msi/.exe)
- Lightweight: ~5MB vs Electron's ~150MB

### Additional Desktop Features
- File browser dialog for selecting contract directories
- Background scanning with system notifications
- Auto-detection of installed tools (Slither, Foundry, etc.)
- Local Python process management (starts/stops FastAPI backend)

### File Structure
```
apps/desktop/
├── package.json
├── src-tauri/
│   ├── Cargo.toml
│   ├── tauri.conf.json
│   ├── capabilities/
│   │   └── default.json
│   ├── src/
│   │   ├── main.rs            # Tauri entry point
│   │   └── lib.rs             # Tauri commands (file dialog, backend mgmt)
│   └── icons/                 # App icons (all sizes)
└── src/                       # Symlink → ../web/frontend/src
```

### Tauri Commands (Rust → JS bridge)
```rust
#[tauri::command]
fn select_contracts_dir() -> Result<String, String>    // native file dialog

#[tauri::command]
fn check_tools() -> Result<ToolStatus, String>         // check installed tools

#[tauri::command]
fn start_backend() -> Result<u16, String>              // start FastAPI on random port

#[tauri::command]
fn stop_backend() -> Result<(), String>                // stop FastAPI
```

---

## Build & Run

```bash
# CLI
cd apps/cli && pip install -e . && solidityguard audit ./contracts

# Web (development)
cd apps/web/backend && pip install -e . && uvicorn solidityguard_api.main:app --reload
cd apps/web/frontend && npm install && npm run dev

# Desktop (development)
cd apps/desktop && npm install && npm run tauri dev

# Desktop (build for distribution)
cd apps/desktop && npm run tauri build
```

---

## Implementation Priority

| Priority | Component | Effort | Dependencies |
|----------|-----------|--------|-------------|
| **P0** | CLI (`apps/cli/`) | Medium | Scanner core only |
| **P0** | Backend (`apps/web/backend/`) | Medium | Scanner core only |
| **P0** | Frontend (`apps/web/frontend/`) | Large | Backend API spec |
| **P1** | Desktop (`apps/desktop/`) | Small | Frontend + Backend |

P0 items can be built in parallel. Desktop wraps the finished frontend.
