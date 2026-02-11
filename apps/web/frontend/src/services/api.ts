import type { AuditStatus, AuditReport, Finding, VulnPattern, ToolInfo } from '../lib/types.ts';

const BASE_URL = import.meta.env.VITE_API_URL || '';
const TOKEN_KEY = 'solidityguard_token';
const isTauri = !!(window as unknown as Record<string, unknown>).__TAURI__;

function getAuthHeaders(): Record<string, string> {
  const token = localStorage.getItem(TOKEN_KEY);
  return token ? { Authorization: `Bearer ${token}` } : {};
}

class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
    ...options,
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    let msg = `${res.status} ${res.statusText}`;
    try {
      const json = JSON.parse(body);
      if (json.detail) msg = json.detail;
    } catch { /* use default */ }
    throw new ApiError(res.status, msg);
  }
  return res.json();
}

// Tauri invoke helper — uses window.__TAURI__ (withGlobalTauri: true)
async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const tauri = (window as any).__TAURI__;
  return tauri.core.invoke(cmd, args);
}

// Tauri-specific: select a local directory via native dialog
export async function selectDirectory(): Promise<string> {
  return tauriInvoke<string>('select_contracts_dir');
}

// Tauri-specific: check which tools are installed locally
export async function checkLocalTools(): Promise<{ slither: boolean; aderyn: boolean; mythril: boolean; forge: boolean; python3: boolean }> {
  return tauriInvoke('check_tools');
}

interface TauriAuditResult {
  id: string;
  status: string;
  phase: string;
  progress: number;
  security_score: number;
  findings: Finding[];
  summary: Record<string, number>;
  tools_used: string[];
  timestamp: string;
}

export const api = {
  startAudit(files: File[], config: { mode: string; tools: string[] }): Promise<{ id: string }> {
    if (isTauri) {
      // In Tauri mode, first file's webkitRelativePath or name is the dir path
      // This is set by the Home page directory picker
      const path = (files[0] as File & { dirPath?: string })?.dirPath || files[0]?.name || '.';
      return tauriInvoke<TauriAuditResult>('run_local_scan', {
        path,
        tools: config.tools,
      }).then((result) => ({ id: result.id }));
    }

    const formData = new FormData();
    files.forEach((file) => formData.append('files', file));
    formData.append('mode', config.mode);
    formData.append('tools', config.tools.join(','));
    return fetch(`${BASE_URL}/api/audit`, {
      method: 'POST',
      body: formData,
      headers: getAuthHeaders(),
    }).then(async (r) => {
      if (!r.ok) {
        const body = await r.text().catch(() => '');
        let msg = `${r.status} ${r.statusText}`;
        try {
          const json = JSON.parse(body);
          if (json.detail) msg = json.detail;
        } catch { /* use default */ }
        throw new ApiError(r.status, msg);
      }
      return r.json();
    });
  },

  // Start a local scan directly with a directory path (Tauri only)
  startLocalScan(path: string, tools: string[]): Promise<TauriAuditResult> {
    return tauriInvoke<TauriAuditResult>('run_local_scan', { path, tools });
  },

  getAuditStatus(id: string): Promise<AuditStatus> {
    if (isTauri) {
      return tauriInvoke<TauriAuditResult>('get_audit', { id }).then((r) => ({
        id: r.id,
        status: r.status === 'completed' ? 'complete' : 'running',
        phase: 7,
        total_phases: 7,
        phase_name: 'Complete',
        progress: r.progress,
        findings_count: {
          CRITICAL: r.summary.critical || 0,
          HIGH: r.summary.high || 0,
          MEDIUM: r.summary.medium || 0,
          LOW: r.summary.low || 0,
          INFO: 0,
        },
        started_at: r.timestamp,
        completed_at: r.timestamp,
      }) as AuditStatus);
    }
    return request(`/api/audit/${encodeURIComponent(id)}`);
  },

  getFindings(id: string): Promise<Finding[]> {
    if (isTauri) {
      return tauriInvoke<Finding[]>('get_findings', { id });
    }
    return request(`/api/audit/${encodeURIComponent(id)}/findings`);
  },

  getReport(id: string): Promise<AuditReport> {
    if (isTauri) {
      return tauriInvoke<TauriAuditResult>('get_audit', { id }).then((r) => ({
        id: r.id,
        score: r.security_score,
        summary: {
          CRITICAL: r.summary.critical || 0,
          HIGH: r.summary.high || 0,
          MEDIUM: r.summary.medium || 0,
          LOW: r.summary.low || 0,
          INFO: 0,
        },
        findings: r.findings,
        tools_used: r.tools_used,
        report_markdown: generateReportMarkdown(r),
        timestamp: r.timestamp,
      }) as AuditReport);
    }
    return request(`/api/audit/${encodeURIComponent(id)}/report`);
  },

  cancelAudit(id: string): Promise<void> {
    if (isTauri) return Promise.resolve();
    return request(`/api/audit/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },

  getPatterns(): Promise<VulnPattern[]> {
    if (isTauri) {
      return Promise.resolve(ALL_PATTERNS);
    }
    return request('/api/patterns');
  },

  getTools(): Promise<ToolInfo[]> {
    if (isTauri) {
      return checkLocalTools().then((status) => [
        { name: 'pattern', status: 'idle', label: 'Pattern Scanner' },
        { name: 'slither', status: status.slither ? 'idle' : 'unavailable', label: 'Slither' },
        { name: 'aderyn', status: status.aderyn ? 'idle' : 'unavailable', label: 'Aderyn' },
        { name: 'mythril', status: status.mythril ? 'idle' : 'unavailable', label: 'Mythril' },
        { name: 'foundry', status: status.forge ? 'idle' : 'unavailable', label: 'Foundry' },
      ] as ToolInfo[]);
    }
    return request('/api/tools');
  },

  getHealth(): Promise<{ status: string }> {
    if (isTauri) return Promise.resolve({ status: 'ok' });
    return request('/api/health');
  },

  getReportMarkdown(id: string): Promise<{ markdown: string; score: number }> {
    if (isTauri) {
      return tauriInvoke<TauriAuditResult>('get_audit', { id }).then((r) => ({
        markdown: generateReportMarkdown(r),
        score: r.security_score,
      }));
    }
    return request(`/api/audit/${encodeURIComponent(id)}/report`);
  },
};

export { ApiError, isTauri };

/** Generate a full professional markdown audit report from scan results. */
function generateReportMarkdown(r: TauriAuditResult): string {
  const date = new Date(r.timestamp).toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
  });
  const critical = r.summary.critical || 0;
  const high = r.summary.high || 0;
  const medium = r.summary.medium || 0;
  const low = r.summary.low || 0;
  const total = r.summary.total || r.findings.length;
  const score = r.security_score;

  const riskLevel = score >= 90 ? 'Low' : score >= 70 ? 'Medium' : score >= 50 ? 'High' : 'Critical';

  const lines: string[] = [];
  lines.push('# SolidityGuard Security Audit Report');
  lines.push('');
  lines.push(`**Date:** ${date}`);
  lines.push(`**Tools:** ${r.tools_used.join(', ')}`);
  lines.push(`**Security Score:** ${score}/100 (${riskLevel} Risk)`);
  lines.push('');
  lines.push('---');
  lines.push('');

  // Executive Summary
  lines.push('## Executive Summary');
  lines.push('');
  if (total === 0) {
    lines.push('No security issues were identified during this audit. The contracts follow security best practices.');
  } else {
    lines.push(`This audit identified **${total} findings** across the scanned contracts:`);
    lines.push('');
    if (critical > 0) lines.push(`- **${critical} Critical** \u2014 immediate action required`);
    if (high > 0) lines.push(`- **${high} High** \u2014 should be fixed before deployment`);
    if (medium > 0) lines.push(`- **${medium} Medium** \u2014 recommended to address`);
    if (low > 0) lines.push(`- **${low} Low/Informational** \u2014 best practice improvements`);
  }
  lines.push('');

  // Severity Distribution
  lines.push('## Severity Distribution');
  lines.push('');
  lines.push('| Severity | Count |');
  lines.push('|----------|-------|');
  lines.push(`| CRITICAL | ${critical} |`);
  lines.push(`| HIGH | ${high} |`);
  lines.push(`| MEDIUM | ${medium} |`);
  lines.push(`| LOW | ${low} |`);
  lines.push(`| **Total** | **${total}** |`);
  lines.push('');

  // Findings
  if (r.findings.length > 0) {
    lines.push('## Findings');
    lines.push('');

    // Summary table
    lines.push('| # | ID | Title | Severity | File |');
    lines.push('|---|-----|-------|----------|------|');
    r.findings.forEach((f, i) => {
      const file = f.file ? `\`${f.file}:${f.line}\`` : '\u2014';
      lines.push(`| ${i + 1} | ${f.id} | ${f.title} | ${f.severity} | ${file} |`);
    });
    lines.push('');

    // Detailed findings
    lines.push('---');
    lines.push('');
    lines.push('## Detailed Findings');
    lines.push('');

    r.findings.forEach((f, i) => {
      lines.push(`### ${i + 1}. ${f.title}`);
      lines.push('');
      lines.push(`**ID:** ${f.id}`);
      lines.push(`**Severity:** ${f.severity}`);
      lines.push(`**Confidence:** ${Math.round(f.confidence * 100)}%`);
      if (f.file) lines.push(`**Location:** \`${f.file}:${f.line}\``);
      if (f.tool) lines.push(`**Tool:** ${f.tool}`);
      if (f.category) lines.push(`**Category:** ${f.category}`);
      if (f.swc) lines.push(`**SWC:** ${f.swc}`);
      lines.push('');

      if (f.description) {
        lines.push('**Description:**');
        lines.push('');
        lines.push(f.description);
        lines.push('');
      }

      if (f.code_snippet) {
        lines.push('**Vulnerable Code:**');
        lines.push('');
        lines.push('```solidity');
        lines.push(f.code_snippet);
        lines.push('```');
        lines.push('');
      }

      if (f.remediation) {
        lines.push('**Remediation:**');
        lines.push('');
        lines.push(f.remediation);
        lines.push('');
      }

      lines.push('---');
      lines.push('');
    });
  }

  // Disclaimer
  lines.push('## Disclaimer');
  lines.push('');
  lines.push('This report is provided for informational purposes only. While SolidityGuard employs multiple analysis tools and pattern detectors, no automated tool can guarantee the absence of all vulnerabilities. A manual expert review is recommended for production deployments.');
  lines.push('');
  lines.push(`*Generated by [SolidityGuard](https://github.com/alt-research/SolidityGuard) v1.1.0*`);

  return lines.join('\n');
}

// All 104 vulnerability patterns for desktop/offline mode
const ALL_PATTERNS: VulnPattern[] = [
  // Reentrancy (ETH-001 to ETH-005)
  { id: 'ETH-001', name: 'Single-function Reentrancy', severity: 'CRITICAL', category: 'Reentrancy', description: 'External call before state update in same function', swc: 'SWC-107' },
  { id: 'ETH-002', name: 'Cross-function Reentrancy', severity: 'CRITICAL', category: 'Reentrancy', description: 'External call in one function, state modified in another sharing state', swc: 'SWC-107' },
  { id: 'ETH-003', name: 'Cross-contract Reentrancy', severity: 'HIGH', category: 'Reentrancy', description: 'Reentrancy across multiple contracts sharing state', swc: 'SWC-107' },
  { id: 'ETH-004', name: 'Read-only Reentrancy', severity: 'HIGH', category: 'Reentrancy', description: 'Reentrancy exploiting view functions returning stale state', swc: null },
  { id: 'ETH-005', name: 'Cross-chain Reentrancy', severity: 'HIGH', category: 'Reentrancy', description: 'Reentrancy via bridge or L2 message callbacks', swc: null },
  // Access Control (ETH-006 to ETH-012)
  { id: 'ETH-006', name: 'Missing Access Control', severity: 'CRITICAL', category: 'Access Control', description: 'Sensitive function callable by anyone', swc: 'SWC-105' },
  { id: 'ETH-007', name: 'tx.origin Authentication', severity: 'CRITICAL', category: 'Access Control', description: 'Using tx.origin for authorization instead of msg.sender', swc: 'SWC-115' },
  { id: 'ETH-008', name: 'Unprotected selfdestruct', severity: 'CRITICAL', category: 'Access Control', description: 'selfdestruct callable without authorization', swc: 'SWC-106' },
  { id: 'ETH-009', name: 'Default Function Visibility', severity: 'HIGH', category: 'Access Control', description: 'Functions without explicit visibility default to public', swc: 'SWC-100' },
  { id: 'ETH-010', name: 'Uninitialized Proxy', severity: 'CRITICAL', category: 'Access Control', description: 'Proxy contract with public init lacking initializer guard', swc: null },
  { id: 'ETH-011', name: 'Missing Modifier on State-changing Function', severity: 'HIGH', category: 'Access Control', description: 'State-changing function lacks access control modifier', swc: null },
  { id: 'ETH-012', name: 'Centralization Risk', severity: 'MEDIUM', category: 'Access Control', description: 'Single admin can change critical parameters', swc: null },
  // Arithmetic (ETH-013 to ETH-017)
  { id: 'ETH-013', name: 'Integer Overflow/Underflow', severity: 'HIGH', category: 'Arithmetic', description: 'Arithmetic overflow or underflow in unchecked block', swc: 'SWC-101' },
  { id: 'ETH-014', name: 'Division Before Multiplication', severity: 'MEDIUM', category: 'Arithmetic', description: 'Precision loss from dividing before multiplying', swc: null },
  { id: 'ETH-015', name: 'Unchecked Math in unchecked Block', severity: 'HIGH', category: 'Arithmetic', description: 'Arithmetic in unchecked block without validation', swc: null },
  { id: 'ETH-016', name: 'Rounding Errors', severity: 'MEDIUM', category: 'Arithmetic', description: 'Rounding errors in financial calculations', swc: null },
  { id: 'ETH-017', name: 'Precision Loss in Token Calculations', severity: 'MEDIUM', category: 'Arithmetic', description: 'Loss of precision in token amount calculations', swc: null },
  // External Calls (ETH-018 to ETH-023)
  { id: 'ETH-018', name: 'Unchecked External Call Return', severity: 'HIGH', category: 'External Calls', description: 'Return value of external call not checked', swc: 'SWC-104' },
  { id: 'ETH-019', name: 'Delegatecall to Untrusted Callee', severity: 'CRITICAL', category: 'External Calls', description: 'Delegatecall with user-controlled target', swc: 'SWC-112' },
  { id: 'ETH-020', name: 'Unsafe Low-level Call', severity: 'HIGH', category: 'External Calls', description: 'Use of low-level call without proper checks', swc: null },
  { id: 'ETH-021', name: 'DoS with Failed Call', severity: 'HIGH', category: 'External Calls', description: 'Failed external call blocks entire transaction', swc: 'SWC-113' },
  { id: 'ETH-022', name: 'Return Value Not Checked (ERC-20)', severity: 'HIGH', category: 'External Calls', description: 'ERC-20 transfer return value not checked', swc: null },
  { id: 'ETH-023', name: 'Insufficient Gas Griefing', severity: 'MEDIUM', category: 'External Calls', description: 'Caller can cause sub-call to fail by sending insufficient gas', swc: 'SWC-126' },
  // Oracle & Price (ETH-024 to ETH-028)
  { id: 'ETH-024', name: 'Oracle Manipulation', severity: 'CRITICAL', category: 'Oracle & Price', description: 'Price oracle can be manipulated in same transaction', swc: null },
  { id: 'ETH-025', name: 'Flash Loan Attack Vector', severity: 'CRITICAL', category: 'Oracle & Price', description: 'Vulnerable to flash loan price manipulation', swc: null },
  { id: 'ETH-026', name: 'Sandwich Attack / MEV', severity: 'HIGH', category: 'Oracle & Price', description: 'Swap without slippage protection enables sandwich attacks', swc: null },
  { id: 'ETH-027', name: 'Missing Slippage Protection', severity: 'HIGH', category: 'Oracle & Price', description: 'Token swap lacks minimum output amount', swc: null },
  { id: 'ETH-028', name: 'Stale Oracle Data', severity: 'HIGH', category: 'Oracle & Price', description: 'Oracle data used without freshness check', swc: null },
  // Storage & State (ETH-029 to ETH-033)
  { id: 'ETH-029', name: 'Uninitialized Storage Pointer', severity: 'HIGH', category: 'Storage & State', description: 'Storage pointer not explicitly initialized', swc: 'SWC-109' },
  { id: 'ETH-030', name: 'Storage Collision (Proxy)', severity: 'CRITICAL', category: 'Storage & State', description: 'Proxy and implementation storage layouts collide', swc: 'SWC-124' },
  { id: 'ETH-031', name: 'Shadowing State Variables', severity: 'MEDIUM', category: 'Storage & State', description: 'Derived contract shadows base state variable', swc: 'SWC-119' },
  { id: 'ETH-032', name: 'Unexpected Ether Balance', severity: 'MEDIUM', category: 'Storage & State', description: 'Contract logic depends on this.balance which can be forced', swc: 'SWC-132' },
  { id: 'ETH-033', name: 'Write to Arbitrary Storage', severity: 'CRITICAL', category: 'Storage & State', description: 'User input controls storage write location', swc: 'SWC-124' },
  // Logic Errors (ETH-034 to ETH-040)
  { id: 'ETH-034', name: 'Strict Equality on Balance', severity: 'HIGH', category: 'Logic Errors', description: 'Using == for balance checks instead of >= or <=', swc: 'SWC-132' },
  { id: 'ETH-035', name: 'Transaction Order Dependence', severity: 'HIGH', category: 'Logic Errors', description: 'Contract behavior depends on transaction ordering', swc: 'SWC-114' },
  { id: 'ETH-036', name: 'Timestamp Dependence', severity: 'MEDIUM', category: 'Logic Errors', description: 'Using block.timestamp for critical logic', swc: 'SWC-116' },
  { id: 'ETH-037', name: 'Weak Randomness', severity: 'HIGH', category: 'Logic Errors', description: 'Using block attributes as randomness source', swc: 'SWC-120' },
  { id: 'ETH-038', name: 'Signature Malleability', severity: 'HIGH', category: 'Logic Errors', description: 'ECDSA signature without s-value check', swc: 'SWC-117' },
  { id: 'ETH-039', name: 'Signature Replay Attack', severity: 'CRITICAL', category: 'Logic Errors', description: 'Signed message can be replayed', swc: 'SWC-121' },
  { id: 'ETH-040', name: 'Front-running Vulnerability', severity: 'HIGH', category: 'Logic Errors', description: 'Transaction can be front-run for profit', swc: 'SWC-114' },
  // Token Issues (ETH-041 to ETH-048)
  { id: 'ETH-041', name: 'ERC-20 Non-standard Returns', severity: 'HIGH', category: 'Token Issues', description: 'Not handling ERC-20 tokens with non-standard return values', swc: null },
  { id: 'ETH-042', name: 'Fee-on-Transfer Incompatibility', severity: 'HIGH', category: 'Token Issues', description: 'Not accounting for fee-on-transfer tokens', swc: null },
  { id: 'ETH-043', name: 'Rebasing Token Incompatibility', severity: 'HIGH', category: 'Token Issues', description: 'Not handling rebasing tokens correctly', swc: null },
  { id: 'ETH-044', name: 'ERC-777 Reentrancy Hook', severity: 'CRITICAL', category: 'Token Issues', description: 'ERC-777 tokensReceived hook enables reentrancy', swc: null },
  { id: 'ETH-045', name: 'Missing Zero Address Check', severity: 'MEDIUM', category: 'Token Issues', description: 'No validation for address(0) in critical parameters', swc: null },
  { id: 'ETH-046', name: 'Approval Race Condition', severity: 'MEDIUM', category: 'Token Issues', description: 'ERC-20 approve race condition', swc: null },
  { id: 'ETH-047', name: 'Infinite Approval Risk', severity: 'LOW', category: 'Token Issues', description: 'Unlimited token approval without timeout', swc: null },
  { id: 'ETH-048', name: 'Token Supply Manipulation', severity: 'HIGH', category: 'Token Issues', description: 'Token supply can be manipulated by privileged role', swc: null },
  // Proxy & Upgrade (ETH-049 to ETH-054)
  { id: 'ETH-049', name: 'Uninitialized Implementation', severity: 'CRITICAL', category: 'Proxy & Upgrade', description: 'Implementation contract not disabled in constructor', swc: null },
  { id: 'ETH-050', name: 'Storage Layout Mismatch', severity: 'CRITICAL', category: 'Proxy & Upgrade', description: 'Storage layout changed between proxy versions', swc: null },
  { id: 'ETH-051', name: 'Function Selector Clash', severity: 'HIGH', category: 'Proxy & Upgrade', description: 'Proxy and implementation share 4-byte selector', swc: null },
  { id: 'ETH-052', name: 'Missing Upgrade Authorization', severity: 'CRITICAL', category: 'Proxy & Upgrade', description: 'Upgrade function lacks proper access control', swc: null },
  { id: 'ETH-053', name: 'selfdestruct in Implementation', severity: 'HIGH', category: 'Proxy & Upgrade', description: 'Implementation contract can self-destruct', swc: null },
  { id: 'ETH-054', name: 'Transparent Proxy Selector Collision', severity: 'HIGH', category: 'Proxy & Upgrade', description: 'Admin functions clash with implementation selectors', swc: null },
  // DeFi Specific (ETH-055 to ETH-065)
  { id: 'ETH-055', name: 'Governance Manipulation', severity: 'HIGH', category: 'DeFi', description: 'Governance can be manipulated via flash loans', swc: null },
  { id: 'ETH-056', name: 'Liquidation Manipulation', severity: 'HIGH', category: 'DeFi', description: 'Liquidation parameters can be manipulated', swc: null },
  { id: 'ETH-057', name: 'Vault Share Inflation', severity: 'CRITICAL', category: 'DeFi', description: 'First depositor can inflate share price', swc: null },
  { id: 'ETH-058', name: 'Donation Attack', severity: 'HIGH', category: 'DeFi', description: 'Direct token transfer manipulates share calculations', swc: null },
  { id: 'ETH-059', name: 'AMM Constant Product Error', severity: 'CRITICAL', category: 'DeFi', description: 'Incorrect constant product formula implementation', swc: null },
  { id: 'ETH-060', name: 'Missing Transaction Deadline', severity: 'MEDIUM', category: 'DeFi', description: 'Swap transaction lacks deadline parameter', swc: null },
  { id: 'ETH-061', name: 'Unrestricted Flash Mint', severity: 'HIGH', category: 'DeFi', description: 'Flash mint without proper access control or limits', swc: null },
  { id: 'ETH-062', name: 'Pool Imbalance Attack', severity: 'HIGH', category: 'DeFi', description: 'Pool can be imbalanced to extract value', swc: null },
  { id: 'ETH-063', name: 'Reward Distribution Error', severity: 'HIGH', category: 'DeFi', description: 'Incorrect reward calculation or distribution', swc: null },
  { id: 'ETH-064', name: 'Insecure Callback Handler', severity: 'HIGH', category: 'DeFi', description: 'Callback/hook handler lacks validation', swc: null },
  { id: 'ETH-065', name: 'Cross-protocol Integration Risk', severity: 'MEDIUM', category: 'DeFi', description: 'External protocol integration without validation', swc: null },
  // Gas & DoS (ETH-066 to ETH-070)
  { id: 'ETH-066', name: 'Unbounded Loop', severity: 'HIGH', category: 'Gas & DoS', description: 'Loop iterates over unbounded array', swc: 'SWC-128' },
  { id: 'ETH-067', name: 'Block Gas Limit DoS', severity: 'HIGH', category: 'Gas & DoS', description: 'Operation can exceed block gas limit', swc: 'SWC-128' },
  { id: 'ETH-068', name: 'Unexpected Revert in Loop', severity: 'MEDIUM', category: 'Gas & DoS', description: 'Single revert in loop blocks all iterations', swc: 'SWC-113' },
  { id: 'ETH-069', name: 'Griefing Attack', severity: 'MEDIUM', category: 'Gas & DoS', description: 'Attacker can cause loss to others without profit', swc: null },
  { id: 'ETH-070', name: 'Storage Slot Exhaustion', severity: 'LOW', category: 'Gas & DoS', description: 'Unbounded storage growth causes gas increase', swc: null },
  // Miscellaneous (ETH-071 to ETH-080)
  { id: 'ETH-071', name: 'Floating Pragma', severity: 'LOW', category: 'Miscellaneous', description: 'Compiler version not locked', swc: 'SWC-103' },
  { id: 'ETH-072', name: 'Outdated Compiler Version', severity: 'LOW', category: 'Miscellaneous', description: 'Using compiler version with known bugs', swc: 'SWC-102' },
  { id: 'ETH-073', name: 'Hash Collision with abi.encodePacked', severity: 'MEDIUM', category: 'Miscellaneous', description: 'abi.encodePacked with dynamic types enables hash collision', swc: 'SWC-133' },
  { id: 'ETH-074', name: 'Right-to-Left Override Character', severity: 'HIGH', category: 'Miscellaneous', description: 'Unicode RTL override character in source code', swc: 'SWC-130' },
  { id: 'ETH-075', name: 'Code With No Effects', severity: 'LOW', category: 'Miscellaneous', description: 'Statement has no effect on state', swc: 'SWC-135' },
  { id: 'ETH-076', name: 'Missing Event Emission', severity: 'LOW', category: 'Miscellaneous', description: 'State change without corresponding event emission', swc: null },
  { id: 'ETH-077', name: 'Incorrect Inheritance Order', severity: 'MEDIUM', category: 'Miscellaneous', description: 'C3 linearization order causes unexpected behavior', swc: 'SWC-125' },
  { id: 'ETH-078', name: 'Unencrypted Private Data On-Chain', severity: 'LOW', category: 'Miscellaneous', description: 'Private variables are readable on-chain', swc: 'SWC-136' },
  { id: 'ETH-079', name: 'Hardcoded Gas Amount', severity: 'LOW', category: 'Miscellaneous', description: 'Hardcoded gas in call may break after EIP changes', swc: 'SWC-134' },
  { id: 'ETH-080', name: 'Incorrect Constructor Name', severity: 'HIGH', category: 'Miscellaneous', description: 'Constructor function name does not match contract name (pre-0.4.22)', swc: 'SWC-118' },
  // Transient Storage (ETH-081 to ETH-085)
  { id: 'ETH-081', name: 'Transient Storage Slot Collision', severity: 'CRITICAL', category: 'Transient Storage', description: 'TSTORE slot collision between contracts', swc: null },
  { id: 'ETH-082', name: 'Transient Storage Not Cleared', severity: 'HIGH', category: 'Transient Storage', description: 'Transient storage not cleaned up end of transaction', swc: null },
  { id: 'ETH-083', name: 'TSTORE Reentrancy Bypass', severity: 'CRITICAL', category: 'Transient Storage', description: 'Reentrancy guard using TSTORE can be bypassed', swc: null },
  { id: 'ETH-084', name: 'Transient Storage Delegatecall Exposure', severity: 'HIGH', category: 'Transient Storage', description: 'Transient storage shared via delegatecall', swc: null },
  { id: 'ETH-085', name: 'Transient Storage Type-Safety Bypass', severity: 'MEDIUM', category: 'Transient Storage', description: 'TSTORE/TLOAD bypass Solidity type safety', swc: null },
  // EIP-7702 / Pectra (ETH-086 to ETH-089)
  { id: 'ETH-086', name: 'Broken tx.origin == msg.sender', severity: 'CRITICAL', category: 'EIP-7702', description: 'EIP-7702 breaks tx.origin == msg.sender assumption', swc: null },
  { id: 'ETH-087', name: 'Malicious EIP-7702 Delegation', severity: 'HIGH', category: 'EIP-7702', description: 'EOA delegates to malicious implementation', swc: null },
  { id: 'ETH-088', name: 'EIP-7702 Cross-Chain Replay', severity: 'CRITICAL', category: 'EIP-7702', description: 'Authorization can be replayed on different chains', swc: null },
  { id: 'ETH-089', name: 'EOA Code Assumption Failure', severity: 'HIGH', category: 'EIP-7702', description: 'Contract assumes EOAs have no code', swc: null },
  // Account Abstraction (ETH-090 to ETH-093)
  { id: 'ETH-090', name: 'UserOp Hash Collision', severity: 'HIGH', category: 'Account Abstraction', description: 'User operation hash collision enables replay', swc: null },
  { id: 'ETH-091', name: 'Paymaster Exploitation', severity: 'CRITICAL', category: 'Account Abstraction', description: 'Paymaster can be drained by malicious UserOps', swc: null },
  { id: 'ETH-092', name: 'Bundler Manipulation', severity: 'HIGH', category: 'Account Abstraction', description: 'Bundler can manipulate UserOp execution order', swc: null },
  { id: 'ETH-093', name: 'Validation-Execution Phase Confusion', severity: 'CRITICAL', category: 'Account Abstraction', description: 'Storage access in validation phase causes issues', swc: null },
  // Modern DeFi (ETH-094 to ETH-097)
  { id: 'ETH-094', name: 'Uniswap V4 Hook Auth Bypass', severity: 'CRITICAL', category: 'Modern DeFi', description: 'Hook callback lacks pool manager authorization', swc: null },
  { id: 'ETH-095', name: 'Hook Data Manipulation', severity: 'HIGH', category: 'Modern DeFi', description: 'Hook data can be manipulated by caller', swc: null },
  { id: 'ETH-096', name: 'Cached State Desynchronization', severity: 'HIGH', category: 'Modern DeFi', description: 'Cached state diverges from on-chain state', swc: null },
  { id: 'ETH-097', name: 'Known Compiler Bug', severity: 'HIGH', category: 'Modern DeFi', description: 'Contract uses Solidity version with known bugs', swc: null },
  // Input Validation (ETH-098 to ETH-099)
  { id: 'ETH-098', name: 'Missing Input Validation', severity: 'HIGH', category: 'Input Validation', description: 'Missing boundary checks on user input', swc: null },
  { id: 'ETH-099', name: 'Unsafe ABI Decoding', severity: 'HIGH', category: 'Input Validation', description: 'Calldata manipulation via unsafe ABI decoding', swc: null },
  // Off-Chain & Infrastructure (ETH-100 to ETH-101)
  { id: 'ETH-100', name: 'EIP-7702 Delegation Phishing', severity: 'CRITICAL', category: 'Off-Chain', description: 'Phishing via malicious EIP-7702 delegation requests', swc: null },
  { id: 'ETH-101', name: 'Off-Chain Infrastructure Compromise', severity: 'CRITICAL', category: 'Off-Chain', description: 'UI or signer infrastructure compromise (Bybit-style)', swc: null },
  // Restaking & L2 (ETH-102 to ETH-104)
  { id: 'ETH-102', name: 'Cascading Slashing Risk', severity: 'HIGH', category: 'Restaking & L2', description: 'Restaking creates cascading slashing scenarios', swc: null },
  { id: 'ETH-103', name: 'L2 Sequencer Dependency', severity: 'HIGH', category: 'Restaking & L2', description: 'Critical logic depends on L2 sequencer availability', swc: null },
  { id: 'ETH-104', name: 'L2 Cross-Domain Message Replay', severity: 'CRITICAL', category: 'Restaking & L2', description: 'L2 bridge messages can be replayed', swc: null },
];
