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
export async function checkLocalTools(): Promise<{ slither: boolean; aderyn: boolean; mythril: boolean; forge: boolean }> {
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
        report_markdown: `# SolidityGuard Audit Report\n\nScore: ${r.security_score}/100\nFindings: ${r.summary.total || 0}\nTools: ${r.tools_used.join(', ')}`,
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
      // Return built-in pattern list for desktop mode
      return Promise.resolve([
        { id: 'ETH-001', name: 'Reentrancy', severity: 'CRITICAL', category: 'Reentrancy', description: 'Single-function reentrancy', swc: 'SWC-107' },
        { id: 'ETH-006', name: 'Missing Access Control', severity: 'CRITICAL', category: 'Access Control', description: 'Missing access control on sensitive function', swc: 'SWC-105' },
        { id: 'ETH-013', name: 'Integer Overflow', severity: 'HIGH', category: 'Arithmetic', description: 'Integer overflow/underflow', swc: 'SWC-101' },
        { id: 'ETH-019', name: 'Delegatecall', severity: 'CRITICAL', category: 'External Calls', description: 'Delegatecall to untrusted callee', swc: 'SWC-112' },
        { id: 'ETH-024', name: 'Oracle Manipulation', severity: 'CRITICAL', category: 'Oracle & Price', description: 'Price oracle manipulation', swc: null },
      ] as VulnPattern[]);
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
        markdown: `# SolidityGuard Audit Report\n\nScore: ${r.security_score}/100\nFindings: ${r.summary.total || 0}\nTools: ${r.tools_used.join(', ')}`,
        score: r.security_score,
      }));
    }
    return request(`/api/audit/${encodeURIComponent(id)}/report`);
  },
};

export { ApiError, isTauri };
