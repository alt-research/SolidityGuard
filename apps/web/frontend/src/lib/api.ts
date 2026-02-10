import type { AuditStatus, AuditReport, Finding, VulnPattern, ToolInfo } from './types';

const BASE_URL = import.meta.env.VITE_API_URL || '';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }
  return res.json();
}

export const api = {
  startAudit(data: FormData): Promise<{ id: string }> {
    return fetch(`${BASE_URL}/api/audit`, { method: 'POST', body: data }).then(r => r.json());
  },

  getAuditStatus(id: string): Promise<AuditStatus> {
    return request(`/api/audit/${id}`);
  },

  getFindings(id: string): Promise<Finding[]> {
    return request(`/api/audit/${id}/findings`);
  },

  getReport(id: string): Promise<AuditReport> {
    return request(`/api/audit/${id}/report`);
  },

  cancelAudit(id: string): Promise<void> {
    return request(`/api/audit/${id}`, { method: 'DELETE' });
  },

  getPatterns(): Promise<VulnPattern[]> {
    return request('/api/patterns');
  },

  getTools(): Promise<ToolInfo[]> {
    return request('/api/tools');
  },
};
