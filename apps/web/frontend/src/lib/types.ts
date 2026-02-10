export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type AuditMode = 'quick' | 'standard' | 'deep';

export type AuditStatusType = 'pending' | 'running' | 'complete' | 'failed';

export type ToolName = 'pattern' | 'slither' | 'aderyn' | 'mythril' | 'echidna' | 'foundry' | 'halmos' | 'certora';

export type ToolStatus = 'idle' | 'running' | 'done' | 'error' | 'unavailable';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: number;
  file: string;
  line: number;
  code_snippet: string;
  description: string;
  attack_scenario?: string;
  remediation: string;
  category: string;
  swc: string | null;
  tool?: string;
}

export interface AuditRequest {
  files?: File[];
  path?: string;
  mode: AuditMode;
  tools: ToolName[];
  categories?: string[];
}

export interface AuditStatus {
  id: string;
  status: AuditStatusType;
  phase: number;
  total_phases: number;
  phase_name: string;
  progress: number;
  findings_count: Record<Severity, number>;
  started_at: string;
  completed_at: string | null;
}

export interface AuditReport {
  id: string;
  score: number;
  summary: Record<Severity, number>;
  findings: Finding[];
  tools_used: string[];
  report_markdown: string;
  timestamp: string;
}

export interface VulnPattern {
  id: string;
  name: string;
  severity: Severity;
  category: string;
  description: string;
  swc: string | null;
}

export interface ToolInfo {
  name: ToolName;
  status: ToolStatus;
  label: string;
}

export interface RecentAudit {
  id: string;
  name: string;
  score: number;
  critical_count: number;
  high_count: number;
  files_count: number;
  timestamp: string;
}

export interface WsMessage {
  type: 'phase' | 'progress' | 'finding' | 'complete' | 'error';
  phase?: number;
  total?: number;
  name?: string;
  percent?: number;
  finding?: Finding;
  summary?: Record<Severity, number>;
  score?: number;
  message?: string;
}

export const AUDIT_PHASES = [
  'Entry Point Analysis',
  'Automated Scan',
  'Finding Verification',
  'Pattern Analysis',
  'Exploit PoC Generation',
  'Dynamic Verification',
  'Report Generation',
] as const;

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export const CATEGORIES = [
  'Reentrancy',
  'Access Control',
  'Arithmetic',
  'External Calls',
  'Oracle & Price',
  'Storage & State',
  'Logic Errors',
  'Token Issues',
  'Proxy & Upgrade',
  'DeFi',
  'Gas & DoS',
  'Miscellaneous',
  'Transient Storage',
  'EIP-7702',
  'Account Abstraction',
  'Modern DeFi',
  'Input Validation',
  'Off-Chain',
  'Restaking & L2',
] as const;
