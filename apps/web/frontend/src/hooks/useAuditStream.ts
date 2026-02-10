import { useState, useEffect, useRef, useCallback } from 'react';
import type { Finding, Severity, WsMessage } from '../lib/types.ts';
import { isTauri } from '../services/api.ts';

interface AuditStreamState {
  phase: number;
  phaseName: string;
  totalPhases: number;
  progress: number;
  findings: Finding[];
  findingsCounts: Record<Severity, number>;
  score: number | null;
  isComplete: boolean;
  error: string | null;
  connected: boolean;
}

const INITIAL_STATE: AuditStreamState = {
  phase: 0,
  phaseName: '',
  totalPhases: 7,
  progress: 0,
  findings: [],
  findingsCounts: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
  score: null,
  isComplete: false,
  error: null,
  connected: false,
};

const MAX_RECONNECT_DELAY = 10000;

export function useAuditStream(auditId: string | undefined): AuditStreamState {
  const [state, setState] = useState<AuditStreamState>(INITIAL_STATE);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const reconnectAttempt = useRef(0);

  const handleMessage = useCallback((msg: WsMessage) => {
    setState((prev) => {
      switch (msg.type) {
        case 'phase':
          return {
            ...prev,
            phase: msg.phase ?? prev.phase,
            phaseName: msg.name ?? prev.phaseName,
            totalPhases: msg.total ?? prev.totalPhases,
            progress: 0,
          };
        case 'progress':
          return {
            ...prev,
            progress: msg.percent ?? prev.progress,
          };
        case 'finding':
          if (!msg.finding) return prev;
          return {
            ...prev,
            findings: [...prev.findings, msg.finding],
            findingsCounts: {
              ...prev.findingsCounts,
              [msg.finding.severity]: (prev.findingsCounts[msg.finding.severity] || 0) + 1,
            },
          };
        case 'complete':
          return {
            ...prev,
            isComplete: true,
            progress: 1,
            score: msg.score ?? prev.score,
            findingsCounts: msg.summary ?? prev.findingsCounts,
          };
        case 'error':
          return {
            ...prev,
            error: msg.message ?? 'Unknown error',
          };
        default:
          return prev;
      }
    });
  }, []);

  // Tauri mode: fetch completed audit result directly (no WebSocket)
  useEffect(() => {
    if (!isTauri || !auditId) return;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const tauri = (window as any).__TAURI__;

    tauri.core.invoke('get_audit', { id: auditId })
      .then((result: { security_score: number; findings: Finding[]; summary: Record<string, number>; tools_used: string[] }) => {
        const counts: Record<Severity, number> = {
          CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
        };
        for (const f of result.findings) {
          const sev = (f.severity?.toUpperCase() || 'INFO') as Severity;
          if (sev in counts) counts[sev]++;
        }
        setState({
          phase: 7,
          phaseName: 'Complete',
          totalPhases: 7,
          progress: 1,
          findings: result.findings,
          findingsCounts: counts,
          score: result.security_score,
          isComplete: true,
          error: null,
          connected: true,
        });
      })
      .catch((err: Error) => {
        setState((prev) => ({ ...prev, error: err.message || 'Failed to load audit' }));
      });
  }, [auditId]);

  // Web mode: WebSocket streaming
  useEffect(() => {
    if (isTauri || !auditId) return;

    setState(INITIAL_STATE);
    reconnectAttempt.current = 0;

    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsBase = import.meta.env.VITE_WS_URL || `${protocol}//${window.location.host}`;
      const ws = new WebSocket(`${wsBase}/api/audit/${auditId}/stream`);
      wsRef.current = ws;

      ws.onopen = () => {
        reconnectAttempt.current = 0;
        setState((prev) => ({ ...prev, connected: true, error: null }));
      };

      ws.onmessage = (event) => {
        try {
          const msg: WsMessage = JSON.parse(event.data);
          handleMessage(msg);
        } catch {
          // ignore malformed messages
        }
      };

      ws.onclose = (event) => {
        setState((prev) => ({ ...prev, connected: false }));
        wsRef.current = null;

        // Don't reconnect if the audit completed or was closed intentionally
        if (event.code === 1000) return;

        // Auto-reconnect with exponential backoff
        const delay = Math.min(1000 * 2 ** reconnectAttempt.current, MAX_RECONNECT_DELAY);
        reconnectAttempt.current++;
        reconnectTimer.current = setTimeout(connect, delay);
      };

      ws.onerror = () => {
        setState((prev) => ({ ...prev, error: 'WebSocket connection error' }));
      };
    }

    connect();

    return () => {
      clearTimeout(reconnectTimer.current);
      if (wsRef.current) {
        wsRef.current.close(1000);
        wsRef.current = null;
      }
    };
  }, [auditId, handleMessage]);

  return state;
}
