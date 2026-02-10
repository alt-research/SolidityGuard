import type { WsMessage } from './types';

export function connectAuditStream(
  auditId: string,
  onMessage: (msg: WsMessage) => void,
  onError?: (err: Event) => void,
): () => void {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = import.meta.env.VITE_WS_URL || `${protocol}//${window.location.host}`;
  const ws = new WebSocket(`${host}/api/audit/${auditId}/stream`);

  ws.onmessage = (event) => {
    try {
      const msg: WsMessage = JSON.parse(event.data);
      onMessage(msg);
    } catch {
      // ignore malformed messages
    }
  };

  ws.onerror = (event) => {
    onError?.(event);
  };

  return () => {
    ws.close();
  };
}
