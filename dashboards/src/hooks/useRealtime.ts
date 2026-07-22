import { useEffect, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import type { AgentEvent, TransactionEvent } from '@/api/types';

/** Maximum events kept in memory for the live feed. */
const MAX_EVENTS = 500;

export interface RealtimeState {
  events:    RealtimeEvent[];
  connected: boolean;
  error:     string | null;
  clear:     () => void;
}

export type RealtimeEvent =
  | { category: 'agent'; id: string; timestamp: number; payload: AgentEvent }
  | { category: 'transactional_environment'; id: string; timestamp: number; payload: TransactionEvent };

/**
 * Subscribe to Tauri 'agent-event' events emitted by the Rust backend's
 * background polling thread.  No SSE / HTTP connection is used.
 *
 * The `_url` parameter is kept for API compatibility but is ignored.
 */
export function useRealtime(_url: string, enabled = true): RealtimeState {
  const [events, setEvents]       = useState<RealtimeEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError]         = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) return;

    let unlisten: (() => void)[] = [];
    let cancelled = false;

    listen<AgentEvent>('agent-event', (tauri_event) => {
      const payload = tauri_event.payload;
      const entry: RealtimeEvent = {
        category: 'agent',
        id: `agent-${payload.event_id}`,
        timestamp: payload.ts,
        payload,
      };
      setEvents(prev => [entry, ...prev].slice(0, MAX_EVENTS));
    })
      .then(fn => {
        if (cancelled) { fn(); return; }
        unlisten.push(fn);
        setConnected(true);
        setError(null);
      })
      .catch((err: unknown) => {
        setConnected(false);
        setError(err instanceof Error ? err.message : String(err));
      });
    listen<TransactionEvent>('transaction-event', (tauriEvent) => {
      const payload = tauriEvent.payload;
      const entry: RealtimeEvent = {
        category: 'transactional_environment',
        id: `transaction-${payload.transaction_event_id}`,
        timestamp: payload.occurred_at,
        payload,
      };
      setEvents(prev => [entry, ...prev].slice(0, MAX_EVENTS));
    })
      .then(fn => {
        if (cancelled) { fn(); return; }
        unlisten.push(fn);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : String(err));
      });

    return () => {
      cancelled = true;
      unlisten.forEach(stop => stop());
      setConnected(false);
    };
  }, [enabled]);

  const clear = () => setEvents([]);

  return { events, connected, error, clear };
}
