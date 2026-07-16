import { useEffect, useState } from 'react';
import { listen } from '@tauri-apps/api/event';
import type { AgentEvent } from '@/api/types';

/** Maximum events kept in memory for the live feed. */
const MAX_EVENTS = 500;

export interface RealtimeState {
  events:    AgentEvent[];
  connected: boolean;
  error:     string | null;
  clear:     () => void;
}

/**
 * Subscribe to Tauri 'agent-event' events emitted by the Rust backend's
 * background polling thread.  No SSE / HTTP connection is used.
 *
 * The `_url` parameter is kept for API compatibility but is ignored.
 */
export function useRealtime(_url: string, enabled = true): RealtimeState {
  const [events, setEvents]       = useState<AgentEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError]         = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) return;

    let unlisten: (() => void) | undefined;
    let cancelled = false;

    listen<AgentEvent>('agent-event', (tauri_event) => {
      setEvents(prev => [tauri_event.payload, ...prev].slice(0, MAX_EVENTS));
    })
      .then(fn => {
        if (cancelled) { fn(); return; }
        unlisten = fn;
        setConnected(true);
        setError(null);
      })
      .catch((err: unknown) => {
        setConnected(false);
        setError(err instanceof Error ? err.message : String(err));
      });

    return () => {
      cancelled = true;
      unlisten?.();
      setConnected(false);
    };
  }, [enabled]);

  const clear = () => setEvents([]);

  return { events, connected, error, clear };
}

