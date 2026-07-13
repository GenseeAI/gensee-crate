import { useEffect, useRef, useState } from 'react';
import type { AgentEvent } from '@/api/types';

/** Maximum events kept in memory for the live feed. */
const MAX_EVENTS = 500;

export interface RealtimeState {
  events: AgentEvent[];
  connected: boolean;
  error: string | null;
  clear: () => void;
}

/**
 * Open an SSE connection to `url` and collect incoming agent events.
 * Automatically reconnects on error (browser SSE semantics).
 */
export function useRealtime(url: string, enabled = true): RealtimeState {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    if (!enabled) return;

    const es = new EventSource(url);
    esRef.current = es;

    es.addEventListener('open', () => {
      setConnected(true);
      setError(null);
    });

    es.addEventListener('message', (e: MessageEvent<string>) => {
      try {
        const event = JSON.parse(e.data) as AgentEvent;
        setEvents(prev => [event, ...prev].slice(0, MAX_EVENTS));
      } catch {
        // Silently ignore malformed frames.
      }
    });

    es.addEventListener('error', () => {
      setConnected(false);
      setError('Connection lost — browser will retry automatically.');
    });

    return () => {
      es.close();
      esRef.current = null;
      setConnected(false);
    };
  }, [url, enabled]);

  const clear = () => setEvents([]);

  return { events, connected, error, clear };
}
