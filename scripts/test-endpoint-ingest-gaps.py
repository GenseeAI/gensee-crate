#!/usr/bin/env python3
"""Exercise the real CLI's sensor-gap alert rate limit across process restarts."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'target/debug/gensee').resolve())
with tempfile.TemporaryDirectory(prefix='gensee-ingest-gaps-') as directory:
    env = dict(os.environ, GENSEE_HOME=directory, GENSEE_STORE_ENCRYPTION='0',
               GENSEE_TELEMETRY_REMOTE='0', GENSEE_TELEMETRY_COLLECTION='0')
    def ingest(offsets, boot='test-boot'):
        events = [{
            'schema_version': 1, 'event_id': f'{boot}-{offset}', 'boot_id': boot,
            'observed_at_ms': 1788640000000 + offset, 'event_type': 'write',
            'action': 'notify', 'actor': {'pid': 100 + offset, 'pidversion': 1},
            'file': {'path': f'/synthetic/{offset}.txt'}, 'dropped_events': 1,
        } for offset in offsets]
        subprocess.run([binary, 'ingest', 'endpoint-security'], env=env,
                       input=''.join(json.dumps(e) + '\n' for e in events),
                       text=True, capture_output=True, check=True)
    ingest(range(200))
    ingest([300])  # Restart and change PID/path: same sensor incident.
    ingest([61000])  # Later incident must remain visible.
    ingest([62000], 'new-boot')  # Another sensor generation is independent.
    # The sensor uses a metadata-only diagnostic when revoked payloads carry
    # loss and no live event remains to carry the delta.
    diagnostic = {
        'schema_version': 1, 'event_id': 'diagnostic-boot:900:gap',
        'boot_id': 'diagnostic-boot', 'sensor_cursor': 900,
        'observed_at_ms': 1788640123000, 'event_type': 'sensor_gap',
        'action': 'notify', 'actor': {'pid': 9999}, 'dropped_events': 7,
    }
    subprocess.run([binary, 'ingest', 'endpoint-security'], env=env,
                   input=json.dumps(diagnostic) + '\n', text=True,
                   capture_output=True, check=True)
    with sqlite3.connect(Path(directory) / 'gensee.db') as database:
        rows = database.execute('SELECT rule_id, count(*) FROM alerts GROUP BY rule_id').fetchall()
        assert rows == [('endpoint_security_event_gap', 4)], rows
        assert database.execute('SELECT count(*) FROM alerts WHERE request_id IS NOT NULL').fetchone()[0] == 0
        assert database.execute("SELECT count(*) FROM alerts WHERE action != 'allow' OR severity != 'info'").fetchone()[0] == 0
        payload = json.loads(database.execute("SELECT args FROM system_events WHERE type='sensor_gap'").fetchone()[0])
        assert payload['dropped_events'] == 7
        # Revoked-payload privacy is tested against real sensor output in
        # CoworkEndpointScopeTests; this fixture checks durable gap ingestion.
    dashboard = json.loads(subprocess.run([binary, 'dashboard-state'], env=env,
                           text=True, capture_output=True, check=True).stdout)
    assert dashboard['alerts'] == []
    assert all(request['high_risk_alert_count'] == 0 for request in dashboard['requests'])
    assert dashboard['summary']['alerts_count'] == 0
    assert len(dashboard['monitoringGaps']) == 4
    print('Endpoint ingest gap regression passed')
