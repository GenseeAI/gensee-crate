#!/usr/bin/env python3
"""Exercise false-positive feedback without granting or tuning permissions."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

binary = str(Path(sys.argv[1] if len(sys.argv) > 1 else 'target/debug/gensee').resolve())
with tempfile.TemporaryDirectory(prefix='gensee-feedback-isolation-') as directory:
    root = Path(directory)
    env = dict(os.environ, GENSEE_HOME=directory, GENSEE_STORE_ENCRYPTION='0',
               GENSEE_TELEMETRY_COLLECTION='0', GENSEE_TELEMETRY_REMOTE='0')
    def run(*args):
        return subprocess.run([binary, *args], env=env, text=True, capture_output=True, check=True).stdout
    policy = run('policy', 'print-default').encode()
    (root / 'policy.json').write_bytes(policy)
    (root / 'approvals.json').write_text('[]')
    for label, verdict in [('false_positive', 'allow'), ('feedback_withdrawn', 'agree')]:
        run('feedback', 'record', '--event-key', 'alert:123', '--rule', 'policy_credential_content_read',
            '--gensee', 'ask', '--verdict', verdict, '--label', label,
            '--path', '/private/tmp/example.txt', '--note', 'Triage only; permissions unchanged.')
        assert (root / 'policy.json').read_bytes() == policy
        assert json.loads((root / 'approvals.json').read_text()) == []
    with sqlite3.connect(root / 'gensee.db') as database:
        labels = database.execute('SELECT label FROM human_feedback ORDER BY created_at, rowid').fetchall()
        assert labels == [('false_positive',), ('feedback_withdrawn',)], labels
    print('Feedback permission isolation passed')
