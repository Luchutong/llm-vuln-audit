#!/usr/bin/env python3
"""Read-only counterfactual progress replay; never invokes models or changes scores."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from audit.investigation import POLICY, pause_reason, progress, valid_submission  # noqa: E402


def replay(database: Path, run_id: str | None = None):
    before = hashlib.sha256(database.read_bytes()).hexdigest()
    with sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True) as db:
        db.row_factory = sqlite3.Row
        if not run_id:
            run_id = db.execute('SELECT id FROM runs ORDER BY created_at DESC LIMIT 1').fetchone()[0]
        rows = db.execute('SELECT a.*,t.task_key FROM planner_task_attempts a JOIN planner_tasks t ON t.id=a.task_id '
            'WHERE a.run_id=? AND a.attempt>0 ORDER BY a.created_at,a.id', (run_id,)).fetchall()
    previous, reads, known, tasks = {}, {}, [], {}
    for row in rows:
        key = row['task_key']
        result, seen = json.loads(row['result'] or '{}'), json.loads(row['seen'] or '[]')
        old = previous.get(key, {})
        computed = progress(old, result, seen, reads.get(key, []), known)
        original = result.get('host_progress') or {}
        result['host_progress'] = computed
        pause = pause_reason(result) if valid_submission(result) else None
        task = tasks.setdefault(key, dict(task_key=key, attempts=[], first_pause=None, raw_claim_count=0))
        task['raw_claim_count'] += len(result.get('findings') or [])
        task['attempts'].append(dict(attempt=row['attempt'], original_new_conclusions=original.get('new_conclusions'),
            new_conclusions=computed['new_conclusions'], new_evidence=computed['new_evidence'],
            stalled_passes=computed['stalled_passes'], settled_candidates=computed['settled_candidates']))
        if pause and not task['first_pause']:
            task['first_pause'] = dict(attempt=row['attempt'], **pause)
        previous[key] = result
        reads.setdefault(key, []).extend(seen)
        if valid_submission(result):
            known.extend(result.get('findings') or [])
    assert hashlib.sha256(database.read_bytes()).hexdigest() == before
    return dict(policy=POLICY, run_id=run_id, source_db_sha256=before, source_db_unchanged=True,
        scope='counterfactual classification of original submissions; no new execution or score change',
        model_requests=0, runner_jobs=0, recorded_attempts=len(rows), raw_claim_count=sum(t['raw_claim_count'] for t in tasks.values()),
        tasks=list(tasks.values()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--run-id')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.resolve() == args.db.resolve():
        parser.error('--out must not overwrite the source database')
    report = replay(args.db, args.run_id)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'tasks'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
