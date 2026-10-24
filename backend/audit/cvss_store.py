"""Versioned project ratings, independent of conclusion and POC revisions."""
from __future__ import annotations
import copy
import json
import os
import sqlite3
import uuid
from pathlib import Path
from .cvss_assessment import normalise_record, stamp


def encoded(value):
    return json.dumps(value, ensure_ascii=False)


def decode_rating(item):
    for key in ('cvss', 'cvss_assessment'):
        value = item.get(key)
        if isinstance(value, str):
            item[key] = json.loads(value) if value else None
    return item


class CvssConflict(ValueError):
    pass


class CvssStoreMixin:
    def _init_cvss(self):
        tables = ('findings', 'project_findings')
        columns = {table:{row['name'] for row in self._rows(f'PRAGMA table_info({table})')} for table in tables}
        needs_columns = any('cvss_assessment' not in columns[table] for table in tables)
        if needs_columns and self.path != ':memory:' and any(self._row(f'SELECT COUNT(*) AS n FROM {table}')['n'] for table in tables):
            destination = Path(f'{self.path}.pre-cvss31-{uuid.uuid4().hex[:12]}.bak')
            descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(descriptor)
            with sqlite3.connect(destination) as backup:
                self._db.backup(backup)
        self._db.execute('BEGIN IMMEDIATE')
        try:
            for table in tables:
                for column in ('cvss', 'cvss_assessment', 'legacy_severity'):
                    if column not in columns[table]:
                        self._db.execute(f'ALTER TABLE {table} ADD COLUMN {column} TEXT')
                for row in self._rows(f'SELECT id, severity, revision FROM {table} WHERE cvss_assessment IS NULL'):
                    item = normalise_record(dict(row))
                    self._write_cvss(table, row['id'], item, int(row['revision'] or 1))
            self._db.execute('''CREATE TABLE IF NOT EXISTS project_finding_cvss_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_finding_id TEXT NOT NULL,
                assessment_revision INTEGER NOT NULL,
                conclusion_revision INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                payload TEXT NOT NULL,
                UNIQUE(project_finding_id, assessment_revision)
            )''')
            self._db.execute('CREATE INDEX IF NOT EXISTS idx_cvss_history ON project_finding_cvss_history(project_finding_id, id DESC)')
            self._db.execute('COMMIT')
        except Exception:
            self._db.execute('ROLLBACK')
            raise

    def _write_cvss(self, table, ident, item, conclusion_revision):
        info = copy.deepcopy(item['cvss_assessment'])
        info['conclusion_revision'] = conclusion_revision
        self._db.execute(f'UPDATE {table} SET cvss=?, cvss_assessment=?, legacy_severity=?, severity=? WHERE id=?',
            (encoded(item.get('cvss')), encoded(info), item.get('legacy_severity'), item['severity'], ident))

    def _merge_cvss(self, ident, finding, revision, previous, run_id):
        # The ledger rating belongs to a conclusion version. A re-score inside the run
        # that produced it is a correction; another run's rediscovery of the *same*
        # conclusion must not churn it and keeps its own score in that run. Only a
        # manual revision or a genuinely corrected conclusion otherwise replaces it.
        old_info = (previous or {}).get('cvss_assessment') or {}
        same_origin = old_info.get('run_id') is not None and old_info.get('run_id') == run_id
        if (previous and old_info.get('conclusion_revision') == revision
                and (old_info.get('source') == 'manual'
                     or (previous.get('cvss') and not same_origin))):
            # A manual rating, or another run's automatic rating of the same conclusion,
            # is not churn for a rediscovery to erase.  A re-score inside the very run
            # that produced the rating is a correction and may replace it.
            self._write_cvss('project_findings', ident, previous, revision)
            return
        item = normalise_record(finding)
        info = item['cvss_assessment']
        info['run_id'] = info.get('run_id') or run_id
        source = self.get_run(run_id)
        if source:
            info['snapshot_id'] = info.get('snapshot_id') or source['snapshot_id']
        # Identical rediscoveries add a run relation, not another rating revision.
        if previous and previous.get('cvss') == item['cvss'] and old_info.get('metric_details') == info.get('metric_details') and old_info.get('conclusion_revision') == revision:
            self._write_cvss('project_findings', ident, previous, revision)
            return
        info['assessment_revision'] = int(old_info.get('assessment_revision') or 0) + 1
        info['conclusion_revision'] = revision
        info['created_at'] = stamp()
        self._write_cvss('project_findings', ident, item, revision)
        self._append_cvss_history(ident, item, revision)

    def _append_cvss_history(self, ident, item, revision):
        info = item['cvss_assessment']
        self._db.execute('INSERT INTO project_finding_cvss_history (project_finding_id,assessment_revision,conclusion_revision,created_at,payload) VALUES (?,?,?,?,?)',
            (ident, info['assessment_revision'], revision, info.get('created_at') or stamp(),
             encoded({key:item.get(key) for key in ('cvss','cvss_assessment','legacy_severity')})))

    def update_project_cvss(self, ident, rating, *, expected_revision, expected_assessment_revision, reason):
        with self._lock:
            self._db.execute('BEGIN IMMEDIATE')
            try:
                finding = self.get_project_finding(ident)
                if not finding:
                    raise KeyError(ident)
                current = finding.get('cvss_assessment') or {}
                if finding['revision'] != expected_revision or int(current.get('assessment_revision') or 0) != expected_assessment_revision:
                    raise CvssConflict('结论或评分已更新，请刷新后比较并重新提交。')
                item = copy.deepcopy(rating)
                info = item['cvss_assessment']
                info.update(source='manual', reason=reason, assessment_revision=expected_assessment_revision + 1,
                            conclusion_revision=expected_revision, created_at=stamp())
                item['legacy_severity'] = finding.get('legacy_severity')
                self._write_cvss('project_findings', ident, item, expected_revision)
                self._append_cvss_history(ident, item, expected_revision)
                self._db.execute('UPDATE project_findings SET updated_at=? WHERE id=?', (stamp(),ident))
                self._db.execute('COMMIT')
            except Exception:
                self._db.execute('ROLLBACK')
                raise
        return self.get_project_finding(ident)

    def project_cvss_history(self, ident, *, offset=0, limit=25):
        with self._lock:
            finding = self.get_project_finding(ident)
            if not finding:
                raise KeyError(ident)
            rows = self._rows('SELECT * FROM project_finding_cvss_history WHERE project_finding_id=? ORDER BY id DESC LIMIT ? OFFSET ?', (ident,limit,offset))
            total = self._row('SELECT COUNT(*) AS n FROM project_finding_cvss_history WHERE project_finding_id=?', (ident,))['n']
            items = []
            for row in rows:
                item = json.loads(row['payload'])
                applicable = row['conclusion_revision'] == finding['revision']
                info = item['cvss_assessment']
                if not applicable:
                    info['status'] = 'stale'
                run = self.get_run(info.get('run_id') or '')
                items.append({'id':row['id'], 'cvss':item.get('cvss'), 'cvss_assessment':info,
                              'applicable':applicable, 'source_run_available':run is not None})
        return {'items':items, 'total':total, 'offset':offset, 'limit':limit}
