"""Explicit, separately budgeted continuation runs; parent facts remain immutable."""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from .execution_state import TERMINAL
from .config import model_unavailable_reason
from .final_review import canonical_groups, comparison_candidates


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class ContinuationStoreMixin:
    def pending_continuation_verifications(self, run_id):
        row = self._row('SELECT task_spec FROM runs WHERE id=?', (run_id,))
        info = (json.loads(row[0] or '{}') if row else {}).get('continuation') or {}
        if not info or info['mode'] == 'review':
            return []
        selected = set(info.get('retest_finding_ids') or [])
        inherited = set(info.get('inherited_finding_ids') or [])
        versions = info.get('inherited_subject_versions') or {}
        entries, _ = canonical_groups(self.list_findings(run_id))
        return [e['frozen_claim']['finding_id'] for e in entries
                if (selected.intersection(r['finding_id'] for r in e['source_record_refs'])
                    or (info['mode'] == 'audit' and (
                        e['frozen_claim']['finding_id'] not in inherited
                        or int(e['current_claim_ref']['project_revision'] or e['current_claim_ref']['revision']) > int(versions.get(e['canonical_id'], 0)))))
                and e['frozen_claim']['verification_status'] not in {'verified', 'rejected'}]

    def continuation_options(self, run_id):
        run = self.get_run(run_id)
        if run is None:
            raise KeyError(run_id)
        supported = bool(self.host_queue_enabled(run_id) and self.batch_review_enabled(run_id))
        records = self.attach_final_decisions(run_id, self.list_findings(run_id)) if supported else []
        entries, _ = canonical_groups(records)
        by_id = {r['id']: r for r in records}
        items = []
        for entry in entries:
            claim = entry['frozen_claim']
            raw = by_id[claim['finding_id']]
            status = str(raw.get('verification_status') or 'unverified')
            contested = (self._current_review(raw) or {}).get('decision') == 'contested'
            items.append(dict(finding_id=raw['id'], ledger_id=raw.get('project_finding_id'),
                revision=int(raw.get('revision') or 1), title=raw['title'], verification_status=status,
                disposition=entry['final_disposition'], can_retest=status != 'verified' or contested))
        active = [r['id'] for r in self._rows(
            "SELECT id FROM runs WHERE status IN ('pending','running','paused')"
            " AND json_extract(task_spec,'$.continuation.parent_run_id')=?", (run_id,))]
        children = [dict(r) for r in self._rows(
            "SELECT id,status,created_at,json_extract(task_spec,'$.continuation.mode') AS mode FROM runs"
            " WHERE json_extract(task_spec,'$.continuation.parent_run_id')=? ORDER BY created_at DESC", (run_id,))]
        return dict(parent_run_id=run_id, available=supported and run['status'] in TERMINAL and not active,
            reason='已有继续任务尚未结束' if active else '仅支持已结束的宿主队列审计' if not supported or run['status'] not in TERMINAL else '',
            active_run_ids=active, continuations=children, items=items, retestable_count=sum(i['can_retest'] for i in items),
            pending_review_count=sum(not e.get('final_batch_review') or e['final_disposition'] != 'accepted' for e in entries),
            defaults=dict(run_limits=dict(responses=256, tools=2048, seconds=1800),
                          poc=dict(session_policy='session-queue-v1', max_seconds=600, max_jobs=12, execute_requests=60, conclude_requests=3)))

    def create_continuation(self, parent_id, request, *, model_profile=None):
        """Copy host facts and queues under one transaction, without touching the ledger.

        Job/context identities remain original facts. Finding/verification/task IDs are
        new local references. No claim, capability, active job or spent budget is copied.
        """
        request_hash = hashlib.sha256(encoded(request).encode()).hexdigest()
        child_id = uuid.uuid5(uuid.NAMESPACE_URL, f'audit-continuation:{parent_id}:{request["request_id"]}').hex
        with self._lock:
            existing = self.get_run(child_id)
            if existing:
                if existing['task_spec']['continuation']['request_hash'] != request_hash:
                    raise ValueError('相同 request_id 不能使用不同复测参数')
                return existing
            parent = self.get_run(parent_id)
            if parent is None:
                raise KeyError(parent_id)
            options = self.continuation_options(parent_id)
            if not options['available']:
                raise ValueError(options['reason'])
            if self.get_snapshot(parent['snapshot_id']) is None or not self.get_project_map(parent_id):
                raise ValueError('原源码快照或冻结项目图不可用')
            eligible = {i['finding_id'] for i in options['items'] if i['can_retest']}
            selected = set(eligible if request['finding_ids'] is None else request['finding_ids'])
            if not selected.issubset(eligible):
                raise ValueError('复测只能选择本运行当前未决或正式复核存疑的结论')
            if request['mode'] == 'review':
                selected = set()
            elif request['mode'] == 'poc_review' and not selected:
                raise ValueError('没有选中的未决 POC；可选择仅补终审')
            now = datetime.now(timezone.utc).isoformat()
            rows = {table: [dict(r) for r in self._rows(f'SELECT * FROM {table} WHERE run_id=?', (parent_id,))]
                    for table in ('planner_tasks', 'planner_task_attempts', 'findings', 'verification_reviews', 'poc_verification_jobs')}
            parent_records = self.attach_final_decisions(parent_id, self.list_findings(parent_id))
            parent_entries, _ = canonical_groups(parent_records)
            peers = comparison_candidates(parent_entries)
            selected_subjects = {i['ledger_id'] or i['finding_id'] for i in options['items'] if i['finding_id'] in selected}
            carried = {e['canonical_id']: e['final_batch_review'] for e in parent_entries
                       if e['final_disposition'] == 'accepted' and e.get('final_batch_review')
                       and e['canonical_id'] not in selected_subjects
                       and not any(p['item_id'] in selected_subjects for p in peers.get(e['canonical_id'], []))}
            verifications = [dict(v) for f in rows['findings'] for v in self._rows('SELECT * FROM verifications WHERE finding_id=?', (f['id'],))]
            mapping = {parent_id: child_id}
            for table in ('planner_tasks', 'findings', 'verification_reviews'):
                mapping.update({r['id']: uuid.uuid4().hex for r in rows[table]})
            mapping.update({v['id']: uuid.uuid4().hex for v in verifications})
            parent_goal = self.get_task_goal(parent_id)
            parent_session = self.get_planner_session(parent_id)
            if parent_goal is None or parent_session is None:
                raise ValueError('原任务缺少目标或 Planner 会话')
            child_session = uuid.uuid4().hex
            mapping[parent_session['session_id']] = child_session
            policy = dict(parent.get('poc_policy') or {})
            policy.update(max_seconds=request['poc']['max_seconds'], max_jobs=request['poc']['max_jobs'],
                sdk_requests=dict(version='sdk-requests-v1', execute=request['poc']['execute_requests'], conclude=request['poc']['conclude_requests'],
                                  max_seconds=request['poc']['max_seconds']))
            if policy.get('runtime') == 'claude_sdk':
                policy.update(session_policy=request['poc'].get('session_policy', 'session-queue-v1'),
                              item_warning_seconds=request['poc']['max_seconds'])
            if request['mode'] == 'review':
                policy.update(mode='off', required=False)
            else:
                policy.update(enabled=True, mode='required' if policy.get('mode') == 'required' else 'auto')
            inherited_versions = {}
            for finding in rows['findings']:
                subject = finding.get('project_finding_id') or mapping[finding['id']]
                inherited_versions[subject] = max(inherited_versions.get(subject, 0), int(finding.get('project_revision') or finding.get('revision') or 1))
            info = dict(version='continuation-v1', parent_run_id=parent_id,
                root_run_id=(parent['task_spec'].get('continuation') or {}).get('root_run_id', parent_id),
                mode=request['mode'], request_id=request['request_id'], request_hash=request_hash,
                parent_usage=parent.get('execution_summary', {}).get('run_usage'),
                inherited_finding_ids=[mapping[f['id']] for f in rows['findings']],
                inherited_subject_versions=inherited_versions,
                retest_finding_ids=[mapping[i] for i in sorted(selected)],
                source_refs={mapping[f['id']]: f['id'] for f in rows['findings']})
            task = {**parent['task_spec'], 'workflow_limits': None, 'continuation': info}
            child = {**parent, 'id': child_id, 'created_at': now, 'task_spec': task, 'poc_policy': policy,
                     'run_limits': request['run_limits'], 'project_baseline': parent.get('project_baseline') or []}
            if model_profile is not None:
                child.update(model=model_profile['model'], model_profile=dict(model_profile))
            if reason := model_unavailable_reason((child.get('model_profile') or {}).get('model') or child['model']):
                raise ValueError(reason)
            info['model_profile_selection'] = request.get('model_profile_id', 'original')

            owned_refs = {'id', 'run_id', 'goal_id', 'task_id', 'origin_task_id', 'plan_id', 'session_id',
                          'finding_id', 'run_finding_id', 'verification_id', 'derived_from_finding_id', 'unit_id',
                          'item_id', 'duplicate_of', 'distinct_from'}
            def remap(value, field=None):
                if isinstance(value, dict):
                    return {k: v if k in {'continuation_source', 'job_results', 'normal_evidence', 'attack_evidence'} else remap(v, k)
                            for k, v in value.items()}
                if isinstance(value, list):
                    return [remap(v, field) for v in value]
                return mapping.get(value, value) if isinstance(value, str) and field in owned_refs else value

            def insert(table, row, *, omit=()):
                values = {}
                for key, value in row.items():
                    if key in omit:
                        continue
                    # Only host queue references change ownership. Observations,
                    # scripts, citations, CVSS provenance and runner bytes stay exact.
                    if table in {'planner_tasks', 'planner_task_attempts'} and key in {'result', 'context_spec', 'dependencies'} and isinstance(value, str):
                        try:
                            value = encoded(remap(json.loads(value)))
                        except (ValueError, TypeError):
                            pass
                    elif key in owned_refs:
                        value = mapping.get(value, value) if isinstance(value, str) else value
                    values[key] = value
                self._db.execute(f'INSERT INTO {table} ({",".join(values)}) VALUES ({",".join("?" for _ in values)})', tuple(values.values()))

            def setup():
                current = self._row('SELECT status FROM runs WHERE id=?', (parent_id,))
                if not current or current[0] not in TERMINAL:
                    raise ValueError('原运行已变化，不能创建继续任务')
                if self._row("SELECT id FROM runs WHERE id!=? AND status IN ('pending','running','paused') AND json_extract(task_spec,'$.continuation.parent_run_id')=?", (child_id, parent_id)):
                    raise ValueError('已有继续任务尚未结束')
                child_goal = self._row('SELECT id FROM task_goals WHERE run_id=?', (child_id,))[0]
                mapping[parent_goal['id']] = child_goal
                self._db.execute("INSERT INTO planner_project_maps SELECT ?,snapshot_id,scope,payload,? FROM planner_project_maps WHERE run_id=?", (child_id, now, parent_id))
                self._db.execute("INSERT INTO planner_sessions(run_id,goal_id,session_id,status,current_round,max_rounds,current_revision,created_at,updated_at) VALUES(?,?,?,'pending',0,?,0,?,?)",
                    (child_id, child_goal, child_session, task['max_planner_rounds'], now, now))
                for row in rows['planner_tasks']:
                    row.update(plan_id=None, claimed_by=None, claimed_at=None)
                    if request['mode'] == 'audit' and row['state'] in {'blocked', 'running'}:
                        row.update(state='ready', error=None, finished_at=None, max_attempts=row['attempts'] + task['max_iterations'])
                    insert('planner_tasks', row)
                for row in rows['planner_task_attempts']:
                    # Historical reads support coverage; historical cost is not new cost.
                    row.update(plan_id=None, usage=None)
                    insert('planner_task_attempts', row, omit=('id',))
                for row in rows['findings']:
                    insert('findings', row)
                    if parent.get('project_id') and row.get('project_finding_id'):
                        self._db.execute("INSERT OR IGNORE INTO project_finding_runs(project_id,project_finding_id,run_id,run_finding_id,relation,revision,created_at) VALUES(?,?,?,?,'carried',?,?)",
                            (parent['project_id'], row['project_finding_id'], child_id, mapping[row['id']], row.get('project_revision') or 1, now))
                for row in verifications:
                    data = json.loads(row.get('agent') or '{}')
                    data['continuation_source'] = dict(run_id=parent_id, verification_id=row['id'])
                    row['agent'] = encoded(data)
                    insert('verifications', row)
                for row in rows['verification_reviews']:
                    row['plan_id'] = None
                    insert('verification_reviews', row)
                for row in rows['poc_verification_jobs']:
                    row['id'] = uuid.uuid4().hex
                    insert('poc_verification_jobs', row)
                for event in self._rows("SELECT payload,created_at FROM events WHERE run_id=? AND kind='coverage_review_recorded'", (parent_id,)):
                    self._db.execute("INSERT INTO events(run_id,kind,payload,created_at) VALUES(?,'coverage_review_recorded',?,?)", (child_id, event['payload'], event['created_at']))
                carry_items, carry_decisions = [], []
                for item in self._review_candidates(child_id, 'final'):
                    old_key = next((old for old, new in mapping.items() if new == item['item_id']), item['item_id'])
                    if old_key not in carried:
                        continue
                    decision = remap(dict(carried[old_key]))
                    decision.update(item_id=item['item_id'], revision=item['revision'],
                        inherited_from_run_id=parent_id)
                    carry_items.append(item)
                    carry_decisions.append(decision)
                if carry_items:
                    batch_id = uuid.uuid4().hex
                    self._db.execute("INSERT INTO audit_review_batches(id,run_id,epoch,phase,input_hash,items,decisions,status,created_at,finished_at) VALUES(?,?,0,'final',?,?,?,'completed',?,?)",
                        (batch_id, child_id, hashlib.sha256(encoded(carry_items).encode()).hexdigest(), encoded(carry_items), encoded(carry_decisions), now, now))
                    for item, decision in zip(carry_items, carry_decisions):
                        self._db.execute('INSERT INTO audit_review_items VALUES(?,?,?,?,?,?)',
                            (child_id, 'final', item['item_id'], item['revision'], batch_id, encoded(decision)))
                stage = 'discovery' if request['mode'] == 'audit' else 'review' if request['mode'] == 'review' else 'poc'
                state = self._row('SELECT workflow FROM run_execution_state WHERE run_id=?', (child_id,))
                workflow = json.loads(state[0])
                if stage != 'discovery':
                    workflow['limits']['poc' if stage == 'poc' else 'review'] += workflow['limits']['discovery']
                    workflow['limits']['discovery'] = 0
                    queue = self.task_queue_state(child_id)
                    complete = not (self.coverage_review(child_id) or {}).get('pending_total') and not self.audit_direction_summary(child_id)['unsettled_total'] and not queue['blocked'] and not queue['active']
                    workflow['discovery_stop'] = dict(state='met' if complete else 'inconclusive',
                        basis='沿用原审计已保存的源码取证，继续验证与终审；原有覆盖限制保留。', code='continuation')
                workflow['stage'] = stage
                self._db.execute('UPDATE run_execution_state SET workflow=? WHERE run_id=?', (encoded(workflow), child_id))
                self.append_event(child_id, None, 'run_continuation_created', info)

            self.create_run(child, _setup=setup)
            return self.get_run(child_id)
