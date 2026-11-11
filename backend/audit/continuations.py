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


def risk_input(value, *, operation_read=None, source_only=False):
    # These two collections are navigation sets. Cloned UUIDs may change their
    # tie order; compare every fact while preserving order in actual evidence.
    if operation_read is not None:
        from .risk_coverage import operation_facts
        value = operation_facts(value, operation_read, source_only=source_only)
    return encoded({**value, **{key: sorted(value[key], key=encoded)
                               for key in ('findings', 'tasks') if key in value}})


class ContinuationStoreMixin:
    def repair_paused_continuation_frontier(self, run_id):
        """Recover the historical-reopen bug once, only at a quiescent audit checkpoint."""
        from .runtime import policy_from_snapshot
        from .execution_state import stamp
        with self._lock:
            self._db.execute('BEGIN IMMEDIATE')
            try:
                run = self._row('SELECT status,task_spec,agent_policy FROM runs WHERE id=?', (run_id,))
                state = self._row('SELECT phase,workflow FROM run_execution_state WHERE run_id=?', (run_id,))
                if (not run or run['status'] != 'paused' or not state or state['phase'] != 'paused'
                        or run_id in self._active_clocks):
                    raise ValueError('接续修复要求已静止的暂停检查点')
                task = json.loads(run['task_spec'] or '{}')
                workflow = json.loads(state['workflow'] or '{}')
                stop = workflow.get('discovery_stop') or {}
                if ((task.get('continuation') or {}).get('mode') != 'audit'
                        or workflow.get('stage') != 'poc' or stop.get('code') != 'blocker_unresolved'
                        or workflow.get('continuation_frontier_repair')):
                    raise ValueError('本检查点不是历史重开额度阻塞后的源码阶段')
                if (self._row("SELECT 1 FROM planner_tasks WHERE run_id=? AND state='running'", (run_id,))
                        or self._row("SELECT 1 FROM poc_attempts WHERE run_id=? AND state!='completed'", (run_id,))):
                    raise ValueError('仍有执行中的源码或 POC，不能调整阶段')
                baselines = self.task_reopen_baselines(run_id)
                limit = int(policy_from_snapshot(json.loads(run['agent_policy'] or '{}')).task_reopens)
                blocked = [row['task_key'] for row in self._rows(
                    "SELECT task_key,revisions FROM planner_tasks WHERE run_id=? AND state='blocked'", (run_id,))
                    if int(row['revisions'] or 0) >= limit and baselines.get(row['task_key'], 0) > 0
                    and max(0, int(row['revisions'] or 0) - baselines.get(row['task_key'], 0)) < limit]
                if not blocked:
                    raise ValueError('没有因继承历史次数而被误限的阻塞任务')
                before = dict(workflow['limits'])
                moved = min(int(workflow.get('transferred') or 0),
                            max(0, workflow['limits']['poc'] - workflow['used']['poc']))
                if moved < 1:
                    raise ValueError('无未使用的已转移请求可用于恢复源码阶段')
                workflow['limits']['discovery'] += moved
                workflow['limits']['poc'] -= moved
                workflow['transferred'] = max(0, int(workflow.get('transferred') or 0) - moved)
                workflow['stage'] = 'discovery'
                workflow.pop('discovery_stop')
                workflow['continuation_frontier_repair'] = dict(policy='historical-reopens-v1',
                    prior_discovery_stop=stop, blocked_tasks=blocked, transferred_back=moved)
                self._db.execute('UPDATE run_execution_state SET workflow=?,updated_at=? WHERE run_id=?',
                                 (encoded(workflow), stamp(), run_id))
                self.append_event(run_id, None, 'continuation_frontier_repaired',
                    dict(before=before, limits=workflow['limits'], **workflow['continuation_frontier_repair']))
                self._db.execute('COMMIT')
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute('ROLLBACK')
                raise
        return self.workflow_state(run_id)

    def task_reopen_baselines(self, run_id):
        """Historical revisions stay intact; an explicit audit has a new bounded allowance."""
        row = self._row('SELECT task_spec FROM runs WHERE id=?', (run_id,))
        info = (json.loads(row[0] or '{}') if row else {}).get('continuation') or {}
        if info.get('mode') != 'audit':
            return {}
        if 'task_reopen_baselines' in info:
            return info['task_reopen_baselines']
        # Compatibility for already-created audit continuations. Only original
        # copied tasks in an immutable terminal parent own a historical baseline.
        return {r['task_key']: int(r['revisions'] or 0) for r in self._rows(
            'SELECT p.task_key,p.revisions FROM planner_tasks p JOIN planner_tasks c'
            ' ON c.task_key=p.task_key AND c.created_at=p.created_at'
            ' JOIN runs r ON r.id=p.run_id WHERE c.run_id=? AND p.run_id=?'
            " AND r.status IN ('completed','unreachable','inconclusive','failed','cancelled','interrupted')",
            (run_id, info.get('parent_run_id')))}

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
        execution = self._row('SELECT phase FROM run_execution_state WHERE run_id=?', (run_id,))
        checkpoint = (run['status'] == 'paused' and execution and execution[0] == 'paused'
                      and run_id not in self._active_clocks)
        ready = run['status'] in TERMINAL or checkpoint
        return dict(parent_run_id=run_id, available=supported and ready and not active, review_only=bool(checkpoint),
            reason='已有继续任务尚未结束' if active else '仅支持已结束或已静止暂停的宿主队列审计' if not supported or not ready else '',
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
            if options.get('review_only') and request['mode'] != 'review':
                raise ValueError('暂停记录只允许从静止检查点补终审；执行新 POC 或源码审计须先恢复或结束原记录')
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
                       and parent['task_spec'].get('capability_policy') == 'audit-capability-v1'
                       and e['final_batch_review'].get('focus')
                       and e['canonical_id'] not in selected_subjects
                       and not any(p['item_id'] in selected_subjects for p in peers.get(e['canonical_id'], []))}
            parent_risks = {item['item_id']: item for item in self._review_candidates(parent_id, 'final')
                            if item['kind'] == 'risk'}
            carried_risks = {}
            for row in self._rows("SELECT item_id,revision,decision FROM audit_review_items WHERE run_id=? AND phase='final'", (parent_id,)):
                item = parent_risks.get(row['item_id'])
                decision = json.loads(row['decision'])
                if (item and item['revision'] == row['revision']
                        and parent['task_spec'].get('capability_policy') == 'audit-capability-v1'
                        and decision.get('focus')
                        and decision.get('decision') in {'resolve', 'skip'}
                        and decision.get('risk_outcome') in {'supported', 'no_evidence', 'not_applicable'}):
                    carried_risks[row['item_id']] = decision
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
                required = request.get('require_dynamic', False) or policy.get('mode') == 'required'
                policy.update(enabled=True, mode='required' if required else 'auto', required=required)
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
                task_reopen_baselines={r['task_key']: int(r.get('revisions') or 0) for r in rows['planner_tasks']},
                retest_finding_ids=[mapping[i] for i in sorted(selected)],
                source_refs={mapping[f['id']]: f['id'] for f in rows['findings']})
            if options.get('review_only'):
                info['parent_checkpoint'] = dict(status='paused', phase='paused',
                    parent_execution_epoch=parent.get('execution_epoch'), purpose='review_only',
                    unresolved_verifications=options['retestable_count'])
            task = {**parent['task_spec'], 'workflow_limits': None, 'continuation': info,
                    'budget_exhaustion_policy': 'pause-v1', 'review_reuse_policy': 'incremental-v1',
                    'output_policy': parent['task_spec'].get('output_policy', 'audit-evidence-v1'),
                    'risk_fact_policy': 'operation-v2'}
            if request.get('close_unresolved'):
                if request['mode'] != 'audit' or not self.exhaustive_enabled(parent_id):
                    raise ValueError('逐项收尾要求全量审计的 audit 继续任务')
                task.update(completion_recovery_policy='assigned-gaps-v1', risk_fact_policy='operation-v2')
                info['close_unresolved'] = True
            upgrade = request.get('audit_policy') == 'exhaustive-v1'
            if upgrade:
                if request['mode'] != 'audit':
                    raise ValueError('高召回策略仅适用于继续源码审计')
                task.update(completion_policy='coverage_review', stop_on_achieved=False,
                    workflow_policy='discovery_first', review_policy='batch-v1',
                    orchestration_policy='host-queue-v1', exploration_policy='exhaustive-v1',
                    focus_scope='all', scenario=None, risk_coverage_policy='bounded-v2',
                    role_policy='worker-evidence-v2', investigation_policy='bounded-v1')
                info['audit_policy_upgrade'] = dict(previous_scope=parent['task_spec'].get('focus_scope', 'targeted'),
                    previous_exploration=parent['task_spec'].get('exploration_policy', 'legacy'),
                    exploration='exhaustive-v1', risk_coverage='bounded-v2')
            from .capability import POLICY, freeze_focus
            task.update(capability_policy=POLICY, audit_focus=freeze_focus(task))
            child = {**parent, 'id': child_id, 'created_at': now, 'task_spec': task, 'poc_policy': policy,
                     'run_limits': request['run_limits'], 'project_baseline': parent.get('project_baseline') or []}
            if request.get('close_unresolved'):
                child['agent_policy'] = {**(parent.get('agent_policy') or {}),
                    'worker_explore_responses': 1, 'worker_yield_max_responses': 1,
                    'worker_max_tokens': max(8192, int((parent.get('agent_policy') or {}).get('worker_max_tokens', 4096)))}
            if upgrade:
                child['agent_policy'] = {**(child.get('agent_policy') or {}),
                    'worker_max_tokens': max(8192, int((parent.get('agent_policy') or {}).get('worker_max_tokens', 4096)))}
            if model_profile is not None:
                child.update(model=model_profile['model'], model_profile=dict(model_profile))
                original_profile = parent.get('model_profile') or {}
                if (request.get('structured_output') is None
                        and original_profile.get('structured_output') in {'json_object','json_schema'}
                        and all(original_profile.get(key) == model_profile.get(key)
                                for key in ('profile_id','model','base_url'))):
                    child['model_profile']['structured_output'] = original_profile['structured_output']
            if request.get('structured_output') is not None:
                if not (child.get('model_profile', {}).get('model') and child.get('model_profile', {}).get('base_url')):
                    raise ValueError('结构化输出需要完整冻结模型档案；请选择当前可用模型档案')
                child['model_profile'] = {**(child.get('model_profile') or {}),
                                          'structured_output': request['structured_output']}
            if reason := model_unavailable_reason((child.get('model_profile') or {}).get('model') or child['model']):
                raise ValueError(reason)
            info['model_profile_selection'] = request.get('model_profile_id', 'original')
            continuation_map = None
            if upgrade:
                repository = getattr(self, '_report_repository', None)
                if repository is None:
                    raise ValueError('高召回继续需要可读取原快照的源码仓库，不能仅凭旧索引启用风险覆盖')
                try:
                    enriched = repository.build_project_map(parent['snapshot_id'], None, include_risk_signals=True)
                except (FileNotFoundError, ValueError) as exc:
                    raise ValueError('原源码快照不可读，无法补建高召回风险索引') from exc
                continuation_map = {**self.get_project_map(parent_id), 'risk_signals': enriched.get('risk_signals', [])}
                info['risk_signal_count'] = len(continuation_map['risk_signals'])
                from .risk_coverage import freeze as freeze_obligations
                task['risk_obligation_set'] = freeze_obligations(continuation_map, task, parent['snapshot_id'])

            owned_refs = {'id', 'run_id', 'goal_id', 'task_id', 'origin_task_id', 'plan_id', 'session_id',
                          'finding_id', 'run_finding_id', 'verification_id', 'derived_from_finding_id', 'unit_id',
                          'item_id', 'finding_ids', 'duplicate_of', 'distinct_from', 'supports', 'related_finding_id'}
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
                    if ((table in {'planner_tasks', 'planner_task_attempts'} and key in {'result', 'context_spec', 'dependencies'})
                            or (table == 'findings' and key == 'audit_metadata')) and isinstance(value, str):
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
                paused_checkpoint = (current and current[0] == 'paused' and options.get('review_only')
                    and parent_id not in self._active_clocks
                    and self._row('SELECT phase FROM run_execution_state WHERE run_id=?', (parent_id,))[0] == 'paused')
                if not current or (current[0] not in TERMINAL and not paused_checkpoint):
                    raise ValueError('原运行已变化，不能创建继续任务')
                if self._row("SELECT id FROM runs WHERE id!=? AND status IN ('pending','running','paused') AND json_extract(task_spec,'$.continuation.parent_run_id')=?", (child_id, parent_id)):
                    raise ValueError('已有继续任务尚未结束')
                child_goal = self._row('SELECT id FROM task_goals WHERE run_id=?', (child_id,))[0]
                mapping[parent_goal['id']] = child_goal
                self._db.execute("INSERT INTO planner_project_maps SELECT ?,snapshot_id,scope,payload,? FROM planner_project_maps WHERE run_id=?", (child_id, now, parent_id))
                if continuation_map is not None:
                    self._db.execute('UPDATE planner_project_maps SET payload=? WHERE run_id=?', (encoded(continuation_map), child_id))
                self._db.execute("INSERT INTO planner_sessions(run_id,goal_id,session_id,status,current_round,max_rounds,current_revision,created_at,updated_at) VALUES(?,?,?,'pending',0,?,0,?,?)",
                    (child_id, child_goal, child_session, task['max_planner_rounds'], now, now))
                for row in rows['planner_tasks']:
                    row.update(plan_id=None, claimed_by=None, claimed_at=None)
                    if request['mode'] == 'audit' and row['state'] in (
                            {'blocked', 'running', 'cancelled', 'exhausted', 'skipped', 'deferred'} if upgrade else {'blocked', 'running'}):
                        row.update(state='ready', error=None, finished_at=None, max_attempts=row['attempts'] + task['max_iterations'])
                    insert('planner_tasks', row)
                for row in rows['planner_task_attempts']:
                    # Historical reads support coverage; historical cost is not new cost.
                    row.update(plan_id=None, usage=None)
                    insert('planner_task_attempts', row, omit=('id',))
                if upgrade and parent['task_spec'].get('exploration_policy') != 'exhaustive-v1':
                    records = self._audit_direction_records(child_id)
                    files = {f['path']: f for f in continuation_map.get('files', [])}
                    for row in self._rows('SELECT * FROM planner_tasks WHERE run_id=?', (child_id,)):
                        current_result = json.loads(row['result'] or '{}')
                        for attempt in self.list_task_attempts(row['id']):
                            result = attempt.get('result') or {}
                            if result.get('error') or result.get('terminal_reason') not in {None, '', 'completed'}:
                                continue
                            self._capture_observation_leads(row, result, records, attempt.get('seen'), files,
                                omitted_leads=current_result.get('host_omitted_leads') or [])
                            current_result['host_omitted_leads'] = result.get('host_omitted_leads') or []
                        self._db.execute('UPDATE planner_tasks SET result=? WHERE id=?', (encoded(current_result), row['id']))
                    self._persist_audit_directions_tx(child_id, records)
                    info['inherited_advisory_leads'] = sum(r.get('source_kind') == 'observation' for r in records.values())
                    self._db.execute('UPDATE runs SET task_spec=? WHERE id=?', (encoded(task), child_id))
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
                if not upgrade:
                    settled_records = remap(self._audit_direction_records(parent_id))
                    from .exhaustive import fingerprint as lead_fingerprint
                    for record in settled_records.values():
                        if (record.get('triage') or {}).get('outcome') == 'covered':
                            for ref in record['triage'].get('finding_refs', []):
                                copied = self._row('SELECT * FROM findings WHERE run_id=? AND id=?',(child_id,ref['id']))
                                if copied:
                                    ref['fingerprint'] = lead_fingerprint(dict(copied))
                    self._persist_audit_directions_tx(child_id, settled_records)
                for event in self._rows("SELECT payload,created_at FROM events WHERE run_id=? AND kind='coverage_review_recorded'", (parent_id,)):
                    if upgrade:
                        continue  # A targeted skip does not discharge a whole-source obligation.
                    self._db.execute("INSERT INTO events(run_id,kind,payload,created_at) VALUES(?,'coverage_review_recorded',?,?)", (child_id, event['payload'], event['created_at']))
                if request.get('close_unresolved'):
                    from .completion_recovery import seed_tasks
                    unresolved_risks = {o['id'] for o in (self.risk_coverage(parent_id) or {}).get('items',[])
                                        if o['state'] in {'pending','blocked'}}
                    info['closure_manifest'] = seed_tasks(self, child_id, now, unresolved_risks)
                    self._db.execute('UPDATE runs SET task_spec=? WHERE id=?', (encoded(task), child_id))
                carry_items, carry_decisions = [], []
                for item in self._review_candidates(child_id, 'final'):
                    old_key = next((old for old, new in mapping.items() if new == item['item_id']), item['item_id'])
                    prior = carried.get(old_key)
                    semantic = task.get('risk_fact_policy') in {'operation-v1','operation-v2'}
                    if (item['kind'] == 'risk' and old_key in carried_risks
                            and risk_input(remap(parent_risks[old_key]['payload']),
                                operation_read=parent_risks[old_key]['operation_read'] if semantic else None)
                            == risk_input(item['payload'],operation_read=item['operation_read'] if semantic else None)):
                        prior = carried_risks[old_key]
                    if prior is None:
                        continue
                    decision = remap(dict(prior))
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
                from .incremental_review import inherit
                info['review_reuse'] = inherit(self, parent_id, child_id, mapping)
                self._db.execute('UPDATE runs SET task_spec=? WHERE id=?',(encoded(task),child_id))
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
