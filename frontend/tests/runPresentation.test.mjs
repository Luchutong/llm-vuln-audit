import test from 'node:test';
import assert from 'node:assert/strict';
import { compactExecution, runStage, displayCount, elapsedLabel, resultStatus, sumCounts } from '../src/runPresentation.ts';
import { summarizeActivity, processLabel, processPage } from '../src/activitySummary.ts';
import { projectActivity } from '../src/activity.ts';
import { createFinalReviewCache } from '../src/finalReviewCache.ts';
import { ApiError } from '../src/api.ts';

const detail = (phase = 'task_execute') => ({ run: { id: 'r', status: 'running', poc_mode: 'off' }, tasks: [{id:'t',title:'检查上传',state:'running'}], execution_summary: { phase, run_usage:{seconds:760}, poc:{mode:'off'} } });
const event = (id, kind, payload={}) => ({ id, kind, run_id:'r', created_at:'2026-10-30T00:00:00Z', payload:{role:'worker',task_id:'t',agent_invocation_id:'inv',request_index:1,...payload} });
const pair = (id, payload={}) => [event(id,'tool_call',{tool:'read_source',span_id:`s${id}`,args:{path:'src/a.php'},...payload}), event(id+1,'tool_result',{tool:'read_source',span_id:`s${id}`,status:'ok',...payload})];
const flush = () => new Promise(resolve => setImmediate(resolve));

test('stage uses workflow first and never guesses a missing historical stage', () => {
  const d=detail('poc_execute');
  assert.equal(runStage(d),'poc');
  d.execution_summary.workflow={stage:'review'};
  assert.equal(runStage(d),'review');
  assert.equal(runStage(detail('ended')),null);
  assert.equal(runStage({run:{status:'completed'}}),null);
});
test('compact facts distinguish unavailable data, waiting, observations and publication', () => {
  assert.equal(displayCount(undefined),'暂无数据'); assert.equal(displayCount(0),'0');
  assert.equal(elapsedLabel(760),'已运行 12 分钟'); assert.equal(elapsedLabel(undefined),'运行时间暂无数据');
  const d=detail('poc_execute'); d.run.poc_mode='auto';
  d.execution_summary.poc={mode:'auto',available:false,reason:'runner_unconfigured'};
  d.execution_summary.poc_statistics={model:{waiting_seconds:12},experiments:{observations:2},conclusion:{published:0}};
  assert.match(compactExecution(d).progress,/已有实验观测，尚未发布/);
  assert.match(compactExecution(d).pocLabel,/配置/);
  d.execution_summary.poc_statistics.experiments.observations=0;
  assert.match(compactExecution(d).progress,/等待模型响应/);
  d.execution_summary.poc={mode:'off'};
  assert.equal(compactExecution(d).pocLabel,'自动验证未启用');
});
test('a completed status cannot override pending final review or incomplete host facts', () => {
  const d=detail(); d.run.status='completed'; d.goal={status:'met'};
  assert.equal(resultStatus(d,null),'执行已结束');
  d.run.final_summary={complete:false}; assert.equal(resultStatus(d,null),'审计未完成');
  assert.equal(resultStatus(d,{run_outcome:{audit_complete:false},counts:{pending:2}}),'审计未完成');
  assert.equal(resultStatus(d,{run_outcome:{audit_complete:true},counts:{pending:0}}),'目标已达成');
});
test('routine operations dedupe reads without mixing tasks, identities or revisions', () => {
  const events=[...pair(1),...pair(3),...pair(5,{identity:'alice'}),...pair(7,{identity:'bob'}),...pair(9,{identity:'bob',revision:2}),...pair(11,{task_id:'other'})];
  const grouped=summarizeActivity(projectActivity(events,detail()),events);
  assert.deepEqual(grouped.map(g=>g.operations),[2,1,1,1,1]);
  assert.match(processLabel(grouped[0]),/已读取 1 个文件 · 2 次操作/);
  assert.equal(grouped.flatMap(g=>g.items).length,6);
});
test('formal settlement, publication, stage changes and experiment failures stay visible', () => {
  const events=[...pair(1),event(3,'workflow_stage_changed',{stage:'review'}),event(4,'task_assessment',{summary:'排查结算'}),event(5,'poc_queue_item_published',{status:'verified'}),event(6,'review_batch_completed',{phase:'final',items:5}),event(7,'poc_job_finished',{exit_code:1})];
  const grouped=summarizeActivity(projectActivity(events,detail()),events);
  assert.deepEqual(grouped.filter(i=>i.type==='message').map(i=>i.kind),['workflow_stage_changed','task_assessment','poc_queue_item_published','review_batch_completed','poc_job_finished']);
});
test('only an error with same-execution recovery folds; originals remain expandable', () => {
  const events=[event(1,'agent_parse_error',{category:'invalid_json'}),event(2,'agent_code',{request_index:2}),event(3,'agent_parse_error',{agent_invocation_id:'other',category:'invalid_json'})];
  const groups=summarizeActivity(projectActivity(events,detail()),events);
  assert.equal(groups[0].recoveries,1); assert.match(processLabel(groups[0]),/已自动恢复 1 次/);
  assert.equal(groups.at(-1).type,'message'); assert.equal(groups.at(-1).tone,'warning');
});
test('pinned groups retain focused children when results fail or new calls arrive', () => {
  const events=[...pair(1),...pair(3)];
  const items=projectActivity(events,detail()), g=summarizeActivity(items,events)[0];
  const pinned={[g.key]:g.items.map(i=>i.key)};
  const later=[...events,...pair(5)];
  const groups=summarizeActivity(projectActivity(later,detail()),later,new Set([g.key]),pinned);
  assert.deepEqual(groups[0].items.map(i=>i.key),pinned[g.key]);
  assert.equal(groups[1].operations,1);
  const changed=items.map(i=>({...i,status:'error'}));
  assert.equal(summarizeActivity(changed,events,new Set([g.key]),pinned)[0].warnings,2);
});
test('paging keeps inspected history and unresolved errors while limiting routine noise', () => {
  const events=Array.from({length:100},(_,i)=>event(i+1,'audit_progress',{message:`进度 ${i}`}));
  const groups=summarizeActivity(projectActivity(events,detail()),events);
  const visible=processPage(groups,25,new Set([groups[0].key]));
  assert.equal(visible.length,26); assert.equal(visible[0].key,groups[0].key);
});
test('final review cache shares reads, retains frozen facts and aborts only after last subscriber', async () => {
  let calls=0, signal, finish;
  const cache=createFinalReviewCache((id,s)=>{calls++;signal=s;return new Promise(resolve=>finish=resolve)});
  const off1=cache.subscribe('a:completed','a',()=>{}), off2=cache.subscribe('a:completed','a',()=>{});
  assert.equal(calls,1); off1(); await flush(); assert.equal(signal.aborted,false);
  finish({counts:{canonical:6},provenance:{immutable:true}}); await flush(); off2(); await flush();
  const off3=cache.subscribe('a:completed','a',()=>{}); assert.equal(calls,1); off3();
  const off4=cache.subscribe('b:completed','b',()=>{}); off4(); await flush(); assert.equal(signal.aborted,true);
  assert.equal(cache.read('b:completed').state,'idle'); assert.equal(cache.read('a:completed').facts.counts.canonical,6);
});
test('missing legacy facts differ from retryable errors and stale late responses cannot publish', async () => {
  let count=0, oldFinish;
  const cache=createFinalReviewCache(async(id)=>{count++; if(id==='legacy')throw new ApiError(404,'missing'); if(count===2)throw new Error('offline'); return {counts:{canonical:3}}});
  const off=cache.subscribe('legacy','legacy',()=>{}); await flush(); assert.equal(cache.read('legacy').state,'missing'); off();
  const stop=cache.subscribe('new','new',()=>{}); await flush(); assert.equal(cache.read('new').state,'error'); cache.retry('new','new'); await flush(); assert.equal(cache.read('new').facts.counts.canonical,3); stop();
  const stale=createFinalReviewCache(()=>new Promise(resolve=>oldFinish=resolve));
  const leave=stale.subscribe('old','old',()=>{}); leave(); await flush(); oldFinish({counts:{canonical:999}}); await flush(); assert.equal(stale.read('old').facts,null);
});

test('in-flight reads never count as read files and unrecovered action errors stay explicit', () => {
  const events=[event(1,'tool_call',{tool:'read_source',call_id:'pending',args:{path:'not-read.php'}}),event(2,'agent_code',{error:'interpreter stopped'})];
  const groups=summarizeActivity(projectActivity(events,detail()),events);
  assert.equal(groups[0].files,0); assert.equal(groups[0].running,1);
  assert.doesNotMatch(processLabel(groups[0]),/已读取/);
  assert.equal(groups[1].type,'message'); assert.match(groups[1].text,/interpreter stopped/);
});
test('known legacy 409 falls back but an unrelated 409 stays retryable', async () => {
  const cache=createFinalReviewCache(async(id)=>{throw new ApiError(409,'conflict', id==='old' ? 'This run predates Planner v2; it keeps its historical report layout' : 'Snapshot is changing')});
  const one=cache.subscribe('old','old',()=>{}), two=cache.subscribe('current','current',()=>{});
  await flush(); assert.equal(cache.read('old').state,'missing'); assert.equal(cache.read('current').state,'error'); one(); two();
});

test('different workers and long chronological gaps bound routine summaries', () => {
  const events=[...pair(1,{worker_id:'one'}),...pair(3,{worker_id:'two'}),...pair(5,{worker_id:'two'})];
  events[4].created_at='2026-10-30T01:00:00Z'; events[5].created_at='2026-10-30T01:00:01Z';
  assert.equal(summarizeActivity(projectActivity(events,detail()),events).length,3);
});

test('missing coverage counters stay unknown rather than becoming zero or NaN', () => {
  assert.equal(sumCounts(2, 3), 5); assert.equal(sumCounts(2, undefined), undefined);
  assert.equal(displayCount(sumCounts(2, undefined)), '暂无数据');
});
