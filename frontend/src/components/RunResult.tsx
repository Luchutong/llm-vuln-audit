import { ArrowUpRight, CircleHelp, ShieldCheck } from 'lucide-react';
import type { RunDetail } from '../types';
import { ReportDownloads } from './ReportDownloads';
import { useFinalReview } from '../useFinalReview';
import { FINAL_REVIEW_PUBLISH_LABELS, FINAL_REVIEW_COUNT_LABELS } from '../finalReview';
import { displayCount, resultStatus } from '../runPresentation';
import { executionSummary, stopReason } from '../execution';
import { ContinueAuditButton } from './ContinueAudit';
import { CompactText } from './CompactText';

export function RunResult({ detail, onChanged, onDetails }: {
  detail: RunDetail; onChanged: () => void; onDetails: (tab: 'report' | 'findings') => void;
}) {
  const { run } = detail;
  const { state, facts, error, retry } = useFinalReview(run.id, run.status);
  const host = run.final_summary;
  const goal = detail.goal ?? detail.goals?.[0];
  const incomplete = facts ? facts.run_outcome?.audit_complete === false || (facts.counts?.pending ?? 0) > 0 : host?.complete === false;
  const status = resultStatus(detail, facts);
  const reason = stopReason(facts?.run_outcome ?? null) || stopReason(executionSummary(detail)) || stopReason(host ?? null) || goal?.terminal_reason || detail.planner?.terminal_reason;
  const loading = state === 'idle' || state === 'loading';
  const source = state === 'error' ? '终审结果暂不可用' : facts ? facts.provenance?.immutable === true ? '冻结终审结果' : facts.provenance?.immutable === false ? '阶段终审结果（未冻结）' : '终审结果（冻结状态未记录）' : host ? '宿主阶段结果（历史回退）' : '历史执行结果';
  const complete = facts?.run_outcome?.audit_complete === true && !incomplete;
  return <section className={`result-card run-result${complete ? '' : ' run-result-neutral'}`} aria-label="审计结果">
    <div className="result-heading">{complete ? <ShieldCheck size={21} /> : <CircleHelp size={21} />}<div><h2>{status}</h2><span className="small muted">{loading ? '正在读取终审结果…' : source}</span></div></div>
    {state === 'error' ? <p role="status">终审读取失败：{error} <button className="text-button" onClick={retry}>重试终审读取</button></p> : <>
      {facts ? <>
        {(facts.counts?.accepted ?? 0) > 0 && <p className="run-result-conclusion">已确认 {facts.counts.accepted} 条结论，审计报告及证据包已保留。{(facts.counts?.pending ?? 0) > 0 && `另有 ${facts.counts.pending} 条待终审，在同一报告中单独标注。`}</p>}
        <p className="run-result-conclusion">{FINAL_REVIEW_PUBLISH_LABELS[facts.quality_result?.publishability] ?? '报告结论暂无数据'}{(facts.counts?.pending ?? 0) > 0 ? '，未完成项保留待审。' : incomplete ? '，本次审计未完成。' : '。'}</p>
        <div className="run-result-counts">{(['canonical', 'accepted', 'pending'] as const).map((key) => <div key={key}><strong>{displayCount(facts.counts?.[key])}</strong><span>{FINAL_REVIEW_COUNT_LABELS[key]}</span></div>)}</div>
        {typeof facts.counts?.contested === 'number' && facts.counts.contested > 0 && <p className="small muted">另有 {facts.counts.contested} 项存疑或排除，见终审报告。</p>}
      </> : !loading && <>
        <p className="small muted">此运行未保存冻结终审事实，终审接受数量暂无数据。</p>
        {host && <div className="run-result-counts"><div><strong>{displayCount(host.ledger_group_count)}</strong><span>台账分组</span></div><div><strong>{displayCount(host.valid_finding_count)}</strong><span>有效运行记录</span></div></div>}
      </>}
    </>}
    {reason && <CompactText text={reason} label="停止原因" />}
    <div className="result-actions"><button className="btn btn-primary" onClick={() => onDetails('report')}>查看报告</button><button className="btn" onClick={() => onDetails('findings')}>发现与验证<ArrowUpRight size={14} /></button><ContinueAuditButton run={run} onChanged={onChanged} /><ReportDownloads runId={run.id} status={run.status} hasAccepted={(facts?.counts?.accepted ?? 0) > 0} compact /></div>
  </section>;
}
