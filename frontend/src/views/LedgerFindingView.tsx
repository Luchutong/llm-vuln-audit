import { CvssEditor, SeverityBadge } from '../components/CvssPanel';
import { ArrowLeft, ArrowUpRight, FileArchive, GitBranch, LoaderCircle } from 'lucide-react';
import { Disclosure } from '../components/Disclosure';
import { LongContent } from '../components/LongContent';
import { DeleteFindingButton } from '../components/RecordActions';
import { LEDGER_DISPOSITION_LABELS, RELATION_LABELS, ledgerFindingForDisplay, ledgerReturnHash } from '../ledger';
import { localDate, runLabel } from '../status';
import type { LedgerFindingDetail, LedgerRunReference } from '../types';
import { useLedgerResource } from '../useLedgerResource';
import { AutomaticVerificationPanel, FindingDetail, HistoricalVerificationPanel, VERIFICATION_LABELS } from './FindingsView';
import '../ledger.css';

function SourceRun({ run, empty }: { run: LedgerRunReference | null; empty: string }) {
  return run ? <div className="ledger-run-reference"><a href={`#run/${encodeURIComponent(run.id)}`}>审计任务 {run.id.slice(0, 8)}<ArrowUpRight size={13} /></a><span>{runLabel(run.status)} · {localDate(run.created_at)}</span><span className="ledger-source-zip"><FileArchive size={14} />{run.snapshot_name}</span><span className="ledger-source-id">快照 {run.snapshot_id}</span></div> : <p className="ledger-subtle">{empty}</p>;
}

export function LedgerFindingView({ findingId }: { findingId: string }) {
  const { data: detail, error, refresh, refreshing } = useLedgerResource<LedgerFindingDetail>(`/project-findings/${encodeURIComponent(findingId)}`);

  if (!detail) return <section className="ledger-page"><a className="ledger-back" href="#findings"><ArrowLeft size={16} />返回漏洞发现</a><div className="ledger-state" role={error ? 'alert' : 'status'}>{error ? <><h1>无法读取漏洞详情</h1><p>{error}</p><button className="btn" onClick={refresh}>重新加载</button></> : <><LoaderCircle size={24} className="spin" /><p>正在读取漏洞详情…</p></>}</div></section>;
  const { finding, project } = detail;
  const display = ledgerFindingForDisplay(detail);
  const sourceSnapshot = detail.last_run?.snapshot_id ?? '';
  const historyVerifications = detail.verifications.filter((record) => record.id !== detail.current_verification?.id || !record.id);
  const currentVerification = detail.current_verification;

  return <article className="ledger-page ledger-detail-page">
    <div className="ledger-backlinks"><a className="ledger-back" href={ledgerReturnHash(window.location.hash, project.id)}><ArrowLeft size={16} />返回漏洞列表</a><a href={`#sources/${encodeURIComponent(project.id)}?tab=findings`}>包内漏洞</a><a href="#findings">全部漏洞</a><button className="text-button" aria-label="刷新漏洞详情" disabled={refreshing} onClick={refresh}>{refreshing ? '刷新中…' : '刷新'}</button><DeleteFindingButton finding={finding} /></div>
    {error && <div className="ledger-error" role="alert"><span>刷新失败：{error}</span><button className="btn" onClick={refresh}>重试</button></div>}
    <header className="ledger-page-head"><div><span className="ledger-eyebrow">VULNERABILITY DETAIL</span><h1>{finding.title}</h1><p>{project.name} · 首次发现 {localDate(finding.discovered_at)} · 最近更新 {localDate(finding.updated_at)}</p><div className="ledger-detail-tags"><SeverityBadge finding={finding} /><span className={`chip chip-${finding.verification_status}`}>{VERIFICATION_LABELS[finding.verification_status] ?? finding.verification_status}</span><span className="chip">{LEDGER_DISPOSITION_LABELS[finding.disposition] ?? finding.disposition}</span><span className="chip">第 {finding.revision} 版</span></div></div></header>
    <section className="ledger-provenance" aria-label="漏洞来源">
      <div><h2>所属源码包</h2><a href={`#sources/${encodeURIComponent(project.id)}?tab=findings`}>{project.name}<ArrowUpRight size={13} /></a><p>相同源码内容下的跨任务结论。</p><span className="ledger-source-id">台账 {finding.id}</span></div>
      <div><h2>当前证据来源</h2><SourceRun run={detail.last_run} empty="来源任务不可用；保留台账正文和原始证据引用。" /></div>
      <div><h2>首次发现来源</h2><SourceRun run={detail.origin_run} empty="首次发现任务不可用；历史发现时间仍保留。" /></div>
    </section>
    <div className="ledger-detail-note"><GitBranch size={16} /><p>正文展示源码包台账的最新结论。证据绑定其实际 ZIP 快照；重复发现、沿用和历史版本保留在下方审计记录中。</p></div>
    {currentVerification && <div className="ledger-verification-source"><strong>当前验证来源</strong><span>{currentVerification.source === 'poc_agent' ? 'POC Agent 自动验证' : '历史验证记录'}{currentVerification.finding_revision ? ` · 结论第 ${currentVerification.finding_revision} 版` : ''}</span>{currentVerification.run_id && <a href={`#run/${encodeURIComponent(currentVerification.run_id)}`}>审计任务 {currentVerification.run_id.slice(0, 8)}<ArrowUpRight size={13} /></a>}</div>}
    {finding.poc && <div className="ledger-verification-source"><strong>POC 来源</strong>{detail.poc_finding_id ? <span>来自当前证据任务中的发现 {detail.poc_finding_id.slice(0, 8)}，下载保留该原始脚本。</span> : <span>保留台账中的脚本正文；暂未找到匹配的原始下载文件。</span>}</div>}
    <CvssEditor finding={display} onChanged={refresh} />
    <FindingDetail finding={display} snapshotId={sourceSnapshot} canonical pocDownloadPath={detail.poc_download_path} />
    <section className="ledger-history" aria-label="跨任务审计记录"><header><h2>跨任务审计记录</h2><span>{detail.history.length} 条</span></header><p>首次发现、再次发现、更正和沿用分别记录；沿用关系不表示在该任务中重新取证。</p>{!detail.history.length ? <div className="ledger-state">暂无可用的任务关系记录。</div> : <div className="ledger-table-wrap"><table className="ledger-table ledger-history-table"><thead><tr><th>审计关系</th><th>结论版本</th><th>来源 ZIP</th><th>审计任务</th><th>时间</th></tr></thead><tbody>{detail.history.map((relation) => <tr key={`${relation.run_id}:${relation.relation}:${relation.revision}`}><td data-label="审计关系">{RELATION_LABELS[relation.relation] ?? relation.relation}</td><td data-label="结论版本">第 {relation.revision} 版</td><td data-label="来源 ZIP"><span>{relation.snapshot_name ?? '来源 ZIP 不可用'}</span>{relation.snapshot_id && <span className="ledger-source-id">{relation.snapshot_id}</span>}</td><td data-label="审计任务"><a href={`#run/${encodeURIComponent(relation.run_id)}`}>{relation.run_id.slice(0, 8)}<ArrowUpRight size={12} /></a>{relation.run_status && <span className="ledger-subtle">{runLabel(relation.run_status)}</span>}{relation.run_finding_id && <span className="ledger-source-id">发现 {relation.run_finding_id.slice(0, 8)}</span>}</td><td data-label="时间">{localDate(relation.created_at)}</td></tr>)}</tbody></table></div>}</section>
    <section className="ledger-history" aria-label="历史验证记录"><header><h2>历史验证记录</h2><span>{historyVerifications.length} 条</span></header><p>这些记录用于追溯原始执行和人工复核；当前版本的验证状态以正文中的状态为准。</p>{!historyVerifications.length ? <div className="ledger-state">没有其他历史验证记录。</div> : historyVerifications.map((record, index) => <Disclosure key={record.id ?? index} title={<span className="disclosure-heading"><span className={`chip chip-${record.status ?? 'unverified'}`}>{VERIFICATION_LABELS[record.status ?? 'unverified'] ?? record.status}</span><span>{record.source === 'poc_agent' ? '自动验证' : '历史人工记录'}</span>{record.created_at && <span>{localDate(record.created_at)}</span>}</span>}><div className="ledger-verification-source">{record.run_id && <a href={`#run/${encodeURIComponent(record.run_id)}`}>来源任务 {record.run_id.slice(0, 8)}<ArrowUpRight size={13} /></a>}{record.finding_revision && <span>来源结论第 {record.finding_revision} 版</span>}{record.finding_id && <span className="ledger-source-id">发现 {record.finding_id}</span>}</div><AutomaticVerificationPanel finding={{ ...display, verifications: [record] }} /><HistoricalVerificationPanel finding={{ ...display, verifications: [record] }} observation={false} />{record.id && <LongContent label="验证记录 ID" value={record.id} />}</Disclosure>)}</section>
  </article>;
}
