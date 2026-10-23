import { SeverityBadge } from '../components/CvssPanel';
import { CVSS_STATUS_LABELS } from '../cvss';
import { useEffect, useState } from 'react';
import { ArrowUpRight, ChevronLeft, ChevronRight, LoaderCircle, Search, ShieldCheck } from 'lucide-react';
import { LEDGER_DISPOSITIONS, LEDGER_DISPOSITION_LABELS, LEDGER_PAGE_SIZE, LEDGER_SEVERITIES, LEDGER_VERIFICATIONS, SEVERITY_LABELS, ledgerFilters, ledgerHash, ledgerQuery } from '../ledger';
import type { LedgerFilters } from '../ledger';
import type { Project, ProjectFindingPage } from '../types';
import { localDate } from '../status';
import { useLedgerResource } from '../useLedgerResource';
import { VERIFICATION_LABELS } from './FindingsView';
import '../ledger.css';

export function LedgerFindingsView({ projectId, projects }: { projectId?: string; projects: Project[] }) {
  const [filters, setFilters] = useState(() => ledgerFilters(window.location.hash, projectId));
  const [search, setSearch] = useState(filters.q);
  const query = ledgerQuery({ ...filters, projectId: projectId ?? filters.projectId });
  const { data: page, error, refresh, refreshing } = useLedgerResource<ProjectFindingPage>(`/project-findings?${query}`);
  const Heading = projectId ? 'h2' : 'h1';

  useEffect(() => {
    const sync = () => {
      const next = ledgerFilters(window.location.hash, projectId);
      setFilters(next);
      setSearch(next.q);
    };
    sync();
    window.addEventListener('hashchange', sync);
    return () => window.removeEventListener('hashchange', sync);
  }, [projectId]);

  useEffect(() => {
    if (!page) return;
    const latest = ledgerFilters(window.location.hash, projectId);
    if (ledgerQuery(latest) !== query) return;
    const lastPage = Math.max(1, Math.ceil(page.total / LEDGER_PAGE_SIZE));
    if (latest.page > lastPage) {
      window.history.replaceState(null, '', ledgerHash(window.location.hash, { ...latest, page: lastPage }, Boolean(projectId)));
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    }
  }, [page, projectId, query]);

  const change = (update: Partial<LedgerFilters>) => {
    const next = { ...filters, page: 1, ...update, ...(projectId ? { projectId } : {}) };
    const hash = ledgerHash(window.location.hash, next, Boolean(projectId));
    if (hash === window.location.hash) { setFilters(next); setSearch(next.q); }
    else window.location.hash = hash;
  };
  const totalPages = page ? Math.max(1, Math.ceil(page.total / LEDGER_PAGE_SIZE)) : 1;
  const filtered = Boolean(filters.q || filters.severity || filters.cvssStatus || filters.verification || filters.disposition || (!projectId && filters.projectId));
  const reset = () => change({ q: '', projectId: projectId ?? '', severity: '', cvssStatus: '', verification: '', disposition: '', page: 1 });

  return <section className={`ledger-page${projectId ? ' ledger-page-embedded' : ''}`} aria-label="漏洞台账">
    <header className="ledger-page-head">
      <div><span className="ledger-eyebrow">VULNERABILITY LEDGER</span><Heading>漏洞发现</Heading><p>同一源码包中的发现跨审计任务持续保存，重复发现合并为一条结论。</p></div>
      <span className="ledger-heading-icon"><ShieldCheck size={25} /></span>
    </header>
    <form className="ledger-filters" onSubmit={(event) => { event.preventDefault(); change({ q: search.trim() }); }}>
      <label className="ledger-search"><span>搜索漏洞</span><div><Search size={16} /><input aria-label="搜索漏洞" placeholder="标题、摘要或源码路径" maxLength={200} value={search} onChange={(event) => setSearch(event.target.value)} /><button className="btn" type="submit">搜索</button></div></label>
      {!projectId && <label><span>所属源码包</span><select aria-label="所属源码包" value={filters.projectId} onChange={(event) => change({ projectId: event.target.value })}><option value="">全部源码包</option>{filters.projectId && !projects.some((project) => project.id === filters.projectId) && <option value={filters.projectId}>源码包 {filters.projectId.slice(0, 8)}</option>}{projects.map((project) => <option key={project.id} value={project.id}>{project.name}</option>)}</select></label>}
      <label><span>严重性</span><select aria-label="严重性" value={filters.severity} onChange={(event) => change({ severity: event.target.value })}><option value="">全部严重性</option>{LEDGER_SEVERITIES.map((severity) => <option key={severity} value={severity}>{SEVERITY_LABELS[severity]}</option>)}</select></label>
      <label><span>量化状态</span><select aria-label="量化状态" value={filters.cvssStatus ?? ''} onChange={(event)=>change({cvssStatus:event.target.value})}><option value="">全部量化状态</option>{Object.entries(CVSS_STATUS_LABELS).map(([value,label])=><option key={value} value={value}>{label}</option>)}</select></label>
      <label><span>验证状态</span><select aria-label="验证状态" value={filters.verification} onChange={(event) => change({ verification: event.target.value })}><option value="">全部验证状态</option>{LEDGER_VERIFICATIONS.map((verification) => <option key={verification} value={verification}>{VERIFICATION_LABELS[verification]}</option>)}</select></label>
      <label><span>结论状态</span><select aria-label="结论状态" value={filters.disposition} onChange={(event) => change({ disposition: event.target.value })}><option value="">当前结论</option>{LEDGER_DISPOSITIONS.map((disposition) => <option key={disposition} value={disposition}>{disposition === 'all' ? '全部状态（含撤回）' : LEDGER_DISPOSITION_LABELS[disposition]}</option>)}</select></label>
    </form>
    <div className="ledger-list-meta"><span>{page ? `共 ${page.total} 条漏洞结论` : error ? '读取失败' : '正在读取漏洞台账…'}{!filters.disposition && ' · 默认隐藏已撤回、重复和已取代结论'}</span><div className="ledger-list-actions">{filtered && <button type="button" className="text-button" onClick={reset}>重置筛选</button>}<button type="button" className="text-button" aria-label="刷新漏洞台账" disabled={refreshing} onClick={refresh}>{refreshing ? '刷新中…' : '刷新'}</button></div></div>
    {error && page && <div className="ledger-error" role="alert"><span>刷新失败：{error}</span><button className="btn" onClick={refresh}>重试</button></div>}
    {!page && error ? <div className="ledger-state" role="alert"><p>漏洞台账读取失败：{error}</p><button className="btn" onClick={refresh}>重新加载</button></div> : !page ? <div className="ledger-state" role="status"><LoaderCircle size={22} className="spin" /><p>正在读取漏洞台账…</p></div> : !page.items.length ? <div className="ledger-state"><ShieldCheck size={30} /><h3>{filtered ? '没有匹配的漏洞发现' : '还没有漏洞发现'}</h3><p>{filtered ? '调整筛选条件，或查看包含历史处置的全部状态。' : '在源码包中发起审计后，形成的漏洞结论会显示在这里。'}</p><p>没有发现不代表源码包安全。</p>{filtered && <button className="btn" onClick={reset}>重置筛选</button>}</div> : <div className="ledger-table-wrap"><table className="ledger-table"><thead><tr><th>漏洞结论</th><th>严重性</th><th>验证状态</th>{!projectId && <th>所属源码包</th>}<th>源码位置</th><th>最近更新</th></tr></thead><tbody>{page.items.map((finding) => <tr key={finding.id}>
      <td data-label="漏洞结论"><a className="ledger-finding-link" href={`#findings/${encodeURIComponent(finding.id)}?from=${encodeURIComponent(window.location.hash)}`}><strong>{finding.title}</strong><ArrowUpRight size={15} /></a><p className="ledger-row-summary">{finding.summary}</p><div className="ledger-row-tags"><span className="chip">第 {finding.revision} 版</span>{finding.disposition !== 'open' && <span className="chip">{LEDGER_DISPOSITION_LABELS[finding.disposition] ?? finding.disposition}</span>}</div></td>
      <td data-label="严重性"><SeverityBadge finding={finding} /></td>
      <td data-label="验证状态"><span className={`chip chip-${finding.verification_status}`}>{VERIFICATION_LABELS[finding.verification_status] ?? finding.verification_status}</span></td>
      {!projectId && <td data-label="所属源码包"><a href={`#sources/${encodeURIComponent(finding.project_id)}?tab=findings`}>{finding.project_name || projects.find((project) => project.id === finding.project_id)?.name || '未命名源码包'}</a></td>}
      <td data-label="源码位置"><span className="ledger-location">{finding.file_path || '—'}{finding.symbol && finding.symbol !== '<project>' ? `:${finding.symbol}` : ''}</span><span className="ledger-subtle">{finding.last_run?.snapshot_name ?? '来源 ZIP 信息不可用'}</span></td>
      <td data-label="最近更新"><span className="ledger-date">{localDate(finding.updated_at)}</span><span className="ledger-subtle">首次发现 {localDate(finding.discovered_at)}</span></td>
    </tr>)}</tbody></table></div>}
    {page && page.total > 0 && <nav className="ledger-pagination" aria-label="漏洞列表分页"><span>第 {filters.page} / {totalPages} 页 · 每页 {LEDGER_PAGE_SIZE} 条</span><div><button className="btn" disabled={filters.page <= 1} onClick={() => change({ page: filters.page - 1 })}><ChevronLeft size={15} />上一页</button><button className="btn" disabled={filters.page >= totalPages} onClick={() => change({ page: filters.page + 1 })}>下一页<ChevronRight size={15} /></button></div></nav>}
  </section>;
}
