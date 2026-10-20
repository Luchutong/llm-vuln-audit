import { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowUpRight, Bug, ChevronLeft, FileArchive, Menu, Moon, Search, Settings, ShieldCheck, Sun, X } from 'lucide-react';
import { api, errorText } from './api';
import type { Config, Project, Run, Snapshot, SnapshotSummary } from './types';
import { RunView } from './views/RunView';
import { SettingsView } from './views/SettingsView';
import { SourceLibrary, SourceProjectView, SourceTaskView } from './views/SourcesView';
import { LedgerFindingsView } from './views/LedgerFindingsView';
import { LedgerFindingView } from './views/LedgerFindingView';
import { Overlay } from './components/Overlay';
import { BrandWordmark } from './components/BrandWordmark';
import { runLabel, TERMINAL } from './status';
import { newAuditHref, parseRoute, sourceHref } from './routes';

function stored(key: string, fallback: string) { try { return localStorage.getItem(key) ?? fallback; } catch { return fallback; } }

export default function App() {
  const [current, setCurrent] = useState(() => parseRoute(window.location.hash));
  const [snapshots, setSnapshots] = useState<SnapshotSummary[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [config, setConfig] = useState<Config | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ready, setReady] = useState(false);
  const [revision, setRevision] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [theme, setTheme] = useState(() => stored('audit-theme', 'dark') === 'light' ? 'light' : 'dark');
  const [collapsed, setCollapsed] = useState(() => stored('audit-sidebar', 'open') === 'closed');
  const [mobileOpen, setMobileOpen] = useState(false);
  const [draft, setDraft] = useState<{ key: number; seed?: Run }>({ key: 0 });
  const alive = useRef(true);
  const loading = useRef(false);
  const load = useCallback(async () => {
    if (loading.current) return;
    loading.current = true;
    try {
      const [snapshotList, configData, runList, projectList] = await Promise.all([
        api<SnapshotSummary[]>('/snapshots'), api<Config>('/config'), api<Run[]>('/runs'), api<Project[]>('/projects'),
      ]);
      if (alive.current) { setSnapshots(snapshotList); setConfig(configData); setRuns(runList); setProjects(projectList); setError(null); setReady(true); setRevision((value) => value + 1); }
    } catch (exc) { if (alive.current) setError(errorText(exc)); }
    finally { loading.current = false; }
  }, []);
  useEffect(() => {
    alive.current = true;
    void load();
    const timer = window.setInterval(() => { if (!document.hidden) void load(); }, 5000);
    return () => { alive.current = false; window.clearInterval(timer); };
  }, [load]);
  useEffect(() => {
    const sync = () => { setCurrent(parseRoute(window.location.hash)); setMobileOpen(false); };
    window.addEventListener('hashchange', sync);
    return () => window.removeEventListener('hashchange', sync);
  }, []);
  useEffect(() => {
    if (current.page !== 'new') setDraft((value) => value.seed ? { key: value.key } : value);
  }, [current.page]);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'dark' ? '#0e0f0f' : '#edf2fa');
    try { localStorage.setItem('audit-theme', theme); } catch { /* Optional persistence. */ }
  }, [theme]);
  const navigate = (hash: string) => { window.location.hash = hash; setCurrent(parseRoute(hash)); setMobileOpen(false); };
  const newTask = (seed?: Run) => {
    setDraft((value) => ({ key: value.key + 1, seed }));
    navigate(seed ? seed.project_id ? newAuditHref(seed.project_id, seed.snapshot_id) : `#new?snapshot=${encodeURIComponent(seed.snapshot_id)}` : '#sources');
  };
  const openRun = (id: string) => { navigate(`#run/${encodeURIComponent(id)}`); void load(); };
  const imported = (snapshot: Snapshot) => {
    setNotice(`${snapshot.name}：${snapshot.snapshot_reused ? '已复用已有 ZIP 快照' : 'ZIP 已导入'}，${snapshot.project_reused ? '已归入相同源码的已有项目' : '已创建源码项目'}。选择审计目标后即可开始。`);
    void load();
    navigate(snapshot.project_id ? sourceHref(snapshot.project_id) : '#sources');
  };
  const toggleSidebar = () => setCollapsed((value) => { try { localStorage.setItem('audit-sidebar', value ? 'open' : 'closed'); } catch { /* Optional persistence. */ } return !value; });
  const projectNames = new Map(projects.map((project) => [project.id, project.name]));
  const filtered = runs.filter((run) => `${run.task_spec?.objective ?? ''} ${run.snapshot_name} ${run.id} ${run.project_id ? projectNames.get(run.project_id) ?? '' : ''}`.toLowerCase().includes(search.toLowerCase()));
  const groups = new Map<string, { name: string; runs: Run[] }>();
  for (const run of filtered) {
    const key = run.project_id ?? '__legacy__';
    const group = groups.get(key) ?? { name: run.project_id ? projectNames.get(run.project_id) ?? '未命名项目' : '历史审计', runs: [] };
    group.runs.push(run); groups.set(key, group);
  }
  const sourcesActive = ['sources', 'project', 'new'].includes(current.page);
  const sidebar = <>
    <div className="side-brand"><span className="brand-mark"><ShieldCheck size={21} /></span><div><BrandWordmark /><small>源码审计工作空间</small></div></div>
    <nav className="source-primary-nav" aria-label="工作空间导航"><a href="#sources" className={`nav-item${sourcesActive ? ' active' : ''}`} aria-current={sourcesActive ? 'page' : undefined}><FileArchive size={18} />源码包<span>{projects.length}</span></a><a href="#findings" className={`nav-item${current.page === 'findings' || current.page === 'finding' ? ' active' : ''}`} aria-current={current.page === 'findings' || current.page === 'finding' ? 'page' : undefined}><Bug size={18} />漏洞发现<ArrowUpRight size={14} /></a></nav>
    <label className="sidebar-search"><Search size={16} /><input aria-label="搜索历史任务" placeholder="搜索审计记录" value={search} onChange={(event) => setSearch(event.target.value)} /></label>
    <div className="sidebar-section-title">审计记录 <span>{runs.length}</span></div>
    <nav className="history-list" aria-label="历史审计任务">
      {!filtered.length && <div className="sidebar-empty">{runs.length ? '没有匹配的审计记录' : '从源码包开始第一次审计，任务将保存在这里。'}</div>}
      {[...groups].map(([key, group]) => <div key={key} className="history-group">
        {key !== '__legacy__' && <a className="sidebar-section-title source-group-link" href={sourceHref(key)}>{group.name}<span>{group.runs.length}</span></a>}
        {group.runs.map((run) => <button key={run.id} className={`history-item${current.runId === run.id ? ' active' : ''}`} onClick={() => openRun(run.id)} aria-current={current.runId === run.id ? 'page' : undefined}>
          <span className={`status-dot status-${run.status}${!TERMINAL.has(run.status) ? ' live' : ''}`} />
          <span className="history-item-body"><span className="history-title">{run.task_spec?.objective ?? '历史审计'}</span><span className="history-meta"><span>{run.snapshot_name}</span><span>{runLabel(run.status)}</span></span></span>
        </button>)}
      </div>)}
    </nav>
    <div className="side-footer">
      <a className={`nav-item${current.page === 'settings' ? ' active' : ''}`} href="#settings"><Settings size={18} />工作空间设置<ArrowUpRight size={14} /></a>
      <div className="side-footer-row"><span><span className={`status-dot ${config?.configured ? 'status-completed' : 'status-inconclusive'}`} />{config ? config.configured ? '模型已配置' : '模型待配置' : '正在连接服务'}</span><button className="icon-button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label={theme === 'dark' ? '切换浅色主题' : '切换深色主题'}>{theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}</button></div>
      <p className="sidebar-footnote">每一条结论，都有源码依据。</p>
    </div>
  </>;
  const pageLabel = current.page === 'settings' ? '设置' : current.page === 'run' ? '审计会话' : current.page === 'finding' ? '漏洞详情' : current.page === 'findings' ? '漏洞发现' : current.page === 'new' ? '新建审计' : '源码包';
  return <div className={`shell${collapsed ? ' sidebar-collapsed' : ''}`}>
    <aside className="side desktop-side">{sidebar}<button className="sidebar-collapse icon-button" aria-label="收起侧栏" onClick={toggleSidebar}><ChevronLeft size={16} /></button></aside>
    {mobileOpen && <Overlay title="审计工作空间" onClose={() => setMobileOpen(false)} drawer className="mobile-sidebar"><div className="side" onClick={(event) => { if ((event.target as Element).closest('a[href^="#"]')) setMobileOpen(false); }}>{sidebar}</div></Overlay>}
    <main className="main">
      <div className="workspace-bar"><button className="icon-button desktop-menu" aria-label={collapsed ? '展开侧栏' : '收起侧栏'} onClick={toggleSidebar}><Menu size={18} /></button><button className="icon-button mobile-menu" aria-label="打开导航" onClick={() => setMobileOpen(true)}><Menu size={19} /></button><span>工作空间 <span className="breadcrumb-divider">/</span> {pageLabel}</span><span className="workspace-tag">CODE AGENT</span></div>
      {error && <div className="service-error" role="alert"><span>服务连接失败：{error}</span><button className="text-button" onClick={() => void load()}>重试</button><button className="icon-button" aria-label="关闭连接错误" onClick={() => setError(null)}><X size={15} /></button></div>}
      {notice && <div className="source-import-notice" role="status"><ShieldCheck size={17} /><span>{notice}</span><button className="icon-button" aria-label="关闭导入提示" onClick={() => setNotice(null)}><X size={15} /></button></div>}
      {current.page === 'run' ? <RunView key={current.runId} runId={current.runId!} onNewTask={newTask} onChanged={load} />
        : current.page === 'project' ? <SourceProjectView key={current.projectId} projectId={current.projectId!} tab={current.tab!} snapshotId={current.snapshotId} projects={projects} revision={revision} />
        : current.page === 'new' ? <SourceTaskView key={`${current.projectId ?? 'legacy'}-${draft.key}`} projectId={current.projectId} snapshotId={current.snapshotId} seed={draft.seed?.snapshot_id === current.snapshotId ? draft.seed : undefined} config={config} allSnapshots={snapshots} onOpenRun={openRun} onChanged={load} />
        : current.page === 'findings' ? <LedgerFindingsView projects={projects} />
        : current.page === 'finding' ? <LedgerFindingView key={current.findingId} findingId={current.findingId!} />
        : current.page === 'settings' ? <div className="settings-page"><header className="page-head"><span className="eyebrow">WORKSPACE SETTINGS</span><h1>工作空间设置</h1><p>查看模型连接、运行状态和默认执行预算。</p></header><SettingsView config={config} onChanged={load} /></div>
        : current.page === 'missing' ? <div className="sources-page"><div className="sources-empty"><h1>页面不存在</h1><a className="btn" href="#sources">返回源码包库</a></div></div>
        : <SourceLibrary projects={projects} snapshots={snapshots} runs={runs} loading={!ready && !error} onImported={imported} />}
    </main>
  </div>;
}
