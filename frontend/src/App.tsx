import { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowUpRight, ChevronLeft, Menu, Moon, Plus, Search, Settings, ShieldCheck, Sun, X } from 'lucide-react';
import { api, errorText } from './api';
import type { Config, Run, SnapshotSummary } from './types';
import { TaskView } from './views/TaskView';
import { RunView } from './views/RunView';
import { SettingsView } from './views/SettingsView';
import { Overlay } from './components/Overlay';
import { BrandWordmark } from './components/BrandWordmark';
import { runLabel, TERMINAL } from './status';

type Route = { page: 'tasks' | 'settings'; runId: string | null };
function route(): Route {
  const match = window.location.hash.match(/^#run\/([^/?]+)/);
  return { page: window.location.hash.startsWith('#settings') ? 'settings' : 'tasks', runId: match ? decodeURIComponent(match[1]) : null };
}
function stored(key: string, fallback: string) { try { return localStorage.getItem(key) ?? fallback; } catch { return fallback; } }

export default function App() {
  const [current, setCurrent] = useState(route);
  const [snapshots, setSnapshots] = useState<SnapshotSummary[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [config, setConfig] = useState<Config | null>(null);
  const [error, setError] = useState<string | null>(null);
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
      const [snapshotList, configData, runList] = await Promise.all([api<SnapshotSummary[]>('/snapshots'), api<Config>('/config'), api<Run[]>('/runs')]);
      if (alive.current) { setSnapshots(snapshotList); setConfig(configData); setRuns(runList); setError(null); }
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
    const sync = () => { setCurrent(route()); setMobileOpen(false); };
    window.addEventListener('hashchange', sync);
    return () => window.removeEventListener('hashchange', sync);
  }, []);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'dark' ? '#0e0f0f' : '#edf2fa');
    try { localStorage.setItem('audit-theme', theme); } catch { /* Optional persistence. */ }
  }, [theme]);
  const newTask = (seed?: Run) => { setDraft((value) => ({ key: value.key + 1, seed })); window.location.hash = ''; setCurrent({ page: 'tasks', runId: null }); setMobileOpen(false); };
  const openRun = (id: string) => { window.location.hash = `#run/${encodeURIComponent(id)}`; setCurrent({ page: 'tasks', runId: id }); setMobileOpen(false); void load(); };
  const toggleSidebar = () => setCollapsed((value) => { try { localStorage.setItem('audit-sidebar', value ? 'open' : 'closed'); } catch { /* Optional persistence. */ } return !value; });
  const filtered = runs.filter((run) => `${run.task_spec?.objective ?? ''} ${run.snapshot_name} ${run.id}`.toLowerCase().includes(search.toLowerCase()));
  const sidebar = <>
    <div className="side-brand"><span className="brand-mark"><ShieldCheck size={21} /></span><div><BrandWordmark /><small>源码审计工作空间</small></div></div>
    <button className="new-task-button" onClick={() => newTask()}><Plus size={18} />新建审计<span className="shortcut">＋</span></button>
    <label className="sidebar-search"><Search size={16} /><input aria-label="搜索历史任务" placeholder="搜索审计记录" value={search} onChange={(event) => setSearch(event.target.value)} /></label>
    <div className="sidebar-section-title">审计记录 <span>{runs.length}</span></div>
    <nav className="history-list" aria-label="历史审计任务">
      {!filtered.length && <div className="sidebar-empty">{runs.length ? '没有匹配的审计记录' : '发送第一个任务后，记录将保存在这里。'}</div>}
      {filtered.map((run) => <button key={run.id} className={`history-item${current.runId === run.id ? ' active' : ''}`} onClick={() => openRun(run.id)} aria-current={current.runId === run.id ? 'page' : undefined}>
        <span className={`status-dot status-${run.status}${!TERMINAL.has(run.status) ? ' live' : ''}`} />
        <span className="history-item-body"><span className="history-title">{run.task_spec?.objective ?? '历史审计'}</span><span className="history-meta"><span>{run.snapshot_name}</span><span>{runLabel(run.status)}</span></span></span>
      </button>)}
    </nav>
    <div className="side-footer">
      <button className={`nav-item${current.page === 'settings' ? ' active' : ''}`} onClick={() => { window.location.hash = '#settings'; setCurrent({ page: 'settings', runId: null }); setMobileOpen(false); }}><Settings size={18} />工作空间设置<ArrowUpRight size={14} /></button>
      <div className="side-footer-row"><span><span className={`status-dot ${config?.configured ? 'status-completed' : 'status-inconclusive'}`} />{config ? config.configured ? '模型已配置' : '模型待配置' : '正在连接服务'}</span><button className="icon-button" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')} aria-label={theme === 'dark' ? '切换浅色主题' : '切换深色主题'}>{theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}</button></div>
      <p className="sidebar-footnote">每一条结论，都有源码依据。</p>
    </div>
  </>;
  return <div className={`shell${collapsed ? ' sidebar-collapsed' : ''}`}>
    <aside className="side desktop-side">{sidebar}<button className="sidebar-collapse icon-button" aria-label="收起侧栏" onClick={toggleSidebar}><ChevronLeft size={16} /></button></aside>
    {mobileOpen && <Overlay title="审计工作空间" onClose={() => setMobileOpen(false)} drawer className="mobile-sidebar"><div className="side">{sidebar}</div></Overlay>}
    <main className="main">
      <div className="workspace-bar"><button className="icon-button desktop-menu" aria-label={collapsed ? '展开侧栏' : '收起侧栏'} onClick={toggleSidebar}><Menu size={18} /></button><button className="icon-button mobile-menu" aria-label="打开导航" onClick={() => setMobileOpen(true)}><Menu size={19} /></button><span>工作空间 <span className="breadcrumb-divider">/</span> {current.page === 'settings' ? '设置' : '源码审计'}</span><span className="workspace-tag">CODE AGENT</span></div>
      {error && <div className="service-error" role="alert"><span>服务连接失败：{error}</span><button className="text-button" onClick={() => void load()}>重试</button><button className="icon-button" aria-label="关闭连接错误" onClick={() => setError(null)}><X size={15} /></button></div>}
      {current.runId ? <RunView key={current.runId} runId={current.runId} onNewTask={newTask} onChanged={load} /> : current.page === 'settings' ? <div className="settings-page"><header className="page-head"><span className="eyebrow">WORKSPACE SETTINGS</span><h1>工作空间设置</h1><p>查看模型连接、运行状态和默认执行预算。</p></header><SettingsView config={config} onChanged={load} /></div> : <TaskView key={draft.key} seed={draft.seed} snapshots={snapshots} config={config} onOpenRun={openRun} onChanged={load} />}
    </main>
  </div>;
}
