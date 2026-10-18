import { useCallback, useEffect, useState } from 'react';
import { ShieldCheck, Settings, FolderGit2 } from 'lucide-react';
import { api, errorText } from './api';
import type { Config, SnapshotSummary } from './types';
import { TaskView } from './views/TaskView';
import { RunView } from './views/RunView';
import { SettingsView } from './views/SettingsView';

type Page = 'tasks' | 'settings';

const NAV: { key: Page; label: string; icon: typeof ShieldCheck }[] = [
  { key: 'tasks', label: '源码审计', icon: ShieldCheck },
  { key: 'settings', label: '配置', icon: Settings },
];

/**
 * Application shell — dark sidebar + light content area, responsive.
 */
export default function App() {
  const [page, setPage] = useState<Page>(() => pageFromHash());
  const [runId, setRunId] = useState<string | null>(() => runFromHash());
  const [snapshots, setSnapshots] = useState<SnapshotSummary[]>([]);
  const [config, setConfig] = useState<Config | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    Promise.all([api<SnapshotSummary[]>('/snapshots'), api<Config>('/config')])
      .then(([snapshotList, configData]) => {
        setSnapshots(snapshotList);
        setConfig(configData);
        setError(null);
      })
      .catch((exc) => setError(errorText(exc)));
  }, []);

  useEffect(() => {
    load();
    const timer = window.setInterval(load, 15000);
    return () => window.clearInterval(timer);
  }, [load]);

  useEffect(() => {
    const sync = () => {
      setPage(pageFromHash());
      setRunId(runFromHash());
    };
    window.addEventListener('hashchange', sync);
    return () => window.removeEventListener('hashchange', sync);
  }, []);

  const openRun = (id: string) => {
    window.location.hash = `#run/${id}`;
    setRunId(id);
  };

  const go = (next: Page) => {
    window.location.hash = next === 'tasks' ? '' : `#${next}`;
    setPage(next);
    setRunId(null);
  };

  return (
    <div className="shell">
      <aside className="side">
        <div className="side-brand">
          <div className="brand-logo">
            <div className="brand-icon">P</div>
            <div>
              <div className="brand-name">PHP Audit</div>
              <div className="brand-sub">可追溯的源码审计工作台</div>
            </div>
          </div>
        </div>

        <nav className="side-nav">
          <div className="nav-label">导航</div>
          {NAV.map((item) => {
            const Icon = item.icon;
            return (
              <button
                key={item.key}
                className={`nav-item${page === item.key && !runId ? ' active' : ''}`}
                onClick={() => go(item.key)}
              >
                <Icon size={16} />
                {item.label}
              </button>
            );
          })}
        </nav>

        <div className="side-foot">
          <div className="row" style={{ gap: 6 }}>
            <FolderGit2 size={13} />
            <span>{snapshots.length} 个源码快照</span>
          </div>
        </div>
      </aside>

      <main className="main">
        {error && <div className="error-box" style={{ marginBottom: 14 }}>{error}</div>}

        {runId ? (
          <RunView runId={runId} onBack={() => go('tasks')} />
        ) : page === 'tasks' ? (
          <>
            <div className="page-head">
              <h1>PHP 源码目标审计</h1>
              <p>上传 PHP 源码 ZIP，设定目标与验收条件，启动多 worker 审计并查看证据化结果。</p>
            </div>
            <TaskView
              snapshots={snapshots}
              config={config}
              onOpenRun={openRun}
              onChanged={load}
            />
          </>
        ) : (
          <>
            <div className="page-head">
              <h1>配置</h1>
              <p>模型连接状态、健康熔断与默认预算。</p>
            </div>
            <SettingsView config={config} onChanged={load} />
          </>
        )}
      </main>
    </div>
  );
}

function pageFromHash(): Page {
  const hash = window.location.hash.replace('#', '');
  if (hash.startsWith('settings')) return 'settings';
  return 'tasks';
}

function runFromHash(): string | null {
  const match = window.location.hash.match(/^#run\/(.+)$/);
  return match ? match[1] : null;
}
