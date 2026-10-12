import { useCallback, useEffect, useState } from 'react';
import { api, errorText } from './api';
import type { Config, Prompt, SnapshotSummary } from './types';
import { TaskView } from './views/TaskView';
import { RunView } from './views/RunView';
import { PromptsView } from './views/PromptsView';
import { SettingsView } from './views/SettingsView';

type Page = 'tasks' | 'prompts' | 'settings';

const NAV: { key: Page; label: string }[] = [
  { key: 'tasks', label: '审计任务' },
  { key: 'prompts', label: 'Prompt 与实验' },
  { key: 'settings', label: '配置' },
];

/**
 * Application shell.
 *
 * The run is part of the route state, not a separate page: opening a run keeps the nav in
 * place, and the URL hash carries the run id so a reload lands back on the same run rather
 * than at the task list.
 */
export default function App() {
  const [page, setPage] = useState<Page>(() => pageFromHash());
  const [runId, setRunId] = useState<string | null>(() => runFromHash());
  const [snapshots, setSnapshots] = useState<SnapshotSummary[]>([]);
  const [prompts, setPrompts] = useState<Prompt[]>([]);
  const [config, setConfig] = useState<Config | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    Promise.all([api<SnapshotSummary[]>('/snapshots'), api<Prompt[]>('/prompts'), api<Config>('/config')])
      .then(([snapshotList, promptList, configData]) => {
        setSnapshots(snapshotList);
        setPrompts(promptList);
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
    setPage('tasks');
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
          PHP Audit
          <small>可追溯的白盒审计工作台</small>
        </div>
        {NAV.map((item) => (
          <button
            key={item.key}
            className={`nav-item${page === item.key && !runId ? ' active' : ''}`}
            onClick={() => go(item.key)}
          >
            {item.label}
          </button>
        ))}
        <div style={{ marginTop: 18, padding: '0 8px' }} className="small faint">
          {snapshots.length} 个快照 · {prompts.length} 个 Prompt 版本
        </div>
      </aside>

      <main className="main">
        {error && <div className="error-box" style={{ marginBottom: 14 }}>{error}</div>}

        {runId ? (
          <RunView runId={runId} onBack={() => go('tasks')} />
        ) : page === 'tasks' ? (
          <>
            <div className="page-head">
              <h1>审计任务</h1>
              <p>导入源码快照，选择范围与预算，启动一次可追溯的审计运行。</p>
            </div>
            <TaskView
              snapshots={snapshots}
              prompts={prompts}
              config={config}
              onOpenRun={openRun}
              onChanged={load}
            />
          </>
        ) : page === 'prompts' ? (
          <>
            <div className="page-head">
              <h1>Prompt 与实验</h1>
              <p>P0 → P1 → P2 的全文与改动原因，以及同一快照、同一预算下的对比。</p>
            </div>
            <PromptsView prompts={prompts} onChanged={load} />
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
  if (hash.startsWith('prompts')) return 'prompts';
  if (hash.startsWith('settings')) return 'settings';
  return 'tasks';
}

function runFromHash(): string | null {
  const match = window.location.hash.match(/^#run\/(.+)$/);
  return match ? match[1] : null;
}
