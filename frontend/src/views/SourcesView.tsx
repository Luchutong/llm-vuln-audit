import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, ArrowUpRight, FileArchive, FileCode2, FolderOpen, LoaderCircle, Plus, Search, ShieldCheck, Upload } from 'lucide-react';
import { api, errorText } from '../api';
import type { Config, Project, Run, Snapshot, SnapshotSummary } from '../types';
import { localDate, runLabel } from '../status';
import { newAuditHref, sourceHref } from '../routes';
import type { SourceTab } from '../routes';
import { SourceViewer } from '../components/SourceViewer';
import { Disclosure } from '../components/Disclosure';
import { LongContent } from '../components/LongContent';
import { TaskView } from './TaskView';
import { LedgerFindingsView } from './LedgerFindingsView';
import { CleanupRunsButton, DeleteRunButton, DeleteSnapshotButton } from '../components/RecordActions';
import '../sources.css';

export function SourceLibrary({ projects, snapshots, runs, loading, onImported }: {
  projects: Project[]; snapshots: SnapshotSummary[]; runs: Run[]; loading: boolean; onImported: (snapshot: Snapshot) => void;
}) {
  const [query, setQuery] = useState(() => new URLSearchParams(window.location.hash.split('?')[1]).get('q') ?? '');
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const [dragging, setDragging] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const request = useRef<AbortController | null>(null);
  const uploadLock = useRef(false);
  const dragDepth = useRef(0);
  useEffect(() => () => request.current?.abort(), []);
  useEffect(() => {
    const sync = () => setQuery(new URLSearchParams(window.location.hash.split('?')[1]).get('q') ?? '');
    window.addEventListener('hashchange', sync);
    return () => window.removeEventListener('hashchange', sync);
  }, []);
  const upload = async (file: File) => {
    if (uploadLock.current) return;
    setError(null);
    if (!file.name.toLowerCase().endsWith('.zip')) { setError('请选择项目源码 ZIP 压缩包。'); return; }
    if (!file.size) { setError('压缩包为空，请重新选择。'); return; }
    if (file.size > 64 * 1024 * 1024) { setError('ZIP 压缩包不能超过 64 MiB。'); return; }
    uploadLock.current = true; setUploading(true);
    const abort = new AbortController(); request.current = abort;
    try {
      const body = new FormData(); body.append('file', file);
      const snapshot = await api<Snapshot>('/snapshots', { method: 'POST', body, signal: abort.signal });
      if (!abort.signal.aborted) onImported(snapshot);
    } catch (exc) { if (!abort.signal.aborted) setError(`导入失败：${errorText(exc)}`); }
    finally { uploadLock.current = false; if (!abort.signal.aborted) setUploading(false); }
  };
  const visible = projects.filter((project) => `${project.name} ${project.id} ${snapshots.filter((row) => row.project_id === project.id).map((row) => row.name).join(' ')}`.toLowerCase().includes(query.trim().toLowerCase()));
  const liveRuns = runs.filter((run) => run.status === 'running' || run.status === 'pending');
  return <section className={`sources-page${dragging ? ' sources-dragging' : ''}`}
    onDragEnter={(event) => { if (event.dataTransfer.types.includes('Files')) { event.preventDefault(); dragDepth.current++; setDragging(true); } }}
    onDragOver={(event) => { if (event.dataTransfer.types.includes('Files')) event.preventDefault(); }}
    onDragLeave={() => { dragDepth.current = Math.max(0, dragDepth.current - 1); if (!dragDepth.current) setDragging(false); }}
    onDrop={(event) => { event.preventDefault(); dragDepth.current = 0; setDragging(false); if (event.dataTransfer.files.length !== 1) setError('请一次导入一个源码 ZIP。'); else void upload(event.dataTransfer.files[0]); }}>
    <header className="sources-head"><div><span className="eyebrow">SOURCE LIBRARY</span><h1>源码包</h1><p>从已有源码开始审计，让每一条发现都有归属。</p></div><button className="btn btn-primary" disabled={uploading} onClick={() => input.current?.click()}>{uploading ? <LoaderCircle size={17} className="spin" /> : <Upload size={17} />}{uploading ? '正在导入并建立索引…' : '上传源码 ZIP'}</button></header>
    <input ref={input} type="file" className="sr-only" tabIndex={-1} aria-label="上传项目源码 ZIP" accept=".zip,application/zip" disabled={uploading} onChange={(event) => { const file = event.target.files?.[0]; if (file) void upload(file); event.target.value = ''; }} />
    <div className="sources-metrics" aria-label="源码库统计"><SourceMetric label="源码项目" value={projects.length} /><SourceMetric label="ZIP 快照" value={snapshots.length} /><SourceMetric label="进行中审计" value={liveRuns.length} /><SourceMetric label="累计漏洞候选" value={projects.reduce((sum, row) => sum + (row.finding_counts?.total ?? 0), 0)} /></div>
    <div className="sources-toolbar"><label className="sources-search"><Search size={17} /><input aria-label="搜索源码包" placeholder="搜索项目名称或 ZIP 文件名" value={query} onChange={(event) => { setQuery(event.target.value); const params = new URLSearchParams(); if (event.target.value) params.set('q', event.target.value); window.history.replaceState(null, '', `#sources${params.size ? `?${params}` : ''}`); }} /></label><span className="faint small">相同源码内容归组 · 最大 64 MiB / ZIP</span></div>
    {error && <div className="error-box" role="alert">{error}<button className="text-button" disabled={uploading} onClick={() => input.current?.click()}>重新选择</button></div>}
    {loading && !projects.length ? <div className="sources-empty" role="status"><LoaderCircle className="spin" /><p>正在读取源码包…</p></div> : !visible.length ? <div className="sources-empty"><FolderOpen size={35} /><h2>{query ? '没有匹配的源码包' : '导入第一个源码 ZIP'}</h2><p>{query ? '试试项目名称或 ZIP 文件名。' : '源码会保存为不可变快照。之后可反复选择它发起审计，发现累计在所属项目中。'}</p>{!query && <button className="btn" disabled={uploading} onClick={() => input.current?.click()}><Plus size={16} />选择 ZIP，或拖放到此处</button>}</div> : <div className="sources-grid">{visible.map((project) => {
      const latest = snapshots.find((row) => row.id === project.latest_snapshot_id);
      const active = liveRuns.filter((run) => run.project_id === project.id).length;
      return <article className="source-card" key={project.id}><div className="source-card-heading"><span className="source-card-icon"><FileArchive size={24} /></span><div><a className="source-card-title" href={sourceHref(project.id)}>{project.name}</a><p>{latest?.name ?? '源码内容项目'}</p></div>{active > 0 && <span className="chip chip-running">{active} 项审计中</span>}</div><div className="source-card-stats"><span><strong>{project.snapshot_count}</strong> ZIP 快照</span><span><strong>{project.run_count}</strong> 次审计</span><span><strong>{project.finding_counts?.total ?? 0}</strong> 累计候选</span><span><strong>{project.finding_counts?.verified ?? 0}</strong> 验证通过记录</span></div><div className="source-card-footer"><span className="faint small">最近活动 {localDate(project.updated_at)}</span><div><a className="btn" href={sourceHref(project.id)}>工作台<ArrowUpRight size={14} /></a>{project.latest_snapshot_id ? <a className="btn btn-primary" href={newAuditHref(project.id, project.latest_snapshot_id)}>开始审计</a> : <button className="btn" disabled={uploading} onClick={() => input.current?.click()}>上传源码 ZIP</button>}</div></div></article>;
    })}</div>}
    {dragging && <div className="drop-overlay"><FileArchive size={38} /><strong>松开以导入源码 ZIP</strong><span>保存后选择审计目标 · 最大 64 MiB</span></div>}
  </section>;
}

function SourceMetric({ label, value }: { label: string; value: number }) { return <div><strong>{value}</strong><span>{label}</span></div>; }

function useProject(projectId: string, revision: number) {
  const [project, setProject] = useState<Project | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retry, setRetry] = useState(0);
  const request = useRef<AbortController | null>(null);
  useEffect(() => {
    return () => { request.current?.abort(); request.current = null; };
  }, [projectId]);
  useEffect(() => {
    // A slow initial read must survive the next workspace polling tick.
    if (request.current) return;
    const abort = new AbortController();
    request.current = abort;
    api<Project>(`/projects/${encodeURIComponent(projectId)}?include_findings=false`, { signal: abort.signal })
      .then((data) => { if (!abort.signal.aborted) { setProject(data); setError(null); } })
      .catch((exc) => { if (!abort.signal.aborted) setError(errorText(exc)); })
      .finally(() => { if (request.current === abort) request.current = null; });
  }, [projectId, revision, retry]);
  return { project, error, retry: () => setRetry((value) => value + 1) };
}

function ProjectLoading({ error, retry }: { error: string | null; retry: () => void }) {
  return <div className="sources-page"><a className="sources-back" href="#sources"><ArrowLeft size={15} />源码包库</a><div className="sources-empty" role={error ? 'alert' : 'status'}>{error ? <><h2>源码包读取失败</h2><p>{error}</p><button className="btn" onClick={retry}>重试</button></> : <><LoaderCircle className="spin" /><p>正在读取源码包…</p></>}</div></div>;
}

export function SourceProjectView({ projectId, tab, snapshotId, projects, revision }: { projectId: string; tab: SourceTab; snapshotId?: string; projects: Project[]; revision: number }) {
  const { project, error, retry } = useProject(projectId, revision);
  if (!project) return <ProjectLoading error={error} retry={retry} />;
  return <section className="sources-page"><a className="sources-back" href="#sources"><ArrowLeft size={15} />源码包库</a>
    <header className="sources-head"><div><span className="eyebrow">SOURCE WORKSPACE</span><h1>{project.name}</h1><p>相同源码内容归组 · {project.snapshot_count} 个 ZIP 快照 · 漏洞跨审计累计</p></div><div className="records-header-actions"><CleanupRunsButton projectId={project.id} name={project.name} />{project.latest_snapshot_id ? <a className="btn btn-primary" href={newAuditHref(project.id, project.latest_snapshot_id)}><Plus size={16} />开始审计</a> : <a className="btn" href="#sources">上传源码 ZIP</a>}</div></header>
    {error && <div className="error-box" role="alert">刷新失败：{error} <button className="text-button" onClick={retry}>重试</button></div>}
    <div className="sources-metrics"><SourceMetric label="审计任务" value={project.run_count} /><SourceMetric label="ZIP 快照" value={project.snapshot_count} /><SourceMetric label="累计漏洞候选" value={project.finding_counts?.total ?? 0} /><SourceMetric label="累计验证通过记录" value={project.finding_counts?.verified ?? 0} /></div>
    <nav className="tabs sources-tabs" aria-label="源码包视图">{([{ key: 'tasks', label: '审计任务' }, { key: 'findings', label: '漏洞发现' }, { key: 'archives', label: 'ZIP 与源码' }] as const).map((item) => <a className={`tab${item.key === tab ? ' active' : ''}`} aria-current={item.key === tab ? 'page' : undefined} href={sourceHref(projectId, item.key)} key={item.key}>{item.label}</a>)}</nav>
    {tab === 'findings' ? <LedgerFindingsView projectId={projectId} projects={projects} /> : tab === 'archives' ? <SnapshotBrowser key={projectId} project={project} initialSnapshotId={snapshotId} /> : <div className="panel sources-tasks"><div className="panel-head"><span className="panel-title">审计任务</span><span className="faint small">每次审计固定使用一个 ZIP 快照</span></div>{!project.runs?.length ? <div className="sources-empty"><ShieldCheck size={30} /><h2>还没有审计任务</h2><p>选择已有 ZIP，填写你想排查的漏洞方向。</p>{project.latest_snapshot_id ? <a className="btn btn-primary" href={newAuditHref(project.id, project.latest_snapshot_id)}>开始第一次审计</a> : <a className="btn" href="#sources">上传源码 ZIP</a>}</div> : project.runs.map((run) => <div className="records-run-row" key={run.id}><a className="source-run" href={`#run/${encodeURIComponent(run.id)}`}><span className={`status-dot status-${run.status}`} /><div><strong>{run.task_spec?.objective ?? '历史审计任务'}</strong><span><FileArchive size={13} />{run.snapshot_name}<span className="mono">{run.snapshot_id.slice(0, 8)}</span></span></div><span className={`chip chip-${run.status}`}>{runLabel(run.status)}</span><time>{localDate(run.created_at)}</time><ArrowUpRight size={16} /></a><DeleteRunButton run={run} compact /></div>)}</div>}
  </section>;
}

function SnapshotBrowser({ project, initialSnapshotId }: { project: Project; initialSnapshotId?: string }) {
  const snapshots = project.snapshots ?? [];
  const [selected, setSelected] = useState(initialSnapshotId ?? project.latest_snapshot_id ?? snapshots[0]?.id ?? '');
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState('');
  const [limit, setLimit] = useState(100);
  const [revision, setRevision] = useState(0);
  useEffect(() => { setSelected(initialSnapshotId ?? project.latest_snapshot_id ?? snapshots[0]?.id ?? ''); }, [initialSnapshotId, project.latest_snapshot_id]);
  useEffect(() => {
    if (!selected) return;
    const abort = new AbortController(); setSnapshot(null); setError(null); setLimit(100);
    if (!snapshots.some((row) => row.id === selected)) { setError('所选 ZIP 不属于此源码项目。'); return; }
    api<Snapshot>(`/snapshots/${encodeURIComponent(selected)}`, { signal: abort.signal }).then((data) => { if (!abort.signal.aborted) setSnapshot(data); }).catch((exc) => { if (!abort.signal.aborted) setError(errorText(exc)); });
    return () => abort.abort();
  }, [selected, revision]);
  if (!snapshots.length) return <div className="sources-empty"><FileArchive size={30} /><h2>没有可用的 ZIP 快照</h2><p>此项目的 ZIP 记录已移除。上传相同源码可再次关联到项目。</p><a className="btn" href="#sources">前往源码包库上传</a></div>;
  const files = snapshot?.files.filter((file) => file.path.toLowerCase().includes(query.toLowerCase())) ?? [];
  return <div className="sources-archives"><div className="panel panel-body sources-archive-picker"><label>选择 ZIP 快照<select aria-label="浏览 ZIP 快照" value={selected} onChange={(event) => { setSelected(event.target.value); window.location.hash = `${sourceHref(project.id, 'archives')}&snapshot=${encodeURIComponent(event.target.value)}`; }}>{!snapshots.some((row) => row.id === selected) && <option value={selected}>快照不可用</option>}{snapshots.map((row) => <option key={row.id} value={row.id}>{row.name} · {row.archive_sha256.slice(0, 12)} · {localDate(row.created_at)}</option>)}</select></label>{selected && snapshots.some((row) => row.id === selected) && <a className="btn btn-primary" href={newAuditHref(project.id, selected)}>基于此 ZIP 开始审计</a>}</div>
    {error ? <div className="error-box" role="alert">快照读取失败：{error} <button className="text-button" onClick={() => setRevision((value) => value + 1)}>重试</button></div> : !snapshot ? <div className="empty" role="status">正在读取 ZIP 快照…</div> : <>
      <div className="panel panel-body sources-snapshot-info"><h2><FileArchive size={19} />{snapshot.name}</h2><span className="faint small">导入于 {localDate(snapshot.created_at)} · 不可变快照 · {snapshot.files.length} 个文件</span><LongContent label="ZIP SHA-256" value={snapshot.archive_sha256} /><DeleteSnapshotButton snapshot={{ ...snapshot, file_count: snapshot.files.length, unit_count: snapshot.units?.length ?? 0, warning_count: snapshot.warnings.length }} /><p className="small muted">此处浏览该 ZIP 的原始源码；漏洞发现页展示整个源码项目的共享台账。</p>{snapshot.warnings.length > 0 && <Disclosure title={`导入提示（${snapshot.warnings.length}）`}><LongContent value={snapshot.warnings} label="导入提示" /><LongContent value={snapshot.skipped_files ?? []} label="跳过的条目" /></Disclosure>}</div>
      <div className="panel"><div className="panel-head sources-files-head"><span className="panel-title">源码文件</span><label className="sources-search"><Search size={15} /><input aria-label="搜索源码文件" placeholder="按路径搜索" value={query} onChange={(event) => { setQuery(event.target.value); setLimit(100); }} /></label></div><div className="panel-body sources-files">{!files.length && <div className="empty">没有匹配的文件。</div>}{files.slice(0, limit).map((file) => file.kind === 'binary' ? <div className="source-binary" key={file.path}><FileArchive size={14} /><span className="mono">{file.path}</span><span className="faint small">二进制 · {file.size} B</span></div> : <Disclosure key={`${snapshot.id}/${file.path}`} title={<span className="source-file-title"><FileCode2 size={14} /><span className="mono">{file.path}</span><small>{file.line_count} 行</small></span>}><SourceViewer snapshotId={snapshot.id} path={file.path} end={Math.min(file.line_count || 200, 200)} /></Disclosure>)}{files.length > limit && <button className="btn" onClick={() => setLimit((value) => value + 100)}>继续显示（{limit} / {files.length}）</button>}</div></div>
    </>}
  </div>;
}

export function SourceTaskView({ projectId, snapshotId, seed, config, allSnapshots, onOpenRun, onChanged }: { projectId?: string; snapshotId?: string; seed?: Run; config: Config | null; allSnapshots: SnapshotSummary[]; onOpenRun: (id: string) => void; onChanged: () => void }) {
  if (!projectId) return <TaskView initialSnapshotId={snapshotId} seed={seed} snapshots={allSnapshots} config={config} onOpenRun={onOpenRun} onChanged={onChanged} />;
  return <ProjectTaskView projectId={projectId} snapshotId={snapshotId} seed={seed} config={config} onOpenRun={onOpenRun} onChanged={onChanged} />;
}

function ProjectTaskView({ projectId, snapshotId, seed, config, onOpenRun, onChanged }: { projectId: string; snapshotId?: string; seed?: Run; config: Config | null; onOpenRun: (id: string) => void; onChanged: () => void }) {
  const { project, error, retry } = useProject(projectId, 0);
  if (!project) return <ProjectLoading error={error} retry={retry} />;
  const selected = snapshotId ?? project.latest_snapshot_id ?? project.snapshots?.[0]?.id;
  if (!selected || !project.snapshots?.some((row) => row.id === selected)) return <div className="sources-page"><a className="sources-back" href={sourceHref(projectId)}><ArrowLeft size={15} />返回源码包</a><div className="sources-empty" role="alert"><h2>所选 ZIP 不属于此源码项目</h2><p>请返回工作台，从已保存的 ZIP 快照发起审计。</p></div></div>;
  return <TaskView project={project} initialSnapshotId={selected} seed={seed} snapshots={project.snapshots} config={config} onOpenRun={onOpenRun} onChanged={onChanged} />;
}
