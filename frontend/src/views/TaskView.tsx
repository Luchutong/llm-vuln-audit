import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, ArrowUp, Check, ChevronDown, FileArchive, FileCode2, FolderOpen, LoaderCircle, Paperclip, ShieldCheck, SlidersHorizontal, Sparkles, X } from 'lucide-react';
import { api, errorText, post } from '../api';
import type { Budget, Config, Project, Run, Snapshot, SnapshotSummary, TaskSpec } from '../types';
import { localDate } from '../status';
import { sourceHref } from '../routes';
import { Overlay } from '../components/Overlay';
import { LongContent } from '../components/LongContent';
import { Disclosure } from '../components/Disclosure';

const EMPTY_TASK: TaskSpec = { objective: '', success_criteria: '', max_iterations: 3, max_total_attempts: 64, max_planner_rounds: 24, max_workers: 2, stop_on_achieved: true, require_poc: false };
const EXAMPLES = [
  { title: '追踪危险数据流', description: '查找任意文件写入或危险上传漏洞', objective: '审计文件上传入口，查找可被外部输入触发的任意文件写入、路径穿越或危险文件上传漏洞。' },
  { title: '检查认证边界', description: '查找管理功能的认证与授权绕过', objective: '审计项目中的管理路由，查找无需认证或越权访问敏感管理功能的漏洞。' },
  { title: '查找配置缺陷', description: '检查会话与 Cookie 的可利用风险', objective: '审计会话与 Cookie 配置，查找可导致会话泄露、劫持或跨站请求风险的可利用配置缺陷。' },
];
function clamp(value: string, minimum: number, maximum: number) { return Math.max(minimum, Math.min(maximum, Math.trunc(Number(value) || minimum))); }
/** The start screen freezes one decision: what to audit.
 *
 * Acceptance is the server's default ``TaskSpec.success_criteria`` (a goal-related risk
 * backed by original line evidence, with a risk level and trigger conditions), so the
 * request omits the field instead of sending a second editable text the user would have
 * to phrase again.  The frozen run still shows that default wherever a task is described.
 */
function startTask(task: TaskSpec, objective: string): Partial<TaskSpec> {
  const payload: Partial<TaskSpec> = { ...task, objective };
  delete payload.success_criteria;
  return payload;
}

export function TaskView({ snapshots, config, seed, project, initialSnapshotId, onOpenRun, onChanged }: { snapshots: SnapshotSummary[]; config: Config | null; seed?: Run; project?: Project; initialSnapshotId?: string; onOpenRun: (runId: string) => void; onChanged: () => void }) {
  const [selected, setSelected] = useState<string | null>(initialSnapshotId ?? seed?.snapshot_id ?? null);
  const [snapshotRevision, setSnapshotRevision] = useState(0);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [task, setTask] = useState<TaskSpec>(() => ({ ...EMPTY_TASK, ...seed?.task_spec }));
  const [budgets, setBudgets] = useState<Budget>(seed?.budgets ?? config?.budget_limits?.defaults ?? config?.budgets ?? { responses: 24, tools: 96, seconds: 1800 });
  const [dialog, setDialog] = useState<'snapshots' | 'snapshot' | 'options' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fileLimit, setFileLimit] = useState(100);
  const [attachmentError, setAttachmentError] = useState<string | null>(null);
  const [uploadName, setUploadName] = useState('');
  const [uploading, setUploading] = useState(false);
  const [loading, setLoading] = useState(false);
  const [starting, setStarting] = useState(false);
  const [dragging, setDragging] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const uploadRequest = useRef<AbortController | null>(null);
  const cached = useRef<Snapshot | null>(null);
  const startLock = useRef(false);
  const startGeneration = useRef(0);
  const configuredBudget = useRef(Boolean(seed || config));
  const dragDepth = useRef(0);
  const objectiveRef = useRef<HTMLTextAreaElement>(null);
  const active = useRef(true);
  const chooseSnapshot = (id: string) => {
    setSelected(id);
    if (project) window.location.hash = `#sources/${encodeURIComponent(project.id)}/new?snapshot=${encodeURIComponent(id)}`;
  };
  useEffect(() => {
    uploadRequest.current?.abort();
    setUploading(false);
    setUploadName('');
    setSelected(initialSnapshotId ?? seed?.snapshot_id ?? null);
    startGeneration.current += 1;
    startLock.current = false;
    setStarting(false);
  }, [initialSnapshotId, seed?.snapshot_id]);

  useEffect(() => {
    if (!configuredBudget.current && config) { setBudgets(config.budget_limits?.defaults ?? config.budgets); configuredBudget.current = true; }
  }, [config]);
  useEffect(() => {
    active.current = true;
    return () => { active.current = false; uploadRequest.current?.abort(); };
  }, []);
  useEffect(() => {
    if (!selected) { setSnapshot(null); setLoading(false); return; }
    const abort = new AbortController();
    setLoading(true); setError(null); setSnapshot(null);
    const request = cached.current?.id === selected ? Promise.resolve(cached.current) : api<Snapshot>(`/snapshots/${selected}`, { signal: abort.signal });
    request.then((data) => {
      if (abort.signal.aborted) return;
      if (project && data.project_id !== project.id) throw new Error('所选 ZIP 不属于当前源码项目。');
      setSnapshot(data);
      setLoading(false);
    }).catch((exc) => { if (!abort.signal.aborted) { setLoading(false); setError(`源码快照读取失败：${errorText(exc)}`); } });
    return () => abort.abort();
  }, [selected, seed, snapshotRevision, project?.id]);

  const upload = async (file: File) => {
    if (starting || uploading || project) return;
    setAttachmentError(null); setError(null);
    if (!file.name.toLowerCase().endsWith('.zip')) { setAttachmentError('请选择项目源码 ZIP 压缩包。'); return; }
    if (file.size > 64 * 1024 * 1024) { setAttachmentError('ZIP 压缩包不能超过 64 MiB。'); return; }
    if (!file.size) { setAttachmentError('压缩包为空，请重新选择。'); return; }
    const abort = new AbortController();
    uploadRequest.current?.abort(); uploadRequest.current = abort;
    setUploading(true); setUploadName(file.name);
    try {
      const body = new FormData(); body.append('file', file);
      const created = await api<Snapshot>('/snapshots', { method: 'POST', body, signal: abort.signal });
      if (abort.signal.aborted) return;
      cached.current = created; setSnapshot(created); setSelected(created.id); onChanged();
    } catch (exc) { if (!abort.signal.aborted) setAttachmentError(`导入失败：${errorText(exc)}`); }
    finally { if (!abort.signal.aborted) { setUploading(false); setUploadName(''); } }
  };
  const remove = () => { uploadRequest.current?.abort(); setUploading(false); setUploadName(''); setSelected(null); setSnapshot(null); setAttachmentError(null); };
  const start = async () => {
    if (startLock.current || uploading || loading) return;
    setError(null);
    if (!snapshot || snapshot.id !== selected) { setError('请先上传或选择源码 ZIP。'); return; }
    const objective = task.objective.trim();
    if ([...objective].length < 8 || [...objective].length > 2000) { setError('审计任务需填写 8–2000 个字符。'); objectiveRef.current?.focus(); return; }
    if (!config?.configured) { setError('模型尚未配置完成，请在工作空间设置中检查连接。'); return; }
    startLock.current = true; setStarting(true);
    const generation = ++startGeneration.current;
    const sourceHash = window.location.hash;
    try {
      const run = await post<Run>('/runs', { snapshot_id: snapshot.id, budgets, task: startTask(task, objective) });
      if (active.current) {
        onChanged();
        if (startGeneration.current === generation && window.location.hash === sourceHash) onOpenRun(run.id);
      }
    } catch (exc) { if (active.current && startGeneration.current === generation) setError(`任务创建失败：${errorText(exc)}`); }
    finally {
      if (startGeneration.current === generation) { startLock.current = false; if (active.current) setStarting(false); }
    }
  };
  const stats = snapshot?.stats ?? {};
  const textCount = stats.text_files ?? snapshot?.files.filter((file) => file.kind === 'text' || (file.kind === undefined && !file.excluded)).length ?? 0;
  const busy = uploading || loading || starting;
  return <section className={`draft-workspace${project ? ' source-draft' : ''}${dragging ? ' is-dragging' : ''}`}
    onDragEnter={(event) => { if (!project && event.dataTransfer.types.includes('Files')) { event.preventDefault(); dragDepth.current += 1; setDragging(true); } }}
    onDragOver={(event) => { if (event.dataTransfer.types.includes('Files')) event.preventDefault(); }}
    onDragLeave={() => { dragDepth.current = Math.max(0, dragDepth.current - 1); if (!dragDepth.current) setDragging(false); }}
    onDrop={(event) => { event.preventDefault(); dragDepth.current = 0; setDragging(false); if (project) return; if (event.dataTransfer.files.length > 1) setAttachmentError('一次任务请选择一个项目 ZIP。'); else if (event.dataTransfer.files[0]) void upload(event.dataTransfer.files[0]); }}>
    {dragging && <div className="drop-overlay"><FileArchive size={38} /><strong>松开以导入源码 ZIP</strong><span>最大 64 MiB · 一个项目，一次审计</span></div>}
    <div className="draft-intro">
      {project && <a className="sources-back" href={sourceHref(project.id)}><ArrowLeft size={15} />{project.name} · 返回工作台</a>}
      <div className="welcome-symbol"><ShieldCheck size={30} /></div>
      <span className="eyebrow">YOUR CODE. YOUR EVIDENCE.</span>
      <h1>{project ? '基于已有源码，开始审计。' : seed ? '开始新的漏洞审计方向' : '选择源码，开始漏洞审计。'}</h1>
      <p>{project ? `审计归属于 ${project.name}，发现将累计到该源码项目。` : '选择完整项目 ZIP，定义漏洞审计目标。'}<br />本次任务固定使用下方所选的 ZIP 快照。</p>
      <div className="example-grid">{EXAMPLES.map((example, index) => <button type="button" key={example.title} className="example-card" disabled={busy} onClick={() => { setTask((value) => ({ ...value, objective: example.objective })); objectiveRef.current?.focus(); }}><span className="example-number">0{index + 1}</span><strong>{example.title}</strong><span>{example.description}</span><ArrowUp size={14} /></button>)}</div>
    </div>
    <div className="composer-wrap">
      {config && !config.configured && <div className="inline-notice"><span className="status-dot status-inconclusive" />模型尚未配置，上传后可前往<a href="#settings">设置</a>检查连接。</div>}
      <form className="composer" onSubmit={(event) => { event.preventDefault(); void start(); }} onKeyDown={(event) => { if (event.key === 'Enter' && (event.ctrlKey || event.metaKey) && !event.nativeEvent.isComposing) { event.preventDefault(); void start(); } }}>
        {project && <div className="source-draft-picker"><label>审计使用的 ZIP<select aria-label="选择源码 ZIP" disabled={busy} value={selected ?? ''} onChange={(event) => chooseSnapshot(event.target.value)}>{snapshots.map((row) => <option value={row.id} key={row.id}>{row.name} · {row.archive_sha256.slice(0, 12)} · {localDate(row.created_at)}</option>)}</select></label></div>}
        {(snapshot || uploading || loading) && <div className="attachment-card">
          <span className="attachment-icon">{uploading || loading ? <LoaderCircle size={23} className="spin" /> : <FileArchive size={23} />}</span>
          <span className="attachment-copy"><strong>{uploading ? uploadName : snapshot?.name ?? '读取源码快照…'}</strong><span>{uploading ? '上传并建立源码索引…' : loading ? '正在读取快照摘要…' : `${textCount} 个可读文件 · ${snapshot?.immutable ? '不可变快照' : '源码快照'}`}</span>
            {!uploading && !loading && snapshot && <span>ZIP SHA-256 · <span className="mono">{snapshot.archive_sha256.slice(0, 16)}</span> · 导入于 {localDate(snapshot.created_at)}</span>}
            {!uploading && !loading && snapshot?.project && <span className="faint small">
              项目 · {snapshot.project.name} · 已有 {snapshot.project.run_count} 次审计
              {snapshot.project_reused ? ' · 已归入现有项目' : ' · 新项目'}
            </span>}
          </span>
          {!busy && <span className="attachment-ready"><Check size={14} />就绪</span>}
          {!project && <button type="button" className="icon-button" disabled={starting} aria-label="移除附件" onClick={remove}><X size={16} /></button>}
        </div>}
        {attachmentError && <div className="composer-error" role="alert"><FileArchive size={16} /><span>{attachmentError}</span><button type="button" className="text-button" onClick={() => fileInput.current?.click()}>重新选择</button></div>}
        <div className="composer-fields">
          <label className="composer-field"><span>审计任务 <span className="faint">/ 你想查清什么</span></span><textarea ref={objectiveRef} aria-label="审计任务" rows={2} maxLength={4000} disabled={starting} value={task.objective} onChange={(event) => setTask((value) => ({ ...value, objective: event.target.value }))} placeholder="例如：追踪文件上传入口，检查是否存在任意文件写入路径…" /></label>
          <p className="field-hint">验收条件按平台默认要求冻结：结论需有原始源码行号证据、明确风险等级与触发条件。</p>
        </div>
        {error && <div className="composer-error" role="alert">{error}{selected && !snapshot && !loading && <button className="text-button" type="button" onClick={() => setSnapshotRevision((value) => value + 1)}>重试读取 ZIP</button>}</div>}
        <div className="composer-toolbar"><div className="composer-tools">
          <input ref={fileInput} type="file" className="sr-only" tabIndex={-1} aria-label="上传项目源码 ZIP" accept=".zip,application/zip,application/x-zip-compressed" disabled={busy} onChange={(event) => { const file = event.target.files?.[0]; if (file) void upload(file); event.target.value = ''; }} />
          {!project && <button type="button" className="tool-button" disabled={busy} onClick={() => fileInput.current?.click()} aria-label="上传源码 ZIP"><Paperclip size={18} /><span>添加源码</span></button>}
          <button type="button" className="icon-button" disabled={busy} aria-label="选择已有快照" title="选择已有快照" onClick={() => setDialog('snapshots')}><FolderOpen size={18} /></button>
          <span className="toolbar-divider" />
          <button type="button" className="tool-button" disabled={!snapshot || busy} onClick={() => setDialog('snapshot')}><FileCode2 size={17} /><span>快照{snapshot ? ` · ${textCount}` : ''}</span><ChevronDown size={12} /></button>
          <button type="button" className="icon-button" disabled={busy} aria-label="高级执行设置" title="高级执行设置" onClick={() => setDialog('options')}><SlidersHorizontal size={17} /></button>
        </div><button type="submit" className={`send-button${project ? ' source-start-button' : ''}`} disabled={busy || !config?.configured || !snapshot || snapshot.id !== selected} aria-label="开始审计">{starting ? <LoaderCircle size={19} className="spin" /> : <ArrowUp size={21} />}{project && <span>{starting ? '创建中…' : '开始审计'}</span>}</button></div>
      </form>
      <div className="composer-footnote"><span><ShieldCheck size={12} /> 源码只读审计 · 执行过程持久保存</span><span>Ctrl / ⌘ + Enter 发送</span></div>
    </div>
    {dialog === 'snapshots' && <Overlay title="选择已有源码快照" onClose={() => setDialog(null)}><div className="overlay-body snapshot-list">{!snapshots.length ? <div className="empty">还没有源码快照，请先上传完整项目 ZIP。</div> : snapshots.map((item) => <button type="button" className="snapshot-option" key={item.id} onClick={() => { chooseSnapshot(item.id); setSnapshotRevision((value) => value + 1); setAttachmentError(null); setDialog(null); }}><FileArchive size={22} /><span><strong>{item.name}</strong><small>{item.file_count} 个文件 · {localDate(item.created_at)} · {item.archive_sha256.slice(0, 12)}</small></span>{item.id === selected && <Check size={18} />}</button>)}</div></Overlay>}
    {dialog === 'snapshot' && snapshot && <Overlay title="项目快照摘要" onClose={() => setDialog(null)}><div className="overlay-body grid">
      <p className="small muted">整包快照即本次审计范围，包含依赖目录和其它语言文本；二进制文件只登记。Planner 按目标选择阅读方向。</p>
      <div className="stats-grid"><div className="panel stat"><strong className="stat-value">{stats.files ?? snapshot.files.length}</strong><span className="stat-label">快照文件</span></div><div className="panel stat"><strong className="stat-value">{textCount}</strong><span className="stat-label">可读文本</span></div><div className="panel stat"><strong className="stat-value">{stats.binary_files ?? 0}</strong><span className="stat-label">二进制文件</span></div></div>
      <LongContent label="语言分布" value={stats.languages ?? {}} />
      <p className="field-hint">依赖 / 生成目录 {stats.dependency_tree_files ?? 0} 个文件 · PHP 语法索引 {stats.php_files ?? 0} 个文件</p>
      {snapshot.warnings?.length > 0 && <Disclosure title={`导入告警（${snapshot.warnings.length}）`}><LongContent label="已保存的导入告警" value={snapshot.warnings.join('\n')} /></Disclosure>}
      {(snapshot.skipped_files?.length ?? 0) > 0 && <Disclosure title={`跳过的条目（${stats.skipped_count ?? snapshot.skipped_files?.length}）`}><LongContent label="跳过条目预览（最多 200 条）" value={snapshot.skipped_files} /></Disclosure>}
      <Disclosure title="快照文件清单"><div className="scope-list">{snapshot.files.slice(0, fileLimit).map((file) => <div key={file.path} className="scope-item"><FileCode2 size={14} /><span><span className="mono">{file.path}</span><small>{file.kind === 'binary' ? '二进制 · 不可读' : `${file.line_count} 行 · ${file.language ?? '文本'}`}{file.dependency_tree ? ' · 依赖 / 生成目录' : ''}</small></span></div>)}</div>{snapshot.files.length > fileLimit && <button type="button" className="btn" onClick={() => setFileLimit((value) => value + 100)}>加载更多 100 个文件</button>}</Disclosure>
      <LongContent label="归档 SHA256" value={snapshot.archive_sha256} />
    </div></Overlay>}
    {dialog === 'options' && <Overlay title="高级执行设置" onClose={() => setDialog(null)}><div className="overlay-body">
      <div className="settings-section-label"><Sparkles size={16} />Planner 与 worker</div><div className="form-grid">
        {([{ key: 'max_iterations', label: '每个动态任务最大尝试', min: 1, max: 8 }, { key: 'max_total_attempts', label: '共享总尝试上限', min: 1, max: 512 }, { key: 'max_planner_rounds', label: 'Planner 最大回合', min: 1, max: 128 }, { key: 'max_workers', label: '并发 worker', min: 1, max: 4 }] as const).map((field) => <label className="field" key={field.key}><span className="field-label">{field.label}</span><input type="number" min={field.min} max={field.max} value={task[field.key]} onChange={(event) => setTask((value) => ({ ...value, [field.key]: clamp(event.target.value, field.min, field.max) }))} /><span className="field-hint">{field.min}–{field.max}</span></label>)}
      </div><div className="settings-section-label"><SlidersHorizontal size={16} />每次 Planner / worker 回合的预算</div><div className="form-grid">
        {([{ key: 'responses', label: '模型响应次数', min: 1, max: 256 }, { key: 'tools', label: '工具调用次数', min: 0, max: 2048 }, { key: 'seconds', label: '墙钟时间（秒）', min: 30, max: 14400 }] as const).map((field) => <label className="field" key={field.key}><span className="field-label">{field.label}</span><input type="number" min={field.min} max={field.max} value={budgets[field.key]} onChange={(event) => setBudgets((value) => ({ ...value, [field.key]: clamp(event.target.value, field.min, field.max) }))} /><span className="field-hint">{field.min}–{field.max}</span></label>)}
      </div><p className="field-hint">预算按回合计算，所有 worker 共享总尝试上限。运行中可暂停并原样继续，目标与快照保持冻结。</p>
      <label className="checkbox option-checkbox"><input type="checkbox" checked={task.stop_on_achieved} onChange={(event) => setTask((value) => ({ ...value, stop_on_achieved: event.target.checked }))} /><span>目标达成后停止未开始的任务</span></label>
      <label className="checkbox option-checkbox"><input type="checkbox" checked={task.require_poc} onChange={(event) => setTask((value) => ({ ...value, require_poc: event.target.checked }))} /><span>目标达成时要求 POC</span></label>
    </div><div className="overlay-footer"><button type="button" className="btn btn-primary" onClick={() => setDialog(null)}>保存设置</button></div></Overlay>}
  </section>;
}
