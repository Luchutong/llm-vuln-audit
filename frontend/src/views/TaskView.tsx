import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, ArrowUp, Braces, Check, ChevronDown, Database, FileArchive, FileCode2, FolderOpen, LoaderCircle, Paperclip, ShieldCheck, SlidersHorizontal, Sparkles, Terminal, X, type LucideIcon } from 'lucide-react';
import { api, ApiError, errorText, post } from '../api';
import type { Budget, Config, PocMode, PocReadiness, Project, Run, Snapshot, SnapshotSummary, TaskSpec, WorkflowAllocation, WorkflowStage } from '../types';
import { draftRunLimits, draftWorkflowAllocation, FALLBACK_RUN_BOUNDS, POC_MODE_LABELS, pocReason, workflowLimitsIssue } from '../execution';
import '../execution.css';
import { localDate } from '../status';
import { sourceHref } from '../routes';
import { Overlay } from '../components/Overlay';
import { LongContent } from '../components/LongContent';
import { Disclosure } from '../components/Disclosure';
import { SourceViewer } from '../components/SourceViewer';
import { draftTask, taskForStart, taskWithPolicy, type CompletionPolicy } from '../taskDraft';

const EXAMPLES = [
  { title: '追踪危险数据流', description: '查找任意文件写入或危险上传漏洞', objective: '审计文件上传入口，查找可被外部输入触发的任意文件写入、路径穿越或危险文件上传漏洞。' },
  { title: '检查认证边界', description: '查找管理功能的认证与授权绕过', objective: '审计项目中的管理路由，查找无需认证或越权访问敏感管理功能的漏洞。' },
  { title: '查找配置缺陷', description: '检查会话与 Cookie 的可利用风险', objective: '审计会话与 Cookie 配置，查找可导致会话泄露、劫持或跨站请求风险的可利用配置缺陷。' },
];

/**
 * 分场景专属提示词（S-sqli / S-xss / S-cmd）。
 *
 * 统一版 P0/P1/P2 让一份 Prompt 同时判定 SQL 注入 / 反射型 XSS / 命令注入三类；这里补齐的是
 * 每个漏洞类型单独一份的"分场景"提示词。点击快捷填充后，整段会作为审计任务 objective 冻结进
 * 本次运行，Planner 与 worker 按该方向只追这一条漏洞线，而不是三线混在一起下结论。
 */
interface ScenarioPreset {
  key: 'sqli' | 'xss_r' | 'command_injection';
  label: string;
  description: string;
  icon: LucideIcon;
  objective: string;
}

const SCENARIO_PRESETS: ScenarioPreset[] = [
  {
    key: 'sqli',
    label: 'SQL 注入',
    description: 'S-sqli · 输入拼接进 SQL 结构',
    icon: Database,
    objective: `审计方向（S-sqli · SQL 注入分场景）：
在所选源码中只聚焦 SQL 注入这一类漏洞，逐一给出候选结论与可核对证据。

判定标准：
1. 写出「输入来源 → 传播路径 → 危险操作」完整三段链，每一段都落到原始文件的具体行号；任何一段无法在代码中指出，就不得判定为候选漏洞。
2. 只有外部输入被拼接进 SQL 语句结构（查询 / 表名 / 列名 / ORDER BY / LIMIT 等），而非仅作为参数绑定数据传入时，才构成注入；重点关注 mysqli_query、PDO::query 等直接执行拼接 SQL 的位置。
3. 逐条核对已有防护是否真正覆盖该输入路径：参数绑定（prepare/execute）、类型强制转换、白名单、mysqli_real_escape_string / addslashes 等；不能看到函数名就认为安全，要指出它为何仍可能被绕过或恰好只覆盖了部分路径。

输出要求：
- 每个候选漏洞附上原始行号区间，且必须是本次实际读过的代码。
- 写明触发条件：路由 / 入口、参数名、所需登录或配置前提、影响等级。
- 提供可直接运行的 POC：目标地址 + 正常输入 + 攻击输入 + 两者可观测差异（如数据库报错、盲注时间差、注入成功回显）。
- 无法确定时写明缺失上下文（例如危险操作在未读到的文件里），不要臆断。`,
  },
  {
    key: 'xss_r',
    label: '反射型 XSS',
    description: 'S-xss · 输入以可执行形式进入输出',
    icon: Braces,
    objective: `审计方向（S-xss · 反射型 XSS 分场景）：
在所选源码中只聚焦反射型 XSS 这一类漏洞，逐一给出候选结论与可核对证据。

判定标准：
1. 写出「输入来源 → 传播路径 → 输出点」完整三段链，每一段标注原始文件行号。
2. 判断输出上下文（HTML 正文 / 标签属性 / <script> / URL）与所用转义是否匹配；htmlspecialchars 未指定 ENT_QUOTES 与正确字符集、属性或 JS 上下文未按需编码，本身就是漏洞。
3. 仅"响应里出现了输入"不足以判定，必须说明输入是否以可执行形式落在这个上下文中（能否触发 <script>、事件属性、javascript: 等）。

输出要求：
- 每个候选漏洞附上原始行号区间。
- 写明触发条件与影响（执行任意脚本、窃取会话、钓鱼）。
- 提供可直接运行的 POC：正常输入 + 攻击输入 + 浏览器中可观测的差异（弹窗、写入 DOM、跳转等）。`,
  },
  {
    key: 'command_injection',
    label: '命令注入',
    description: 'S-cmd · 输入影响命令解释',
    icon: Terminal,
    objective: `审计方向（S-cmd · 命令注入分场景）：
在所选源码中只聚焦命令注入这一类漏洞，逐一给出候选结论与可核对证据。

判定标准：
1. 写出「输入来源 → 传播路径 → 命令执行点」完整三段链，每一段标注原始文件行号。
2. 判断输入落在命令的参数位置还是结构位置：shell_exec / system / exec / popen / proc_open / 反引号 直接拼接输入即属结构位置，风险最高。
3. 逐条核对 escapeshellarg / escapeshellcmd、白名单、强制类型转换等防护是否真正覆盖本路径；escapeshellarg 未加引号、参数顺序错位、注入点绕过等常见疏漏需明确指出。

输出要求：
- 每个候选漏洞附上原始行号区间。
- 写明触发条件与影响（执行任意命令、反弹 shell、任意文件读写）。
- 提供可直接运行的 POC：正常输入 + 攻击输入 + 命令执行结果的可观测差异（如输出内容、文件落地、外带请求）。`,
  },
];
function clamp(value: string, minimum: number, maximum: number) { return Math.max(minimum, Math.min(maximum, Math.trunc(Number(value) || minimum))); }
/** The three discovery-first stages share the run's response ceiling. */
const QUOTA_FIELDS = [
  { key: 'discovery', label: '源码规划与挖掘', min: 1 },
  { key: 'poc', label: 'POC 验证', min: 0 },
  { key: 'review', label: '验证复核与收束', min: 1 },
] as const satisfies readonly { key: WorkflowStage; label: string; min: number }[];
const sameQuota = (a: WorkflowAllocation, b: WorkflowAllocation) => a.discovery === b.discovery && a.poc === b.poc && a.review === b.review;
/** The start screen freezes one decision: what to audit.
 *
 * Acceptance is frozen by the server for the user's explicit coverage or goal mode.
 * The request omits that text instead of sending a second editable criterion; the
 * selected mode and baseline policy are sent explicitly and remain visible on the run.
 */
/** One source window the user picked from the snapshot dialog.  The window is appended
 * to the objective at submit time only, so the textarea keeps the preset comparison
 * (`task.objective === preset.objective`) intact and the scope stays visible as a chip. */
interface AuditScope { path: string; start: number; end: number }

function scopeSuffix(scope: AuditScope): string {
  return `\n\n重点审计范围：${scope.path}:${scope.start}-${scope.end}（优先核对所选行窗口及其直接关联的被包含文件；窗口之外若发现同一方向的可触发漏洞仍须上报。）`;
}

export function TaskView({ snapshots, config, seed, project, initialSnapshotId, onOpenRun, onChanged }: { snapshots: SnapshotSummary[]; config: Config | null; seed?: Run; project?: Project; initialSnapshotId?: string; onOpenRun: (runId: string) => void; onChanged: () => void }) {
  const [selected, setSelected] = useState<string | null>(initialSnapshotId ?? seed?.snapshot_id ?? null);
  const [snapshotRevision, setSnapshotRevision] = useState(0);
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [task, setTask] = useState<TaskSpec>(() => draftTask(seed?.task_spec ?? undefined));
  const [budgets, setBudgets] = useState<Budget>(seed?.budgets ?? config?.budget_limits?.defaults ?? config?.budgets ?? { responses: 24, tools: 96, seconds: 1800 });
  const [runLimits, setRunLimits] = useState<Budget>(() => draftRunLimits(seed, config));
  const [pocMode, setPocMode] = useState<PocMode>('off');
  const [quota, setQuota] = useState<WorkflowAllocation>(() => draftWorkflowAllocation(draftRunLimits(seed, config).responses, 'off'));
  const quotaEdited = useRef(false);
  const [readiness, setReadiness] = useState<PocReadiness | null>(null);
  const [readinessError, setReadinessError] = useState<string | null>(null);
  const [readinessLoading, setReadinessLoading] = useState(false);
  const [readinessRevision, setReadinessRevision] = useState(0);
  const [dialog, setDialog] = useState<'snapshots' | 'snapshot' | 'options' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fileLimit, setFileLimit] = useState(100);
  const [scope, setScope] = useState<AuditScope | null>(null);
  const [rangePath, setRangePath] = useState<string | null>(null);
  const [rangeStart, setRangeStart] = useState(1);
  const [rangeEnd, setRangeEnd] = useState(80);
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
    if (!configuredBudget.current && config) { setBudgets(config.budget_limits?.defaults ?? config.budgets); setRunLimits(draftRunLimits(seed, config)); configuredBudget.current = true; }
  }, [config]);
  // Untouched quotas follow the run ceiling; an edited split is the user's decision and
  // is only validated, never silently rewritten, when that ceiling changes.
  useEffect(() => {
    if (!quotaEdited.current) setQuota(draftWorkflowAllocation(runLimits.responses, pocMode));
  }, [runLimits.responses, pocMode]);
  // Turning POC off cannot strand a quota no stage may spend.
  useEffect(() => {
    if (pocMode !== 'off') return;
    setQuota((value) => value.poc ? { ...value, discovery: value.discovery + value.poc, poc: 0 } : value);
  }, [pocMode]);
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

  useEffect(() => {
    setReadiness(null); setReadinessError(null);
    if (!selected || pocMode === 'off') { setReadinessLoading(false); return; }
    const abort = new AbortController();
    setReadinessLoading(true);
    api<PocReadiness>(`/poc/readiness?snapshot_id=${encodeURIComponent(selected)}`, { signal: abort.signal })
      .then((value) => { if (!abort.signal.aborted) setReadiness(value); })
      .catch((exc) => { if (!abort.signal.aborted) setReadinessError(errorText(exc)); })
      .finally(() => { if (!abort.signal.aborted) setReadinessLoading(false); });
    return () => abort.abort();
  }, [selected, pocMode, readinessRevision]);

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
  const editQuota = () => { quotaEdited.current = true; };
  const resetQuota = () => { quotaEdited.current = false; setQuota(draftWorkflowAllocation(runLimits.responses, pocMode)); };
  const start = async () => {
    if (startLock.current || uploading || loading) return;
    setError(null);
    if (!snapshot || snapshot.id !== selected) { setError('请先上传或选择源码 ZIP。'); return; }
    const objective = task.objective.trim();
    if ([...objective].length < 8 || [...objective].length > 2000) { setError('审计任务需填写 8–2000 个字符。'); objectiveRef.current?.focus(); return; }
    if (!config?.configured) { setError('模型尚未配置完成，请在工作空间设置中检查连接。'); return; }
    if (pocMode === 'required' && (!readiness?.available || readinessLoading)) { setError('必须验证模式需要可用的自动验证环境，请先检查环境或选择其它模式。'); return; }
    const issue = workflowLimitsIssue(quota, runLimits.responses, pocMode);
    if (task.workflow_policy === 'discovery_first' && issue) { setError(`阶段请求配额：${issue}`); setDialog('options'); return; }
    startLock.current = true; setStarting(true);
    const generation = ++startGeneration.current;
    const sourceHash = window.location.hash;
    try {
      const payload = taskForStart(task, objective, scope ? scopeSuffix(scope) : '');
      if (payload.workflow_policy === 'discovery_first' && !sameQuota(quota, draftWorkflowAllocation(runLimits.responses, pocMode))) payload.workflow_limits = quota;
      const run = await post<Run>('/runs', { snapshot_id: snapshot.id, budgets, run_limits: runLimits, poc_mode: pocMode, task: payload });
      if (active.current) {
        onChanged();
        if (startGeneration.current === generation && window.location.hash === sourceHash) onOpenRun(run.id);
      }
    } catch (exc) {
      if (active.current && startGeneration.current === generation) {
        setError(`任务创建失败：${errorText(exc)}`);
        if (exc instanceof ApiError && exc.status === 409 && pocMode !== 'off') setReadinessRevision((value) => value + 1);
      }
    }
    finally {
      if (startGeneration.current === generation) { startLock.current = false; if (active.current) setStarting(false); }
    }
  };
  const stats = snapshot?.stats ?? {};
  const textCount = stats.text_files ?? snapshot?.files.filter((file) => file.kind === 'text' || (file.kind === undefined && !file.excluded)).length ?? 0;
  const sourceProject = snapshot?.project ?? project;
  const inheritedCount = snapshot?.project?.finding_counts?.total ?? project?.finding_counts?.total;
  const busy = uploading || loading || starting;
  const runBounds = config?.run_budget_limits ?? FALLBACK_RUN_BOUNDS;
  const automaticQuota = draftWorkflowAllocation(runLimits.responses, pocMode);
  const quotaAdjusted = !sameQuota(quota, automaticQuota);
  const quotaIssue = workflowLimitsIssue(quota, runLimits.responses, pocMode);
  const quotaTotal = quota.discovery + quota.poc + quota.review;
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
      <div className="example-grid">{EXAMPLES.map((example, index) => <button type="button" key={example.title} className="example-card" disabled={busy} onClick={() => { setTask((value) => ({ ...value, objective: example.objective, scenario: null })); objectiveRef.current?.focus(); }}><span className="example-number">0{index + 1}</span><strong>{example.title}</strong><span>{example.description}</span><ArrowUp size={14} /></button>)}</div>
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
          <label className="composer-field"><span>审计模式</span><select aria-label="审计模式" disabled={starting} value={task.completion_policy ?? 'goal'} onChange={(event) => setTask((value) => taskWithPolicy(value, event.target.value as CompletionPolicy))}><option value="coverage_review">全量覆盖复核 · 检查完整源码范围</option><option value="goal">快速目标审计 · 按目标达成收束</option></select></label>
          <p className="field-hint">{task.completion_policy === 'coverage_review' ? '全量模式会复核尚未覆盖的源码方向；发现漏洞后继续处理可执行任务。先源码挖掘，再分批验证并正式复核。达到预算仍会停止并保留已落库结果，不代表读完每行。' : '快速模式允许在目标达成后停止后续任务，适合检查一个明确风险或入口。'}</p>
          <label className="checkbox"><input type="checkbox" aria-label="使用已有漏洞作为审计线索" disabled={starting} checked={task.baseline_policy !== 'fresh'} onChange={(event) => setTask((value) => ({ ...value, baseline_policy: event.target.checked ? 'inherit' : 'fresh' }))} /><span>使用已有漏洞作为审计线索{inheritedCount !== undefined ? `（项目台账 ${inheritedCount} 条）` : ''}</span></label>
          <p className="field-hint">{task.baseline_policy === 'fresh' ? '本次从空白漏洞基线独立审计，不向 Agent 继承历史结论；项目台账与旧记录仍保留，新发现继续关联该源码项目。' : '本次会冻结项目已有漏洞作为线索，适合继续排查或复核既有结论。'}{sourceProject && <> <a href={sourceHref(sourceProject.id, 'findings')}>查看项目漏洞台账及清理入口</a></>}</p>
          <label className="composer-field"><span>审计任务 <span className="faint">/ 你想查清什么</span></span><textarea ref={objectiveRef} aria-label="审计任务" rows={2} maxLength={4000} disabled={starting} value={task.objective} onChange={(event) => setTask((value) => ({ ...value, objective: event.target.value, scenario: null }))} placeholder="例如：追踪文件上传入口，检查是否存在任意文件写入路径…" /></label>
          <div className="scenario-fill">
            <span className="scenario-fill-label"><Sparkles size={13} />分场景快捷填充</span>
            <div className="scenario-fill-options">
              {SCENARIO_PRESETS.map((preset) => (
                <button
                  key={preset.key}
                  type="button"
                  className={`scenario-chip${task.objective === preset.objective ? ' active' : ''}`}
                  disabled={starting}
                  title={`${preset.label} · ${preset.description}`}
                  onClick={() => { setTask((value) => ({ ...value, objective: preset.objective, scenario: preset.key })); objectiveRef.current?.focus(); }}
                >
                  <preset.icon size={14} />
                  {preset.label}
                </button>
              ))}
            </div>
          </div>
          <p className="field-hint">验收条件按所选模式冻结：{task.completion_policy === 'coverage_review' ? '结算可执行任务，并记录覆盖缺口或按路径给出跳过理由；' : '找到有证据支持的目标相关风险；'}结论需有原始源码行号证据与明确触发条件，CVSS 3.1 指标不足时保留待评分。{scope && <span className="scope-chip" title="提交时会拼进审计任务末尾"><span className="mono">{scope.path}:{scope.start}-{scope.end}</span><button type="button" className="icon-button" aria-label="移除重点范围" disabled={starting} onClick={() => setScope(null)}><X size={12} /></button></span>}</p>
        </div>
        {error && <div className="composer-error" role="alert">{error}{selected && !snapshot && !loading && <button className="text-button" type="button" onClick={() => setSnapshotRevision((value) => value + 1)}>重试读取 ZIP</button>}</div>}
        <div className="composer-toolbar"><div className="composer-tools">
          <input ref={fileInput} type="file" className="sr-only" tabIndex={-1} aria-label="上传项目源码 ZIP" accept=".zip,application/zip,application/x-zip-compressed" disabled={busy} onChange={(event) => { const file = event.target.files?.[0]; if (file) void upload(file); event.target.value = ''; }} />
          {!project && <button type="button" className="tool-button" disabled={busy} onClick={() => fileInput.current?.click()} aria-label="上传源码 ZIP"><Paperclip size={18} /><span>添加源码</span></button>}
          <button type="button" className="icon-button" disabled={busy} aria-label="选择已有快照" title="选择已有快照" onClick={() => setDialog('snapshots')}><FolderOpen size={18} /></button>
          <span className="toolbar-divider" />
          <button type="button" className="tool-button" disabled={!snapshot || busy} onClick={() => setDialog('snapshot')}><FileCode2 size={17} /><span>快照{snapshot ? ` · ${textCount}` : ''}</span><ChevronDown size={12} /></button>
          <button type="button" className="icon-button" disabled={busy} aria-label="高级执行设置" title="高级执行设置" onClick={() => setDialog('options')}><SlidersHorizontal size={17} /></button>
        </div><button type="submit" className={`send-button${project ? ' source-start-button' : ''}`} disabled={busy || !config?.configured || !snapshot || snapshot.id !== selected || (pocMode === 'required' && (!readiness?.available || readinessLoading))} aria-label="开始审计">{starting ? <LoaderCircle size={19} className="spin" /> : <ArrowUp size={21} />}{project && <span>{starting ? '创建中…' : '开始审计'}</span>}</button></div>
        <p className="field-hint">整次上限：模型 {runLimits.responses} 次 · 工具 {runLimits.tools} 次 · 活跃 {runLimits.seconds} 秒；POC：{POC_MODE_LABELS[pocMode]}。可在高级执行设置调整。</p>
        {task.workflow_policy === 'discovery_first' && <p className="field-hint" aria-label="阶段请求配额预览">阶段请求配额{quotaAdjusted ? '（自定义）' : '（自动）'}：源码挖掘 {quota.discovery} · POC 验证 {quota.poc} · 最终复核 {quota.review}（合计 {quotaTotal} / {runLimits.responses}）。{quotaIssue ? <span className="quota-warning" role="alert">{quotaIssue}</span> : '源码阶段提前完成的余额可转给验证，最终复核额度保留；实际配额以创建时的冻结结果为准。可在高级执行设置调整。'}</p>}
        {pocMode === 'required' && !readiness?.available && <p className="field-hint" role="status">{readinessLoading ? '正在检查必须验证所需环境…' : readinessError ? '自动验证环境检查失败，请重新检查或切换模式。' : pocReason(readiness?.reason, readiness?.message)}</p>}
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
      <Disclosure title="快照文件清单"><div className="scope-list">{snapshot.files.slice(0, fileLimit).map((file) => <div key={file.path} className="scope-item"><FileCode2 size={14} /><span><span className="mono">{file.path}</span><small>{file.kind === 'binary' ? '二进制 · 不可读' : `${file.line_count} 行 · ${file.language ?? '文本'}`}{file.dependency_tree ? ' · 依赖 / 生成目录' : ''}</small></span>{file.kind !== 'binary' && file.line_count > 0 && <button type="button" className="text-button" onClick={() => { setRangePath(file.path); setRangeStart(1); setRangeEnd(Math.min(file.line_count || 200, 200)); }}>选范围</button>}</div>)}</div>{snapshot.files.length > fileLimit && <button type="button" className="btn" onClick={() => setFileLimit((value) => value + 100)}>加载更多 100 个文件</button>}</Disclosure>
      {rangePath && <div className="scope-picker"><div className="scope-picker-head"><span className="mono">{rangePath}</span><label>起始行 <input type="number" min={1} max={9999} value={rangeStart} onChange={(event) => setRangeStart(Math.max(1, Math.trunc(Number(event.target.value) || 1)))} /></label><label>结束行 <input type="number" min={1} max={9999} value={rangeEnd} onChange={(event) => setRangeEnd(Math.max(1, Math.trunc(Number(event.target.value) || 1)))} /></label><button type="button" className="btn btn-primary" onClick={() => { const file = snapshot.files.find((row) => row.path === rangePath); const top = Math.min(rangeStart, rangeEnd); const bottom = Math.max(rangeStart, rangeEnd); setScope({ path: rangePath, start: top, end: Math.min(bottom, file?.line_count || bottom) }); setDialog(null); }}>把该范围填入审计任务</button></div><SourceViewer snapshotId={snapshot.id} path={rangePath} start={Math.max(1, Math.min(rangeStart, rangeEnd) - 10)} end={Math.min(rangeEnd + 10, Math.max(rangeEnd, 220))} highlight={[{ start_line: Math.min(rangeStart, rangeEnd), end_line: Math.max(rangeStart, rangeEnd) }]} height={260} /></div>}
      <LongContent label="归档 SHA256" value={snapshot.archive_sha256} />
    </div></Overlay>}
    {dialog === 'options' && <Overlay title="高级执行设置" onClose={() => setDialog(null)}><div className="overlay-body">
      <div className="settings-section-label"><Sparkles size={16} />Planner 与 worker</div><div className="form-grid">
        {([{ key: 'max_iterations', label: task.workflow_policy === 'discovery_first' ? '每任务无进展／失败重试上限' : '每个动态任务最大尝试', min: 1, max: 8 }, { key: 'max_total_attempts', label: '共享总尝试上限', min: 1, max: 512 }, { key: 'max_planner_rounds', label: 'Planner 最大回合', min: 1, max: 128 }, { key: 'max_workers', label: '并发 worker', min: 1, max: 4 }] as const).map((field) => <label className="field" key={field.key}><span className="field-label">{field.label}</span><input type="number" min={field.min} max={field.max} value={task[field.key]} onChange={(event) => setTask((value) => ({ ...value, [field.key]: clamp(event.target.value, field.min, field.max) }))} /><span className="field-hint">{field.min}–{field.max}</span></label>)}
      </div><div className="settings-section-label"><SlidersHorizontal size={16} />整次审计硬预算</div><div className="form-grid">
        {([{ key: 'responses', label: '整次模型请求上限' }, { key: 'tools', label: '整次工具调用上限' }, { key: 'seconds', label: '整次活跃时间（秒）' }] as const).map((field) => <label className="field" key={field.key}><span className="field-label">{field.label}</span><input type="number" min={runBounds.min[field.key]} max={runBounds.max[field.key]} value={runLimits[field.key]} onChange={(event) => setRunLimits((value) => ({ ...value, [field.key]: clamp(event.target.value, runBounds.min[field.key], runBounds.max[field.key]) }))} /><span className="field-hint">{runBounds.min[field.key]}–{runBounds.max[field.key]}</span></label>)}
      </div><p className="field-hint">Planner、侦察、worker 与 POC 共享整次额度。{task.workflow_policy === 'discovery_first' && '先完成源码挖掘，再每批最多验证两条并交给 Planner 正式复核；成功小批推进仍消耗共享总尝试，不占无进展重试。'}失败请求也计入消耗；暂停不重置预算，暂停后的静止时间不计入活跃时间。达到上限将自动结束为未完成，并保存阶段报告。</p>
      {task.workflow_policy === 'discovery_first' && <>
        <div className="settings-section-label"><SlidersHorizontal size={16} />阶段请求配额</div>
        <div className="form-grid">
          {QUOTA_FIELDS.map((field) => <label className="field" key={field.key}><span className="field-label">{field.label}</span><input type="number" min={field.min} max={runLimits.responses} value={quota[field.key]} disabled={field.key === 'poc' && pocMode === 'off'} aria-label={`${field.label}请求配额`} onChange={(event) => { editQuota(); setQuota((value) => ({ ...value, [field.key]: clamp(event.target.value, field.min, Math.max(field.min, runLimits.responses)) })); }} /><span className="field-hint">{field.min}–{runLimits.responses}</span></label>)}
        </div>
        <p className="field-hint">三段共用整次模型请求上限，合计 {quotaTotal} / {runLimits.responses}。少于上限的部分在创建时归入源码挖掘；POC 关闭时 POC 配额固定为 0，关闭前已留出的余额会并入源码挖掘。{quotaAdjusted ? '当前为自定义配额，创建时按此冻结。' : '当前为自动分配，创建时不提交自定义配额，由服务端按默认规则冻结。'}</p>
        {quotaIssue && <p className="field-hint quota-warning" role="alert">{quotaIssue}</p>}
        <button type="button" className="text-button" disabled={!quotaAdjusted} onClick={resetQuota}>恢复自动分配（{automaticQuota.discovery} / {automaticQuota.poc} / {automaticQuota.review}）</button>
      </>}
      <div className="settings-section-label"><SlidersHorizontal size={16} />单次 Planner / worker 执行预算</div><div className="form-grid">
        {([{ key: 'responses', label: '模型响应次数', min: 1, max: 256 }, { key: 'tools', label: '工具调用次数', min: 0, max: 2048 }, { key: 'seconds', label: '墙钟时间（秒）', min: 30, max: 14400 }] as const).map((field) => <label className="field" key={field.key}><span className="field-label">{field.label}</span><input type="number" min={field.min} max={field.max} value={budgets[field.key]} onChange={(event) => setBudgets((value) => ({ ...value, [field.key]: clamp(event.target.value, field.min, field.max) }))} /><span className="field-hint">{field.min}–{field.max}</span></label>)}
      </div><p className="field-hint">单次执行和整次审计均受限，先到达的上限生效。所有 worker 还共享总尝试上限，暂停继续保留全部消耗。</p>
      <label className="checkbox option-checkbox"><input type="checkbox" checked={task.stop_on_achieved} disabled={task.completion_policy === 'coverage_review'} onChange={(event) => setTask((value) => ({ ...value, stop_on_achieved: event.target.checked }))} /><span>目标达成后停止未开始的任务{task.completion_policy === 'coverage_review' ? '（全量覆盖复核时关闭）' : ''}</span></label>
      <div className="settings-section-label"><ShieldCheck size={16} />POC 自动验证</div>
      <label className="field"><span className="field-label">自动验证模式</span><select value={pocMode} onChange={(event) => setPocMode(event.target.value as PocMode)}><option value="off">关闭 · 仅源码审计</option><option value="auto">自动 · 环境可用时验证</option><option value="required">必须 · 需要验证后收束</option></select></label>
      <p className="field-hint">关闭时不启动 POC agent。自动模式环境不可用时跳过验证，源码结论仍保留为未验证；必须模式要求环境可用且结论已复现。</p>
      {pocMode !== 'off' && <div className="poc-readiness" role="status"><p>{readinessLoading ? '正在检查自动验证环境…' : readinessError ? `环境检查失败：${readinessError}` : readiness ? `${readiness.available ? '环境可用' : '环境不可用'}：${pocReason(readiness.reason, readiness.message)}` : '请先选择源码 ZIP。'}</p>{readiness && <span className="faint small">检查于 {localDate(readiness.checked_at)} · 浏览器验证{readiness.capabilities.browser ? '可用' : '不可用'}</span>}<button type="button" className="text-button" disabled={!selected || readinessLoading} onClick={() => setReadinessRevision((value) => value + 1)}>重新检查环境</button></div>}
      <label className="checkbox option-checkbox"><input type="checkbox" checked={task.require_poc} onChange={(event) => setTask((value) => ({ ...value, require_poc: event.target.checked }))} /><span>发现需附 POC 脚本（与自动验证独立）</span></label>
    </div><div className="overlay-footer"><button type="button" className="btn btn-primary" onClick={() => setDialog(null)}>保存设置</button></div></Overlay>}
  </section>;
}
