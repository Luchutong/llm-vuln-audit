import { useMemo, useState } from 'react';
import { downloadUrl } from '../api';
import type { Evidence, Finding, ProjectFinding, RunDetail, Verification, VerificationStatus } from '../types';
import { SourceViewer } from '../components/SourceViewer';
import { Disclosure } from '../components/Disclosure';
import { LongContent } from '../components/LongContent';
import { isVulnerabilityFinding, sourceObservations, vulnerabilityFindings } from '../results';
import { groupLedgerEvidence } from '../ledger';

const CATEGORY_LABELS: Record<string, string> = {
  sqli: 'SQL 注入',
  xss_r: '反射型 XSS',
  command_injection: '命令注入',
  task_goal: '漏洞候选',
};

function categoryLabel(category: string | null | undefined) {
  if (category?.startsWith('task_goal')) return '漏洞候选';
  return CATEGORY_LABELS[category ?? ''] ?? (category ? `任务类别：${category}` : '未标注类别');
}

function findingKindLabel(finding: Finding): string | null {
  if (!finding.finding_kind) return null;
  return `类型：${finding.finding_kind}`;
}

function isGenericSourceFinding(finding: Finding): boolean {
  return (finding.category.startsWith('task_goal') || Boolean(finding.finding_kind)) && !finding.poc;
}

function verdictLabel(finding: Finding, verdict: string | null | undefined): string {
  if (!isVulnerabilityFinding(finding)) {
    if (verdict === 'confirmed') return '确认结论';
    if (verdict === 'rejected') return '驳回结论';
    return '待定';
  }
  return VERDICT_LABELS[verdict ?? ''] ?? '未确定';
}

const EXECUTION_LABELS: Record<string, string> = {
  success: '执行成功，出现预期差异',
  syntax_error: '脚本语法错误',
  connection_failed: '无法连接目标',
  environment_mismatch: '环境不匹配',
  not_triggered: '执行成功但漏洞未触发',
  not_run: '未执行 / 仅静态阅读',
  other_error: '其他执行错误',
};

const VERDICT_LABELS: Record<string, string> = {
  confirmed: '确认漏洞',
  rejected: '排除（误报）',
  uncertain: '无法确定',
};

/** The POC agent's status is the current claim; a human verdict is history. */
export const VERIFICATION_LABELS: Record<VerificationStatus, string> = {
  verified: '已验证',
  rejected: '未通过',
  inconclusive: '未决',
  not_applicable: '不适用',
  environment_unavailable: '环境不可用',
  unverified: '未验证',
  stale: '结论已更新，待重新验证',
};

const VERIFICATION_HINTS: Record<VerificationStatus, string> = {
  verified: '隔离靶场中执行成功并复现了预期差异。',
  rejected: '隔离靶场执行成功，但未能复现；静态源码证据仍然保留，等待 Planner 更正。',
  inconclusive: '靶场未能给出决定性结果（脚本、观测或浏览器证据不足）。',
  not_applicable: '该项目不是受支持的 DVWA 环境，因此没有执行自动验证。',
  environment_unavailable: '隔离靶场不可用，本次没有执行自动验证。',
  unverified: '尚未执行自动验证；未验证不等于排除。',
  stale: '结论或证据已变更，之前的验证结果不再适用于当前版本。',
};

function verificationStatus(finding: Finding): VerificationStatus {
  return finding.verification_status ?? 'unverified';
}

function verificationChip(status: VerificationStatus): string {
  if (status === 'verified') return 'chip-verified';
  if (status === 'rejected') return 'chip-rejected';
  if (status === 'unverified' || status === 'not_applicable') return 'chip';
  return 'chip-inconclusive';
}

function verificationSummary(finding: Finding): string {
  const status = verificationStatus(finding);
  const verdict = finding.verification_verdict;
  return verdict ? `${VERIFICATION_LABELS[status]}（${verdict}）` : VERIFICATION_LABELS[status];
}

function recordSource(record: Verification): 'poc_agent' | 'legacy_human' {
  return record.source === 'poc_agent' ? 'poc_agent' : 'legacy_human';
}

/**
 * Disposition is the third axis, beside "did the citations hold up" and "does it
 * reproduce": whether the run still stands behind this conclusion. Nothing here is ever
 * deleted — a withdrawn conclusion keeps its row, its evidence and its human verdict,
 * because "this run changed its mind" is itself part of the record.
 */
const DISPOSITION_LABELS: Record<string, string> = {
  retracted: '已被 Planner 撤回',
  duplicate: '被 Planner 判为重复',
  superseded: '已被后续结论取代',
  contested: 'Planner 对人工结论存疑',
};

function dispositionLabel(finding: Finding): string | null {
  const disposition = finding.disposition ?? 'open';
  return disposition === 'open' ? null : DISPOSITION_LABELS[disposition] ?? disposition;
}

const SOURCE_CONTEXT_LINES = 4;
const MAX_SOURCE_WINDOW_LINES = 400;
const MAX_EVIDENCE_LINES_PER_WINDOW = MAX_SOURCE_WINDOW_LINES - SOURCE_CONTEXT_LINES * 2;

interface EvidenceWindow {
  start: number;
  end: number;
  highlights: Evidence[];
}

/**
 * Keep every source request below the API's 400-line limit. Most findings need one
 * window, but split widely separated or unusually large cited ranges without ever
 * rendering a line from one file under the path of another.
 */
function evidenceWindows(references: Evidence[]): EvidenceWindow[] {
  const chunks: Evidence[] = [];
  for (const reference of references) {
    for (let start = reference.start_line; start <= reference.end_line; start += MAX_EVIDENCE_LINES_PER_WINDOW) {
      chunks.push({
        ...reference,
        start_line: start,
        end_line: Math.min(reference.end_line, start + MAX_EVIDENCE_LINES_PER_WINDOW - 1),
      });
    }
  }
  chunks.sort((left, right) => left.start_line - right.start_line || left.end_line - right.end_line);

  const windows: EvidenceWindow[] = [];
  for (const reference of chunks) {
    const start = Math.max(1, reference.start_line - SOURCE_CONTEXT_LINES);
    const end = reference.end_line + SOURCE_CONTEXT_LINES;
    const previous = windows.at(-1);
    const combinedEnd = previous ? Math.max(previous.end, end) : end;

    if (previous && start <= previous.end + 1 && combinedEnd - previous.start + 1 <= MAX_SOURCE_WINDOW_LINES) {
      previous.end = combinedEnd;
      previous.highlights.push(reference);
    } else {
      windows.push({ start, end, highlights: [reference] });
    }
  }
  return windows;
}

function evidenceRangeLabel(references: Evidence[]): string {
  return references.map((reference) => `${reference.start_line}-${reference.end_line}`).join('、');
}

function auditUnitLocation(finding: Pick<Finding, 'file_path' | 'unit_start_line' | 'unit_end_line' | 'task_id' | 'task_key' | 'attempt'>): string {
  const source = finding.file_path ? `${finding.file_path}:${finding.unit_start_line}-${finding.unit_end_line}` : '';
  if (finding.task_id) {
    return `动态任务：${finding.task_key || finding.task_id.slice(0, 8)}${finding.attempt !== undefined ? ` · 第 ${finding.attempt} 次尝试` : ''}${source ? ` · 来源：${source}` : ''}`;
  }
  return source ? `审计单元：${source}` : '未提供审计单元；可展开下方源码引用。';
}

/**
 * Findings and their automatic verification.
 *
 * A vulnerability candidate is a claim, not a final result. POC-bearing candidates are
 * executed by the isolated POC agent; this view only reads back what it recorded, and
 * keeps any pre-migration human record visible as read-only history.
 */
export function FindingsView({ detail, snapshotId }: { detail: RunDetail; snapshotId: string }) {
  const [selected, setSelected] = useState<string | null>(null);

  const findings = vulnerabilityFindings(detail);
  const current = findings.find((finding) => finding.id === selected) ?? findings[0] ?? null;

  return (
    <div className="grid">
    <ProjectLedgerView detail={detail} />
    {!findings.length ? <div className="empty">这次运行尚无漏洞候选。排查记录单独列在下方。<br />没有候选不代表整个项目安全，请结合审计覆盖与缺失上下文判断。</div> : (
    <div className="finding-layout">
      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">漏洞候选</span>
          <span className="faint small">{findings.length}</span>
        </div>
        <div style={{ maxHeight: 620, overflowY: 'auto' }}>
          {findings.map((finding) => (
            <button
              key={finding.id}
              onClick={() => setSelected(finding.id)}
              aria-pressed={current?.id === finding.id}
              style={{
                display: 'block', width: '100%', textAlign: 'left', padding: '10px 14px',
                border: 'none', borderBottom: '1px solid var(--line-soft)', cursor: 'pointer',
                background: current?.id === finding.id ? 'var(--accent-soft)' : 'transparent',
              }}
            >
              <div className="row" style={{ flexWrap: 'wrap', marginBottom: 3 }}>
                <span className={`chip chip-${finding.validation_state}`}>
                  {finding.validation_state === 'candidate' ? '证据通过' : '证据不通过'}
                </span>
                <span className={`chip sev-${finding.severity}`}>{finding.severity}</span>
                <span className={verificationChip(verificationStatus(finding))}>{verificationSummary(finding)}</span>
                {dispositionLabel(finding) && <span className="chip chip-paused">{dispositionLabel(finding)}</span>}
                {finding.known_state === 'known' && <span className="chip">项目已有</span>}
                {finding.revision > 1 && <span className="chip">第 {finding.revision} 版</span>}
              </div>
              <div className="small disclosure-preview" style={{ fontWeight: 500 }}>{finding.title}</div>
              <div className="faint small">{categoryLabel(finding.category)}</div>
              {findingKindLabel(finding) && <div className="faint small">{findingKindLabel(finding)}</div>}
              <div className="mono faint disclosure-preview" style={{ fontSize: 11.5 }}>
                {auditUnitLocation(finding)}
              </div>
            </button>
          ))}
        </div>
      </div>

      {current && <FindingDetail key={current.id} finding={current} snapshotId={snapshotId} />}
    </div>
    )}
    <SourceObservationsView detail={detail} snapshotId={snapshotId} />
    </div>
  );
}

/**
 * The shared ledger this run reasoned over.
 *
 * A run's own findings are an attempt; the project ledger is what survives it. Listing
 * both here is what makes persistence visible: a conclusion discovered by an earlier
 * run still appears (as ``既有`` or ``沿用``), and a rediscovery is marked as such rather
 * than presented as a new finding.
 */
function ProjectLedgerView({ detail }: { detail: RunDetail }) {
  const project = detail.project;
  if (!project) return null;
  const ledger = detail.project_findings ?? [];
  const carried = detail.carried_findings ?? [];
  const carriedIds = new Set(carried.map((row) => row.id));
  const thisRun = new Set(
    (detail.findings ?? [])
      .map((finding) => finding.project_finding_id)
      .filter((id): id is string => Boolean(id)),
  );
  const counts = project.finding_counts;
  const summary = counts
    ? `${counts.total} 条记录 · ${counts.verified} 条已验证 · ${counts.environment_unavailable ?? 0} 条环境不可用 · ${counts.rejected} 条未通过`
    : `${ledger.length} 条记录`;
  const rows = ledger.length ? ledger : carried;

  const marker = (row: ProjectFinding) => {
    if (carriedIds.has(row.id)) return '沿用';
    if (thisRun.has(row.id)) return '本次';
    return '既有';
  };

  return <section className="panel" aria-label="项目台账">
    <div className="panel-head">
      <span className="panel-title">项目台账 · {project.name}</span>
      <span className="faint small">{summary}</span>
    </div>
    <div className="panel-body grid">
      <p className="small muted">
        项目按源码内容识别；同一份源码的后续审计沿用这里的结论，不会重复计为新发现。
        本次运行并入 <strong>{[...thisRun].length}</strong> 条，沿用 <strong>{carried.length}</strong> 条。
      </p>
      {carried.length > 0 && <Disclosure title={`本次沿用（${carried.length}）`}>
        {carried.map((row) => <div key={row.id} className="row" style={{ flexWrap: 'wrap', padding: '4px 0' }}>
          <span className={`chip sev-${row.severity}`}>{row.severity}</span>
          <a className="small" style={{ flex: 1 }} href={`#findings/${encodeURIComponent(row.id)}`}>{row.title}</a>
          <span className={verificationChip(row.verification_status)}>{VERIFICATION_LABELS[row.verification_status] ?? row.verification_status}</span>
          <span className="chip">沿用</span>
          <span className="mono faint small">{projectLocation(row)}</span>
        </div>)}
      </Disclosure>}
      <Disclosure title={`全部项目结论（${rows.length}）`}>
        {!rows.length ? <p className="small faint">项目台账尚无结论。</p> : rows.map((row) => <div key={row.id} className="row" style={{ flexWrap: 'wrap', padding: '4px 0', borderBottom: '1px solid var(--line-soft)' }}>
          <span className={`chip sev-${row.severity}`}>{row.severity}</span>
          <a className="small" style={{ flex: 1 }} href={`#findings/${encodeURIComponent(row.id)}`}>{row.title}</a>
          <span className={verificationChip(row.verification_status ?? 'unverified')}>
            {VERIFICATION_LABELS[row.verification_status ?? 'unverified'] ?? row.verification_status}
          </span>
          {row.revision > 1 && <span className="chip">第 {row.revision} 版</span>}
          <span className="chip">{marker(row)}</span>
          <span className="mono faint small">{projectLocation(row)}</span>
        </div>)}
      </Disclosure>
    </div>
  </section>;
}

/** The Planner's sentinel symbol is a ledger key, not a source location. */
function projectLocation(row: ProjectFinding): string {
  const symbol = row.symbol && row.symbol !== '<project>' ? `:${row.symbol}` : '';
  return `${row.file_path || '—'}${symbol}`;
}

/** Original source facts and prior human reviews stay readable without becoming vulnerabilities. */
export function SourceObservationsView({ detail, snapshotId }: { detail: RunDetail; snapshotId: string }) {
  const observations = sourceObservations(detail);
  return <section className="panel" aria-label="排查记录（非漏洞）">
    <div className="panel-head"><span className="panel-title">排查记录（非漏洞）</span><span className="faint small">{observations.length} 条</span></div>
    <div className="panel-body grid">
      <p className="small muted">源码行为、防护措施和未形成漏洞候选的结论保存在这里，不计入漏洞数量或漏洞目标达标结果。历史原文、源码引用、版本和人工记录均保留；历史任务状态沿用当时的判定。</p>
      {!observations.length ? <p className="small faint">尚无排查记录。</p> : <Disclosure title={`查看排查记录（${observations.length}）`}>
        {observations.map((observation) => <Disclosure key={observation.id} title={<span className="disclosure-heading"><span className="chip">排查记录</span><span className="disclosure-preview">{observation.title}</span></span>}>
          <FindingDetail finding={observation} snapshotId={snapshotId} observation />
        </Disclosure>)}
      </Disclosure>}
    </div>
  </section>;
}

export function FindingDetail({ finding, snapshotId, observation = false, pocDownloadPath, canonical = false }: { finding: Finding; snapshotId: string; observation?: boolean; pocDownloadPath?: string | null; canonical?: boolean }) {
  const poc = finding.poc;
  const evidenceKey = JSON.stringify(finding.evidence);
  const evidenceGroups = useMemo(() => groupLedgerEvidence(JSON.parse(evidenceKey) as Evidence[], snapshotId).map((group) => ({ ...group, windows: evidenceWindows(group.references) })), [evidenceKey, snapshotId]);
  const pocUrl = pocDownloadPath === undefined ? downloadUrl(`/findings/${finding.id}/poc`) : pocDownloadPath;
  const genericSourceFinding = isGenericSourceFinding(finding);
  return (
    <div className="grid">
      <section className="panel" aria-label={observation ? '排查记录详情' : canonical ? '漏洞台账详情' : '漏洞候选详情'}>
        <div className="panel-head">
          <div>
            <div className="panel-title">{finding.title}</div>
            <div className="faint small">{observation ? '排查记录' : categoryLabel(finding.category)}{finding.finding_kind ? ` · ${finding.finding_kind}` : ''}</div>
          </div>
          <div className="row" style={{ flexWrap: 'wrap' }}>
            {!canonical && finding.project_finding_id && <a className="btn" href={`#findings/${encodeURIComponent(finding.project_finding_id)}`}>查看源码包漏洞</a>}
            {!observation && <span className={`chip sev-${finding.severity}`}>{finding.severity}</span>}
            <span className={`chip chip-${finding.validation_state}`}>
              {observation ? (finding.validation_state === 'invalid_evidence' ? '引用不通过' : '排查依据') : finding.validation_state === 'candidate' ? '证据通过' : '证据不通过'}
            </span>
            <span className={verificationChip(verificationStatus(finding))}>{verificationSummary(finding)}</span>
            {dispositionLabel(finding) && <span className="chip chip-paused">{dispositionLabel(finding)}</span>}
            {finding.known_state === 'known' && <span className="chip">项目已有</span>}
            {finding.revision > 1 && <span className="chip">第 {finding.revision} 版</span>}
          </div>
        </div>
        <div className="panel-body grid">
          <p className="small muted">{observation ? '此记录用于追溯排查过程，不构成漏洞确认或项目安全保证。历史人工记录原样保留。' : '源码引用通过只表示证据可核验，漏洞是否成立还要看隔离靶场的自动验证结果。未验证不等于排除。'}</p>
          <LongContent value={auditUnitLocation(finding)} label="审计来源" />
          <LongContent value={finding.summary} label={observation ? '排查原文' : '分析依据'} />
          {observation && <Disclosure title="查看原始排查记录"><LongContent value={finding} label="原始排查记录" /></Disclosure>}
          {(finding.validation_errors ?? []).length > 0 && (
            <Disclosure title={`引用校验说明（${finding.validation_errors.length}）`}>
              <div className="error-box">
                {observation ? '此记录未形成有效漏洞候选，校验说明与原文保留供排查。' : finding.validation_state === 'candidate' ? '无法核实的引用已剔除，剩余引用支撑此候选。' : '引用全部无法核实，此候选不计入可信发现。'}
                <LongContent value={finding.validation_errors} label="引用校验问题" />
              </div>
            </Disclosure>
          )}
          <Disclosure title="数据流、前置条件与修复建议">
            <Chain label={genericSourceFinding ? '相关输入' : '输入来源'} value={finding.input_source} />
            <Chain label={genericSourceFinding ? '数据或控制流' : '传播路径'} value={finding.propagation} />
            <Chain label="敏感操作" value={finding.dangerous_operation} />
            <Chain label="边界或防护" value={finding.protection || '无'} />
            <Chain label="前置条件" value={(finding.preconditions ?? []).join('；') || '无'} />
            <Chain label="缺失上下文" value={(finding.missing_context ?? []).join('；') || '无'} />
            <Chain label="修复建议" value={finding.remediation} />
          </Disclosure>
        </div>
      </section>

      <section className="panel" aria-label={observation ? '排查依据源码' : '证据源码'}>
        <div className="panel-head">
            <span className="panel-title">{observation ? '排查依据源码' : '证据源码'}</span>
          <span className="faint small">{evidenceGroups.length} 个文件 · {finding.evidence.length} 处引用</span>
        </div>
        <div className="panel-body">
          {evidenceGroups.length === 0 ? <div className="empty">没有可显示的已验证证据行。</div> : evidenceGroups.map((group) => {
            const windows = group.windows;
            return (
              <Disclosure key={`${group.snapshotId}:${group.path}`} title={<span className="disclosure-heading"><span className="mono disclosure-preview">{group.path}</span><span className="faint small">{group.references.length} 处引用</span></span>}>
                <LongContent value={group.path} label="证据文件" />
                {canonical && <LongContent value={group.snapshotId || '来源快照缺失'} label="证据 ZIP 快照" />}
                <LongContent value={evidenceRangeLabel(group.references)} label="证据行" />
                {windows.map((window, windowIndex) => (
                  <Disclosure key={`${window.start}-${window.end}-${windowIndex}`} title={`查看源码 ${window.start}–${window.end} 行`}>
                    {group.snapshotId ? <SourceViewer snapshotId={group.snapshotId} path={group.path} start={window.start} end={window.end} highlight={window.highlights} height={280} /> : <p className="small muted">来源快照不可用，保留原始引用供追溯。</p>}
                  </Disclosure>
                ))}
              </Disclosure>
            );
          })}
        </div>
      </section>

      {poc && (
        <section className="panel" aria-label="POC 脚本">
          <div className="panel-head">
            <span className="panel-title">POC 脚本</span>
            {pocUrl && <a className="btn" href={pocUrl} download>下载 POC</a>}
          </div>
          <div className="panel-body">
            <Disclosure title={`查看 ${poc.filename}`}>
              <div className="grid detail-fields">
                <Chain label="正常输入（对照）" value={poc.normal_input} />
                <Chain label="攻击输入" value={poc.attack_input} />
                <Chain label="预期差异" value={poc.expected_result} />
                <Chain label="运行说明" value={poc.instructions} />
              </div>
              <LongContent value={poc.script} label="POC 脚本全文" />
            </Disclosure>
          </div>
        </section>
      )}

      <section className="panel" aria-label={observation ? '历史人工记录' : 'POC 自动验证'}>
        <div className="panel-head">
          <span className="panel-title">{observation ? '历史人工记录（只读）' : 'POC 自动验证'}</span>
          <span className={`chip ${verificationChip(verificationStatus(finding))}`}>{verificationSummary(finding)}</span>
        </div>
        <div className="panel-body grid">
          {!observation && <p className="small muted">
            {VERIFICATION_HINTS[verificationStatus(finding)]}
            {' '}自动验证由独立的 POC Agent 在隔离的 <code>poc-runner</code> 中对本地 DVWA 执行；平台不会在应用进程里运行上传的源码或 POC 脚本。
          </p>}
          {!observation && <AutomaticVerificationPanel finding={finding} />}
          <HistoricalVerificationPanel finding={finding} observation={observation} />
        </div>
      </section>
      <Lineage finding={finding} />
    </div>
  );
}

/** Archived revisions and the Planner's disposition never rewrite the evidence itself. */
function Lineage({ finding }: { finding: Finding }) {
  const disposition = dispositionLabel(finding);
  const archived = finding.superseded_summary ?? [];
  if (!disposition && (finding.revision ?? 1) <= 1 && !archived.length) return null;
  return <section className="panel" aria-label="结论沿革">
    <div className="panel-head"><span className="panel-title">结论沿革</span><span className="chip">第 {finding.revision ?? 1} 版</span></div>
    <div className="panel-body grid">
      {disposition && <div className="row"><span className="chip chip-paused">{disposition}</span><span className="small muted">撤回只改变结论状态，正文与证据保留</span></div>}
      <Disclosure title={`查看处置与历史版本（${archived.length}）`}>
        <Chain label="处置理由" value={finding.disposition_reason ?? ''} />
        <Chain label="标注者" value={finding.disposition_by === 'human' ? '人工' : finding.disposition_by === 'planner' ? 'Planner' : finding.disposition_by ?? ''} />
        <Chain label="处置时间" value={finding.disposition_at ?? ''} />
        <Chain label={finding.disposition === 'duplicate' ? '重复于' : '派生自'} value={finding.derived_from_finding_id ?? ''} />
        {archived.map((revision) => <Disclosure key={revision.revision} title={<span className="disclosure-heading"><span className="chip">第 {revision.revision} 版</span><span className="disclosure-preview">{revision.title}</span>{revision.disposition && revision.disposition !== 'open' && <span className="chip chip-paused">{DISPOSITION_LABELS[revision.disposition] ?? revision.disposition}</span>}</span>}>
          <Chain label="被取代时间" value={revision.replaced_at ?? ''} />
          <Chain label="历史标题" value={revision.title} />
          <Chain label="历史摘要" value={revision.summary} />
          <LongContent value={revision.evidence} label="历史源码引用" />
          <LongContent value={{ 严重性: revision.severity, 引用校验: revision.validation_state, 引用问题: revision.validation_errors, 处置: revision.disposition, 处置理由: revision.disposition_reason, 标注者: revision.disposition_by }} label="历史结论状态" />
        </Disclosure>)}
      </Disclosure>
    </div>
  </section>;
}

function Chain({ label, value }: { label: string; value: string }) {
  if (!value) return null;
  return <div className="field"><LongContent value={value} label={label} /></div>;
}

/**
 * The POC agent's record, read-only.
 *
 * Every line here comes from the host or the isolated runner, not from the model's
 * prose: the target it was prepared against, the job ids it actually ran, and the
 * artifacts it copied out. A finding with no automatic record is not concealed: the
 * status chip above and the counts here say "unverified" out loud.
 */
export function AutomaticVerificationPanel({ finding }: { finding: Finding }) {
  const records = (finding.verifications ?? []).filter((record) => recordSource(record) === 'poc_agent');
  if (!records.length) {
    return <p className="small faint">没有自动验证记录。未验证不等于排除：静态源码证据仍然成立。</p>;
  }
  return <div className="grid">
    {records.map((record, index) => {
      const status = (record.status ?? 'inconclusive') as VerificationStatus;
      const target = record.target ?? {};
      const jobs = record.agent?.jobs ?? [];
      const targetText = [target.name, target.base_url, target.security ? `security=${target.security}` : '', target.version]
        .filter(Boolean).join(' · ');
      return <Disclosure key={record.id ?? index} title={<span className="disclosure-heading">
        <span className={verificationChip(status)}>{VERIFICATION_LABELS[status] ?? status}</span>
        <span className="faint small">{record.created_at?.slice(0, 19).replace('T', ' ')}</span>
      </span>}>
        <div className="grid detail-fields">
          <Chain label="自动验证状态" value={verdictLabels(record.status, record.verdict)} />
          <Chain label="目标环境" value={targetText} />
          <Chain label="runner 作业" value={jobs.join('、')} />
          <Chain label="执行命令" value={record.command || ''} />
          <Chain label="攻击观测" value={record.attack_observation || ''} />
          <Chain label="对照观测" value={record.normal_observation || ''} />
          <Chain label="脚本适配与归因" value={record.modification_notes || ''} />
          <Chain label="备注" value={record.notes || ''} />
        </div>
        {record.modified_script && <Disclosure title="查看适配后的脚本">
          <LongContent value={record.modified_script} label="适配脚本全文" />
        </Disclosure>}
        <Artifacts record={record} />
      </Disclosure>;
    })}
  </div>;
}

/** Pre-migration records stay visible, under a label that says what they are. */
export function HistoricalVerificationPanel({ finding, observation }: { finding: Finding; observation: boolean }) {
  const records = (finding.verifications ?? []).filter((record) => recordSource(record) !== 'poc_agent');
  if (!records.length) {
    return observation ? <p className="small faint">没有历史人工记录。</p> : null;
  }
  return <Disclosure title={`历史人工记录（只读，${records.length}）`}>
    <p className="small muted">这些记录来自人工验证时代，只作为审计轨迹保留；它们不再决定当前结论。</p>
    {records.map((record, index) => (
      <Disclosure key={record.id ?? index} title={<span className="disclosure-heading">
        <span className="chip">{VERDICT_LABELS[record.verdict ?? ''] ?? record.verdict ?? '历史记录'}</span>
        <span className="faint small">{record.created_at?.slice(0, 19).replace('T', ' ')}</span>
      </span>}>
        <div className="small">{EXECUTION_LABELS[record.execution_status ?? ''] ?? record.execution_status}{record.browser_execution ? ' · 含浏览器执行证据' : ''}</div>
        <Chain label="目标环境或版本" value={record.target_version || ''} />
        <Chain label="执行命令" value={record.command || ''} />
        <Chain label="攻击观测" value={record.attack_observation || ''} />
        <Chain label="对照观测" value={record.normal_observation || ''} />
        <Chain label="改动说明" value={record.modification_notes || ''} />
        <Chain label="备注" value={record.notes || ''} />
        {observation && <LongContent value={record} label="历史人工记录原文" />}
        <Artifacts record={record} />
      </Disclosure>
    ))}
  </Disclosure>;
}

function verdictLabels(status: VerificationStatus | undefined, verdict: string | null | undefined): string {
  const label = VERIFICATION_LABELS[(status ?? 'inconclusive') as VerificationStatus] ?? status ?? '';
  return verdict ? `${label}（${verdict}）` : label;
}

function Artifacts({ record }: { record: Verification }) {
  const files = record.files ?? [];
  const artifacts = record.artifacts ?? [];
  if (!files.length && !artifacts.length) return null;
  return <div className="row small">
    <span>证据附件与运行产物：</span>
    {files.map((file, index) => {
      const item = typeof file === 'string' ? { name: file, url: '' } : file;
      const url = item.url ?? (item.stored ? `/api/evidence/${item.stored}` : '');
      return url
        ? <a key={`f-${index}`} className="btn" href={url} target="_blank" rel="noreferrer">{item.name ?? item.filename ?? '附件'}</a>
        : <span key={`f-${index}`} className="chip">{item.name ?? item.filename}</span>;
    })}
    {artifacts.map((artifact, index) => artifact.path ? (
      <a key={`a-${index}`} className="btn" href={`/api/evidence/${artifact.path}`} target="_blank" rel="noreferrer">
        {artifact.name ?? artifact.path}
      </a>
    ) : (
      <span key={`a-${index}`} className="chip">{artifact.name ?? '产物'}</span>
    ))}
  </div>;
}
