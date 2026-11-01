import { FINAL_REVIEW_PUBLISH_LABELS, FINAL_REVIEW_COUNT_LABELS } from '../finalReview';
import { displayCount, sumCounts } from '../runPresentation';
import { useFinalReview } from '../useFinalReview';
import { useCallback, useEffect, useState } from 'react';
import { api, errorText, post } from '../api';
import { scopeFileCount, scopeLabel } from '../types';
import type { RunDetail, Truth } from '../types';
import { Disclosure } from '../components/Disclosure';
import { LongContent } from '../components/LongContent';
import { PlannerNavigation } from './Overview';
import { SourceObservationsView, VERIFICATION_LABELS } from './FindingsView';
import { activeVulnerabilityFindings, vulnerabilityFindings } from '../results';
import { ExecutionStatus, HostSummary } from '../components/ExecutionStatus';
import { CvssPanel } from '../components/CvssPanel';
import { ratingLabel } from '../cvss';

const CATEGORY_LABELS: Record<string, string> = {
  sqli: 'SQL 注入',
  xss_r: '反射型 XSS',
  command_injection: '命令注入',
};

const ATTRIBUTION_LABELS: Record<string, string> = {
  false_positive: '误报（候选但人工排除）',
  false_negative: '漏报（真实存在但未报出）',
  unresolved: '未决（无法判定）',
};

interface ReportViewProps {
  runId: string;
  detail: RunDetail;
  onChanged: () => void;
}

/**
 * The normal workspace produces target tasks. Historical prompt experiments retain their
 * original report below so old records remain readable, while target tasks get a report
 * based on their frozen goal, queue history, and source evidence instead of a truth matrix.
 */
export function ReportView(props: ReportViewProps) {
  if (props.detail.run.task_spec) {
    // Planner runs carry a durable session/task graph.  Old goal-queue records
    // remain readable with their historical report instead of being rendered as
    // if they had Planner revisions and dynamic tasks.
    if (props.detail.planner || props.detail.tasks !== undefined) {
      return <TargetReportView detail={props.detail} />;
    }
    return <LegacyTargetReportView detail={props.detail} />;
  }
  return <LegacyReportView {...props} />;
}

function LegacyReportView({ runId, detail, onChanged }: ReportViewProps) {
  const { run, metrics, attributions } = detail;
  const findings = vulnerabilityFindings(detail);
  const projectMap = detail.project_map;
  const [truths, setTruths] = useState<Truth[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState({
    file_path: '',
    category: 'sqli',
    vulnerable: true,
    independently_verified: true,
    verification_basis: '',
  });
  const [attribution, setAttribution] = useState({
    file_path: '',
    category: 'sqli',
    kind: 'false_positive',
    cause: '',
    check_item: '',
    finding_id: '',
  });

  const loadTruths = useCallback(() => {
    api<Truth[]>(`/snapshots/${run.snapshot_id}/truths`)
      .then(setTruths)
      .catch((exc) => setError(errorText(exc)));
  }, [run.snapshot_id]);

  useEffect(() => { loadTruths(); }, [loadTruths]);

  const addTruth = async () => {
    try {
      // The endpoint replaces the snapshot's truth set rather than appending to it, so
      // the existing samples go back with the new one. A truth set is small and edited
      // as a whole; sending the whole thing is what keeps it that way.
      await post(`/snapshots/${run.snapshot_id}/truths`, { samples: [...(truths ?? []), draft] });
      setDraft({ ...draft, file_path: '', verification_basis: '' });
      loadTruths();
      onChanged();
    } catch (exc) {
      setError(errorText(exc));
    }
  };

  const addAttribution = async () => {
    try {
      await post(`/runs/${runId}/attributions`, {
        ...attribution,
        finding_id: attribution.finding_id || null,
      });
      setAttribution({ ...attribution, cause: '', check_item: '' });
      onChanged();
    } catch (exc) {
      setError(errorText(exc));
    }
  };

  const rejected = findings.filter((finding) => finding.verdict === 'rejected');
  const confirmed = findings.filter((finding) => finding.verdict === 'confirmed');
  const invalid = findings.filter((finding) => finding.validation_state !== 'candidate');

  return (
    <div className="grid">
      {error && <div role="alert" className="error-box">{error}</div>}

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">统计可复现性</span>
          <span className="faint small">同一快照、同一范围、同一模型、同一预算下可复算</span>
        </div>
        <div style={{ padding: '12px 16px' }} className="small">
          <div>快照 <span className="mono">{run.snapshot_id}</span>（{run.snapshot_name}）</div>
          <LongContent value={scopeLabel(run, projectMap)} label="冻结范围" />
          <div>
            历史 Prompt <span className="mono">{run.prompt_id}</span>
            {' · '}模型 <span className="mono">{run.model}</span> · 预算 <span className="mono">{JSON.stringify(run.budgets)}</span>
          </div>
          <div>Truth 状态：<span className={`chip ${metrics.truth_status === 'has_truth_set' ? 'chip-confirmed' : 'chip-pending'}`}>{metrics.truth_status}</span></div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">已知真实样本（真值集）</span>
          <span className="faint small">
            与 Agent 输入隔离：Agent 只看到代码，看不到这里
          </span>
        </div>
        <div style={{ padding: '12px 16px' }}>
          <Disclosure title={`查看真值集与录入样本（${truths?.length ?? 0}）`}>
          {truths && truths.length > 0 ? (
            <div className="table-scroll"><table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13, marginBottom: 12 }}>
              <thead>
                <tr style={{ color: 'var(--ink-soft)', fontSize: 12 }}>
                  <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>文件</th>
                  <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>类别</th>
                  <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>实际</th>
                  <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>独立核验</th>
                  <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>依据</th>
                </tr>
              </thead>
              <tbody>
                {truths.map((truth, index) => (
                  <tr key={index} style={{ borderTop: '1px solid var(--line-soft)' }}>
                    <td className="mono small" style={{ padding: '6px 8px' }}>{truth.file_path}</td>
                    <td style={{ padding: '6px 8px' }}>{CATEGORY_LABELS[truth.category]}</td>
                    <td style={{ padding: '6px 8px' }}>
                      <span className={`chip ${truth.vulnerable ? 'chip-candidate' : 'chip-no_candidate'}`}>
                        {truth.vulnerable ? '存在' : '不存在'}
                      </span>
                    </td>
                    <td style={{ padding: '6px 8px' }}>{truth.independently_verified ? '是' : '否'}</td>
                    <td className="small muted" style={{ padding: '6px 8px' }}><LongContent value={truth.verification_basis} label="核验依据" /></td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          ) : (
            <div className="small muted" style={{ marginBottom: 12 }}>
              还没有真实样本。没有它，召回率与漏报数不可计算。
            </div>
          )}

          <div className="grid form-grid">
            <label className="field">
              <span className="field-label">文件路径</span>
              <input type="text" className="mono" value={draft.file_path} placeholder="src/path/to/source.ext" onChange={(event) => setDraft({ ...draft, file_path: event.target.value })} />
            </label>
            <label className="field">
              <span className="field-label">类别</span>
              <select value={draft.category} onChange={(event) => setDraft({ ...draft, category: event.target.value })}>
                {Object.entries(CATEGORY_LABELS).map(([value, text]) => <option key={value} value={value}>{text}</option>)}
              </select>
            </label>
            <label className="field">
              <span className="field-label">实际</span>
              <select value={draft.vulnerable ? '1' : '0'} onChange={(event) => setDraft({ ...draft, vulnerable: event.target.value === '1' })}>
                <option value="1">存在漏洞</option>
                <option value="0">不存在</option>
              </select>
            </label>
            <label className="field">
              <span className="field-label">独立核验</span>
              <select value={draft.independently_verified ? '1' : '0'} onChange={(event) => setDraft({ ...draft, independently_verified: event.target.value === '1' })}>
                <option value="1">是</option>
                <option value="0">否</option>
              </select>
            </label>
            <label className="field">
              <span className="field-label">核验依据</span>
              <input type="text" value={draft.verification_basis} placeholder="例如：独立复现记录、代码评审编号或测试报告" onChange={(event) => setDraft({ ...draft, verification_basis: event.target.value })} />
            </label>
            <button className="btn btn-primary" onClick={addTruth} disabled={!draft.file_path}>录入样本</button>
          </div>
          </Disclosure>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">失败归因</span>
          <span className="faint small">每条误报 / 漏报都要能指到提示词里的哪一条</span>
        </div>
        <div style={{ padding: '12px 16px' }}>
          <Disclosure title={`查看归因与记录问题（${attributions.length}）`}>
          {attributions.length > 0 && (
            <div className="table-scroll"><table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13, marginBottom: 12 }}>
              <thead>
                <tr style={{ color: 'var(--ink-soft)', fontSize: 12 }}>
                  <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>类型</th>
                  <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>文件</th>
                  <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>类别</th>
                  <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>原因</th>
                  <th style={{ textAlign: 'left', padding: '6px 8px', fontWeight: 500 }}>对应检查项</th>
                </tr>
              </thead>
              <tbody>
                {attributions.map((item, index) => (
                  <tr key={item.id ?? index} style={{ borderTop: '1px solid var(--line-soft)' }}>
                    <td style={{ padding: '6px 8px' }}><span className="chip">{ATTRIBUTION_LABELS[item.kind] ?? item.kind}</span></td>
                    <td className="mono small" style={{ padding: '6px 8px' }}>{item.file_path}</td>
                    <td style={{ padding: '6px 8px' }}>{CATEGORY_LABELS[item.category]}</td>
                    <td className="small" style={{ padding: '6px 8px' }}><LongContent value={item.cause} label="归因原因" /></td>
                    <td className="small muted" style={{ padding: '6px 8px' }}><LongContent value={item.check_item} label="对应检查项" /></td>
                  </tr>
                ))}
              </tbody>
            </table></div>
          )}

          <div className="grid form-grid">
            <label className="field">
              <span className="field-label">类型</span>
              <select value={attribution.kind} onChange={(event) => setAttribution({ ...attribution, kind: event.target.value })}>
                {Object.entries(ATTRIBUTION_LABELS).map(([value, text]) => <option key={value} value={value}>{text}</option>)}
              </select>
            </label>
            <label className="field">
              <span className="field-label">文件路径</span>
              <input type="text" className="mono" value={attribution.file_path} onChange={(event) => setAttribution({ ...attribution, file_path: event.target.value })} />
            </label>
            <label className="field">
              <span className="field-label">类别</span>
              <select value={attribution.category} onChange={(event) => setAttribution({ ...attribution, category: event.target.value })}>
                {Object.entries(CATEGORY_LABELS).map(([value, text]) => <option key={value} value={value}>{text}</option>)}
              </select>
            </label>
            <label className="field">
              <span className="field-label">原因</span>
              <input type="text" value={attribution.cause} placeholder="例如：判据没有要求核对输出上下文" onChange={(event) => setAttribution({ ...attribution, cause: event.target.value })} />
            </label>
            <label className="field">
              <span className="field-label">对应检查项</span>
              <input type="text" value={attribution.check_item} placeholder="例如：三、漏洞判定标准 / 反射型 XSS 第 2 条" onChange={(event) => setAttribution({ ...attribution, check_item: event.target.value })} />
            </label>
            <label className="field">
              <span className="field-label">关联发现（可选）</span>
              <select value={attribution.finding_id} onChange={(event) => setAttribution({ ...attribution, finding_id: event.target.value })}>
                <option value="">不关联</option>
                {findings.map((finding) => (
                  <option key={finding.id} value={finding.id}>
                    [{CATEGORY_LABELS[finding.category]}] {finding.file_path.split('/').pop()}:{finding.line}
                  </option>
                ))}
              </select>
            </label>
            <button className="btn btn-primary" onClick={addAttribution} disabled={!attribution.file_path}>记录</button>
          </div>
          </Disclosure>
        </div>
      </div>

      <SourceObservationsView detail={detail} snapshotId={run.snapshot_id} />
      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">本次运行的问题清单</span>
        </div>
        <div style={{ padding: '12px 16px' }}>
          <div className="small">
            <div>证据不通过的候选：<strong>{invalid.length}</strong> 条，不计入可信发现。</div>
            <div>人工排除的发现：<strong>{rejected.length}</strong> 条，计入假阳性并需要归因。</div>
            <div>人工确认的候选：<strong>{confirmed.length}</strong> 条。</div>
            <div>未完成单元：<strong>{metrics.incomplete_units}</strong> 个，单独列出，不作为阴性结果。</div>
          </div>
        </div>
      </div>
    </div>
  );
}

const TARGET_RUN_STATUS_LABELS: Record<string, string> = {
  completed: '目标已达成',
  unreachable: '目标不可达',
  inconclusive: '目标未决',
  failed: '运行失败',
  cancelled: '运行已取消',
  interrupted: '运行已中断',
};

const TARGET_WORK_STATE_LABELS: Record<string, string> = {
  open: '排队中',
  running: '执行中',
  done: '已完成',
  exhausted: '轮次耗尽',
  blocked: '受阻',
  skipped: '已跳过',
};

const TARGET_GOAL_STATUS_LABELS: Record<string, string> = {
  open: '待达成',
  met: '已达成',
  unreachable: '不可达',
  inconclusive: '未决',
};

function sourceReferences(detail: RunDetail['findings'][number]) {
  if (detail.evidence.length === 0) return '无可核验源码引用';
  return detail.evidence.map((reference) => `${reference.path}:${reference.start_line}-${reference.end_line}`).join('、');
}

function ReportFindings({ detail }: Pick<ReportViewProps, 'detail'>) {
  const findings = vulnerabilityFindings(detail);
  const valid = findings.filter((finding) => finding.validation_state === 'candidate').length;
  return (
    <>
    <section className="panel" aria-label="报告漏洞候选">
      <div className="panel-head"><span className="panel-title">漏洞候选与源码证据</span><span className="faint small">{valid} 条引用通过 · {findings.length - valid} 条无效记录</span></div>
      <div className="panel-body">
        {findings.length === 0 ? <div className="empty">尚无漏洞候选。请结合排查记录、审计覆盖与缺失上下文判断当前结果。</div> : <Disclosure title={`查看报告漏洞候选（${findings.length}）`}>
          {findings.map((finding) => (
            <Disclosure key={finding.id} title={<span className="disclosure-heading"><span className={`chip chip-${finding.validation_state}`}>{finding.validation_state === 'candidate' ? '引用通过' : '引用不通过'}</span><span className="disclosure-preview">{finding.title}</span></span>}>
              <div className="grid">
                <div className="small">{finding.finding_kind || finding.category || '源码观察'} · {ratingLabel(finding)} · {finding.verification_status ? `自动验证：${VERIFICATION_LABELS[finding.verification_status] ?? finding.verification_status}` : finding.verdict ? `历史人工结论：${finding.verdict}` : '自动验证：待验证'}</div>
                <CvssPanel finding={finding} />
                <LongContent value={finding.summary} label="发现摘要" />
                <LongContent value={{ 引用校验: finding.validation_state, 自动验证: finding.verification_status ? VERIFICATION_LABELS[finding.verification_status] ?? finding.verification_status : '未验证', 验证结论: finding.verification_verdict, 结论处置: finding.disposition ?? 'open', 处置理由: finding.disposition_reason, 标注者: finding.disposition_by, 版本: finding.revision ?? 1, 派生自: finding.derived_from_finding_id }} label="结论的独立状态" />
                {(finding.superseded_summary ?? []).length > 0 && <Disclosure title={`历史结论（${finding.superseded_summary.length}）`}><LongContent value={finding.superseded_summary} label="历史版本与引用" /></Disclosure>}
                <LongContent value={sourceReferences(finding)} label="源码引用" />
                <LongContent value={finding.missing_context} label="缺失上下文" />
              </div>
            </Disclosure>
          ))}
        </Disclosure>}
      </div>
    </section>
    <SourceObservationsView detail={detail} snapshotId={detail.run.snapshot_id} />
    </>
  );
}

function TargetReportView({ detail }: Pick<ReportViewProps, 'detail'>) {
  const { run, metrics } = detail;
  const projectMap = detail.project_map;
  const task = run.task_spec;
  const goal = detail.goal ?? detail.goals?.[0];
  const planner = detail.planner;
  const plans = detail.plans ?? [];
  const tasks = detail.tasks ?? [];
  const usedAttempts = tasks.reduce((total, item) => total + item.attempts, 0);
  if (!task) return null;

  return (
    <div className="grid">
      <section className="panel" aria-label="项目级审计报告">
        <div className="panel-head"><span className="panel-title">项目级审计报告</span><span className={`chip chip-${run.status}`}>{TARGET_RUN_STATUS_LABELS[run.status] ?? run.status}</span></div>
        <div className="panel-body grid">
          <div className="grid detail-fields">
            <div className="field"><LongContent value={task.objective} label="报告审计目标" /></div>
            <div className="field"><LongContent value={task.success_criteria} label="报告验收条件" /></div>
            <div className="field"><span className="field-label">规划与执行预算</span><span className="small">{task.orchestration_policy === 'host-queue-v1' ? '宿主按需调度 · 统一终审 · 按整次预算' : `Planner ${planner?.current_round ?? 0}/${planner?.max_rounds ?? task.max_planner_rounds} 回合`} · worker {usedAttempts}/{task.max_total_attempts} 次</span></div>
            <div className="field"><LongContent value={goal?.terminal_reason ?? planner?.terminal_reason ?? '尚未收束'} label="报告运行结论" /></div>
          </div>
          <p className="small muted">报告覆盖本次冻结的 {scopeFileCount(run, projectMap)} 个可读文本文件。受阻或预算耗尽仍保留为未决结果。</p>
          <Disclosure title="运行参数与冻结范围"><LongContent value={{ 快照: run.snapshot_id, 名称: run.snapshot_name, 模型: run.model, 预算: run.budgets, 用量: run.usage, 范围: scopeLabel(run, projectMap), 显式文件列表: run.scope, 模型档案: run.model_profile }} label="运行参数与冻结范围" /></Disclosure>
        </div>
      </section>

      <FinalReviewPanel runId={run.id} status={run.status} />
      <ExecutionStatus detail={detail} />
      <HostSummary detail={detail} />
      {detail.report_narrative && <section className="panel"><div className="panel-head"><span className="panel-title">Planner 历史叙述</span><span className="faint small">以宿主最终事实为准</span></div><div className="panel-body"><LongContent label="Planner 已提交叙述" value={detail.report_narrative} /></div></section>}

      <section className="panel" aria-label="Planner 版本记录">
        <div className="panel-head"><span className="panel-title">Planner 版本记录</span><span className="faint small">{plans.length} 个版本</span></div>
        <div className="panel-body">
          {plans.length === 0 ? <div className="empty">尚无 Planner 回合。</div> : <Disclosure title={`查看版本记录（${plans.length}）`}>
            {plans.map((plan) => <Disclosure key={plan.id} title={`第 ${plan.round_no} 回合 · ${plan.task_snapshot.length} 个任务`}>
              <LongContent value={plan.basis_summary || '—'} label="调度依据" />
              <LongContent value={plan.next_action || '—'} label="下一步" />
              <LongContent value={plan.task_snapshot} label="任务快照" />
              {plan.error && <LongContent value={plan.error} label="错误" />}
            </Disclosure>)}
          </Disclosure>}
        </div>
      </section>

      <section className="panel" aria-label="动态任务与尝试">
        <div className="panel-head"><span className="panel-title">动态任务与尝试</span><span className="faint small">已结算 {metrics.terminal_tasks ?? 0}/{metrics.total_tasks ?? tasks.length}</span></div>
        <div className="panel-body">
          {tasks.length === 0 ? <div className="empty">尚未创建动态任务。</div> : <Disclosure title={`查看任务结果（${tasks.length}）`}>
            {tasks.map((item) => <Disclosure key={item.id} title={<span className="disclosure-heading"><span className={`chip chip-${item.state}`}>{item.state}</span><span className="disclosure-preview">{item.title}</span><span className="faint small">{item.attempts}/{item.max_attempts} 次</span></span>}>
              <LongContent value={item.task_key} label="任务标识" />
              <LongContent value={item.objective} label="任务目标" />
              <LongContent value={item.result?.summary ?? item.error ?? '—'} label="结果摘要" />
              <LongContent value={item.attempt_history ?? []} label="尝试历史" />
            </Disclosure>)}
          </Disclosure>}
        </div>
      </section>
      <PlannerNavigation detail={detail} />
      <ReportFindings detail={detail} />
      <ReviewSummary detail={detail} />
    </div>
  );
}

/**
 * The page, Markdown, JSON and evidence ZIP are four views of one frozen fact package.
 * This panel reads ``/final-review`` itself so the numbers on screen are the host's
 * canonical counts, not a second computation over the mutable finding list.
 */
function FinalReviewPanel({ runId, status }: { runId: string; status: string }) {
  const { facts, state, error, retry } = useFinalReview(runId, status);
  if (state === 'missing') return <p className="small muted">历史运行未保存冻结终审事实，以下为原审计记录。</p>;
  if (state === 'error') return <p role="status">终审事实读取失败：{error} <button className="text-button" onClick={retry}>重试终审读取</button></p>;
  if (!facts) return <p className="small muted">正在读取宿主冻结事实…</p>;
  if (!facts.counts || !facts.coverage?.files || !facts.coverage?.directions || !facts.coverage?.verification || !facts.quality_result) return <p className="small muted">终审事实部分字段暂无数据，可下载报告查看已保存内容。</p>;
  const counts = facts.counts;
  const quality = facts.quality_result;
  const coverage = facts.coverage;
  const dimensions = facts.run_outcome?.dimensions;
  const accepted = (facts.canonical_findings ?? []).filter((item) => item.final_disposition === 'accepted');
  const conflicts = (facts.canonical_findings ?? []).flatMap((item) => (item.conflicts ?? []).map((conflict) => ({ canonical_id: item.canonical_id, title: item.frozen_claim.title, ...conflict })));
  return <section className="panel" aria-label="终审事实包">
    <div className="panel-head"><span className="panel-title">终审事实包</span><span className="chip">{FINAL_REVIEW_PUBLISH_LABELS[quality.publishability] ?? quality.publishability ?? '暂无数据'}</span></div>
    <div className="panel-body grid">
      <div className="grid detail-fields">
        {(Object.keys(FINAL_REVIEW_COUNT_LABELS) as Array<keyof typeof FINAL_REVIEW_COUNT_LABELS>).map((key) => <div className="field" key={key}><span className="field-label">{FINAL_REVIEW_COUNT_LABELS[key]}：{displayCount(counts[key])}</span></div>)}
      </div>
      <p className="small muted">
        {quality.report_kind === 'final' ? '完整终审' : '阶段报告'} · 文件读取 {displayCount(coverage.files.read)}/{displayCount(coverage.files.total)}、复核 {displayCount(coverage.files.reviewed)}、跳过 {displayCount(coverage.files.skipped)} · 必做方向结算 {displayCount(sumCounts(coverage.directions.resolved, coverage.directions.skipped))}/{displayCount(coverage.directions.required ?? coverage.directions.total)} · 后续建议 {displayCount(coverage.directions.advisory)} · 动态验证 {displayCount(coverage.verification.verified)}/{displayCount(coverage.verification.total)} · 撤回 {displayCount(counts.withdrawn)} 条历史记录。
      </p>
      {dimensions && <div className="grid small" aria-label="冻结完成性维度"><p>目标关联{dimensions.focus_complete ? '已结算' : '未完成'} · 源码复核{dimensions.source_review_complete ? '已结算' : '未完成'} · 风险义务{dimensions.risk_obligations_complete ? '已结算' : '未完成'} · 独立终审{dimensions.final_review_complete ? '已结算' : '未完成'}</p><p>动态验证：{dimensions.dynamic_verification.mode === 'off' ? '未启用' : dimensions.dynamic_verification.mode === 'auto' ? '可选执行' : dimensions.dynamic_verification.requirement_met ? '已满足至少一条兼容验证' : '尚未满足至少一条兼容验证'}。交付材料{dimensions.delivery_readiness.complete ? '完整' : '仍需补充'}。</p>{!dimensions.delivery_readiness.complete && <Disclosure title="修复与复测材料待办">{dimensions.delivery_readiness.gaps.map(gap => <p key={gap.canonical_id}>{gap.items.join('；')}</p>)}</Disclosure>}</div>}
      {facts.review_batch && <p className="small muted">
        逐项终审已处置 {displayCount(facts.review_batch.decisions?.length)}/{displayCount(facts.review_batch.item_refs?.length)}
        {' · '}{facts.provenance?.immutable ? '正式报告已冻结，后续发现修改不会改变此版本' : '当前为未冻结视图'}
      </p>}
      {!!facts.review_batches?.batches?.length && <Disclosure title="整合与终审批次历史">
        {facts.review_batches.batches.map((batch) => <div key={batch.id} className="small">
          {batch.phase === 'final' ? '终审' : '按需整合'} · {batch.id.slice(0, 8)} · 已处置 {displayCount(batch.decisions?.length)}/{displayCount(batch.items?.length)}
          {' · '}{({ completed: '已完成', pending: '待审查', stale: '输入已更新', deferred: '本阶段未完成' } as Record<string, string>)[batch.status] ?? batch.status}
        </div>)}
      </Disclosure>}
      {quality.failed_checks?.length > 0 && <p className="small">发布门禁未通过：{quality.failed_checks.join('、')}</p>}
      {conflicts.length > 0 && <Disclosure title={`冲突结论（${conflicts.length}）`}>
        {conflicts.map((conflict) => <LongContent key={`${conflict.canonical_id}-${conflict.kind}`} label={`${conflict.title} · ${conflict.kind}`} value={conflict.detail} />)}
      </Disclosure>}
      {accepted.length > 0 && <Disclosure title={`已接受漏洞（${accepted.length}）`}>
        {accepted.map((item) => <div key={item.canonical_id} className="small">
          <strong>{item.frozen_claim.title}</strong>
          {item.final_batch_review?.focus && <span className="chip">{({ relevant: '目标相关', supporting: '必要辅助链', incidental: '附带发现', unresolved: '相关性待判断' } as Record<string, string>)[item.final_batch_review.focus.relation] ?? '相关性待判断'}</span>}
          <span className="faint"> · {item.frozen_claim.file_path}:{item.frozen_claim.primary_location?.line ?? '—'} · CVSS {item.frozen_claim.cvss?.base_score ?? '—'}</span>
        </div>)}
      </Disclosure>}
      {facts.action_items?.length > 0 && <Disclosure title={`补证与复核动作（${facts.action_items?.length}）`}>
        {facts.action_items.map((item, index) => <LongContent key={`${item.kind}-${item.object}-${index}`} label={item.title || item.kind} value={item.action || item.detail || item.object} />)}
      </Disclosure>}
      {!!facts.advisory_directions?.length && <Disclosure title={`后续建议（${facts.advisory_directions.length}，不阻止收束）`}>
        {facts.advisory_directions.map((item) => <LongContent key={item.id} label={item.id} value={item.text} />)}
      </Disclosure>}
    </div>
  </section>;
}

function ReviewSummary({ detail }: Pick<ReportViewProps, 'detail'>) {
  const candidates = activeVulnerabilityFindings(detail);
  const verified = candidates.filter((finding) => finding.verification_status === 'verified').length;
  const rejected = candidates.filter((finding) => finding.verification_status === 'rejected').length;
  const pending = candidates.filter((finding) => !finding.verification_status || ['unverified', 'stale', 'inconclusive', 'environment_unavailable', 'not_applicable'].includes(finding.verification_status)).length;
  return <section className="panel" aria-label="POC 自动验证清单">
    <div className="panel-head"><span className="panel-title">POC 自动验证</span><span className="faint small">由隔离 runner 在 Lab30 商城 靶场执行</span></div>
    <div className="panel-body small">自动验证通过 {verified} 条 · 未通过 {rejected} 条 · 未验证或环境不可用 {pending} 条。未验证不等于排除；执行记录与产物见「发现与验证」。</div>
  </section>;
}

/** Historical target queue report retained only for old stored runs. */
function LegacyTargetReportView({ detail }: Pick<ReportViewProps, 'detail'>) {
  const { run, units = [] } = detail;
  const projectMap = detail.project_map;
  const task = run.task_spec;
  const goals = detail.goals ?? [];
  const workItems = detail.work_items ?? [];
  const unitById = new Map(units.map((unit) => [unit.id, unit]));
  const finished = workItems.filter((item) => ['done', 'exhausted', 'blocked', 'skipped'].includes(item.state));
  const usedAttempts = workItems.reduce((total, item) => total + item.attempt, 0);
  if (!task) return null;

  return (
    <div className="grid">
      <section className="panel" aria-label="历史目标审计报告">
        <div className="panel-head"><span className="panel-title">目标审计报告</span><span className={`chip chip-${run.status}`}>{TARGET_RUN_STATUS_LABELS[run.status] ?? run.status}</span></div>
        <div className="panel-body grid">
          <div className="grid detail-fields">
            <div className="field"><LongContent value={task.objective} label="报告审计目标" /></div>
            <div className="field"><LongContent value={task.success_criteria} label="报告验收条件" /></div>
            <div className="field"><span className="field-label">冻结范围</span><span className="small">{scopeLabel(run, projectMap)}</span></div>
            <div className="field"><span className="field-label">执行预算</span><span className="small">每项 {task.max_iterations} 轮 · 总计 {usedAttempts}/{task.max_total_attempts} 次 · 最多 {task.max_workers} 个 worker</span></div>
          </div>
          <p className="small muted">此报告记录当次目标队列结果；受阻或预算耗尽仍保留为未决结果。</p>
          <Disclosure title="运行参数与冻结范围"><LongContent value={{ 快照: run.snapshot_id, 名称: run.snapshot_name, 模型: run.model, 预算: run.budgets, 用量: run.usage, 范围: scopeLabel(run, projectMap), 显式文件列表: run.scope, 模型档案: run.model_profile }} label="运行参数与冻结范围" /></Disclosure>
        </div>
      </section>
      <section className="panel" aria-label="目标终态">
        <div className="panel-head"><span className="panel-title">目标终态</span><span className="faint small">{goals.length} 条记录</span></div>
        <div className="panel-body">{goals.length === 0 ? <div className="empty">协调器尚未写入目标状态。</div> : goals.map((goal) => <Disclosure key={goal.id} title={<span className="disclosure-heading"><span className={`chip chip-${goal.status}`}>{TARGET_GOAL_STATUS_LABELS[goal.status] ?? goal.status}</span><span className="faint small">尝试 {goal.attempts}/{goal.max_total_attempts} 次</span></span>}>
          <LongContent value={goal.objective} label="目标" />
          <LongContent value={goal.terminal_reason || '尚未收束'} label="终态依据" />
        </Disclosure>)}</div>
      </section>
      <PlannerNavigation detail={detail} />
      <ReportFindings detail={detail} />
      <section className="panel" aria-label="工作项完成情况">
        <div className="panel-head"><span className="panel-title">工作项完成情况</span><span className="faint small">已结算 {finished.length}/{workItems.length}</span></div>
        <div className="panel-body">{workItems.length === 0 ? <div className="empty">工作队列尚未建立。</div> : <Disclosure title={`查看历史工作项（${workItems.length}）`}>
          {workItems.map((item) => {
            const unit = unitById.get(item.unit_id);
            return <Disclosure key={item.id} title={<span className="disclosure-heading"><span className={`chip chip-${item.state}`}>{TARGET_WORK_STATE_LABELS[item.state] ?? item.state}</span><span className="mono disclosure-preview">{unit ? `${unit.file_path}:${unit.start_line}-${unit.end_line}` : item.unit_id}</span><span className="faint small">{item.attempt}/{item.max_attempts} 次</span></span>}>
              <LongContent value={item.summary} label="工作项摘要" />
              <LongContent value={item.error || item.result?.summary || '—'} label="结果摘要" />
              {item.result?.terminal_reason && <LongContent value={item.result.terminal_reason} label="终止依据" />}
            </Disclosure>;
          })}
        </Disclosure>}</div>
      </section>
      <ReviewSummary detail={detail} />
    </div>
  );
}
