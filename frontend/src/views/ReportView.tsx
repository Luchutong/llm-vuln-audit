import { useState } from 'react';
import { api, errorText, post } from '../api';
import type { RunDetail, Truth } from '../types';

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
    return <TargetReportView detail={props.detail} />;
  }
  return <LegacyReportView {...props} />;
}

function LegacyReportView({ runId, detail, onChanged }: ReportViewProps) {
  const { run, metrics, findings, attributions } = detail;
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

  const loadTruths = () => {
    api<Truth[]>(`/snapshots/${run.snapshot_id}/truths`)
      .then(setTruths)
      .catch((exc) => setError(errorText(exc)));
  };

  if (truths === null) loadTruths();

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
      {error && <div className="error-box">{error}</div>}

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">统计可复现性</span>
          <span className="faint small">同一快照、同一范围、同一模型、同一预算下可复算</span>
        </div>
        <div style={{ padding: '12px 16px' }} className="small">
          <div>快照 <span className="mono">{run.snapshot_id}</span>（{run.snapshot_name}）</div>
          <div>范围 {run.scope.length} 个文件：<span className="mono">{run.scope.join('、')}</span></div>
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
          {truths && truths.length > 0 ? (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13, marginBottom: 12 }}>
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
                    <td className="small muted" style={{ padding: '6px 8px' }}>{truth.verification_basis}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="small muted" style={{ marginBottom: 12 }}>
              还没有真实样本。没有它，召回率与漏报数不可计算。
            </div>
          )}

          <div className="grid" style={{ gridTemplateColumns: '2fr 1fr auto auto 3fr auto', alignItems: 'end' }}>
            <div className="field">
              <span className="field-label">文件路径</span>
              <input type="text" className="mono" value={draft.file_path} placeholder="vulnerabilities/sqli/source/low.php" onChange={(event) => setDraft({ ...draft, file_path: event.target.value })} />
            </div>
            <div className="field">
              <span className="field-label">类别</span>
              <select value={draft.category} onChange={(event) => setDraft({ ...draft, category: event.target.value })}>
                {Object.entries(CATEGORY_LABELS).map(([value, text]) => <option key={value} value={value}>{text}</option>)}
              </select>
            </div>
            <div className="field">
              <span className="field-label">实际</span>
              <select value={draft.vulnerable ? '1' : '0'} onChange={(event) => setDraft({ ...draft, vulnerable: event.target.value === '1' })}>
                <option value="1">存在漏洞</option>
                <option value="0">不存在</option>
              </select>
            </div>
            <div className="field">
              <span className="field-label">独立核验</span>
              <select value={draft.independently_verified ? '1' : '0'} onChange={(event) => setDraft({ ...draft, independently_verified: event.target.value === '1' })}>
                <option value="1">是</option>
                <option value="0">否</option>
              </select>
            </div>
            <div className="field">
              <span className="field-label">核验依据</span>
              <input type="text" value={draft.verification_basis} placeholder="例如：独立复现记录、代码评审编号或测试报告" onChange={(event) => setDraft({ ...draft, verification_basis: event.target.value })} />
            </div>
            <button className="btn btn-primary" onClick={addTruth} disabled={!draft.file_path}>录入样本</button>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">失败归因</span>
          <span className="faint small">每条误报 / 漏报都要能指到提示词里的哪一条</span>
        </div>
        <div style={{ padding: '12px 16px' }}>
          {attributions.length > 0 && (
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13, marginBottom: 12 }}>
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
                    <td className="small" style={{ padding: '6px 8px' }}>{item.cause}</td>
                    <td className="small muted" style={{ padding: '6px 8px' }}>{item.check_item}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <div className="grid" style={{ gridTemplateColumns: '1.2fr 1.2fr 1fr 2fr 1.5fr 1.5fr auto', alignItems: 'end' }}>
            <div className="field">
              <span className="field-label">类型</span>
              <select value={attribution.kind} onChange={(event) => setAttribution({ ...attribution, kind: event.target.value })}>
                {Object.entries(ATTRIBUTION_LABELS).map(([value, text]) => <option key={value} value={value}>{text}</option>)}
              </select>
            </div>
            <div className="field">
              <span className="field-label">文件路径</span>
              <input type="text" className="mono" value={attribution.file_path} onChange={(event) => setAttribution({ ...attribution, file_path: event.target.value })} />
            </div>
            <div className="field">
              <span className="field-label">类别</span>
              <select value={attribution.category} onChange={(event) => setAttribution({ ...attribution, category: event.target.value })}>
                {Object.entries(CATEGORY_LABELS).map(([value, text]) => <option key={value} value={value}>{text}</option>)}
              </select>
            </div>
            <div className="field">
              <span className="field-label">原因</span>
              <input type="text" value={attribution.cause} placeholder="例如：判据没有要求核对输出上下文" onChange={(event) => setAttribution({ ...attribution, cause: event.target.value })} />
            </div>
            <div className="field">
              <span className="field-label">对应检查项</span>
              <input type="text" value={attribution.check_item} placeholder="例如：三、漏洞判定标准 / 反射型 XSS 第 2 条" onChange={(event) => setAttribution({ ...attribution, check_item: event.target.value })} />
            </div>
            <div className="field">
              <span className="field-label">关联发现（可选）</span>
              <select value={attribution.finding_id} onChange={(event) => setAttribution({ ...attribution, finding_id: event.target.value })}>
                <option value="">不关联</option>
                {findings.map((finding) => (
                  <option key={finding.id} value={finding.id}>
                    [{CATEGORY_LABELS[finding.category]}] {finding.file_path.split('/').pop()}:{finding.line}
                  </option>
                ))}
              </select>
            </div>
            <button className="btn btn-primary" onClick={addAttribution} disabled={!attribution.file_path}>记录</button>
          </div>
        </div>
      </div>

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

/**
 * A target report is an account of one bounded source task, not an experiment scorecard.
 * It deliberately makes the scope and stopping conditions visible so a reader can judge
 * what the result establishes and what it does not.
 */
function TargetReportView({ detail }: Pick<ReportViewProps, 'detail'>) {
  const { run, findings, metrics, units } = detail;
  const task = run.task_spec;
  const goals = detail.goals ?? [];
  const workItems = detail.work_items ?? [];
  const unitById = new Map(units.map((unit) => [unit.id, unit]));
  const validFindings = findings.filter((finding) => finding.validation_state === 'candidate');
  const invalidFindings = findings.filter((finding) => finding.validation_state !== 'candidate');
  const confirmedFindings = findings.filter((finding) => finding.verdict === 'confirmed');
  const rejectedFindings = findings.filter((finding) => finding.verdict === 'rejected');
  const finished = workItems.filter((item) => ['done', 'exhausted', 'blocked', 'skipped'].includes(item.state));
  const pending = workItems.filter((item) => !['done', 'exhausted', 'blocked', 'skipped'].includes(item.state));
  const usedAttempts = workItems.reduce((total, item) => total + item.attempt, 0);

  if (!task) return null;

  return (
    <div className="grid">
      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">目标审计报告</span>
          <span className={`chip chip-${run.status}`}>{TARGET_RUN_STATUS_LABELS[run.status] ?? run.status}</span>
        </div>
        <div style={{ padding: '12px 16px' }} className="grid">
          <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))' }}>
            <div className="field">
              <span className="field-label">目标</span>
              <span className="small">{task.objective}</span>
            </div>
            <div className="field">
              <span className="field-label">验收条件</span>
              <span className="small">{task.success_criteria}</span>
            </div>
            <div className="field">
              <span className="field-label">冻结范围</span>
              <span className="small">{run.scope.length} 个 PHP 源码文件</span>
            </div>
            <div className="field">
              <span className="field-label">执行预算</span>
              <span className="small">每项 {task.max_iterations} 轮 · 总计 {usedAttempts}/{task.max_total_attempts} 次 · 最多 {task.max_workers} 个 worker</span>
            </div>
          </div>
          <div className="small muted">
            此报告仅说明本次冻结源码范围、目标与预算内的审计结果。它不使用固定漏洞类别、真值集或混淆矩阵，
            也不会把预算耗尽解释为项目不存在其他风险。
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">可复现信息</span>
          <span className="faint small">运行参数与源码范围随任务固定</span>
        </div>
        <div style={{ padding: '12px 16px' }} className="small grid">
          <div>快照 <span className="mono">{run.snapshot_id}</span>（{run.snapshot_name}）</div>
          <div>模型 <span className="mono">{run.model}</span> · 响应 {run.usage.requests} 次 · 工具调用 {run.usage.tool_calls} 次</div>
          <div>范围：</div>
          <div className="mono faint" style={{ overflowWrap: 'anywhere', maxHeight: 100, overflowY: 'auto' }}>
            {run.scope.join('\n') || '未记录源码文件'}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">目标终态</span>
          <span className="faint small">依据协调器记录的工作项结论和验收条件</span>
        </div>
        {goals.length === 0 ? (
          <div className="empty">协调器尚未写入目标状态。</div>
        ) : (
          <div>
            {goals.map((goal) => (
              <div key={goal.id} style={{ padding: '10px 16px', borderBottom: '1px solid var(--line-soft)' }}>
                <div className="row" style={{ flexWrap: 'wrap' }}>
                  <span className={`chip chip-${goal.status}`}>{TARGET_GOAL_STATUS_LABELS[goal.status] ?? goal.status}</span>
                  <span className="small">尝试 {goal.attempts}/{goal.max_total_attempts} 次</span>
                </div>
                <div className="small" style={{ marginTop: 4 }}>{goal.objective}</div>
                {goal.terminal_reason && <div className="faint small" style={{ marginTop: 3 }}>{goal.terminal_reason}</div>}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">证据化结果</span>
          <span className="faint small">{validFindings.length} 条引用校验通过 · {invalidFindings.length} 条不计入可信结果</span>
        </div>
        {findings.length === 0 ? (
          <div className="empty">没有生成满足验收条件的发现。</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ color: 'var(--ink-soft)', fontSize: 12 }}>
                  <th style={{ textAlign: 'left', padding: '8px 14px', fontWeight: 500 }}>结论</th>
                  <th style={{ textAlign: 'left', padding: '8px 10px', fontWeight: 500 }}>类型</th>
                  <th style={{ textAlign: 'left', padding: '8px 10px', fontWeight: 500 }}>源码证据</th>
                  <th style={{ textAlign: 'left', padding: '8px 10px', fontWeight: 500 }}>验证</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((finding) => (
                  <tr key={finding.id} style={{ borderTop: '1px solid var(--line-soft)' }}>
                    <td style={{ padding: '8px 14px', minWidth: 220 }}>
                      <div className="small" style={{ fontWeight: 500 }}>{finding.title}</div>
                      <div className="faint small" style={{ marginTop: 3 }}>{finding.summary}</div>
                    </td>
                    <td style={{ padding: '8px 10px', minWidth: 120 }}>
                      <div className="small">{finding.finding_kind || '源码观察'}</div>
                      <div className="faint small">{finding.severity || '未分级'}</div>
                    </td>
                    <td className="mono small" style={{ padding: '8px 10px', minWidth: 220 }}>{sourceReferences(finding)}</td>
                    <td style={{ padding: '8px 10px', minWidth: 110 }}>
                      <span className={`chip chip-${finding.validation_state}`}>
                        {finding.validation_state === 'candidate' ? '引用通过' : '引用不通过'}
                      </span>
                      {finding.verdict && <div className="faint small" style={{ marginTop: 3 }}>{finding.verdict}</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">工作项完成情况</span>
          <span className="faint small">已结算 {finished.length}/{workItems.length} · 仍在处理 {pending.length}</span>
        </div>
        {workItems.length === 0 ? (
          <div className="empty">工作队列尚未建立。</div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr style={{ color: 'var(--ink-soft)', fontSize: 12 }}>
                  <th style={{ textAlign: 'left', padding: '8px 14px', fontWeight: 500 }}>范围</th>
                  <th style={{ textAlign: 'left', padding: '8px 10px', fontWeight: 500 }}>状态</th>
                  <th style={{ textAlign: 'left', padding: '8px 10px', fontWeight: 500 }}>轮次</th>
                  <th style={{ textAlign: 'left', padding: '8px 10px', fontWeight: 500 }}>最近结论</th>
                </tr>
              </thead>
              <tbody>
                {workItems.map((item) => {
                  const unit = unitById.get(item.unit_id);
                  return (
                    <tr key={item.id} style={{ borderTop: '1px solid var(--line-soft)' }}>
                      <td style={{ padding: '8px 14px', minWidth: 220 }}>
                        <div className="mono small">{unit ? `${unit.file_path}:${unit.start_line}-${unit.end_line}` : item.unit_id}</div>
                        <div className="faint small">{item.summary}</div>
                      </td>
                      <td style={{ padding: '8px 10px' }}><span className={`chip chip-${item.state}`}>{TARGET_WORK_STATE_LABELS[item.state] ?? item.state}</span></td>
                      <td style={{ padding: '8px 10px', whiteSpace: 'nowrap' }}>{item.attempt}/{item.max_attempts}</td>
                      <td style={{ padding: '8px 10px', minWidth: 220 }}>
                        <div className="small">{item.error || item.result?.summary || '—'}</div>
                        {item.result?.terminal_reason && <div className="faint small">{item.result.terminal_reason}</div>}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">人工复核清单</span>
          <span className="faint small">在“发现与复核”中记录结论和附件</span>
        </div>
        <div style={{ padding: '12px 16px' }} className="small">
          <div>待人工复核：<strong>{metrics.awaiting_verification}</strong> 条。</div>
          <div>确认结论：<strong>{confirmedFindings.length}</strong> 条；驳回结论：<strong>{rejectedFindings.length}</strong> 条。</div>
          <div>证据引用不通过：<strong>{invalidFindings.length}</strong> 条，已从可信结果中排除。</div>
          <div style={{ marginTop: 7 }} className="muted">
            “执行轨迹”保留工具调用、worker 状态和模型提供的可审计依据摘要；不显示或导出模型内部思维链。
          </div>
        </div>
      </div>
    </div>
  );
}
