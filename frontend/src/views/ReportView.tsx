import { useState } from 'react';
import { api, errorText, post } from '../api';
import type { RunDetail, Snapshot, Truth } from '../types';

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

/**
 * Report tab: the run's account of itself, plus the two things a reader needs in order to
 * trust it — a truth set to measure against, and an attribution for every way the audit
 * was wrong. Both are recorded per snapshot and per run, not per session, so the numbers
 * stay reproducible after a restart.
 */
export function ReportView({
  runId,
  detail,
  onChanged,
}: {
  runId: string;
  detail: RunDetail;
  onChanged: () => void;
}) {
  const { run, metrics, findings, attributions } = detail;
  const isGoalTask = Boolean(run.task_spec);
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
            {run.task_spec
              ? '目标任务执行器'
              : <>Prompt <span className="mono">{run.prompt_id}</span></>}
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
              {isGoalTask
                ? '目标任务不使用固定三类漏洞真值集；请依据目标、工作项历史和证据链复核结果。'
                : '还没有真实样本。没有它，召回率与漏报数不可计算。'}
            </div>
          )}

          {isGoalTask ? (
            <div className="small muted">
              这份快照的固定类别真值集不会参与本次目标任务的统计，因此这里不提供录入入口。
            </div>
          ) : <div className="grid" style={{ gridTemplateColumns: '2fr 1fr auto auto 3fr auto', alignItems: 'end' }}>
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
              <input type="text" value={draft.verification_basis} placeholder="例如：人工执行 POC 复现，见 DVWA low 分支" onChange={(event) => setDraft({ ...draft, verification_basis: event.target.value })} />
            </div>
            <button className="btn btn-primary" onClick={addTruth} disabled={!draft.file_path}>录入样本</button>
          </div>}
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">{isGoalTask ? '目标任务复盘' : '失败归因'}</span>
          <span className="faint small">{isGoalTask ? '以目标、工作项轮次和证据链复核终态' : '每条误报 / 漏报都要能指到提示词里的哪一条'}</span>
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

          {isGoalTask ? (
            <div className="small muted">
              自定义目标任务不使用固定三类漏洞的误报/漏报归因表；请在目标工作项、事件时间线和人工验证记录中复盘。
            </div>
          ) : <div className="grid" style={{ gridTemplateColumns: '1.2fr 1.2fr 1fr 2fr 1.5fr 1.5fr auto', alignItems: 'end' }}>
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
          </div>}
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">本次运行的问题清单</span>
        </div>
        <div style={{ padding: '12px 16px' }}>
          <div className="small">
            <div>证据不通过的候选：<strong>{invalid.length}</strong> 条，不计入可信发现。</div>
            <div>人工排除的发现：<strong>{rejected.length}</strong> 条，{isGoalTask ? '保留人工结论供复盘。' : '计入假阳性并需要归因。'}</div>
            <div>人工确认的候选：<strong>{confirmed.length}</strong> 条。</div>
            <div>未完成单元：<strong>{metrics.incomplete_units}</strong> 个，单独列出，不作为阴性结果。</div>
          </div>
        </div>
      </div>
    </div>
  );
}
