import type { RunDetail } from '../types';
import type { AuditEvent } from '../types';

const CATEGORY_LABELS: Record<string, string> = {
  sqli: 'SQL 注入',
  xss_r: '反射型 XSS',
  command_injection: '命令注入',
};

function Stat({ value, label, note }: { value: string | number; label: string; note?: string }) {
  return (
    <div className="panel stat">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
      {note && <div className="stat-note">{note}</div>}
    </div>
  );
}

function percent(value: number | null | undefined) {
  return value === null || value === undefined ? '—' : `${(value * 100).toFixed(1)}%`;
}

/**
 * Run summary.
 *
 * The counts are deliberately split by what is actually knowable. On a project with no
 * independently verified truth set there is no ground truth to compare against, so recall
 * and the false-negative count are reported as not computable — printing 0 there would
 * claim the auditor missed nothing, which is exactly the claim nobody can make.
 */
export function Overview({
  detail,
  events,
}: {
  detail: RunDetail;
  events: AuditEvent[];
}) {
  const { run, units, findings, metrics } = detail;
  const evaluation = metrics.evaluation;
  const withTruth = metrics.truth_status === 'has_truth_set';

  const unitRows = units.map((unit) => {
    const result = unit.result as { conclusions?: Record<string, string>; exploration_incomplete?: string | null } | null;
    return {
      unit,
      conclusions: result?.conclusions ?? null,
      partial: result?.exploration_incomplete ?? null,
      candidates: findings.filter((finding) => finding.unit_id === unit.id).length,
    };
  });

  const unfinished = unitRows.filter(
    (row) => row.unit.status !== 'completed' || row.partial,
  );

  return (
    <div className="grid">
      <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))' }}>
        <Stat value={`${run.completed_units}/${run.total_units}`} label="已审计单元" note={`未完成 ${metrics.incomplete_units} · 待处理 ${metrics.pending_units ?? units.filter((u) => u.status === 'pending').length}`} />
        <Stat value={metrics.candidates} label="候选（证据通过）" note={`证据不通过 ${metrics.discarded_candidates ?? 0}`} />
        <Stat value={metrics.confirmed} label="人工确认" note={`排除 ${metrics.rejected} · 待验证 ${metrics.awaiting_verification}`} />
        <Stat value={percent(metrics.audit_coverage)} label="审计覆盖率" note="已完成单元 / 全部单元" />
        <Stat value={percent(metrics.verification_coverage)} label="验证覆盖率" note="已验证候选 / 全部候选" />
        <Stat value={run.usage.requests} label="模型响应次数" note={`工具 ${run.usage.tool_calls} · 输入 ${run.usage.input_tokens} tok`} />
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">统计口径</span>
          <span className={`chip ${withTruth ? 'chip-confirmed' : 'chip-pending'}`}>
            {withTruth ? '已建立已知真实样本' : '无已知真实样本'}
          </span>
        </div>
        <div style={{ padding: '12px 16px' }}>
          {withTruth && evaluation ? (
            <>
              <div className="grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))' }}>
                <Stat value={evaluation.TP} label="TP" />
                <Stat value={evaluation.FP} label="FP" />
                <Stat value={evaluation.FN} label="FN" />
                <Stat value={evaluation.TN} label="TN" />
                <Stat value={percent(evaluation.precision)} label="精确率" />
                <Stat value={percent(evaluation.recall)} label="召回率" />
                <Stat value={percent(evaluation.f1)} label="F1" />
                {/* `eligible` counts the verified samples; `unresolved` ones are dropped again
                    below, so the number that actually feeds the matrix is the difference. */}
                <Stat
                  value={evaluation.total_samples}
                  label="样本数"
                  note={`参与计算 ${evaluation.eligible - evaluation.unresolved.length} / 核验 ${evaluation.eligible}`}
                />
              </div>
              <div className="small muted" style={{ marginTop: 10 }}>
                这 {evaluation.eligible} 个样本是已知答案的演示文件，用来说明流程走得通，
                <strong>不能据此声称对未知 PHP 项目的检测能力</strong>。
                未决样本 {evaluation.unresolved.length} 个已单列，不进混淆矩阵：既不记漏报，也不记真阴，
                因此上面的精确率与召回率只是在其余样本上的比值。
              </div>
              {evaluation.unresolved.length > 0 && (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5, marginTop: 8 }}>
                  <thead>
                    <tr style={{ color: 'var(--ink-soft)', fontSize: 11.5 }}>
                      <th style={{ textAlign: 'left', padding: '4px 8px 4px 0', fontWeight: 500 }}>未决样本</th>
                      <th style={{ textAlign: 'left', padding: '4px 8px', fontWeight: 500 }}>真值</th>
                      <th style={{ textAlign: 'left', padding: '4px 8px', fontWeight: 500 }}>未决原因</th>
                    </tr>
                  </thead>
                  <tbody>
                    {evaluation.unresolved.map((sample, index) => (
                      <tr key={index} style={{ borderTop: '1px solid var(--line-soft)' }}>
                        <td style={{ padding: '4px 8px 4px 0' }} className="mono">
                          {sample.file_path} <span className="faint">{CATEGORY_LABELS[sample.category]}</span>
                        </td>
                        <td style={{ padding: '4px 8px' }}>{sample.vulnerable ? '漏洞' : '无漏洞'}</td>
                        <td style={{ padding: '4px 8px' }} className="muted">{sample.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          ) : (
            <div className="small muted">
              这个快照没有独立核验过的真实样本集，所以只报告候选数、人工结论、审计覆盖率与验证覆盖率。
              <strong>召回率、漏报数与真阴数在此标记为「不可计算」</strong>，而不是记为 0：
              没有基准就没有漏报可言，把它们填成 0 等于宣称没有漏掉任何漏洞。
              <div style={{ marginTop: 6 }}>
                如需混淆矩阵，请在「Prompt 与实验」中为该快照录入真实样本（含独立核验依据）后再看。
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">单元级结论</span>
          <span className="faint small">每个单元都检查三类，缺一类不会发生</span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ color: 'var(--ink-soft)', fontSize: 12 }}>
                <th style={{ textAlign: 'left', padding: '8px 14px', fontWeight: 500 }}>单元</th>
                <th style={{ textAlign: 'left', padding: '8px 10px', fontWeight: 500 }}>状态</th>
                <th style={{ textAlign: 'left', padding: '8px 10px', fontWeight: 500 }}>SQL 注入</th>
                <th style={{ textAlign: 'left', padding: '8px 10px', fontWeight: 500 }}>反射型 XSS</th>
                <th style={{ textAlign: 'left', padding: '8px 10px', fontWeight: 500 }}>命令注入</th>
                <th style={{ textAlign: 'left', padding: '8px 10px', fontWeight: 500 }}>模型</th>
              </tr>
            </thead>
            <tbody>
              {unitRows.map(({ unit, conclusions, partial, candidates }) => (
                <tr key={unit.id} style={{ borderTop: '1px solid var(--line-soft)' }}>
                  <td style={{ padding: '8px 14px' }}>
                    <div className="mono small">{unit.file_path}:{unit.start_line}-{unit.end_line}</div>
                    <div className="faint" style={{ fontSize: 11.5 }}>
                      {unit.symbol} · {unit.kind} · 切片 {unit.slice_index}/{unit.slice_count} · 排序优先级 {unit.priority}
                      {candidates > 0 && <> · 候选 {candidates}</>}
                    </div>
                  </td>
                  <td style={{ padding: '8px 10px', minWidth: 96 }}>
                    <span className={`chip chip-${unit.status}`}>{unit.status}</span>
                    {partial && <span className="chip chip-incomplete" title={partial}>探索未走完</span>}
                    {unit.error && (
                      <div className="error-box small" style={{ marginTop: 5, maxWidth: 320, maxHeight: 90, overflowY: 'auto' }}>
                        {unit.error}
                      </div>
                    )}
                  </td>
                  {(['sqli', 'xss_r', 'command_injection'] as const).map((category) => (
                    <td key={category} style={{ padding: '8px 10px' }}>
                      {conclusions?.[category]
                        ? <span className={`chip chip-${conclusions[category]}`}>{CATEGORY_LABELS[category]}·{conclusions[category]}</span>
                        : <span className="faint">—</span>}
                    </td>
                  ))}
                  <td style={{ padding: '8px 10px', whiteSpace: 'nowrap' }}>
                    <span className="faint small" title={unit.usage ? undefined : '未完成：模型调用次数未记录'}>
                      {unit.status !== 'completed' && !unit.usage
                        ? '未记录'
                        : unit.usage ? `${unit.usage.requests} 响应 / ${unit.usage.tool_calls} 工具` : '—'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">未完成与未决单元</span>
          <span className="faint small">单独列出，不当作阴性结果</span>
        </div>
        {unfinished.length === 0 ? (
          <div className="empty">全部单元都正常完成。</div>
        ) : (
          <div>
            {unfinished.map(({ unit, partial }) => (
              <div key={unit.id} style={{ padding: '10px 16px', borderBottom: '1px solid var(--line-soft)' }}>
                <div className="row" style={{ flexWrap: 'wrap' }}>
                  <span className={`chip chip-${unit.status}`}>{unit.status}</span>
                  <span className="mono small">{unit.file_path}:{unit.start_line}-{unit.end_line}</span>
                  {partial && <span className="chip chip-incomplete">{partial}</span>}
                </div>
                {unit.error && <div className="small mono" style={{ marginTop: 5, color: 'var(--danger)' }}>{unit.error}</div>}
                <div className="faint small" style={{ marginTop: 4 }}>
                  该单元不能作为「没有漏洞」的证据。
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {events.length > 0 && (
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">运行事件</span>
            <span className="faint small">已持久化 {events.length} 条</span>
          </div>
          <div style={{ padding: '12px 16px' }} className="small muted">
            事件先写入 SQLite 再推送，所以刷新页面或重启服务后这里的内容不变。
          </div>
        </div>
      )}
    </div>
  );
}
