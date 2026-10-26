import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { api, downloadUrl, errorText } from '../api';
import { Disclosure } from '../components/Disclosure';
import { localDate } from '../status';
import { executionPhase } from '../execution';
import type { AuditEvent, Budget, Evidence, Finding, Prompt } from '../types';
import {
  CLASS_LABELS,
  EXPERIMENT_STATUS,
  PROMPT_PROTOCOL,
  compatibleStrategies,
  defaultStrategies,
  isFullExperiment,
  lineDiff,
  metricLabel,
  numeric,
  percent,
  points,
  experimentBudgetCheck,
  formatDuration,
} from '../promptComparison';
import type {
  ExperimentRecord,
  ExperimentSummary,
  FullExperiment,
  Trial,
  TrialDetail,
  TruthResult,
  VariantSummary,
  ExperimentSource,
  AggregateMetric,
} from '../promptComparison';
import '../promptComparison.css';

const readApi = <T,>(path: string, options?: RequestInit) => api<T>(path, { ...options, timeoutMs: 10000 });

const initialBudgets: Budget = { responses: 24, tools: 96, seconds: 720 };
const initialLimits: Budget = { responses: 256, tools: 2048, seconds: 720 };
const activeStatus = (status?: string) =>
  status === 'running' || status === 'queued' || status === 'pending' || status === 'preparing' || status === 'cancelling';
const stateLabel = (status?: string) => (status ? (EXPERIMENT_STATUS[status] ?? status) : '—');
const labelOf = (item: FullExperiment, id: string) => item.manifest.variants.find((variant) => variant.id === id)?.label ?? id;
const experimentPath = (id: string) => `/prompt-experiments/${encodeURIComponent(id)}`;
const trialPath = (experimentId: string, trialId: string) =>
  `${experimentPath(experimentId)}/trials/${encodeURIComponent(trialId)}`;
const recordModel = (record: ExperimentRecord): string => {
  if (!isFullExperiment(record)) return record.model || '历史未保存模型';
  const model = record.manifest?.model;
  return typeof model === 'string' ? model : model?.model || '准备冻结模型';
};
const pairedLabel = (metric?: AggregateMetric) =>
  !metric || metric.mean == null
    ? '—'
    : `${points(metric.mean)}${metric.sample_std == null ? '' : ` ± ${(metric.sample_std * 100).toFixed(1)}`} (n=${metric.n})`;
const reasonText = (value: string | { code?: string; message?: string | null } | null | undefined) =>
  typeof value === 'string' ? value : value?.message || value?.code || '';
const trialReason = (trial: Trial) => reasonText(trial.termination_reason || trial.stop_reason || trial.error);

function useQuery() {
  const [query, setQuery] = useState(() => new URLSearchParams(window.location.hash.split('?')[1] ?? ''));
  useEffect(() => {
    const update = () => setQuery(new URLSearchParams(window.location.hash.split('?')[1] ?? ''));
    window.addEventListener('hashchange', update);
    return () => window.removeEventListener('hashchange', update);
  }, []);
  const change = (patch: Record<string, string | null>) => {
    const next = new URLSearchParams(window.location.hash.split('?')[1] ?? '');
    for (const [key, value] of Object.entries(patch)) value ? next.set(key, value) : next.delete(key);
    window.location.hash = `${window.location.hash.split('?')[0]}${next.size ? `?${next}` : ''}`;
  };
  return { query, change };
}

function Downloads({ id, legacy = false }: { id: string; legacy?: boolean }) {
  return (
    <div className="row exp-downloads">
      <a className="btn" href={downloadUrl(`${experimentPath(id)}/report?format=markdown`)}>
        Markdown
      </a>
      <a className="btn" href={downloadUrl(`${experimentPath(id)}/report?format=json`)}>
        JSON
      </a>
      {!legacy && (
        <a className="btn" href={downloadUrl(`${experimentPath(id)}/report?format=csv`)}>
          CSV（3 张表 ZIP）
        </a>
      )}
    </div>
  );
}

function LiveExperiment({ experiment, onOpen }: { experiment: FullExperiment; onOpen: (id: string) => void }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const progress = experiment.progress;
  const live = progress?.live;
  const trial =
    experiment.trials.find((item) => item.id === progress?.trial_id) ??
    experiment.trials.find((item) => item.status === 'running');
  const timing = progress?.timing;
  const batch =
    timing?.batches?.find((item) => item.id === timing.active_batch_id) ?? timing?.batches?.at(-1) ?? timing?.initial_batch;
  const legacyTiming = !timing?.initial_batch && experiment.manifest.experiment_wall_seconds !== 7200;
  const phase = live?.phase ?? progress?.phase ?? (trial?.run_id ? 'running' : 'preparing');
  const labels: Record<string, string> = {
    preparing: '准备冻结源码与执行器',
    waiting_for_model: '等待模型响应',
    model_request: '等待模型响应',
    model_waiting: '等待模型响应',
    model_response: '模型已返回',
    run_created: '审计已启动',
  };
  const heartbeat = live?.heartbeat_at ? Date.parse(live.heartbeat_at) : NaN;
  const heartbeatAge = Number.isFinite(heartbeat) ? Math.max(0, (now - heartbeat) / 1000) : null;
  const running = activeStatus(experiment.status) && Boolean(trial && activeStatus(trial.status));
  const elapsed = !running
    ? (trial?.audit_elapsed_seconds ?? live?.audit_elapsed_seconds)
    : live?.audit_elapsed_seconds == null
      ? trial?.audit_elapsed_seconds
      : live.audit_elapsed_seconds + (running && heartbeatAge != null ? heartbeatAge : 0);
  const auditRemaining =
    elapsed == null ? live?.audit_remaining_seconds : Math.max(0, (experiment.manifest.run_limits?.seconds ?? 720) - elapsed);
  const deadline = batch?.deadline_at ? Date.parse(batch.deadline_at) : NaN;
  const batchRemaining = Number.isFinite(deadline)
    ? Math.max(0, (deadline - (batch?.finished_at ? Date.parse(batch.finished_at) : now)) / 1000)
    : batch?.remaining_seconds;
  const usage = live?.usage ?? trial?.usage;
  const finished = experiment.trials.filter((item) => !activeStatus(item.status) && item.status !== 'not_started').length;
  return (
    <section className="exp-live-panel" aria-label="实时审计进度">
      <div className="exp-filter-row">
        <h3>{running ? '当前试次正在运行' : activeStatus(experiment.status) ? '准备下一试次' : '本批执行已结束'}</h3>
        <span className="chip">
          已结束 {finished} / {experiment.trials.length} 个试次
        </span>
        {trial && (
          <button className="btn" onClick={() => onOpen(trial.id)}>
            查看当前试次与日志
          </button>
        )}
      </div>
      <p className="exp-live-phase">
        <strong>
          {progress?.current ? labelOf(experiment, progress.current) : trial ? labelOf(experiment, trial.prompt_id) : '准备实验'}
        </strong>
        {progress?.round_index ? ` · 第 ${progress.round_index} 轮` : trial ? ` · 第 ${trial.round_index} 轮` : ''} ·{' '}
        {labels[phase] ?? executionPhase(phase)}
      </p>
      <div className="exp-live-metrics">
        <div>
          <span>本次审计已用 / 剩余</span>
          <strong>
            {formatDuration(elapsed)} / {formatDuration(auditRemaining)}
          </strong>
        </div>
        <div>
          <span>
            {batch?.kind === 'retry'
              ? '补跑批次剩余（单独计时）'
              : legacyTiming
                ? '历史批次剩余（未设置硬时限）'
                : '初始批次剩余（最多两小时）'}
          </span>
          <strong>{formatDuration(batchRemaining)}</strong>
        </div>
        <div>
          <span>模型请求 / 工具调用</span>
          <strong>
            {numeric(usage?.requests ?? usage?.responses, 0)} / {numeric(usage?.tool_calls, 0)}
          </strong>
        </div>
        <div>
          <span>已知输入 / 输出 tokens</span>
          <strong>
            {numeric(usage?.input_tokens, 0)} / {numeric(usage?.output_tokens, 0)}
          </strong>
        </div>
        <div>
          <span>当前发现数（待正式评分）</span>
          <strong>{numeric(live?.finding_count, 0)}</strong>
        </div>
        <div>
          <span>最近心跳 / 最近事件</span>
          <strong>
            {heartbeatAge == null ? '等待首次心跳' : `${Math.floor(heartbeatAge)} 秒前`} / {live?.last_event_id ?? '—'}
          </strong>
        </div>
      </div>
      <p className="small muted">
        最近事件时间：{live?.last_event_at ? localDate(live.last_event_at) : '尚无事件'}
        。心跳说明执行器仍有反馈，不能据此推断模型请求已经成功；未知用量显示 —。
      </p>
      {running && heartbeatAge != null && heartbeatAge > 30 && (
        <p className="exp-live-stale" role="status">
          已超过 30 秒没有新心跳，正在继续查询；保留最近已知状态，尚不能确认执行器是否停止。
        </p>
      )}
      {live?.read_coverage?.total_files != null && (
        <p className="small muted">
          已读取 {live.read_coverage.read_files} / {live.read_coverage.total_files} 个文件，{live.read_coverage.read_lines} /{' '}
          {live.read_coverage.total_lines} 行。范围完整不代表所有源码均已检查。
        </p>
      )}
      {progress?.tail?.length ? (
        <Disclosure title="执行器最近反馈">
          <pre className="tl-detail exp-live-tail">{progress.tail.join('\n')}</pre>
        </Disclosure>
      ) : null}
      <p className="small muted">
        {legacyTiming
          ? '本历史记录没有冻结统一批次期限；两小时上限仅适用于新建限时实验。'
          : '初始批次包含原定试次，最多 120 分钟；显式补跑是新的独立批次，不延长或覆盖初始批次。'}
        倒计时按最近服务器时间估算，终态以执行器记录为准。
      </p>
    </section>
  );
}

function MetricChart({ variants }: { variants: VariantSummary[] }) {
  const keys = ['precision', 'recall', 'f1'],
    names = ['Precision', 'Recall', 'F1'];
  const width = Math.max(530, variants.length * 165 + 80),
    height = 250,
    top = 20,
    chartHeight = 170;
  return (
    <figure className="exp-chart" aria-label="各版本 Precision、Recall、F1 均值及样本标准差">
      <svg viewBox={`0 0 ${width} ${height}`} role="img" aria-labelledby="exp-score-title">
        <title id="exp-score-title">清单匹配成绩，所有版本使用相同有效轮次；误差线为样本标准差</title>
        {[0, 0.25, 0.5, 0.75, 1].map((value) => (
          <g key={value}>
            <line
              className="exp-gridline"
              x1="45"
              x2={width - 10}
              y1={top + chartHeight * (1 - value)}
              y2={top + chartHeight * (1 - value)}
            />
            <text className="exp-axis" x="38" y={top + chartHeight * (1 - value) + 4} textAnchor="end">
              {value * 100}%
            </text>
          </g>
        ))}
        {variants.map((variant, index) => {
          const group = 65 + (index * (width - 80)) / Math.max(1, variants.length);
          return (
            <g key={variant.id}>
              {keys.map((key, k) => {
                const metric = variant.metrics[key],
                  value = metric?.mean,
                  sd = metric?.sample_std;
                const x = group + k * 34,
                  y = top + chartHeight * (1 - (value ?? 0));
                return (
                  <g key={key} className={`exp-series-${k}`}>
                    <title>
                      {variant.label} {names[k]}：{metricLabel(metric, true)}
                    </title>
                    {value != null ? (
                      <>
                        <rect x={x} y={y} width="27" height={Math.max(0, chartHeight * value)} rx="3" />
                        {sd != null && (
                          <g className="exp-errorbar">
                            <line
                              x1={x + 13.5}
                              x2={x + 13.5}
                              y1={top + chartHeight * (1 - Math.min(1, value + sd))}
                              y2={top + chartHeight * (1 - Math.max(0, value - sd))}
                            />
                            <line
                              x1={x + 8}
                              x2={x + 19}
                              y1={top + chartHeight * (1 - Math.min(1, value + sd))}
                              y2={top + chartHeight * (1 - Math.min(1, value + sd))}
                            />
                            <line
                              x1={x + 8}
                              x2={x + 19}
                              y1={top + chartHeight * (1 - Math.max(0, value - sd))}
                              y2={top + chartHeight * (1 - Math.max(0, value - sd))}
                            />
                          </g>
                        )}
                      </>
                    ) : (
                      <text x={x + 14} y={top + chartHeight - 7} textAnchor="middle" className="exp-axis">
                        —
                      </text>
                    )}
                  </g>
                );
              })}
              <text className="exp-axis" x={group + 47} y={top + chartHeight + 23} textAnchor="middle">
                {variant.label.length > 17 ? `${variant.label.slice(0, 17)}…` : variant.label}
              </text>
            </g>
          );
        })}
        {names.map((name, index) => (
          <g key={name} className={`exp-series-${index}`}>
            <rect x={width / 2 - 125 + index * 95} y={height - 19} width="10" height="10" rx="2" />
            <text className="exp-axis" x={width / 2 - 110 + index * 95} y={height - 10}>
              {name}
            </text>
          </g>
        ))}
      </svg>
      <figcaption className="small muted">0–100% 统一坐标；误差线为 ±1 样本标准差。精确率缺失以 — 表示。</figcaption>
    </figure>
  );
}

function DeltaChart({ variants, baseline }: { variants: VariantSummary[]; baseline: string }) {
  const rows = variants.filter((item) => item.id !== baseline),
    extent = Math.max(0.1, ...rows.map((item) => Math.abs(item.paired_deltas?.f1?.mean ?? 0)));
  return (
    <div className="exp-delta-chart" aria-label="相对基线 F1 变化">
      {rows.map((item) => {
        const delta = item.paired_deltas?.f1?.mean;
        return (
          <div key={item.id} className="exp-delta-row">
            <span>{item.label}</span>
            <div className="exp-delta-track">
              <span className="exp-delta-zero" />
              <span
                className={`exp-delta-bar ${delta != null && delta < 0 ? 'negative' : ''}`}
                style={{
                  width: `${(Math.abs(delta ?? 0) / extent) * 48}%`,
                  left: delta != null && delta < 0 ? `${50 - (Math.abs(delta) / extent) * 48}%` : '50%',
                }}
              />
            </div>
            <strong>{points(delta)}</strong>
          </div>
        );
      })}
      <p className="small muted">逐轮与冻结基线配对后求均值；向左为下降，向右为提升。</p>
    </div>
  );
}

function SummaryPanel({ experiment }: { experiment: FullExperiment }) {
  const summary = experiment.summary;
  if (!summary?.variants?.length) return <div className="empty">等待有效试次完成后评分。执行中的暂定结果不会替代正式比较。</div>;
  const variants = summary.variants,
    provisional = activeStatus(experiment.status),
    actual = summary.actual_total_usage;
  return (
    <div className="grid exp-content">
      <div className={`exp-notice ${summary.preliminary ? 'exp-notice-warn' : ''}`} role="status">
        <strong>
          {provisional ? '暂定成绩 · ' : ''}
          {summary.preliminary ? '初步结果' : '重复实验结果'}
        </strong>{' '}
        · 共同有效 {summary.complete_round_count} / {summary.repeats} 轮
        <p>
          仅同一轮全部所选版本均有效时进入共同统计集合。
          {summary.complete_round_count < 3
            ? '不足三轮，不作稳定优劣结论。'
            : '均值与波动用于描述本次 Lab30 实验，不代表统计显著或对其他项目的普适提升。'}
        </p>
      </div>
      <div className="exp-chart-grid">
        <MetricChart variants={variants} />
        <div>
          <h3>相对基线 ΔF1</h3>
          <p className="small muted">基线：{labelOf(experiment, summary.baseline_prompt_id)}</p>
          <DeltaChart variants={variants} baseline={summary.baseline_prompt_id} />
        </div>
      </div>
      <div className="table-scroll">
        <table className="exp-metric-table">
          <caption>同一共同轮集合的成绩 · 均值 ± 样本标准差</caption>
          <thead>
            <tr>
              <th>策略版本</th>
              <th>Precision</th>
              <th>Recall</th>
              <th>F1</th>
              <th>ΔF1</th>
              <th>ΔRecall</th>
            </tr>
          </thead>
          <tbody>
            {variants.map((item) => (
              <tr key={item.id}>
                <th scope="row">
                  {item.label}
                  {item.id === summary.baseline_prompt_id && <span className="chip">基线</span>}
                </th>
                {['precision', 'recall', 'f1'].map((key) => (
                  <td key={key}>{metricLabel(item.metrics[key], true)}</td>
                ))}
                <td>{item.id === summary.baseline_prompt_id ? '基线' : pairedLabel(item.paired_deltas?.f1)}</td>
                <td>{item.id === summary.baseline_prompt_id ? '基线' : pairedLabel(item.paired_deltas?.recall)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="table-scroll">
        <table>
          <caption>检出计数均值（不是多轮并集）</caption>
          <thead>
            <tr>
              <th>版本</th>
              <th>TP 命中</th>
              <th>D 重复</th>
              <th>U 未匹配</th>
              <th>FN 漏检</th>
              <th>本版有效试次（含非共同轮）</th>
            </tr>
          </thead>
          <tbody>
            {variants.map((item) => (
              <tr key={item.id}>
                <th scope="row">{item.label}</th>
                {['TP', 'D', 'U', 'FN'].map((key) => (
                  <td key={key}>{metricLabel(item.metrics[key])}</td>
                ))}
                <td>{item.valid_trials ?? item.metrics.f1?.n ?? 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="exp-notice small">
        成绩采用 Lab30 官方 30 项清单：TP+FN=30，FP=D+U。U 是未匹配候选，不等于已证伪漏洞；没有独立安全负例，不计算 Accuracy、TN
        或 FPR。零报告时 Precision 缺失、Recall/F1 为 0。
      </div>
      <h3>资源与严重程度</h3>
      <div className="table-scroll">
        <table>
          <caption>共同有效轮次的每次消耗均值</caption>
          <thead>
            <tr>
              <th>版本</th>
              <th>请求</th>
              <th>工具调用</th>
              <th>输入 tokens</th>
              <th>输出 tokens</th>
              <th>总 tokens</th>
              <th>耗时（秒）</th>
              <th>每 TP tokens</th>
            </tr>
          </thead>
          <tbody>
            {variants.map((item) => (
              <tr key={item.id}>
                <th scope="row">{item.label}</th>
                {[
                  'requests',
                  'tool_calls',
                  'input_tokens',
                  'output_tokens',
                  'total_tokens',
                  'duration_seconds',
                  'tokens_per_tp',
                ].map((key) => (
                  <td key={key}>{metricLabel(item.metrics[key])}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="small muted">
        未知 token 不计为零，TP 为 0 时单位 TP 成本缺失。上表仅统计可比试次；实验实际消耗包含无效、取消及补跑。
      </p>
      {actual != null && (
        <Disclosure title="实验实际总消耗（包含失败与补跑）">
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>项目</th>
                  <th>已知总消耗</th>
                  <th>已知记录 / 全部记录</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(actual).map(([key, value]) => (
                  <tr key={key}>
                    <th>
                      {(
                        {
                          requests: '模型请求',
                          tool_calls: '工具调用',
                          input_tokens: '输入 tokens',
                          output_tokens: '输出 tokens',
                          total_tokens: '总 tokens',
                        } as Record<string, string>
                      )[key] ?? key}
                    </th>
                    <td>{numeric(value.known_total)}</td>
                    <td>
                      {value.known_attempts ?? value.known_trials ?? '—'} / {value.attempts ?? value.trials ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="small muted">已知总量仅汇总可确认的用量；缺失记录不计为零。</p>
        </Disclosure>
      )}
      <CvssSummary summary={summary} />
      <FactConclusion experiment={experiment} />
    </div>
  );
}

function CvssSummary({ summary }: { summary: ExperimentSummary }) {
  const perVariant = summary.variants.filter((item) => Object.keys(item.metrics).some((key) => key.startsWith('cvss')));
  return (
    <Disclosure title="CVSS 3.1 评级质量（与检出成绩分开）">
      {perVariant.length > 0 ? (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>版本</th>
                <th>基础分 MAE</th>
                <th>等级一致率</th>
                <th>可评分覆盖率</th>
              </tr>
            </thead>
            <tbody>
              {perVariant.map((item) => (
                <tr key={item.id}>
                  <th>{item.label}</th>
                  <td>{metricLabel(item.metrics.cvss_mae)}</td>
                  <td>{metricLabel(item.metrics.cvss_severity_accuracy ?? item.metrics.cvss_severity_agreement, true)}</td>
                  <td>{metricLabel(item.metrics.cvss_coverage, true)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="small muted">尚无可评分的 CVSS 结果。</p>
      )}
      {summary.cvss_common_rounds?.length ? (
        <>
          <h4>同轮共同命中且均有有效评分的比较集合</h4>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>轮次</th>
                  <th>共同集合</th>
                  <th>版本</th>
                  <th>基础分 MAE</th>
                  <th>等级一致率</th>
                </tr>
              </thead>
              <tbody>
                {summary.cvss_common_rounds.flatMap((round) =>
                  summary.variants.map((variant) => (
                    <tr key={`${round.round_index}-${variant.id}`}>
                      <td>{round.round_index}</td>
                      <td title={round.truth_ids.join(', ')}>{round.total} 项</td>
                      <td>{variant.label}</td>
                      <td>{numeric(round.variants[variant.id]?.score_mae)}</td>
                      <td>{percent(round.variants[variant.id]?.severity_accuracy)}</td>
                    </tr>
                  )),
                )}
              </tbody>
            </table>
          </div>
        </>
      ) : null}
      <p className="small muted">
        严重程度不加入 F1 加权；缺失评分不作为零分，0.0 分仍参与评价。各自命中集合与共同命中集合分别统计。
      </p>
    </Disclosure>
  );
}

function FactConclusion({ experiment }: { experiment: FullExperiment }) {
  const summary = experiment.summary!;
  return (
    <section className="exp-facts" aria-label="量化结论">
      <h3>量化结论</h3>
      <p>固定 Lab30 原始源码、相同模型及预算，主实验关闭 POC；本次有 {summary.complete_round_count} 轮共同有效结果。</p>
      {summary.variants
        .filter((item) => item.id !== summary.baseline_prompt_id)
        .map((item) => {
          const f1 = item.paired_deltas?.f1,
            recall = item.paired_deltas?.recall,
            values = f1?.values?.map((item) => (typeof item === 'number' ? item : item.value));
          return (
            <p key={item.id}>
              <strong>{item.label}</strong> 相对 {labelOf(experiment, summary.baseline_prompt_id)}：F1{' '}
              {f1?.mean == null ? '尚不可比较' : f1.mean > 0 ? '提升' : f1.mean < 0 ? '下降' : '持平'} {points(f1?.mean)}，Recall
              变化 {points(recall?.mean)}。{values && `逐轮 F1 差值：${values.map(points).join('、')}。`}
              {values?.some((value) => value > 0) && values.some((value) => value < 0) && ' 各轮变化方向不一致。'}
            </p>
          );
        })}
      <div className="table-scroll">
        <table>
          <caption>与基线逐轮比较的增检与丢失</caption>
          <thead>
            <tr>
              <th>版本</th>
              <th>轮次</th>
              <th>ΔF1</th>
              <th>新增真值</th>
              <th>丢失真值</th>
            </tr>
          </thead>
          <tbody>
            {summary.variants
              .filter((item) => item.id !== summary.baseline_prompt_id)
              .flatMap((item) =>
                (item.paired_deltas?.f1?.values ?? [])
                  .filter((value) => typeof value !== 'number')
                  .map((value) =>
                    typeof value === 'number' ? null : (
                      <tr key={`${item.id}-${value.round_index}`}>
                        <th>{item.label}</th>
                        <td>{value.round_index}</td>
                        <td>{points(value.value)}</td>
                        <td>{value.gained_truth_ids?.join('、') || '无'}</td>
                        <td>{value.lost_truth_ids?.join('、') || '无'}</td>
                      </tr>
                    ),
                  ),
              )}
          </tbody>
        </table>
      </div>
      <p className="small muted">
        {summary.preliminary ? '当前轮数不足三轮，只能作为初步观察。' : '以上结论仅描述本次数据集与冻结条件。'}
        新增与丢失请查看逐轮命中矩阵；挖掘成绩不能表述为自动验证或成功利用率。
      </p>
    </section>
  );
}

function TruthMatrix({
  experiment,
  query,
  change,
}: {
  experiment: FullExperiment;
  query: URLSearchParams;
  change: (patch: Record<string, string | null>) => void;
}) {
  const rows = experiment.summary?.truth_matrix ?? [],
    variants = experiment.manifest.variants;
  const category = query.get('class') ?? '',
    round = query.get('round') ?? '',
    selectedId = query.get('truth'),
    selected = rows.find((item) => item.id === selectedId),
    shown = rows.filter((item) => !category || item.class === category);
  const matchedTrial = (item: TruthResult, promptId: string) =>
    item.variants[promptId]?.rounds.find((entry) => String(entry.round_index) === round);
  return (
    <div className="exp-content grid">
      <div className="exp-filter-row">
        <label>
          轮次
          <select aria-label="轮次筛选" value={round} onChange={(event) => change({ round: event.target.value || null })}>
            <option value="">共同轮次汇总</option>
            {Array.from({ length: experiment.manifest.repeats }, (_, index) => index + 1).map((index) => (
              <option key={index} value={index}>
                第 {index} 轮
              </option>
            ))}
          </select>
        </label>
        <label>
          漏洞类别
          <select aria-label="类别筛选" value={category} onChange={(event) => change({ class: event.target.value || null })}>
            <option value="">全部 22 类</option>
            {Object.entries(CLASS_LABELS).map(([key, label]) => (
              <option key={key} value={key}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <span className="small muted">筛选仅改变展示，正式总体成绩不变。</span>
      </div>
      {!rows.length ? (
        <div className="empty">等待评分锚点与首个结果生成，正式矩阵固定对应 30 项真值。</div>
      ) : (
        <div className="table-scroll exp-truth-scroll" tabIndex={0} aria-label="30项漏洞命中矩阵">
          <table className="exp-truth-table">
            <caption>官方漏洞命中矩阵 · {shown.length} / 30 项</caption>
            <thead>
              <tr>
                <th>官方真值</th>
                <th>类别</th>
                {variants.map((item) => (
                  <th key={item.id}>{item.label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {shown.map((item) => (
                <tr key={item.id} className={selectedId === item.id ? 'selected' : ''}>
                  <th scope="row">
                    <button className="text-button" onClick={() => change({ truth: item.id })}>
                      {item.id} · {item.title}
                    </button>
                  </th>
                  <td>{CLASS_LABELS[item.class] ?? item.class}</td>
                  {variants.map((variant) => {
                    const cell = item.variants[variant.id],
                      entry = matchedTrial(item, variant.id);
                    return (
                      <td key={variant.id}>
                        <button
                          className={`exp-hit ${round ? (entry?.detected ? 'detected' : entry ? 'missed' : '') : cell?.hits ? 'detected' : cell?.total ? 'missed' : ''}`}
                          aria-label={`${item.id} ${variant.label} ${round ? (entry?.detected ? '命中' : entry ? '未命中' : '无效或未执行') : `${cell?.hits ?? 0}/${cell?.total ?? 0}`}`}
                          onClick={() =>
                            change({
                              truth: item.id,
                              compare: variant.id,
                              ...(entry ? { trial: entry.trial_id, attempt: null } : {}),
                            })
                          }
                        >
                          {round
                            ? entry?.detected
                              ? '✓ 命中'
                              : entry
                                ? '○ 未命中'
                                : '— 无效/未执行'
                            : cell?.total
                              ? `${cell.hits}/${cell.total}${cell.total < experiment.manifest.repeats ? ` · 少 ${experiment.manifest.repeats - cell.total} 轮` : ''}`
                              : '—'}
                        </button>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {selected && (
        <section className="exp-truth-detail" aria-label="真值逐轮对照">
          <h3>
            {selected.id} · {selected.title}
          </h3>
          <p className="small muted">
            {CLASS_LABELS[selected.class] ?? selected.class} · 未命中表示此次审计没有匹配结论，不能推断源码安全。
          </p>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>版本</th>
                  <th>轮次</th>
                  <th>命中情况</th>
                  <th>来源</th>
                </tr>
              </thead>
              <tbody>
                {variants.flatMap((variant) =>
                  (selected.variants[variant.id]?.rounds ?? [])
                    .filter((entry) => !round || String(entry.round_index) === round)
                    .map((entry) => (
                      <tr key={`${variant.id}-${entry.round_index}`}>
                        <td>{variant.label}</td>
                        <td>{entry.round_index}</td>
                        <td>{entry.detected ? '✓ 命中' : '○ 未命中'}</td>
                        <td>
                          <button
                            className="text-button"
                            onClick={() => change({ trial: entry.trial_id, compare: variant.id, attempt: null })}
                          >
                            查看本轮发现与证据{entry.finding_id ? ` · ${entry.finding_id.slice(0, 8)}` : ''}
                          </button>
                        </td>
                      </tr>
                    )),
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}
      <h3>22 类检出情况</h3>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>类别</th>
              {variants.map((item) => (
                <th key={item.id}>{item.label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Object.entries(CLASS_LABELS)
              .filter(([key]) => !category || category === key)
              .map(([key, label]) => {
                const cell = experiment.summary?.class_coverage?.find((item) => item.class === key);
                return (
                  <tr key={key}>
                    <th scope="row">{label}</th>
                    {variants.map((variant) => {
                      const value = cell?.variants[variant.id];
                      return (
                        <td key={variant.id}>
                          <div className="exp-class-rate">
                            <span style={{ width: `${100 * (value?.recall ?? 0)}%` }} />
                            <b>{value ? `${value.detected}/${value.total} · ${percent(value.recall)}` : '—'}</b>
                          </div>
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function FrozenPrompts({
  experiment,
  compare,
  onCompare,
}: {
  experiment: FullExperiment;
  compare: string;
  onCompare: (id: string) => void;
}) {
  const variants = experiment.manifest.variants,
    selected = variants.find((item) => item.id === compare) ?? variants[1] ?? variants[0],
    baseline = variants.find((item) => item.id === experiment.manifest.baseline_prompt_id) ?? variants[0],
    prior = selected?.parent_id ? (variants.find((item) => item.id === selected.parent_id) ?? baseline) : baseline;
  return (
    <div className="exp-content grid">
      <p className="small muted">下列为创建实验时冻结的正文。提示词库之后的编辑不会改变本次内容。</p>
      {variants.map((item) => (
        <Disclosure key={item.id} title={`${item.label} · ${item.id}`}>
          <p>{item.reason || '历史未保存优化原因'}</p>
          <p className="small muted">
            父版本：{item.parent_id || '无'} · SHA-256：<span className="mono">{item.sha256 || item.hash || '历史未保存'}</span>
          </p>
          <pre className="tl-detail exp-prompt-text">{item.text || '历史未保存正文'}</pre>
        </Disclosure>
      ))}
      {selected && prior && (
        <section>
          <div className="exp-filter-row">
            <h3>冻结版本差异</h3>
            <label>
              对照版本
              <select aria-label="提示词差异版本" value={selected.id} onChange={(event) => onCompare(event.target.value)}>
                {variants.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.label}
                  </option>
                ))}
              </select>
            </label>
          </div>
          <p className="small muted">
            {prior.label} → {selected.label}；− 删除，+ 新增。只比较冻结策略正文。
          </p>
          <pre className="exp-diff">
            {lineDiff(prior.text, selected.text).map((line, index) => (
              <div key={index} className={`exp-diff-${line.kind}`}>
                {line.kind === 'added' ? '+ ' : line.kind === 'removed' ? '− ' : '  '}
                {line.text || ' '}
              </div>
            ))}
          </pre>
        </section>
      )}
      <Disclosure title="冻结清单：源码、模型、执行器与预算">
        <pre className="tl-detail">{JSON.stringify(experiment.manifest, null, 2)}</pre>
      </Disclosure>
    </div>
  );
}

function ScopedSource({
  experimentId,
  trialId,
  evidence,
  attempt,
}: {
  experimentId: string;
  trialId: string;
  evidence: { path: string; start_line: number; end_line: number };
  attempt?: string;
}) {
  const [source, setSource] = useState<ExperimentSource | null>(null),
    [error, setError] = useState<string | null>(null);
  useEffect(() => {
    const abort = new AbortController();
    setSource(null);
    setError(null);
    const params = new URLSearchParams({
      path: evidence.path,
      start_line: String(Math.max(1, evidence.start_line - 5)),
      end_line: String(evidence.end_line + 5),
    });
    if (attempt) params.set('attempt', attempt);
    readApi<ExperimentSource>(`${trialPath(experimentId, trialId)}/source?${params}`, { signal: abort.signal })
      .then((value) => {
        if (!abort.signal.aborted) setSource(value);
      })
      .catch((exc) => {
        if (!abort.signal.aborted) setError(errorText(exc));
      });
    return () => abort.abort();
  }, [experimentId, trialId, attempt, evidence.path, evidence.start_line, evidence.end_line]);
  if (error)
    return (
      <div className="error-box" role="alert">
        证据源码不可用：{error}
      </div>
    );
  if (!source)
    return (
      <p className="muted small" role="status">
        正在读取该试次的源码快照…
      </p>
    );
  return (
    <div>
      <p className="small mono">{source.path}</p>
      <div className="source" tabIndex={0} role="region" aria-label="试次证据源码" style={{ maxHeight: 340 }}>
        {source.lines.map((line) => (
          <div
            key={line.number}
            className={`source-row${line.number >= evidence.start_line && line.number <= evidence.end_line ? ' hit' : ''}`}
          >
            <span className="source-no">{line.number}</span>
            <span className="source-text">{line.text || ' '}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function TrialInspector({
  experiment,
  trial,
  onRetry,
  busy,
}: {
  experiment: FullExperiment;
  trial: Trial;
  onRetry: (trialId: string) => void;
  busy: boolean;
}) {
  const { query, change } = useQuery();
  const attemptQuery = query.get('attempt');
  const attemptNumber = attemptQuery === '1' || attemptQuery === '2' ? attemptQuery : '';
  const selectedSaved = attemptNumber
    ? trial.attempts?.find((item) => String(item.attempt_no) === attemptNumber)
    : trial.attempts?.at(-1);
  const attemptSuffix = attemptNumber ? `?attempt=${attemptNumber}` : '';
  const [detail, setDetail] = useState<TrialDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [remaining, setRemaining] = useState(false);
  const [loadingEvents, setLoadingEvents] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const detailRequest = useRef<AbortController | null>(null);
  const eventRequest = useRef<AbortController | null>(null);
  const earlierRequest = useRef<AbortController | null>(null);
  const eventCursor = useRef(0),
    earliestCursor = useRef(0),
    cursorReady = useRef(false);
  const eventBox = useRef<HTMLDivElement>(null);
  const scrollAnchor = useRef<{ top: number; height: number } | null>(null);
  useLayoutEffect(() => {
    if (scrollAnchor.current && eventBox.current) {
      eventBox.current.scrollTop = scrollAnchor.current.top + eventBox.current.scrollHeight - scrollAnchor.current.height;
      scrollAnchor.current = null;
    }
  }, [events]);
  const mergeEvents = (incoming: AuditEvent[]) =>
    setEvents((current) => {
      const merged = new Map(current.map((event) => [event.id, event]));
      for (const event of incoming) merged.set(event.id, event);
      return [...merged.values()].sort((a, b) => a.id - b.id);
    });
  const loadDetail = useCallback(
    async (poll = false) => {
      if (poll && detailRequest.current) return;
      detailRequest.current?.abort();
      const abort = new AbortController();
      detailRequest.current = abort;
      try {
        const value = await readApi<TrialDetail>(`${trialPath(experiment.id, trial.id)}${attemptSuffix}`, {
          signal: abort.signal,
        });
        if (abort.signal.aborted) return;
        setDetail(value);
        setError(null);
        if (!cursorReady.current && value.run?.id) {
          const initialEvents = value.events ?? [];
          mergeEvents(initialEvents);
          eventCursor.current = value.event_cursor ?? initialEvents.reduce((max, event) => Math.max(max, event.id), 0);
          earliestCursor.current = initialEvents.reduce((min, event) => Math.min(min, event.id), Infinity);
          cursorReady.current = true;
          setRemaining(value.has_earlier ?? initialEvents.length >= 100);
        }
      } catch (exc) {
        if (!abort.signal.aborted) setError(errorText(exc));
      } finally {
        if (detailRequest.current === abort) detailRequest.current = null;
      }
    },
    [experiment.id, trial.id, attemptSuffix],
  );
  useEffect(() => {
    setDetail(null);
    setError(null);
    setEvidence(null);
    setEvents([]);
    setRemaining(false);
    eventCursor.current = 0;
    earliestCursor.current = 0;
    cursorReady.current = false;
    scrollAnchor.current = null;
    return () => {
      detailRequest.current?.abort();
      eventRequest.current?.abort();
      earlierRequest.current?.abort();
    };
  }, [experiment.id, trial.id, attemptNumber]);
  useEffect(() => {
    void loadDetail();
  }, [loadDetail, refresh]);
  const loadNewEvents = useCallback(async () => {
    if (!cursorReady.current || eventRequest.current || !(trial.run_id || detail?.run?.id)) return;
    const abort = new AbortController();
    eventRequest.current = abort;
    try {
      // Drain bounded pages in order; never advance this cursor from a later snapshot.
      for (let page = 0; page < 4; page++) {
        const value = await readApi<{ events: AuditEvent[]; remaining: boolean | number }>(
          `${trialPath(experiment.id, trial.id)}/events?after=${eventCursor.current}&limit=200${attemptNumber ? `&attempt=${attemptNumber}` : ''}`,
          { signal: abort.signal },
        );
        if (abort.signal.aborted) return;
        mergeEvents(value.events);
        eventCursor.current = value.events.reduce((max, event) => Math.max(max, event.id), eventCursor.current);
        if (!value.remaining || !value.events.length) break;
      }
    } catch (exc) {
      if (!abort.signal.aborted) setError(errorText(exc));
    } finally {
      if (eventRequest.current === abort) eventRequest.current = null;
    }
  }, [experiment.id, trial.id, trial.run_id, detail?.run?.id, attemptNumber]);
  useEffect(() => {
    const poll = () => {
      if (!document.hidden) {
        void loadDetail(true);
        void loadNewEvents();
      }
    };
    const running = activeStatus(selectedSaved?.status ?? trial.status);
    const timer = running ? window.setInterval(poll, 3000) : undefined;
    const visible = () => {
      if (!document.hidden) poll();
    };
    document.addEventListener('visibilitychange', visible);
    return () => {
      if (timer !== undefined) window.clearInterval(timer);
      document.removeEventListener('visibilitychange', visible);
    };
  }, [selectedSaved?.status, trial.status, loadDetail, loadNewEvents]);
  const loadEarlier = async () => {
    if (earlierRequest.current || !earliestCursor.current || !Number.isFinite(earliestCursor.current)) return;
    const abort = new AbortController();
    earlierRequest.current = abort;
    setLoadingEvents(true);
    try {
      const value = await readApi<{ events: AuditEvent[]; remaining: boolean | number; has_earlier?: boolean }>(
        `${trialPath(experiment.id, trial.id)}/events?before=${earliestCursor.current}&limit=100${attemptNumber ? `&attempt=${attemptNumber}` : ''}`,
        { signal: abort.signal },
      );
      if (abort.signal.aborted) return;
      if (eventBox.current) scrollAnchor.current = { top: eventBox.current.scrollTop, height: eventBox.current.scrollHeight };
      mergeEvents(value.events);
      earliestCursor.current = value.events.reduce((min, event) => Math.min(min, event.id), earliestCursor.current);
      setRemaining(value.has_earlier ?? Boolean(value.remaining));
    } catch (exc) {
      if (!abort.signal.aborted) setError(errorText(exc));
    } finally {
      if (earlierRequest.current === abort) earlierRequest.current = null;
      if (!abort.signal.aborted) setLoadingEvents(false);
    }
  };
  const selectedAttempt = detail?.attempt ?? selectedSaved;
  const isCurrentAttempt = !attemptNumber || Number(attemptNumber) === trial.attempts?.at(-1)?.attempt_no;
  const score = detail ? detail.score : isCurrentAttempt ? trial.score : null;
  const usage = selectedAttempt?.usage ?? (isCurrentAttempt ? trial.usage : undefined);
  const duration =
    selectedAttempt?.audit_elapsed_seconds ??
    selectedAttempt?.duration_seconds ??
    (isCurrentAttempt ? (trial.audit_elapsed_seconds ?? trial.duration_seconds) : undefined);
  const wallDuration = selectedAttempt?.wall_elapsed_seconds ?? (isCurrentAttempt ? trial.wall_elapsed_seconds : undefined);
  const coverage = detail?.read_coverage ?? detail?.trial?.read_coverage ?? trial.read_coverage;
  const phase = detail?.run?.execution_summary?.phase;
  const canRetry =
    trial.can_retry ??
    ((trial.evaluation_status === 'invalid' || trial.status === 'not_started') &&
      (trial.attempts?.length ?? 0) < 2 &&
      !activeStatus(experiment.status));
  return (
    <section className="exp-trial-detail" aria-label="试次详情">
      <div className="exp-filter-row">
        <h3>
          第 {trial.round_index} 轮 · {labelOf(experiment, trial.prompt_id)}
        </h3>
        <span className="chip">{stateLabel(selectedAttempt?.status ?? trial.status)}</span>
        <span className="chip">{stateLabel(selectedAttempt?.evaluation_status ?? trial.evaluation_status)}</span>
        {(trial.attempts?.length ?? 0) > 0 && (
          <label>
            查看执行版本
            <select
              aria-label="查看执行版本"
              value={attemptNumber || String(trial.attempts?.at(-1)?.attempt_no ?? '')}
              onChange={(event) => change({ attempt: event.target.value })}
            >
              {trial.attempts?.map((item, index) => (
                <option key={item.id ?? index} value={item.attempt_no ?? index + 1}>
                  第 {item.attempt_no ?? index + 1} 次{index === (trial.attempts?.length ?? 0) - 1 ? '（当前）' : '（历史）'}
                </option>
              ))}
            </select>
          </label>
        )}
        <button className="btn" onClick={() => setRefresh((value) => value + 1)}>
          刷新试次
        </button>
        {canRetry && (
          <button className="btn" disabled={busy} onClick={() => onRetry(trial.id)}>
            使用冻结配置补跑一次
          </button>
        )}
        <a
          className="btn"
          href={downloadUrl(
            `${trialPath(experiment.id, trial.id)}/report?format=markdown${attemptNumber ? `&attempt=${attemptNumber}` : ''}`,
          )}
        >
          试次报告
        </a>
      </div>
      <p className="small muted">
        {trial.id} ·{' '}
        {reasonText(selectedAttempt?.stop_reason || selectedAttempt?.error) || trialReason(trial) || '尚未记录终止原因'}
        。预算耗尽仍属有效成绩；无效试次保留历史和消耗。
      </p>
      {trial.retry_reason && !canRetry && <p className="small muted">补跑限制：{trial.retry_reason}</p>}
      {error && (
        <div className="error-box" role="alert">
          试次读取失败：{error}
        </div>
      )}
      {!detail && !error && <div className="empty">读取试次记录…</div>}
      <p className="small muted">
        实际消耗：模型请求 {numeric(usage?.requests)} · 工具 {numeric(usage?.tool_calls)} · tokens{' '}
        {numeric(usage?.total_tokens ?? usage?.tokens)}。审计计时 {formatDuration(duration)}；试次总墙钟{' '}
        {formatDuration(wallDuration)}（含准备与收尾）
      </p>
      {phase && (
        <p className="small muted">
          实际执行阶段：{executionPhase(phase)}（{phase}）
        </p>
      )}
      {coverage?.total_files != null && (
        <div className="exp-notice small">
          实际读取：{coverage.read_files} / {coverage.total_files} 个文件（{percent(coverage.file_ratio)}），{coverage.read_lines}{' '}
          / {coverage.total_lines} 行（{percent(coverage.line_ratio)}）。候选范围为完整源码，读取覆盖不表示每行均完成漏洞检查。
        </div>
      )}
      {score && (
        <div className="row exp-trial-numbers">
          <span>TP {score.TP}</span>
          <span>D {score.D}</span>
          <span>U {score.U}</span>
          <span>FN {score.FN}</span>
          <span>P {percent(score.precision)}</span>
          <span>R {percent(score.recall)}</span>
          <span>F1 {percent(score.f1)}</span>
        </div>
      )}
      {(trial.attempts?.length ?? 0) > 0 && (
        <Disclosure title="执行与补跑历史">
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Attempt</th>
                  <th>运行状态</th>
                  <th>有效性</th>
                  <th>原因</th>
                </tr>
              </thead>
              <tbody>
                {trial.attempts?.map((attempt, index) => (
                  <tr key={attempt.id ?? index}>
                    <td>{attempt.attempt_no ?? index + 1}</td>
                    <td>{stateLabel(attempt.status)}</td>
                    <td>{stateLabel(attempt.evaluation_status)}</td>
                    <td>{reasonText(attempt.termination_reason || attempt.stop_reason || attempt.error) || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Disclosure>
      )}
      {detail && (
        <>
          <h4>本次运行的发现与证据</h4>
          {!detail.findings?.length && <p className="small muted">本次没有正式发现记录；这不意味着源码安全。</p>}
          {detail.findings?.map((finding) => <FindingEvidence key={finding.id} finding={finding} onEvidence={setEvidence} />)}
          {evidence && (
            <ScopedSource experimentId={experiment.id} trialId={trial.id} evidence={evidence} attempt={attemptNumber} />
          )}
          <Disclosure title="匹配、重复、未匹配及分类诊断">
            <pre className="tl-detail">
              {JSON.stringify(
                {
                  matches: score?.matches,
                  duplicates: score?.duplicates,
                  unmatched: score?.unmatched,
                  diagnostics: score?.diagnostics,
                  truth_results: score?.truth_results,
                },
                null,
                2,
              )}
            </pre>
          </Disclosure>
          <Disclosure title={`实际审计日志 · ${events.length} 条`}>
            <div className="exp-events" ref={eventBox} tabIndex={0} aria-label="试次审计事件">
              {events.map((event) => (
                <details key={event.id}>
                  <summary>
                    <span className="mono">#{event.id}</span> {event.actor_role || 'host'} · {event.kind}{' '}
                    <span className="muted">{localDate(event.created_at)}</span>
                  </summary>
                  <pre className="tl-detail">{JSON.stringify(event.payload, null, 2)}</pre>
                </details>
              ))}
            </div>
            {remaining && (
              <button className="btn" disabled={loadingEvents} onClick={() => void loadEarlier()}>
                {loadingEvents ? '读取中…' : '读取更早事件'}
              </button>
            )}
          </Disclosure>
        </>
      )}
    </section>
  );
}

function FindingEvidence({ finding, onEvidence }: { finding: Finding; onEvidence: (value: Evidence) => void }) {
  return (
    <Disclosure title={`${finding.title} · ${finding.vulnerability_type || finding.category || 'unknown'}`}>
      <p>{finding.summary}</p>
      <p className="small muted">
        发现 {finding.id} · {finding.disposition || 'open'} · {finding.validation_state}
      </p>
      {finding.primary_location && (
        <p className="small mono">
          主定位：{finding.primary_location.path}:{finding.primary_location.line}
        </p>
      )}
      <div className="row exp-downloads">
        {finding.evidence?.map((item, index) => (
          <button key={index} className="btn" onClick={() => onEvidence(item)}>
            {item.path}:{item.start_line}–{item.end_line}
          </button>
        ))}
      </div>
      <p className="small">输入来源：{finding.input_source || '未填写'}</p>
      <p className="small">传播路径：{finding.propagation || '未填写'}</p>
      <p className="small">关键操作：{finding.dangerous_operation || '未填写'}</p>
      <p className="small">防护核对：{finding.protection || '未填写'}</p>
    </Disclosure>
  );
}

function TrialsPanel({
  experiment,
  selectedId,
  onSelect,
  onRetry,
  busy,
}: {
  experiment: FullExperiment;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onRetry: (id: string) => void;
  busy: boolean;
}) {
  const trial = experiment.trials?.find((item) => item.id === selectedId);
  return (
    <div className="grid exp-content">
      <div className="table-scroll">
        <table>
          <caption>逐轮成绩与终止原因 · 所有 attempts 均保留</caption>
          <thead>
            <tr>
              <th>轮次／版本</th>
              <th>运行状态</th>
              <th>有效性</th>
              <th>TP/D/U/FN</th>
              <th>P/R/F1</th>
              <th>停止原因</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {experiment.trials?.map((item) => (
              <tr key={item.id} className={selectedId === item.id ? 'selected' : ''}>
                <th scope="row">
                  第 {item.round_index} 轮 · {labelOf(experiment, item.prompt_id)}
                </th>
                <td>{stateLabel(item.status)}</td>
                <td>{stateLabel(item.evaluation_status)}</td>
                <td>{item.score ? `${item.score.TP}/${item.score.D}/${item.score.U}/${item.score.FN}` : '—'}</td>
                <td>
                  {item.score
                    ? `${percent(item.score.precision)} / ${percent(item.score.recall)} / ${percent(item.score.f1)}`
                    : '—'}
                </td>
                <td className="exp-reason">{trialReason(item) || '—'}</td>
                <td>
                  <button className="text-button" onClick={() => onSelect(item.id)}>
                    查看试次
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {selectedId && !trial && <div className="exp-notice">此试次不属于当前实验或记录已缺失，请从上表选择。</div>}
      {trial && <TrialInspector key={trial.id} experiment={experiment} trial={trial} onRetry={onRetry} busy={busy} />}
    </div>
  );
}

function LegacyResults({ record }: { record: ExperimentRecord }) {
  if (isFullExperiment(record)) return null;
  return (
    <div className="exp-content grid">
      <div className="exp-notice exp-notice-warn">
        <strong>旧版单元协议 · 只读</strong>
        <p>此记录使用预选文件及单次单元实验，不能与全源码限时审计协议混排。历史结果不重算。</p>
      </div>
      <p className="small">
        {record.variants?.join(' / ')} · {record.units_limit ? `前 ${record.units_limit} 个单元` : '全部单元'} ·{' '}
        {recordModel(record)}
      </p>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>版本</th>
              <th>TP</th>
              <th>FP</th>
              <th>FN</th>
              <th>Precision</th>
              <th>Recall</th>
              <th>F1</th>
            </tr>
          </thead>
          <tbody>
            {record.rows?.map((row) => (
              <tr key={row.variant}>
                <th>{row.variant}</th>
                <td>{row.score?.TP ?? '—'}</td>
                <td>{row.score?.FP ?? '—'}</td>
                <td>{row.score?.FN ?? '—'}</td>
                <td>{percent(row.score?.precision)}</td>
                <td>{percent(row.score?.recall)}</td>
                <td>{percent(row.score?.f1)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Downloads id={record.id} legacy />
      {record.progress?.tail?.length ? (
        <Disclosure title="历史日志">
          <pre className="tl-detail">{record.progress.tail.join('\n')}</pre>
        </Disclosure>
      ) : null}
    </div>
  );
}

export function PromptExperimentsView({ experimentId }: { experimentId?: string }) {
  const [prompts, setPrompts] = useState<Prompt[]>([]),
    [selected, setSelected] = useState<string[]>([]),
    [baseline, setBaseline] = useState(''),
    [repeats, setRepeats] = useState(3),
    [budgets, setBudgets] = useState(initialBudgets),
    [limits, setLimits] = useState(initialLimits);
  const [history, setHistory] = useState<ExperimentRecord[]>([]),
    [current, setCurrent] = useState<ExperimentRecord | null>(null),
    [error, setError] = useState<string | null>(null),
    [busy, setBusy] = useState(false),
    [loading, setLoading] = useState(false),
    [refresh, setRefresh] = useState(0);
  const catalogRequest = useRef<AbortController | null>(null);
  const historyRequest = useRef<AbortController | null>(null);
  const detailRequest = useRef<AbortController | null>(null);
  const mutationRequest = useRef<AbortController | null>(null);
  const alive = useRef(true),
    initialized = useRef(false);
  const [readErrors, setReadErrors] = useState<Record<string, string>>({});
  const { query, change } = useQuery();
  const strategies = useMemo(() => compatibleStrategies(prompts), [prompts]);
  const active = history.find((item) => activeStatus(item.status));
  const running = Boolean(active || (current && activeStatus(current.status)));
  const updateReadError = (channel: string, message?: string) =>
    setReadErrors((previous) => {
      const next = { ...previous };
      if (message) next[channel] = message;
      else delete next[channel];
      return next;
    });
  const loadCatalog = useCallback(async () => {
    catalogRequest.current?.abort();
    const abort = new AbortController();
    catalogRequest.current = abort;
    try {
      const catalog = await readApi<Prompt[]>('/prompts?kind=worker_strategy', { signal: abort.signal });
      if (!alive.current || abort.signal.aborted) return;
      setPrompts(catalog);
      updateReadError('catalog');
      if (!initialized.current && catalog.length) {
        const defaults = defaultStrategies(catalog);
        setSelected(defaults);
        setBaseline(defaults[0] ?? '');
        initialized.current = true;
      }
    } catch (exc) {
      if (alive.current && !abort.signal.aborted) updateReadError('catalog', `策略库：${errorText(exc)}`);
    } finally {
      if (catalogRequest.current === abort) catalogRequest.current = null;
    }
  }, []);
  const loadHistory = useCallback(async (poll = false) => {
    if (poll && historyRequest.current) return;
    historyRequest.current?.abort();
    const abort = new AbortController();
    historyRequest.current = abort;
    try {
      const records = await readApi<ExperimentRecord[]>('/prompt-experiments', { signal: abort.signal });
      if (!alive.current || abort.signal.aborted) return;
      setHistory(records);
      updateReadError('history');
    } catch (exc) {
      if (alive.current && !abort.signal.aborted) updateReadError('history', `实验历史：${errorText(exc)}`);
    } finally {
      if (historyRequest.current === abort) historyRequest.current = null;
      if (!abort.signal.aborted) setLoading(false);
    }
  }, []);
  const loadDetail = useCallback(
    async (poll = false) => {
      if (!experimentId || (poll && detailRequest.current)) return;
      detailRequest.current?.abort();
      const abort = new AbortController();
      detailRequest.current = abort;
      try {
        const detail = await readApi<ExperimentRecord>(experimentPath(experimentId), { signal: abort.signal });
        if (!alive.current || abort.signal.aborted) return;
        setCurrent(detail);
        updateReadError('detail');
      } catch (exc) {
        if (alive.current && !abort.signal.aborted) updateReadError('detail', `实验详情：${errorText(exc)}`);
      } finally {
        if (detailRequest.current === abort) detailRequest.current = null;
      }
    },
    [experimentId],
  );
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      catalogRequest.current?.abort();
      historyRequest.current?.abort();
      detailRequest.current?.abort();
      mutationRequest.current?.abort();
    };
  }, []);
  useEffect(() => {
    setCurrent(null);
    setReadErrors({});
    setError(null);
    mutationRequest.current?.abort();
    return () => detailRequest.current?.abort();
  }, [experimentId]);
  useEffect(() => {
    setLoading(true);
    void loadCatalog();
    void loadHistory();
    void loadDetail();
  }, [loadCatalog, loadHistory, loadDetail, refresh]);
  useEffect(() => {
    const poll = () => {
      if (!document.hidden) {
        void loadHistory(true);
        void loadDetail(true);
      }
    };
    const shouldPoll = running || Boolean(experimentId && !current) || (!initialized.current && history.length === 0);
    const timer = shouldPoll ? window.setInterval(poll, 3000) : undefined;
    const visible = () => {
      if (!document.hidden) {
        poll();
        if (!prompts.length) void loadCatalog();
      }
    };
    document.addEventListener('visibilitychange', visible);
    return () => {
      if (timer !== undefined) window.clearInterval(timer);
      document.removeEventListener('visibilitychange', visible);
    };
  }, [running, experimentId, Boolean(current), history.length, prompts.length, loadHistory, loadDetail, loadCatalog]);
  const failure = error || Object.values(readErrors).filter(Boolean).join('；');
  const mutate = async (path: string, body: unknown) => {
    if (busy) return;
    const abort = new AbortController();
    mutationRequest.current = abort;
    setBusy(true);
    setError(null);
    try {
      const value = await api<ExperimentRecord>(path, { method: 'POST', body: JSON.stringify(body), signal: abort.signal });
      if (!alive.current || abort.signal.aborted) return;
      if (value?.id && value.id !== experimentId) window.location.hash = `#experiments/${encodeURIComponent(value.id)}`;
      else setRefresh((old) => old + 1);
    } catch (exc) {
      if (alive.current && !abort.signal.aborted) setError(errorText(exc));
    } finally {
      if (mutationRequest.current === abort) mutationRequest.current = null;
      if (alive.current) setBusy(false);
    }
  };
  const start = () =>
    validBudgets &&
    void mutate('/prompt-experiments', {
      protocol: PROMPT_PROTOCOL,
      prompt_ids: selected,
      baseline_prompt_id: baseline,
      repeats,
      budgets,
      run_limits: limits,
      experiment_wall_seconds: 7200,
    });
  const toggle = (id: string) => {
    const next = selected.includes(id) ? selected.filter((item) => item !== id) : [...selected, id];
    setSelected(next);
    if (!next.includes(baseline)) setBaseline(next[0] ?? '');
  };
  const full = current && isFullExperiment(current) ? current : null,
    tab = ['overview', 'findings', 'prompts', 'trials'].includes(query.get('tab') ?? '') ? query.get('tab')! : 'overview',
    selectedTrial = full?.trials?.find((item) => item.id === query.get('trial')),
    maxCalls = selected.length * repeats * limits.responses,
    maxTools = selected.length * repeats * limits.tools,
    budgetCheck = experimentBudgetCheck(selected.length, repeats, limits.seconds),
    validBudgets = budgetCheck.valid && budgets.seconds <= 720 && budgets.seconds <= limits.seconds;
  return (
    <div className="exp-page grid">
      {failure && (
        <div className="error-box" role="alert">
          {failure}{' '}
          <button className="text-button" onClick={() => setRefresh((value) => value + 1)}>
            重试读取
          </button>
        </div>
      )}
      {active && active.id !== experimentId && (
        <div className="exp-notice">
          另有实验正在执行，当前不能再启动。<a href={`#experiments/${encodeURIComponent(active.id)}`}>查看进行中的实验</a>
        </div>
      )}
      {!experimentId ? (
        <section className="panel">
          <div className="panel-head">
            <h2 className="panel-title">限时审计对比设置</h2>
            <span className="chip">lab30-full-v2</span>
          </div>
          <div className="exp-content grid">
            <p className="muted small">
              固定原始 Lab30 ZIP、模型、Planner 与证据门禁，只改变 Worker
              策略。各版本独立执行全源码范围的限时审计，真值仅用于审计结束后评分。主实验关闭 POC。
            </p>
            <fieldset className="exp-variants">
              <legend>选择 2–5 个兼容策略版本</legend>
              {strategies.map((item) => (
                <label className="exp-variant-option" key={item.id}>
                  <input
                    type="checkbox"
                    checked={selected.includes(item.id)}
                    disabled={running || busy || (!selected.includes(item.id) && selected.length >= 5)}
                    onChange={() => toggle(item.id)}
                  />
                  <span>
                    <strong>{item.label}</strong>
                    <small className="muted">
                      {item.id} · {item.reason || '未填写优化原因'}
                    </small>
                  </span>
                </label>
              ))}
              {!strategies.length && (
                <p className="muted small">
                  {loading ? '正在读取策略库…' : '没有兼容策略。请先在提示词库新建 worker-strategy-v1 版本。'}
                </p>
              )}
            </fieldset>
            <div className="exp-filter-row">
              <label>
                冻结基线
                <select
                  aria-label="冻结基线"
                  value={baseline}
                  disabled={running || busy}
                  onChange={(event) => setBaseline(event.target.value)}
                >
                  {!selected.length && <option value="">先选择版本</option>}
                  {selected.map((id) => (
                    <option key={id} value={id}>
                      {strategies.find((item) => item.id === id)?.label ?? id}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                每版本重复次数
                <input
                  aria-label="每版本重复次数"
                  type="number"
                  min={1}
                  max={5}
                  value={repeats}
                  disabled={running || busy}
                  onChange={(event) => setRepeats(Math.max(1, Math.min(5, Number(event.target.value) || 1)))}
                />
              </label>
              <a className="btn" href="#prompts">
                管理与派生策略
              </a>
            </div>
            <Disclosure title="统一预算设置">
              <BudgetFields title="单次调用预算" value={budgets} onChange={setBudgets} disabled={running || busy} />
              <BudgetFields title="每次限时审计总预算" value={limits} onChange={setLimits} disabled={running || busy} />
            </Disclosure>
            <div className="exp-notice">
              <strong>
                {selected.length} 个版本 × {repeats} 轮 = {selected.length * repeats} 次限时审计
              </strong>
              <p>
                初始批次硬上限 7200 秒；计划占用 {budgetCheck.requiredSeconds} 秒（含每试次 60 秒收尾与批次 180 秒预留）。累计上限{' '}
                {maxCalls.toLocaleString()} 次模型请求、{maxTools.toLocaleString()} 次工具调用；每次最多 {limits.seconds}{' '}
                秒。执行会真实消耗模型额度，失败及取消也可能产生消耗。
              </p>
            </div>
            {!validBudgets && (
              <div className="error-box" role="alert">
                时间预算不符合两小时上限：每次审计和单次执行均不得超过 720 秒，单次执行不得超过整次审计；{budgetCheck.trials} ×（
                {limits.seconds} + 60）+ 180 = {budgetCheck.requiredSeconds} 秒，必须不超过 7200
                秒。减少重复次数或每次审计秒数后再创建。
              </div>
            )}
            <div className="row exp-downloads">
              <button
                className="btn btn-primary"
                disabled={busy || running || selected.length < 2 || selected.length > 5 || !baseline || !validBudgets}
                onClick={start}
              >
                {busy ? '正在创建…' : running ? '已有实验运行中' : '冻结配置并开始对比'}
              </button>
              <span className="small muted">各轮循环移位、串行执行，默认三版三轮；初始批次最多两小时。</span>
            </div>
          </div>
        </section>
      ) : null}
      {experimentId && !current && !failure && (
        <div className="empty" role="status">
          读取冻结实验及成绩…
        </div>
      )}
      {current && (
        <section className="panel exp-results">
          <div className="panel-head exp-result-head">
            <div>
              <span className="eyebrow">{full ? 'TIMED SOURCE AUDIT' : 'LEGACY UNIT EXPERIMENT'}</span>
              <h2 className="panel-title">{recordModel(current)}</h2>
              <p className="small muted">
                {localDate(current.created_at)} · <span className="mono">{current.id}</span>
              </p>
            </div>
            <div className="row exp-downloads">
              <span className="chip">{stateLabel(current.status)}</span>
              <a className="btn" href="#experiments">
                新建实验
              </a>
              {activeStatus(current.status) && (
                <button
                  className="btn btn-danger"
                  disabled={busy}
                  onClick={() => void mutate(`${experimentPath(current.id)}/cancel`, {})}
                >
                  取消实验
                </button>
              )}
            </div>
          </div>
          {current.error && (
            <div className="error-box" role="alert">
              {current.error}
            </div>
          )}
          {full ? (
            <>
              <div className="exp-tabs" role="tablist" aria-label="实验结果页签">
                {[
                  ['overview', '效果总览'],
                  ['findings', '漏洞明细'],
                  ['prompts', '版本与冻结条件'],
                  ['trials', '逐轮运行记录'],
                ].map(([key, label]) => (
                  <button
                    role="tab"
                    key={key}
                    aria-selected={tab === key}
                    className={tab === key ? 'active' : ''}
                    onClick={() => change({ tab: key })}
                  >
                    {label}
                  </button>
                ))}
              </div>
              {(activeStatus(full.status) || Boolean(full.progress?.timing?.batches?.length)) && (
                <LiveExperiment experiment={full} onOpen={(id) => change({ tab: 'trials', trial: id, attempt: null })} />
              )}
              {tab === 'overview' && <SummaryPanel experiment={full} />}{' '}
              {tab === 'findings' && <TruthMatrix experiment={full} query={query} change={change} />}{' '}
              {tab === 'prompts' && (
                <FrozenPrompts
                  experiment={full}
                  compare={query.get('compare') ?? ''}
                  onCompare={(value) => change({ compare: value })}
                />
              )}
              {tab === 'trials' && (
                <TrialsPanel
                  experiment={full}
                  selectedId={query.get('trial')}
                  onSelect={(id) => change({ trial: id, attempt: null })}
                  busy={busy}
                  onRetry={(id) => void mutate(`${trialPath(full.id, id)}/retry`, {})}
                />
              )}
              {tab === 'findings' && selectedTrial && (
                <div className="exp-content">
                  <TrialInspector
                    key={selectedTrial.id}
                    experiment={full}
                    trial={selectedTrial}
                    busy={busy}
                    onRetry={(id) => void mutate(`${trialPath(full.id, id)}/retry`, {})}
                  />
                </div>
              )}
              <div className="exp-content exp-export">
                <h3>下载完整实验</h3>
                <p className="small muted">下载包含全部版本与轮次，不受当前类别筛选影响。未完成实验在报告中明确标记。</p>
                <Downloads id={full.id} />
              </div>
            </>
          ) : (
            <LegacyResults record={current} />
          )}
        </section>
      )}
      <section className="panel">
        <div className="panel-head">
          <h2 className="panel-title">实验历史</h2>
          <span className="small muted">{history.length} 条 · 新旧协议分别展示</span>
        </div>
        <div className="exp-content grid">
          {!history.length && !loading && <p className="empty">尚无实验。选择策略与基线后开始限时审计对比。</p>}
          {[true, false].map((newProtocol) => {
            const items = history.filter((item) => isFullExperiment(item) === newProtocol);
            return items.length ? (
              <div key={String(newProtocol)}>
                <h3>{newProtocol ? '全源码范围的限时审计' : '旧版单元实验（只读）'}</h3>
                <div className="grid">
                  {items.map((item) => (
                    <a
                      key={item.id}
                      className={`exp-history-row${current?.id === item.id ? ' selected' : ''}`}
                      href={`#experiments/${encodeURIComponent(item.id)}`}
                    >
                      <span className="chip">{stateLabel(item.status)}</span>
                      <strong>{recordModel(item)}</strong>
                      <span className="small muted">
                        {localDate(item.created_at)} ·{' '}
                        {isFullExperiment(item)
                          ? `${item.manifest?.variants?.length ?? 0} 版 × ${item.manifest?.repeats ?? 0} 轮`
                          : '旧版单元协议'}{' '}
                        · {item.id.slice(0, 12)}
                      </span>
                    </a>
                  ))}
                </div>
              </div>
            ) : null;
          })}
        </div>
      </section>
    </div>
  );
}
function BudgetFields({
  title,
  value,
  onChange,
  disabled,
}: {
  title: string;
  value: Budget;
  onChange: (value: Budget) => void;
  disabled: boolean;
}) {
  return (
    <fieldset className="exp-budget">
      <legend>{title}</legend>
      {(
        [
          ['responses', '模型请求'],
          ['tools', '工具调用'],
          ['seconds', '秒'],
        ] as const
      ).map(([key, label]) => (
        <label key={key}>
          {label}
          <input
            type="number"
            min={1}
            aria-label={`${title}${label}`}
            disabled={disabled}
            value={value[key]}
            onChange={(event) => onChange({ ...value, [key]: Math.max(1, Math.floor(Number(event.target.value) || 1)) })}
          />
        </label>
      ))}
    </fieldset>
  );
}
