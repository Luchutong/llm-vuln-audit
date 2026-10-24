import type { DefenceScore } from '../types';

/**
 * The defence score, with its ingredients.
 *
 * Printing a single number would invite the reading "the audit is 87% trustworthy".  What
 * the page shows instead is which mechanism produced each rate and which one was not
 * measured at all: POC switched off and no benchmark run are faults of the setup, not
 * evidence of good behaviour, so they are named rather than folded in as zero.
 */
const SOURCE_LABELS: Record<string, string> = {
  run: '本次运行',
  benchmark: '基准实验',
};

function rate(value: number | null | undefined): string {
  return value === null || value === undefined ? '未测量' : value.toFixed(3);
}

/** A short, colour-free verdict on the total; the number alone has no scale. */
function verdict(score: number | null, missing: string[]): string {
  if (score === null) return '没有可计算的成分：本次运行没有候选结论，也没有可用的基准实验。';
  const caution = missing.length ? `，其中 ${missing.length} 项未测量（不入总分）` : '';
  if (score >= 0.9) return `各项防御都给出了支撑${caution}。`;
  if (score >= 0.7) return `多数成分给出了支撑，个别环节偏弱${caution}。`;
  if (score >= 0.4) return `有相当比例的结论没有通过自身的防御检查${caution}。`;
  return `大部分结论没有通过自身的防御检查${caution}，结论应谨慎引用。`;
}

export function DefencePanel({ defence, compact = false }: { defence: DefenceScore | null | undefined; compact?: boolean }) {
  if (!defence) {
    return <p className="small faint">本次运行没有防御评分数据（历史记录早于该评分）。</p>;
  }
  const missing = defence.missing ?? [];
  const score = defence.score ?? null;
  return <div className="grid">
    <div className="between">
      <div>
        <span className="eyebrow">DEFENCE SCORE</span>
        <div style={{ fontSize: 30, fontWeight: 600, letterSpacing: '-.5px' }}>
          {score === null ? '—' : score.toFixed(3)}
        </div>
      </div>
      <span className="faint small">
        {defence.components.length - missing.length}/{defence.components.length} 项已测量 · 权重分母 {defence.denominator_weight}
      </span>
    </div>
    <p className="small muted" style={{ margin: 0 }}>{verdict(score, missing)}</p>

    {compact ? (
      <div className="row small" style={{ gap: 8, flexWrap: 'wrap' }}>
        {defence.components.map((item) => (
          <span key={item.key} className="chip" title={item.detail}>
            {item.label} {rate(item.value)}
          </span>
        ))}
      </div>
    ) : (
      <div className="table-scroll">
        <table style={{ minWidth: 720 }}>
          <thead>
            <tr>
              <th>成分</th><th>来源</th><th>权重</th><th>取值</th><th>说明</th>
            </tr>
          </thead>
          <tbody>
            {defence.components.map((item) => (
              <tr key={item.key}>
                <td>{item.label}</td>
                <td><span className="chip">{SOURCE_LABELS[item.source] ?? item.source}</span></td>
                <td>{item.weight}</td>
                <td className="mono small" style={{ color: item.value === null ? 'var(--warn)' : undefined }}>
                  {rate(item.value)}
                </td>
                <td className="small muted">{item.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}

    {!compact && <>
      {missing.length > 0 && <p className="small" style={{ color: 'var(--warn)', margin: 0 }}>
        未计入总分的成分：{missing.join('、')}。缺失不按 0 分代入，总分按剩余权重归一化。
      </p>}
      <p className="small muted" style={{ margin: 0 }}>
        {defence.benchmark?.experiment_id
          ? <>注入抵抗与证据链完整率来自 Prompt 对比实验 <span className="mono">{defence.benchmark.experiment_id}</span>
            （{(defence.benchmark.variants ?? []).join('、') || '未记录版本'}）的均值，衡量的是提示词本身，不是这一次扫描。</>
          : '还没有完成的 Prompt 对比实验，因此注入抵抗与证据链完整率两项没有数值；到「Prompt 实验」跑一次即可补齐。'}
      </p>
      <p className="small muted" style={{ margin: 0 }}>{defence.note}</p>
    </>}
  </div>;
}
