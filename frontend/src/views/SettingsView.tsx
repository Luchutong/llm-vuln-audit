import { useState } from 'react';
import { api, errorText, post } from '../api';
import type { Config } from '../types';

interface HealthSnapshot {
  status: string;
  fails: number;
  trips: number;
  cooldown_seconds: number;
  last_error?: string | null;
  last_at?: number | null;
}

interface CheckResult {
  ok: boolean;
  model?: string;
  latency_ms?: number;
  reply?: string;
  error?: string;
}

// These keys are the ones the server actually sends (`ok` / `degraded` / `tripped`); a
// healthy breaker was rendering as the raw string "ok" in the "uncertain" style because
// this map had been written against a `healthy` that never existed.
const HEALTH_LABELS: Record<string, string> = {
  ok: '正常',
  healthy: '正常',
  degraded: '降级',
  tripped: '已熔断',
  unknown: '未知',
};

function healthTone(status: string | undefined) {
  if (status === 'ok' || status === 'healthy') return 'chip-confirmed';
  if (status === 'tripped') return 'chip-failed';
  return 'chip-uncertain';
}

/**
 * Model configuration.
 *
 * The key is read from the server's environment and is never sent to the browser — the
 * page only ever shows a masked hint. "Check connection" performs one real minimal model
 * call, because an endpoint that answers the health probe while returning empty replies
 * is exactly the failure this page needs to catch.
 */
export function SettingsView({ config, onChanged }: { config: Config | null; onChanged: () => void }) {
  const [result, setResult] = useState<CheckResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!config) return <div className="empty">载入配置…</div>;

  const health = (config as Config & { model_health?: HealthSnapshot }).model_health;

  const check = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult(await post<CheckResult>('/config/check', {}));
      onChanged();
    } catch (exc) {
      setError(errorText(exc));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', alignItems: 'start' }}>
      {error && <div className="error-box" style={{ gridColumn: '1 / -1' }}>{error}</div>}

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">模型连接</span>
          <span className={`chip ${config.configured ? 'chip-confirmed' : 'chip-failed'}`}>
            {config.configured ? '已配置' : '缺少配置'}
          </span>
        </div>
        <div style={{ padding: '12px 16px' }}>
          <div className="field">
            <span className="field-label">模型</span>
            <span className="mono small">{config.model || '—'}</span>
          </div>
          <div className="field">
            <span className="field-label">Base URL</span>
            <span className="mono small">{config.base_url || '—'}</span>
          </div>
          <div className="field">
            <span className="field-label">API Key</span>
            <span className="mono small">{(config as Config & { api_key_hint?: string }).api_key_hint || '—'}</span>
            <span className="field-hint">密钥只从服务端环境变量读取，不通过接口下发，也不写入快照或报告。</span>
          </div>
          {((config as Config & { missing?: string[] }).missing ?? []).length > 0 && (
            <div className="error-box" style={{ marginBottom: 10 }}>
              缺少环境变量：{((config as Config & { missing?: string[] }).missing ?? []).join('、')}
            </div>
          )}
          <div className="row">
            <button className="btn btn-primary" onClick={check} disabled={busy}>
              {busy ? '检测中…' : '检测连接'}
            </button>
            <span className="field-hint">发送一次真实的最小请求。</span>
          </div>
          {result && (
            <div
              className={result.ok ? 'small' : 'error-box'}
              style={{ marginTop: 12, color: result.ok ? 'var(--ok)' : undefined }}
            >
              {result.ok
                ? `连通，${result.latency_ms} ms，回复 ${JSON.stringify(result.reply)}`
                : `失败：${result.error}`}
            </div>
          )}
        </div>
      </div>

      <div className="grid">
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">健康熔断</span>
            <span className={`chip ${healthTone(health?.status)}`}>
              {HEALTH_LABELS[health?.status ?? 'unknown'] ?? health?.status}
            </span>
          </div>
          <div style={{ padding: '12px 16px' }} className="small">
            <div>连续失败 {health?.fails ?? 0} 次 · 熔断 {health?.trips ?? 0} 次</div>
            <div>冷却剩余 {health?.cooldown_seconds ?? 0} 秒</div>
            {health?.last_error && <div className="mono small" style={{ marginTop: 6, color: 'var(--danger)' }}>{health.last_error}</div>}
            <div className="muted" style={{ marginTop: 8 }}>
              调用连续失败会退避冷却，避免把一次端点故障放大成整轮运行的失败；冷却结束后自动恢复。
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">默认预算</span>
            <span className="faint small">每个单元</span>
          </div>
          <div style={{ padding: '12px 16px' }} className="small">
            <div>模型响应 {config.budgets.responses} 次</div>
            <div>工具调用 {config.budgets.tools} 次</div>
            <div>墙钟 {config.budgets.seconds} 秒</div>
            <div className="muted" style={{ marginTop: 8 }}>
              预算在运行创建时冻结并写入运行记录；运行开始后队列不再变动。
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">服务与部署</span>
          </div>
          <div style={{ padding: '12px 16px' }} className="small">
            <div>审计应用 <span className="mono">127.0.0.1:8787</span></div>
            <div>演示靶机 DVWA <span className="mono">127.0.0.1:4280</span></div>
            <div>版本 <span className="mono">{config.version}</span></div>
            <div>Worker：<span className="mono">{JSON.stringify(config.worker)}</span></div>
          </div>
        </div>
      </div>
    </div>
  );
}
