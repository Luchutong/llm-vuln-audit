import { useEffect, useMemo, useState } from 'react';
import { api, errorText, post } from '../api';
import type { Config, ModelProfile } from '../types';
import { Disclosure } from '../components/Disclosure';
import { LongContent } from '../components/LongContent';

interface CheckResult {
  ok: boolean;
  model?: string;
  latency_ms?: number;
  reply?: string;
  error?: string;
}

interface ProfileDraft {
  label: string;
  model: string;
  base_url: string;
  api_key: string;
  clear_api_key: boolean;
}

type EditorMode = 'create' | string | null;

const EMPTY_DRAFT: ProfileDraft = {
  label: '',
  model: '',
  base_url: '',
  api_key: '',
  clear_api_key: false,
};

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

function isEnvironmentProfile(profile: ModelProfile) {
  return profile.credential_source === 'environment';
}

function profileCredentialLabel(profile: ModelProfile) {
  if (isEnvironmentProfile(profile)) return '环境变量';
  return profile.api_key_configured ? '已保存密钥' : '未配置密钥';
}

function validateDraft(draft: ProfileDraft): string | null {
  if (!draft.label.trim()) return '请填写易于识别的档案名称。';
  if (!draft.model.trim()) return '请填写模型标识。';
  if (!draft.base_url.trim()) return '请填写模型服务的 Base URL。';
  if (/\s/.test(draft.base_url)) return 'Base URL 不能包含空白或控制字符。';
  try {
    const url = new URL(draft.base_url.trim());
    if (!['http:', 'https:'].includes(url.protocol) || !url.host || url.username || url.password || url.search || url.hash) {
      return 'Base URL 必须是不含凭据、查询参数或片段的完整 http(s) 地址。';
    }
  } catch {
    return 'Base URL 必须是完整的 http(s) 地址。';
  }
  return null;
}

async function deleteProfile(profileId: string): Promise<void> {
  const response = await fetch(`/api/config/profiles/${encodeURIComponent(profileId)}`, { method: 'DELETE' });
  if (response.ok) return;

  let message = `${response.status} ${response.statusText}`;
  try {
    const body: unknown = await response.json();
    if (body && typeof body === 'object' && 'detail' in body) {
      const detail = (body as { detail?: unknown }).detail;
      message = typeof detail === 'string' ? detail : JSON.stringify(detail);
    }
  } catch {
    // Keep the HTTP status when an intermediary sent a non-JSON error page.
  }
  throw new Error(message);
}

/**
 * Provider profiles are intentionally independent. A model identifier alone is
 * not enough to describe a connection: every saved profile carries its own Base
 * URL and encrypted API key, while browser responses only reveal key presence.
 */
export function SettingsView({ config, onChanged }: { config: Config | null; onChanged: () => void }) {
  const [profiles, setProfiles] = useState<ModelProfile[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editor, setEditor] = useState<EditorMode>(null);
  const [draft, setDraft] = useState<ProfileDraft>(EMPTY_DRAFT);
  const [busy, setBusy] = useState<'save' | 'select' | 'delete' | 'check' | null>(null);
  const [result, setResult] = useState<CheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const configSignature = useMemo(
    () => config ? JSON.stringify([config.selected_profile_id, config.model_profiles]) : '',
    [config],
  );

  useEffect(() => {
    if (!config) return;
    const nextProfiles = config.model_profiles ?? [];
    setProfiles(nextProfiles);
    setSelectedId(config.selected_profile_id ?? nextProfiles.find((profile) => profile.selected)?.id ?? null);
    // App refreshes health/status on a timer. Only replace the local catalogue
    // when the server's actual profile selection changes, so a late pre-save
    // polling response cannot briefly undo a successful create/select/update.
  }, [configSignature]);

  if (!config) return <div className="empty">载入配置…</div>;

  const selectedProfile = profiles.find((profile) => profile.id === selectedId) ?? null;
  const editingProfile = editor && editor !== 'create'
    ? profiles.find((profile) => profile.id === editor) ?? null
    : null;
  const isCreating = editor === 'create';
  const disabled = busy !== null;
  const health = config.model_health;

  const applyConfig = (saved: Config) => {
    const nextProfiles = saved.model_profiles ?? [];
    setProfiles(nextProfiles);
    setSelectedId(saved.selected_profile_id ?? nextProfiles.find((profile) => profile.selected)?.id ?? null);
  };

  const beginCreate = () => {
    setEditor('create');
    setDraft({
      ...EMPTY_DRAFT,
      base_url: selectedProfile?.base_url ?? '',
    });
    setError(null);
    setNotice(null);
  };

  const beginEdit = (profile: ModelProfile) => {
    if (isEnvironmentProfile(profile)) {
      setError('环境变量档案由服务端启动配置维护。请新建一个档案来使用其他厂家的 Base URL 与 API Key。');
      return;
    }
    setEditor(profile.id);
    setDraft({
      label: profile.label,
      model: profile.model,
      base_url: profile.base_url,
      // Keys are never returned by the API. An empty edit field means “retain the
      // existing encrypted key”, so opening an edit form can never erase it.
      api_key: '',
      clear_api_key: false,
    });
    setError(null);
    setNotice(null);
  };

  const closeEditor = () => {
    setEditor(null);
    setDraft(EMPTY_DRAFT);
    setError(null);
  };

  const saveProfile = async () => {
    const validationError = validateDraft(draft);
    if (validationError) {
      setError(validationError);
      return;
    }

    const payload: Record<string, string> = {
      label: draft.label.trim(),
      model: draft.model.trim(),
      base_url: draft.base_url.trim().replace(/\/+$/, ''),
    };
    if (isCreating || draft.clear_api_key) {
      // An explicit empty value is distinct from omitting the field: the former
      // clears a saved key, while the latter preserves it during an edit.
      payload.api_key = draft.clear_api_key ? '' : draft.api_key;
    } else if (draft.api_key.trim()) {
      payload.api_key = draft.api_key;
    }

    setBusy('save');
    setError(null);
    setNotice(null);
    try {
      const saved = isCreating
        ? await api<Config>('/config/profiles', { method: 'POST', body: JSON.stringify(payload) })
        : await api<Config>(`/config/profiles/${encodeURIComponent(editingProfile?.id ?? '')}`, {
          method: 'PUT',
          body: JSON.stringify(payload),
        });
      applyConfig(saved);
      setEditor(null);
      setDraft(EMPTY_DRAFT);
      setResult(null);
      setNotice(isCreating ? '已保存模型档案。' : '已更新模型档案。');
      onChanged();
    } catch (exc) {
      setError(errorText(exc));
    } finally {
      setBusy(null);
    }
  };

  const selectProfile = async (profile: ModelProfile) => {
    if (profile.id === selectedId) return;
    setBusy('select');
    setError(null);
    setNotice(null);
    try {
      const saved = await post<Config>(`/config/profiles/${encodeURIComponent(profile.id)}/select`, {});
      applyConfig(saved);
      setResult(null);
      setNotice(`已切换到「${profile.label}」，后续新建审计会使用该档案。`);
      onChanged();
    } catch (exc) {
      setError(errorText(exc));
    } finally {
      setBusy(null);
    }
  };

  const removeProfile = async (profile: ModelProfile) => {
    if (profile.id === selectedId || isEnvironmentProfile(profile)) return;
    if (!window.confirm(`删除模型档案「${profile.label}」？此操作不会影响既有审计记录。`)) return;
    setBusy('delete');
    setError(null);
    setNotice(null);
    try {
      await deleteProfile(profile.id);
      setProfiles((current) => current.filter((item) => item.id !== profile.id));
      if (editor === profile.id) closeEditor();
      setNotice(`已删除「${profile.label}」。`);
      onChanged();
    } catch (exc) {
      setError(errorText(exc));
    } finally {
      setBusy(null);
    }
  };

  const check = async () => {
    setBusy('check');
    setError(null);
    setNotice(null);
    try {
      setResult(await post<CheckResult>('/config/check', {}));
      onChanged();
    } catch (exc) {
      setError(errorText(exc));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="grid settings-grid">
      {(error || notice) && (
        <div
          role={error ? 'alert' : 'status'}
          className={error ? 'error-box' : 'panel'}
          style={{ gridColumn: '1 / -1', ...(notice ? { padding: '10px 14px', color: 'var(--ok)', fontSize: 13 } : {}) }}
        >
          <LongContent value={error ?? notice} label={error ? '配置错误' : '操作结果'} />
        </div>
      )}

      <div className="grid">
        <div className="panel">
          <div className="panel-head">
            <div>
              <div className="panel-title">模型档案</div>
              <div className="faint small">每个档案独立保存模型、Base URL 和 API Key。</div>
            </div>
            <button type="button" className="btn btn-primary" onClick={beginCreate} disabled={disabled}>新建档案</button>
          </div>
          <div style={{ padding: '12px 16px' }}>
            {profiles.length === 0 ? (
              <div className="empty" style={{ padding: '14px 0' }}>还没有模型档案，请新建一个连接配置。</div>
            ) : profiles.map((profile, index) => {
              const selected = profile.id === selectedId;
              const environment = isEnvironmentProfile(profile);
              return (
                <div
                  key={profile.id}
                  style={{
                    padding: '10px 0',
                    borderBottom: index < profiles.length - 1 ? '1px solid var(--line-soft)' : undefined,
                  }}
                >
                  <div className="between" style={{ alignItems: 'flex-start' }}>
                    <div style={{ minWidth: 0 }}>
                      <div className="row" style={{ flexWrap: 'wrap' }}>
                        <strong style={{ overflowWrap: 'anywhere' }}>{profile.label}</strong>
                        {selected && <span className="chip chip-confirmed">当前</span>}
                        <span className={`chip ${profile.api_key_configured ? 'chip-confirmed' : 'chip-uncertain'}`}>
                          {profileCredentialLabel(profile)}
                        </span>
                      </div>
                      <LongContent value={profile.model} label="模型标识" />
                      <LongContent value={profile.base_url} label="服务地址" />
                    </div>
                    <div className="row" style={{ alignItems: 'flex-start', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                      <button
                        type="button"
                        className="btn"
                        disabled={disabled || selected}
                        onClick={() => selectProfile(profile)}
                      >
                        {selected ? '正在使用' : '使用此档案'}
                      </button>
                      <button type="button" className="btn" disabled={disabled || environment} onClick={() => beginEdit(profile)}>编辑</button>
                      <button
                        type="button"
                        className="btn btn-danger"
                        disabled={disabled || selected || environment}
                        onClick={() => removeProfile(profile)}
                      >
                        删除
                      </button>
                    </div>
                  </div>
                  {environment && <div className="field-hint" style={{ marginTop: 5 }}>此档案来自服务端环境变量；如需其他服务商，请新建独立档案。</div>}
                </div>
              );
            })}
          </div>
        </div>

        {editor && (
          <div className="panel">
            <div className="panel-head">
              <div>
                <div className="panel-title">{isCreating ? '新建模型档案' : `编辑档案 · ${editingProfile?.label ?? ''}`}</div>
                <div className="faint small">密钥只在保存时发送；服务端加密保存，之后不会返回给浏览器。</div>
              </div>
              <button type="button" className="btn" onClick={closeEditor} disabled={disabled}>取消</button>
            </div>
            <div style={{ padding: '12px 16px' }}>
              <div className="field">
                <label className="field-label" htmlFor="profile-label">档案名称</label>
                <input
                  id="profile-label"
                  type="text"
                  maxLength={120}
                  value={draft.label}
                  disabled={disabled}
                  placeholder="例如：DeepSeek 生产环境"
                  onChange={(event) => setDraft((current) => ({ ...current, label: event.target.value }))}
                />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="profile-model">模型标识</label>
                <input
                  id="profile-model"
                  type="text"
                  maxLength={200}
                  value={draft.model}
                  disabled={disabled}
                  placeholder="例如：deepseek-chat"
                  onChange={(event) => setDraft((current) => ({ ...current, model: event.target.value }))}
                />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="profile-base-url">Base URL</label>
                <input
                  id="profile-base-url"
                  type="text"
                  maxLength={1024}
                  value={draft.base_url}
                  disabled={disabled}
                  placeholder="例如：https://api.example.com/v1"
                  onChange={(event) => setDraft((current) => ({ ...current, base_url: event.target.value }))}
                />
                <span className="field-hint">填写该服务商的 OpenAI 兼容或项目已支持的聊天补全接口根地址。</span>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="profile-api-key">API Key{isCreating ? '' : '（留空则保留原密钥）'}</label>
                <input
                  id="profile-api-key"
                  type="password"
                  autoComplete="new-password"
                  maxLength={4096}
                  value={draft.api_key}
                  disabled={disabled || draft.clear_api_key}
                  style={{ width: '100%', padding: '7px 10px', border: '1px solid var(--line)', borderRadius: 7, background: 'var(--surface)', color: 'var(--ink)', fontSize: 13, fontFamily: 'inherit' }}
                  placeholder={isCreating ? '输入此服务商的 API Key' : '不修改请留空'}
                  onChange={(event) => setDraft((current) => ({ ...current, api_key: event.target.value }))}
                />
                <span className="field-hint">页面不会回显 API Key；已有密钥会以“已保存密钥”状态显示。</span>
                {!isCreating && (
                  <label className="small row" style={{ marginTop: 7, cursor: disabled ? 'default' : 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={draft.clear_api_key}
                      disabled={disabled}
                      onChange={(event) => setDraft((current) => ({
                        ...current,
                        clear_api_key: event.target.checked,
                        api_key: event.target.checked ? '' : current.api_key,
                      }))}
                    />
                    清除已保存的 API Key
                  </label>
                )}
              </div>
              <div className="row">
                <button type="button" className="btn btn-primary" onClick={saveProfile} disabled={disabled}>
                  {busy === 'save' ? '保存中…' : isCreating ? '保存档案' : '保存修改'}
                </button>
                {!isCreating && <span className="field-hint">留空 API Key 会保留原凭据；勾选上方选项才会清除。</span>}
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="grid">
        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">当前连接</span>
            <span className={`chip ${config.configured ? 'chip-confirmed' : 'chip-failed'}`}>
              {config.configured ? '已配置' : '缺少配置'}
            </span>
          </div>
          <div style={{ padding: '12px 16px' }}>
            <div className="field">
              <span className="field-label">正在使用的档案</span>
              <span className="small">{selectedProfile?.label ?? '未选择'}</span>
            </div>
            <LongContent value={config.model || '—'} label="模型" />
            <LongContent value={config.base_url || '—'} label="Base URL" />
            {(config.missing ?? []).length > 0 && (
              <div className="error-box" style={{ marginBottom: 10 }}>
                缺少配置：{(config.missing ?? []).join('、')}
              </div>
            )}
            <div className="row">
              <button className="btn btn-primary" onClick={check} disabled={disabled || !selectedProfile}>
                {busy === 'check' ? '检测中…' : '检测连接'}
              </button>
              <span className="field-hint">向当前档案发送一次最小请求。</span>
            </div>
            {result && (
              <div role="status" className={result.ok ? 'small' : 'error-box'} style={{ marginTop: 12, color: result.ok ? 'var(--ok)' : undefined }}>
                <LongContent value={result.ok ? `连通，${result.latency_ms} ms，回复 ${JSON.stringify(result.reply)}` : `失败：${result.error}`} label="连接检测结果" />
              </div>
            )}
          </div>
        </div>

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
            {health?.last_error && <LongContent value={health.last_error} label="最近连接错误" />}
            <div className="muted" style={{ marginTop: 8 }}>
              切换或更新档案时会重置连接健康状态，避免把一个服务商的失败带到另一个服务商。
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-head">
            <span className="panel-title">默认预算</span>
            <span className="faint small">每次 agent 回合</span>
          </div>
          <div style={{ padding: '12px 16px' }} className="small">
            <div>模型响应 {config.budgets.responses} 次</div>
            <div>工具调用 {config.budgets.tools} 次</div>
            <div>墙钟 {config.budgets.seconds} 秒</div>
            {config.run_budget_limits && (config.run_budget_limits.profiles ? Object.entries(config.run_budget_limits.profiles).map(([mode, limits]) => <div key={mode} className="muted" style={{ marginTop: 8 }}>{mode === 'coverage_review' ? '全量审计' : '快速目标审计'}整次默认：模型 {limits.responses} 次 · 工具 {limits.tools} 次 · 活跃 {limits.seconds} 秒</div>) : <div className="muted" style={{ marginTop: 8 }}>整次默认上限：模型 {config.run_budget_limits.defaults.responses} 次 · 工具 {config.run_budget_limits.defaults.tools} 次 · 活跃 {config.run_budget_limits.defaults.seconds} 秒</div>)}
            <div className="muted" style={{ marginTop: 8 }}>
              预算在运行创建时冻结；当前进行中的审计结束或取消后才能切换模型档案。
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="panel-head"><span className="panel-title">服务与部署</span></div>
          <div style={{ padding: '12px 16px' }} className="small">
            <div>审计应用 <span className="mono">127.0.0.1:8899</span></div>
            <div>版本 <span className="mono">{config.version}</span></div>
            <Disclosure title="Worker 配置"><LongContent value={config.worker} label="Worker 配置" /></Disclosure>
          </div>
        </div>
      </div>
    </div>
  );
}
