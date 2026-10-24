import { useEffect, useRef, useState } from 'react';
import { api, errorText, post } from '../api';
import { DeletePromptButton } from '../components/RecordActions';
import type { Prompt } from '../types';
import { localDate } from '../status';
import { useLedgerResource } from '../useLedgerResource';

/**
 * The prompt library: add a version, edit a draft, or derive the next version.
 *
 * Two invariants decide what is editable, and both exist to keep a finished report honest:
 * a built-in is refreshed from the release, and a text a run already quoted belongs to that
 * run's record. Instead of rewriting either in place, the page offers "基于此版本另存",
 * which keeps ``parent_id`` and the reason so the chain stays readable.
 */
type Draft = {
  id: string | null;
  label: string;
  text: string;
  reason: string;
  issues: string;
  parentId: string | null;
};

const EMPTY: Draft = { id: null, label: '', text: '', reason: '', issues: '', parentId: null };

const fromPrompt = (prompt: Prompt): Draft => ({
  id: prompt.id,
  label: prompt.label,
  text: prompt.text,
  reason: prompt.reason ?? '',
  issues: (prompt.issues ?? []).join('\n'),
  parentId: prompt.parent_id ?? null,
});

const issuesOf = (value: string) => value.split('\n').map((line) => line.trim()).filter(Boolean);

export function PromptsLibraryView() {
  const { data, error, refresh, refreshing } = useLedgerResource<Prompt[]>('/prompts');
  const prompts = data ?? [];
  const [draft, setDraft] = useState<Draft>(EMPTY);
  const [notice, setNotice] = useState<string | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const selected = draft.id ? prompts.find((item) => item.id === draft.id) ?? null : null;
  // A prompt row can vanish (deleted in another tab) while its draft is open.  Only a row
  // this page has already seen counts as "vanished": a row created a moment ago is missing
  // from the listing until the refetch lands, and resetting the form then would erase what
  // the user just typed.
  const seen = useRef<Set<string>>(new Set());
  useEffect(() => {
    if (!data) return;
    const ids = new Set(data.map((item) => item.id));
    if (draft.id && !ids.has(draft.id) && seen.current.has(draft.id)) setDraft(EMPTY);
    seen.current = ids;
  }, [data, draft.id]);

  const used = selected?.used_by_runs ?? 0;
  const readOnlyReason = !selected ? null
    : selected.builtin ? '内置提示词随版本发布刷新，不能就地修改。'
      : used ? `这份提示词已被 ${used} 次审计引用，就地修改会让那些报告与它实际使用的文本不一致。`
        : null;
  const dirty = selected
    ? draft.label !== selected.label || draft.text !== selected.text || draft.reason !== (selected.reason ?? '')
      || draft.issues !== (selected.issues ?? []).join('\n')
    : Boolean(draft.label || draft.text);

  const save = async () => {
    if (busy) return;
    setBusy(true);
    setFailure(null);
    setNotice(null);
    try {
      const body = { label: draft.label, text: draft.text, reason: draft.reason, issues: issuesOf(draft.issues) };
      if (draft.id) {
        const saved = await api<Prompt>(`/prompts/${draft.id}`, { method: 'PUT', body: JSON.stringify(body) });
        setDraft(fromPrompt(saved));
        setNotice('已保存修改。');
      } else {
        const created = await post<Prompt>('/prompts', { ...body, parent_id: draft.parentId });
        setDraft(fromPrompt(created));
        setNotice(draft.parentId ? `已另存为新版本 ${created.id}。` : `已新建 ${created.id}。`);
      }
      refresh();
    } catch (exc) {
      setFailure(errorText(exc));
      refresh();
    } finally {
      setBusy(false);
    }
  };

  const derive = (prompt: Prompt) => {
    setFailure(null);
    setNotice(null);
    setDraft({ ...fromPrompt(prompt), id: null, label: `${prompt.label} · 修订`, parentId: prompt.id });
  };

  return (
    <div className="grid" style={{ gap: 14 }}>
      {(error || failure) && <div className="error-box" role="alert">{failure ?? `提示词读取失败：${error}`}</div>}

      <div className="grid" style={{ gridTemplateColumns: '300px 1fr', gap: 14 }}>
        <section className="panel">
          <div className="panel-head">
            <span className="panel-title">提示词库</span>
            <button className="btn" onClick={() => { setDraft(EMPTY); setNotice(null); setFailure(null); }}>新建</button>
          </div>
          {!data && !error && <div className="empty">正在读取提示词…</div>}
          {data?.length === 0 && <div className="empty">还没有提示词。</div>}
          {(data ?? []).map((prompt) => (
            <button
              key={prompt.id}
              onClick={() => { setDraft(fromPrompt(prompt)); setNotice(null); setFailure(null); }}
              style={{
                display: 'block', width: '100%', textAlign: 'left', padding: '10px 14px',
                border: 'none', borderBottom: '1px solid var(--line-soft)', cursor: 'pointer',
                background: draft.id === prompt.id ? 'var(--accent-soft)' : 'transparent',
              }}
            >
              <div className="small" style={{ fontWeight: 500 }}>{prompt.label}</div>
              <div className="faint" style={{ fontSize: 11.5 }}>
                {prompt.id} · {prompt.builtin ? '内置' : '草稿'}
                {prompt.parent_id ? ` · 基于 ${prompt.parent_id}` : ''}
                {prompt.used_by_runs ? ` · 已用于 ${prompt.used_by_runs} 次审计` : ''}
              </div>
            </button>
          ))}
          <div style={{ padding: '8px 14px' }} className="faint small">
            {refreshing ? '正在同步…' : `共 ${prompts.length} 条`}
          </div>
        </section>

        <section className="panel">
          <div className="panel-head">
            <span className="panel-title">{draft.id ? '编辑提示词' : draft.parentId ? '基于现有版本新建' : '新建提示词'}</span>
            {selected && <span className="faint small">{localDate(selected.created_at)} · 阶段 {selected.phase}</span>}
          </div>
          <div style={{ padding: '12px 16px' }} className="grid">
            {readOnlyReason && <div className="small" style={{ color: 'var(--warn)' }}>{readOnlyReason}请用下方「基于此版本另存」。</div>}
            {notice && <div className="small muted" role="status">{notice}</div>}

            <label className="field">
              <span className="field-label">标签</span>
              <input
                type="text"
                value={draft.label}
                placeholder="例如 P3 强制证据链 + 前置条件"
                onChange={(event) => setDraft({ ...draft, label: event.target.value })}
              />
            </label>

            {!draft.id && (
              <label className="field">
                <span className="field-label">基于哪一版</span>
                <select
                  value={draft.parentId ?? ''}
                  onChange={(event) => {
                    const parent = prompts.find((item) => item.id === event.target.value);
                    setDraft({
                      ...draft,
                      parentId: event.target.value || null,
                      text: parent ? parent.text : draft.text,
                    });
                  }}
                >
                  <option value="">不基于任何版本</option>
                  {prompts.map((prompt) => <option key={prompt.id} value={prompt.id}>{prompt.id} · {prompt.label}</option>)}
                </select>
              </label>
            )}

            <label className="field">
              <span className="field-label">为什么这样写（优化原因）</span>
              <textarea
                rows={2}
                value={draft.reason}
                onChange={(event) => setDraft({ ...draft, reason: event.target.value })}
              />
            </label>

            <label className="field">
              <span className="field-label">针对哪些问题（每行一条）</span>
              <textarea
                rows={3}
                value={draft.issues}
                onChange={(event) => setDraft({ ...draft, issues: event.target.value })}
              />
            </label>

            <label className="field">
              <span className="field-label">正文（{draft.text.length} 字）</span>
              <textarea
                rows={14}
                className="mono"
                value={draft.text}
                onChange={(event) => setDraft({ ...draft, text: event.target.value })}
              />
            </label>

            <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
              <button
                className="btn btn-primary"
                disabled={busy || !draft.label || !draft.text || (Boolean(draft.id) && (Boolean(readOnlyReason) || !dirty))}
                onClick={() => void save()}
              >
                {draft.id ? (dirty ? '保存修改' : '没有改动') : '保存新版本'}
              </button>
              {selected && <button className="btn" disabled={busy} onClick={() => derive(selected)}>基于此版本另存</button>}
              {selected && <DeletePromptButton prompt={selected} />}
              {draft.id && <button className="btn" disabled={busy} onClick={() => setDraft(EMPTY)}>取消编辑</button>}
            </div>
            <p className="small muted" style={{ margin: 0 }}>
              提示词库保存的是文本版本，新增或修改不会改变任何已完成审计的记录：审计运行时使用的文本会随该次运行原样冻结。
            </p>
          </div>
        </section>
      </div>
    </div>
  );
}
