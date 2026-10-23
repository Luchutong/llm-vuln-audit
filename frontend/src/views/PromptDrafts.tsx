import { Disclosure } from '../components/Disclosure';
import { DeletePromptButton } from '../components/RecordActions';
import { LongContent } from '../components/LongContent';
import type { Prompt } from '../types';
import { localDate } from '../status';
import { useLedgerResource } from '../useLedgerResource';

export function PromptDrafts() {
  const { data, error, refresh, refreshing } = useLedgerResource<Prompt[]>('/prompts');
  return <div className="records-prompt-list">
    <div className="between"><p className="small muted">查看已保存的提示词。仅未被审计引用的自定义草稿可以删除。</p><button className="text-button" disabled={refreshing} onClick={refresh}>刷新提示词</button></div>
    {error && <div role="alert" className="error-box">提示词读取失败：{error} <button className="text-button" onClick={refresh}>重试</button></div>}
    {!data && !error && <div role="status" className="empty">正在读取提示词…</div>}
    {data?.length === 0 && <div className="empty">没有已保存的提示词。</div>}
    {data?.map((prompt) => <section className="records-prompt-row" key={prompt.id} aria-label={`提示词 ${prompt.label}`}><div className="records-prompt-heading"><div><h3>{prompt.label} <span className="chip">{prompt.builtin ? '内置' : '自定义草稿'}</span></h3><p>{localDate(prompt.created_at)} · {prompt.id}</p></div><DeletePromptButton prompt={prompt} /></div><Disclosure title="查看提示词正文"><LongContent value={prompt.text} label="提示词正文" />{prompt.reason && <LongContent value={prompt.reason} label="说明" />}</Disclosure></section>)}
  </div>;
}
