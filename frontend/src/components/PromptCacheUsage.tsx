import type { PromptCacheStats } from '../types';
import { cachePresentation } from '../promptCache';
import { Disclosure } from './Disclosure';

const roles: Record<string, string> = { worker: '源码 Worker', planner: 'Planner', reviewer: '独立审查',
  poc: 'POC', poc_sdk: 'SDK 验证', history_summary: '历史摘要', recon: '项目侦察', unknown: '未分类' };
const tokens = (n?: number | null) => typeof n === 'number' ? n.toLocaleString('zh-CN') : '未报告';

export function PromptCacheUsage({ stats }: { stats?: PromptCacheStats | null }) {
  const display = cachePresentation(stats);
  return <section className="prompt-cache-usage" aria-label="API 输入缓存">
    <Disclosure title={<span>API 输入缓存 · {display.label}{display.partial ? '（部分数据）' : ''}</span>}>
      <div className="grid small">
        <div>命中 {tokens(stats?.cache_read_tokens)} tokens / 已报告缓存的输入 {tokens(stats?.reported_input_tokens)} tokens；已报告缓存写入 {tokens(stats?.cache_write_tokens)} tokens。</div>
        <div>数据覆盖：{display.coverage}。命中率按输入 token 加权，缺少缓存计数的记录不按零命中计算。</div>
        {stats?.by_role && Object.keys(stats.by_role).length > 0 && <div className="table-wrap"><table><thead><tr><th>环节</th><th>输入命中率</th><th>命中 tokens</th><th>数据覆盖</th></tr></thead><tbody>
          {Object.entries(stats.by_role).map(([role, entry]) => <tr key={role}><td>{roles[role] ?? role}</td><td>{cachePresentation(entry).label}</td><td>{tokens(entry.cache_read_tokens)}</td><td>{cachePresentation(entry).coverage}</td></tr>)}
        </tbody></table></div>}
        <p className="muted">普通模型每次响应计一条记录，SDK 验证按阶段汇总。提示缓存仍占用模型请求额度；工具结果复用单独记录，费用以供应商账单为准。</p>
      </div>
    </Disclosure>
  </section>;
}
