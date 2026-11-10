import type { PromptCacheStats } from './types';

export function cachePresentation(stats?: PromptCacheStats | null) {
  const reported = stats?.reported_records ?? 0;
  const total = stats?.usage_records ?? 0;
  const ratio = stats?.cache_hit_ratio;
  return {
    label: typeof ratio === 'number' && Number.isFinite(ratio) && ratio >= 0 && ratio <= 1
      ? `${(ratio * 100).toFixed(1)}%`
      : reported > 0 && stats?.reported_input_tokens === 0 ? '无输入 token'
      : total ? '暂无缓存计数' : '暂无数据',
    coverage: `${reported}/${total} 条用量记录`,
    partial: reported > 0 && reported < total,
  };
}
