export const TERMINAL = new Set(['succeeded', 'completed', 'unreachable', 'inconclusive', 'failed', 'cancelled', 'interrupted']);
export const RUN_LABELS: Record<string, string> = {
  pending: '排队中', running: '审计中', paused: '已暂停', succeeded: '已完成', completed: '已完成',
  unreachable: '目标不可达', inconclusive: '结果未决', failed: '运行失败', cancelled: '已取消', interrupted: '已中断',
};
export const runLabel = (status: string, goalStatus?: string | null) => status === 'completed' && goalStatus === 'met' ? '目标已达成' : RUN_LABELS[status] ?? status;
export function localDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).format(date);
}
