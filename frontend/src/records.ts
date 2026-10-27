import type { Prompt, Run, SnapshotSummary } from './types';

export const RECORDS_CHANGED = 'audit-records-changed';
export interface RunDeletion { run_id: string; status_before: string; deleted: Record<string, number> }
export interface RunCleanup { deleted_runs: number; runs: RunDeletion[] }
export interface FindingDeletion { deleted_project_findings: number; deleted_run_findings: number; deleted: Record<string, number>; affected_project_ids: string[] }
export interface RecordsChange { runIds?: string[]; snapshotId?: string; promptId?: string; projectFindingId?: string; projectId?: string | null; notice: string }

/** Finding cleanup spans historical runs; a paused run could still write on resume. */
export function findingDeletionBlock(runs: Pick<Run, 'status' | 'project_id'>[], projectId?: string): string | null {
  return runs.some((run) => (!projectId || run.project_id === projectId) && ['pending', 'running', 'paused'].includes(run.status))
    ? '请先取消或完成此范围内排队、运行或已暂停的审计，再删除漏洞。' : null;
}

export function findingDeletionPath(projectId?: string, findingId?: string): string {
  return findingId ? `/project-findings/${encodeURIComponent(findingId)}`
    : `/project-findings${projectId ? `?${new URLSearchParams({ project_id: projectId })}` : ''}`;
}

export function runDeletionBlock(run: Pick<Run, 'status'>): string | null {
  return ['pending', 'running'].includes(run.status) ? '请先停止排队或运行中的审计，再删除记录。' : null;
}
export function cleanupCandidates(runs: Run[], projectId?: string): Run[] {
  return runs.filter((run) => (!projectId || run.project_id === projectId) && !runDeletionBlock(run));
}
export function snapshotDeletionBlock(snapshot: Pick<SnapshotSummary, 'id'>, runs: Run[]): string | null {
  const count = runs.filter((run) => run.snapshot_id === snapshot.id).length;
  return count ? `此 ZIP 被 ${count} 次审计引用，请先删除相关审计记录。` : null;
}
export function promptDeletionBlock(prompt: Pick<Prompt, 'id' | 'builtin' | 'used_by_runs' | 'used_by_experiments'>, runs: Run[]): string | null {
  if (prompt.builtin) return '内置提示词不能删除。';
  if (prompt.used_by_experiments) return `此提示词被 ${prompt.used_by_experiments} 次实验引用，需保留冻结版本。`;
  const count = Math.max(prompt.used_by_runs ?? 0, runs.filter((run) => run.prompt_id === prompt.id).length);
  return count ? `此提示词被 ${count} 次审计引用，请先删除相关审计记录。` : null;
}
