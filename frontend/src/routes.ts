export type SourceTab = 'tasks' | 'findings' | 'archives';
export type WorkspaceRoute = {
  page: 'sources' | 'project' | 'new' | 'findings' | 'finding' | 'run' | 'settings' | 'experiments' | 'prompts' | 'missing';
  projectId?: string;
  snapshotId?: string;
  runId?: string;
  findingId?: string;
  experimentId?: string;
  tab?: SourceTab;
};

export function parseRoute(hash: string): WorkspaceRoute {
  const [path, query = ''] = hash.replace(/^#/, '').split('?');
  const params = new URLSearchParams(query);
  let parts: string[];
  try { parts = path.split('/').filter(Boolean).map(decodeURIComponent); }
  catch { return { page: 'missing' }; }
  if (!parts.length || (parts[0] === 'sources' && parts.length === 1)) return { page: 'sources' };
  if (parts[0] === 'settings' && parts.length === 1) return { page: 'settings' };
  if (parts[0] === 'prompts' && parts.length === 1) return { page: 'prompts' };
  if (parts[0] === 'experiments' && parts.length <= 2) return parts[1] ? { page: 'experiments', experimentId: parts[1] } : { page: 'experiments' };
  if (parts[0] === 'run' && parts.length === 2) return { page: 'run', runId: parts[1] };
  if (parts[0] === 'findings' && parts.length <= 2) return parts[1] ? { page: 'finding', findingId: parts[1] } : { page: 'findings' };
  if (parts[0] === 'sources' && parts[1]) {
    if (parts.length === 3 && parts[2] === 'new') return { page: 'new', projectId: parts[1], snapshotId: params.get('snapshot') ?? undefined };
    if (parts.length === 2) {
      const tab = params.get('tab');
      return { page: 'project', projectId: parts[1], tab: tab === 'findings' || tab === 'archives' ? tab : 'tasks', ...(params.has('snapshot') ? { snapshotId: params.get('snapshot')! } : {}) };
    }
  }
  if (parts[0] === 'new' && parts.length === 1) return { page: 'new', snapshotId: params.get('snapshot') ?? undefined };
  return { page: 'missing' };
}

export const sourceHref = (projectId: string, tab: SourceTab = 'tasks') => `#sources/${encodeURIComponent(projectId)}?tab=${tab}`;
export const newAuditHref = (projectId: string, snapshotId?: string | null) => `#sources/${encodeURIComponent(projectId)}/new${snapshotId ? `?snapshot=${encodeURIComponent(snapshotId)}` : ''}`;
