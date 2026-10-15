/**
 * A FastAPI validation error arrives as a list of per-field problems, which reads as
 * unparseable JSON in a banner. Field names stay English; the explanation does not.
 */
function detailText(detail: unknown): string | null {
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    const lines = detail.slice(0, 6).map((item) => {
      const error = item as { type?: string; loc?: unknown[]; msg?: string };
      const field = (error.loc ?? []).filter((part) => part !== 'body' && part !== 'query').join('.');
      if (error.type === 'extra_forbidden') {
        return `请求携带了服务不再接受的字段 ${field || '（未知）'}。请刷新页面后重试；创建审计不再需要源码范围字段。`;
      }
      if (error.type === 'missing') return `缺少必填字段 ${field || '（未知）'}`;
      return `${field ? `${field}：` : ''}${error.msg ?? error.type ?? '字段校验失败'}`;
    });
    if (detail.length > lines.length) lines.push(`另有 ${detail.length - lines.length} 条校验错误`);
    return lines.join('；');
  }
  if (detail && typeof detail === 'object') return JSON.stringify(detail);
  return null;
}

export async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, { ...options, headers: { ...(options?.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }), ...options?.headers } });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try { const body = await response.json(); message = detailText(body.detail) ?? JSON.stringify(body); } catch { /* HTML/network gateway error */ }
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}
export const post = <T>(path: string, body: unknown) => api<T>(path, { method: 'POST', body: JSON.stringify(body) });
export const downloadUrl = (path: string) => `/api${path}`;
export const errorText = (error: unknown) => error instanceof Error ? error.message : String(error);
