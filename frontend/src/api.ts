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
  if (detail && typeof detail === 'object') {
    const message = (detail as { message?: unknown }).message;
    return typeof message === 'string' ? message : JSON.stringify(detail);
  }
  return null;
}

export class ApiError extends Error {
  status: number;
  detail: unknown;
  constructor(status: number, message: string, detail?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

export type ApiOptions = RequestInit & { timeoutMs?: number };

export async function api<T>(path: string, options?: ApiOptions): Promise<T> {
  const { timeoutMs = 0, signal: callerSignal, ...requestOptions } = options ?? {};
  const abort = new AbortController();
  let timedOut = false;
  const forwardAbort = () => abort.abort(callerSignal?.reason);
  if (callerSignal?.aborted) forwardAbort();
  else callerSignal?.addEventListener('abort', forwardAbort, { once: true });
  const timeout =
    timeoutMs > 0
      ? setTimeout(() => {
          timedOut = true;
          abort.abort();
        }, timeoutMs)
      : undefined;
  try {
    const response = await fetch(`/api${path}`, {
      ...requestOptions,
      signal: abort.signal,
      headers: {
        ...(requestOptions.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
        ...requestOptions.headers,
      },
    });
    if (!response.ok) {
      let message = `${response.status} ${response.statusText}`;
      let detail: unknown;
      try {
        const body = await response.json();
        detail = body.detail;
        message = detailText(detail) ?? JSON.stringify(body);
      } catch {
        /* HTML/network gateway error */
      }
      throw new ApiError(response.status, message, detail);
    }
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  } catch (error) {
    if (timedOut && !callerSignal?.aborted)
      throw new ApiError(408, `读取超时（${Math.round(timeoutMs / 1000)} 秒），已保留上次结果，将继续重试。`);
    throw error;
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
    callerSignal?.removeEventListener('abort', forwardAbort);
  }
}

export const post = <T>(path: string, body: unknown) => api<T>(path, { method: 'POST', body: JSON.stringify(body) });
export const remove = <T = void>(path: string) => api<T>(path, { method: 'DELETE' });
export const downloadUrl = (path: string) => `/api${path}`;
export const errorText = (error: unknown) => (error instanceof Error ? error.message : String(error));
