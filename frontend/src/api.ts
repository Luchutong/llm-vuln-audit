export async function api<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, { ...options, headers: { ...(options?.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }), ...options?.headers } });
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try { const body = await response.json(); message = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail ?? body); } catch { /* HTML/network gateway error */ }
    throw new Error(message);
  }
  return response.json() as Promise<T>;
}
export const post = <T>(path: string, body: unknown) => api<T>(path, { method: 'POST', body: JSON.stringify(body) });
export const downloadUrl = (path: string) => `/api${path}`;
export const errorText = (error: unknown) => error instanceof Error ? error.message : String(error);
