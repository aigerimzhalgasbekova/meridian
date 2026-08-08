// Fetch wrapper: JSON bodies, cookie session, CSRF header on mutations.

export interface Me {
  user: {
    email: string;
    emailVerified: boolean;
    pendingEmail: string | null;
    totpEnabled: boolean;
    /** 0 when TOTP is off. Surfaced so the last code is not spent unnoticed. */
    recoveryCodesRemaining: number;
  };
  csrfToken: string;
  mfaPending: boolean;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

let csrfToken = '';
export function setCsrf(token: string): void {
  csrfToken = token;
}

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: {
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(method !== 'GET' ? { 'x-csrf-token': csrfToken } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const data: unknown = res.status === 204 ? {} : await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = (data as { error?: string }).error ?? `request failed (${res.status})`;
    throw new ApiError(res.status, msg);
  }
  return data as T;
}

/** Fetch the current session; records the CSRF token. Null when logged out. */
export async function fetchMe(): Promise<Me | null> {
  try {
    const me = await api<Me>('GET', '/api/me');
    setCsrf(me.csrfToken);
    return me;
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return null;
    throw e;
  }
}
