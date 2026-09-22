let csrfToken = ''
let hostId: string | null = null

export function setCsrf(token: string) {
  csrfToken = token
}

/** Route API calls to a remote richrule agent through this console (null = this host). */
export function setHost(id: string | null) {
  hostId = id
}

export function currentHost() {
  return hostId
}

// Session and console-management endpoints always stay on this host.
const LOCAL_ONLY = /^\/(me|login|logout|hosts)(\/|$|\?)/

/** Absolute API URL for a path, including the remote-host prefix when one is selected. */
export function apiUrl(path: string) {
  const prefix = hostId && !LOCAL_ONLY.test(path) ? `/h/${hostId}` : ''
  return `/api${prefix}${path}`
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {}
  const isForm = body instanceof FormData
  if (body !== undefined && !isForm) headers['Content-Type'] = 'application/json'
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken
  const res = await fetch(apiUrl(path), {
    method,
    headers,
    body: body === undefined ? undefined : isForm ? body : JSON.stringify(body),
    credentials: 'same-origin',
  })
  if (!res.ok) {
    let message = res.statusText
    try {
      const data = await res.json()
      if (typeof data.detail === 'string') message = data.detail
      else if (Array.isArray(data.detail))
        message = data.detail
          .map((d: { loc?: string[]; msg: string }) => `${d.loc?.slice(1).join('.')}: ${d.msg}`)
          .join('; ')
    } catch {
      /* not JSON */
    }
    if (res.status === 401 && !path.startsWith('/login')) window.dispatchEvent(new Event('richrule:unauthorized'))
    throw new ApiError(res.status, message)
  }
  return res.json() as Promise<T>
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
  put: <T>(path: string, body: unknown) => request<T>('PUT', path, body),
  patch: <T>(path: string, body: unknown) => request<T>('PATCH', path, body),
  delete: <T>(path: string) => request<T>('DELETE', path),
  upload: <T>(path: string, form: FormData) => request<T>('POST', path, form),
}
