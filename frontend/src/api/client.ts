// ==========================================
// 统一 HTTP 客户端封装 (轻量零依赖，支持 401 拦截)
// ==========================================

import type { ApiResult } from '@/types/config'

export class ApiError extends Error {
  status: number
  data?: unknown

  constructor(status: number, message: string, data?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.data = data
  }
}

// 401 未授权回调监听
type UnauthorizedHandler = () => void
const unauthorizedHandlers: UnauthorizedHandler[] = []

export function onUnauthorized(handler: UnauthorizedHandler) {
  unauthorizedHandlers.push(handler)
  return () => {
    const idx = unauthorizedHandlers.indexOf(handler)
    if (idx !== -1)
      unauthorizedHandlers.splice(idx, 1)
  }
}

export interface RequestOptions extends Omit<RequestInit, 'body'> {
  body?: unknown
}

export async function request<T = unknown>(
  url: string,
  options: RequestOptions = {},
): Promise<ApiResult<T>> {
  const headers = new Headers(options.headers || {})

  const auth = sessionStorage.getItem('rddns_auth')
  if (auth && !headers.has('Authorization')) {
    headers.set('Authorization', `Basic ${auth}`)
  }

  let reqBody: BodyInit | null | undefined
  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
    reqBody = JSON.stringify(options.body)
  }
  else {
    reqBody = options.body as BodyInit | null | undefined
  }

  const fetchOptions: RequestInit = {
    ...options,
    headers,
    body: reqBody,
  }

  const res = await fetch(url, fetchOptions)

  if (res.status === 401) {
    unauthorizedHandlers.forEach((cb) => {
      try {
        cb()
      }
      catch {}
    })
    throw new ApiError(401, '登录凭据无效或已过期')
  }

  const json: ApiResult<T> = await res.json()
  return json
}

export const api = {
  get: <T = unknown>(url: string, init?: RequestOptions) =>
    request<T>(url, { ...init, method: 'GET' }),
  post: <T = unknown>(url: string, body?: unknown, init?: RequestOptions) =>
    request<T>(url, { ...init, method: 'POST', body }),
  put: <T = unknown>(url: string, body?: unknown, init?: RequestOptions) =>
    request<T>(url, { ...init, method: 'PUT', body }),
  delete: <T = unknown>(url: string, init?: RequestOptions) =>
    request<T>(url, { ...init, method: 'DELETE' }),
}
