export interface ApiProblem {
  code: string
  fallback: string
  params: Record<string, string | number>
}

export class ApiError extends Error {
  readonly code: string
  readonly fallback: string
  readonly params: Record<string, string | number>

  constructor(readonly status: number, problem: ApiProblem) {
    super(problem.fallback)
    this.name = 'ApiError'
    this.code = problem.code
    this.fallback = problem.fallback
    this.params = problem.params
  }
}

function isApiProblem(value: unknown): value is ApiProblem {
  if (!value || typeof value !== 'object') return false
  const candidate = value as Partial<ApiProblem>
  return typeof candidate.code === 'string'
    && typeof candidate.fallback === 'string'
    && !!candidate.params
    && typeof candidate.params === 'object'
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init)
  if (!response.ok) {
    const payload: unknown = await response.json().catch(() => null)
    const detail = payload && typeof payload === 'object'
      ? (payload as { detail?: unknown }).detail
      : null
    const problem: ApiProblem = isApiProblem(detail)
      ? detail
      : {
          code: typeof detail === 'string' ? 'legacy.error' : 'request.failed',
          fallback: typeof detail === 'string'
            ? detail
            : `Request failed with status ${response.status}.`,
          params: { status: response.status },
        }
    throw new ApiError(response.status, problem)
  }
  return response.json() as Promise<T>
}

export type TranslationFunction = (
  key: string,
  params?: Record<string, string | number>,
) => string

export function translateApiError(value: unknown, translate: TranslationFunction): string {
  if (value instanceof ApiError) {
    if (value.code === 'legacy.error') return value.fallback
    const key = `errors.${value.code}`
    const translated = translate(key, value.params)
    return translated === key ? value.fallback : translated
  }
  return value instanceof Error ? value.message : translate('errors.request.failed')
}

export const api = {
  get<T>(path: string) {
    return request<T>(path)
  },
  post<T>(path: string, body?: unknown) {
    return request<T>(path, {
      method: 'POST',
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    })
  },
  put<T>(path: string, body: unknown) {
    return request<T>(path, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
  },
  upload<T>(path: string, file: File) {
    const form = new FormData()
    form.append('file', file)
    return request<T>(path, { method: 'POST', body: form })
  },
}
