import { beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError, api, translateApiError } from './api'

describe('API problem handling', () => {
  beforeEach(() => vi.restoreAllMocks())

  it('retains structured API problems without exposing response bodies', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 409,
      json: async () => ({
        detail: {
          code: 'integration.threatbook.api_key_required',
          fallback: 'The ThreatBook API key has not been configured.',
          params: {},
        },
        private_body: 'must-not-leak',
      }),
    }))

    const error = await api.post('/api/test').catch((value) => value)

    expect(error).toBeInstanceOf(ApiError)
    if (!(error instanceof ApiError)) throw new Error('Expected an ApiError')
    expect(error.code).toBe('integration.threatbook.api_key_required')
    expect(JSON.stringify(error)).not.toContain('must-not-leak')
  })

  it('translates known codes and uses the English fallback for unknown codes', () => {
    const known = new ApiError(409, {
      code: 'task.not_found',
      fallback: 'The task does not exist.',
      params: { task_id: 'abc' },
    })
    const unknown = new ApiError(500, {
      code: 'future.error',
      fallback: 'A future-compatible English fallback.',
      params: {},
    })
    const translate = (key: string) => key === 'errors.task.not_found' ? '任务不存在。' : key

    expect(translateApiError(known, translate)).toBe('任务不存在。')
    expect(translateApiError(unknown, translate)).toBe('A future-compatible English fallback.')
  })
})
