import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import Settings from './Settings.vue'

const apiMock = vi.hoisted(() => ({
  get: vi.fn(),
  put: vi.fn(),
  post: vi.fn(),
}))

vi.mock('../api', () => ({
  api: apiMock,
  translateApiError: (reason: unknown) => reason instanceof Error ? reason.message : 'Request failed.',
}))

const settings = {
  whitelist_api_url: 'http://whitelist.test/query',
  threatbook_api_url: 'https://threatbook.test/ip',
  threatbook_api_key_configured: true,
  upload_max_bytes: 524288000,
  threatbook_batch_size: 100,
  threatbook_safe_ips_per_minute: 800,
  threatbook_daily_budget: 10000,
  threatbook_max_retries: 3,
  ui_language: 'en-US',
  theme_id: 'threatbook-red',
  homepage_mode: 'overview',
  motion_intensity: 'medium',
  integration_tests: {
    whitelist: { status: 'untested', tested_at: null, latency_ms: null, error_code: null, fallback: null },
    threatbook: { status: 'untested', tested_at: null, latency_ms: null, error_code: null, fallback: null },
  },
}

describe('Settings', () => {
  beforeEach(() => {
    apiMock.get.mockReset().mockResolvedValue(settings)
    apiMock.put.mockReset().mockResolvedValue(settings)
    apiMock.post.mockReset().mockResolvedValue({
      ok: true,
      code: 'integration.test_succeeded',
      fallback: 'Connection succeeded.',
      params: {},
      latency_ms: 12,
    })
  })

  it('edits both API endpoints without exposing the saved key', async () => {
    const wrapper = mount(Settings)
    await flushPromises()

    const password = wrapper.find<HTMLInputElement>('input[type="password"]')
    expect(password.exists()).toBe(true)
    expect(password.element.value).toBe('')
    expect(wrapper.text()).toContain('Test whitelist connection')
    expect(wrapper.text()).toContain('Test ThreatBook authentication')
    expect(wrapper.text()).not.toContain('new-secret-key')
  })

  it('saves appearance choices and applies language, theme, homepage, and motion', async () => {
    apiMock.put.mockImplementation(async (_path, payload) => ({ ...settings, ...payload }))
    const wrapper = mount(Settings)
    await flushPromises()

    await wrapper.get<HTMLSelectElement>('[name="ui_language"]').setValue('zh-CN')
    await wrapper.get<HTMLSelectElement>('[name="theme_id"]').setValue('ocean-mist')
    await wrapper.get<HTMLSelectElement>('[name="homepage_mode"]').setValue('landscape')
    await wrapper.get<HTMLSelectElement>('[name="motion_intensity"]').setValue('strong')
    await wrapper.get('[data-action="save-settings"]').trigger('click')
    await flushPromises()

    expect(apiMock.put).toHaveBeenCalledWith('/api/settings', expect.objectContaining({
      ui_language: 'zh-CN',
      theme_id: 'ocean-mist',
      homepage_mode: 'landscape',
      motion_intensity: 'strong',
    }))
    expect(document.documentElement.lang).toBe('zh-CN')
    expect(document.documentElement.dataset.theme).toBe('ocean-mist')
    expect(document.documentElement.dataset.motion).toBe('strong')
    expect(wrapper.text()).toContain('系统设置')
  })

  it('saves integration values and runs both real probes', async () => {
    const wrapper = mount(Settings)
    await flushPromises()

    await wrapper.find<HTMLInputElement>('input[name="whitelist_api_url"]').setValue('http://new.test/query')
    await wrapper.find<HTMLInputElement>('input[name="threatbook_api_url"]').setValue('https://new.test/ip')
    await wrapper.find<HTMLInputElement>('input[type="password"]').setValue('replacement-secret')
    await wrapper.get('[data-action="save-settings"]').trigger('click')
    await flushPromises()
    await wrapper.get('[data-action="test-whitelist"]').trigger('click')
    await flushPromises()
    await wrapper.get('[data-action="test-threatbook"]').trigger('click')
    await flushPromises()

    expect(apiMock.put).toHaveBeenCalledWith('/api/settings', expect.objectContaining({
      whitelist_api_url: 'http://new.test/query',
      threatbook_api_url: 'https://new.test/ip',
      threatbook_api_key: 'replacement-secret',
    }))
    expect(apiMock.put).toHaveBeenCalledTimes(1)
    expect(apiMock.post).toHaveBeenCalledWith('/api/settings/test-whitelist')
    expect(apiMock.post).toHaveBeenCalledWith('/api/settings/test-threatbook')
  })
})
