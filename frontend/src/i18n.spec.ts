import { beforeEach, describe, expect, it, vi } from 'vitest'

import { i18n, setLocale } from './i18n'
import enUS from './locales/en-US'
import zhCN from './locales/zh-CN'
import { applyUiSettings, loadUiSettings } from './ui-settings'

function messageKeys(value: unknown, prefix = ''): string[] {
  if (!value || typeof value !== 'object') return [prefix]
  return Object.entries(value).flatMap(([key, child]) =>
    messageKeys(child, prefix ? `${prefix}.${key}` : key),
  )
}

describe('internationalization foundation', () => {
  beforeEach(() => {
    setLocale('en-US')
    document.documentElement.removeAttribute('data-theme')
    document.documentElement.removeAttribute('data-motion')
  })

  it('defaults to English and keeps both catalogs structurally identical', () => {
    expect(i18n.global.locale.value).toBe('en-US')
    expect(i18n.global.t('common.newQuery')).toBe('New Query')
    expect(messageKeys(zhCN).sort()).toEqual(messageKeys(enUS).sort())
  })

  it('switches the global translator and document language to Chinese', () => {
    setLocale('zh-CN')

    expect(i18n.global.t('common.newQuery')).toBe('新建查询')
    expect(document.documentElement.lang).toBe('zh-CN')
  })

  it('loads global display settings and applies all document attributes', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        ui_language: 'zh-CN',
        theme_id: 'ocean-mist',
        homepage_mode: 'landscape',
        motion_intensity: 'strong',
      }),
    }))

    await loadUiSettings()

    expect(document.documentElement.lang).toBe('zh-CN')
    expect(document.documentElement.dataset.theme).toBe('ocean-mist')
    expect(document.documentElement.dataset.motion).toBe('strong')
    applyUiSettings({
      ui_language: 'en-US',
      theme_id: 'threatbook-red',
      homepage_mode: 'overview',
      motion_intensity: 'medium',
    })
  })

  it('keeps presentation copy out of Vue templates', () => {
    const templates = import.meta.glob(['./App.vue', './views/*.vue'], {
      eager: true,
      query: '?raw',
      import: 'default',
    }) as Record<string, string>
    const protocolAndNativeLabels = /简体中文|当前名单|历史名单|失效名单|未命中|异常/g

    for (const [path, source] of Object.entries(templates)) {
      expect(source.replace(protocolAndNativeLabels, ''), path).not.toMatch(/[一-龥]/)
    }
  })
})
