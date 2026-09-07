import { createI18n } from 'vue-i18n'

import type { UiLanguage } from './types'
import enUS from './locales/en-US'
import zhCN from './locales/zh-CN'

export const i18n = createI18n({
  legacy: false,
  locale: 'en-US',
  fallbackLocale: 'en-US',
  messages: {
    'en-US': enUS,
    'zh-CN': zhCN,
  },
  datetimeFormats: {
    'en-US': { short: { dateStyle: 'medium', timeStyle: 'short' } },
    'zh-CN': { short: { dateStyle: 'medium', timeStyle: 'short', hour12: false } },
  },
})

export function setLocale(locale: UiLanguage) {
  i18n.global.locale.value = locale
  document.documentElement.lang = locale
}
