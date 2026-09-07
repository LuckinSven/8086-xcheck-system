import { reactive } from 'vue'

import { api } from './api'
import { setLocale } from './i18n'
import { applyTheme, type ThemeId, themes } from './theme'
import type { DisplaySettings, HomepageMode, MotionIntensity, UiLanguage } from './types'

export const DEFAULT_DISPLAY_SETTINGS: DisplaySettings = {
  ui_language: 'en-US',
  theme_id: 'threatbook-red',
  homepage_mode: 'overview',
  motion_intensity: 'medium',
}

export const uiSettings = reactive<DisplaySettings>({ ...DEFAULT_DISPLAY_SETTINGS })

const languages: UiLanguage[] = ['en-US', 'zh-CN']
const homepageModes: HomepageMode[] = ['overview', 'landscape', 'operations']
const motionIntensities: MotionIntensity[] = ['off', 'subtle', 'medium', 'strong']

function oneOf<T extends string>(value: unknown, values: readonly T[], fallback: T): T {
  return typeof value === 'string' && values.includes(value as T) ? value as T : fallback
}

function normalizeDisplaySettings(value: Partial<DisplaySettings>): DisplaySettings {
  return {
    ui_language: oneOf(value.ui_language, languages, DEFAULT_DISPLAY_SETTINGS.ui_language),
    theme_id: oneOf(
      value.theme_id,
      themes.map((theme) => theme.id),
      DEFAULT_DISPLAY_SETTINGS.theme_id,
    ) as ThemeId,
    homepage_mode: oneOf(
      value.homepage_mode,
      homepageModes,
      DEFAULT_DISPLAY_SETTINGS.homepage_mode,
    ),
    motion_intensity: oneOf(
      value.motion_intensity,
      motionIntensities,
      DEFAULT_DISPLAY_SETTINGS.motion_intensity,
    ),
  }
}

export function applyUiSettings(value: DisplaySettings) {
  const normalized = normalizeDisplaySettings(value)
  Object.assign(uiSettings, normalized)
  setLocale(normalized.ui_language)
  applyTheme(normalized.theme_id)
  document.documentElement.dataset.motion = normalized.motion_intensity
}

export async function loadUiSettings(): Promise<DisplaySettings> {
  const settings = await api.get<DisplaySettings>('/api/settings')
  applyUiSettings(settings)
  return { ...uiSettings }
}
