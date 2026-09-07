import { beforeEach, describe, expect, it } from 'vitest'

import * as themeModule from './theme'
import { DEFAULT_THEME_ID, applyTheme, themes } from './theme'

describe('server-owned theme preferences', () => {
  beforeEach(() => document.documentElement.removeAttribute('data-theme'))

  it('uses ThreatBook red as the default and applies a supported theme', () => {
    expect(DEFAULT_THEME_ID).toBe('threatbook-red')

    applyTheme('ocean-mist')

    expect(document.documentElement.dataset.theme).toBe('ocean-mist')
  })

  it('does not expose obsolete browser-storage ownership', () => {
    expect(themeModule).not.toHaveProperty('THEME_STORAGE_KEY')
    expect(themeModule).not.toHaveProperty('persistTheme')
    expect(themeModule).not.toHaveProperty('readStoredTheme')
  })

  it('offers exactly the requested six distinct skins', () => {
    expect(themes.map((theme) => theme.id)).toEqual([
      'threatbook-red',
      'intelligence-blue',
      'eye-care',
      'midnight-violet',
      'amber-sand',
      'ocean-mist',
    ])
    expect(new Set(themes.flatMap((theme) => theme.swatches)).size).toBeGreaterThan(12)
  })
})
