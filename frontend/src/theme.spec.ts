import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import {
  DEFAULT_THEME_ID,
  THEME_STORAGE_KEY,
  applyTheme,
  persistTheme,
  readStoredTheme,
  themes,
} from './theme'

describe('theme preferences', () => {
  beforeEach(() => {
    localStorage.clear()
    document.documentElement.removeAttribute('data-theme')
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('falls back to ThreatBook red when no valid preference exists', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'unknown-theme')

    expect(readStoredTheme()).toBe('threatbook-red')
    expect(DEFAULT_THEME_ID).toBe('threatbook-red')
  })

  it('restores a supported stored preference', () => {
    localStorage.setItem(THEME_STORAGE_KEY, 'eye-care')

    expect(readStoredTheme()).toBe('eye-care')
  })

  it('applies and persists the selected theme', () => {
    applyTheme('ocean-mist')
    persistTheme('ocean-mist')

    expect(document.documentElement.dataset.theme).toBe('ocean-mist')
    expect(localStorage.getItem('xcheck-theme')).toBe('ocean-mist')
  })

  it('keeps the UI usable when browser storage is unavailable', () => {
    const blockedStorage = {
      getItem: () => { throw new Error('blocked') },
    }

    expect(readStoredTheme(blockedStorage)).toBe('threatbook-red')
  })

  it('falls back when access to the browser storage property is blocked', () => {
    vi.spyOn(window, 'localStorage', 'get').mockImplementation(() => {
      throw new DOMException('blocked', 'SecurityError')
    })

    expect(readStoredTheme()).toBe('threatbook-red')
    expect(() => persistTheme('eye-care')).not.toThrow()
  })

  it('ignores a blocked preference write', () => {
    const blockedStorage = {
      setItem: () => { throw new Error('blocked') },
    }

    expect(() => persistTheme('eye-care', blockedStorage)).not.toThrow()
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
  })
})
