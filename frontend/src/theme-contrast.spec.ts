import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

import { themes } from './theme'

const styles = readFileSync(resolve(process.cwd(), 'src/styles.css'), 'utf8')

function luminance(hex: string) {
  const compact = hex.slice(1)
  const normalized = compact.length === 3 ? [...compact].map((value) => value.repeat(2)).join('') : compact
  const channels = normalized.match(/[a-f\d]{2}/gi)?.map((value) => Number.parseInt(value, 16) / 255) ?? []
  const linear = channels.map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]
}

function contrast(first: string, second: string) {
  const [lighter, darker] = [luminance(first), luminance(second)].sort((a, b) => b - a)
  return (lighter + 0.05) / (darker + 0.05)
}

function themeTokens(themeId: string) {
  const selector = themeId === 'threatbook-red' ? ':root[data-theme="threatbook-red"]' : `:root[data-theme="${themeId}"]`
  const selectorIndex = styles.indexOf(selector)
  const blockStart = styles.indexOf('{', selectorIndex)
  const blockEnd = styles.indexOf('}', blockStart)
  const declarations = styles.slice(blockStart + 1, blockEnd)
  return Object.fromEntries(
    [...declarations.matchAll(/--([\w-]+):\s*(#[a-f\d]{3,8})/gi)].map((match) => [match[1], match[2]]),
  )
}

describe('theme contrast', () => {
  it.each(themes)('$id keeps text and controls readable', (theme) => {
    const tokens = themeTokens(theme.id)

    expect(contrast(tokens.blue, '#ffffff')).toBeGreaterThanOrEqual(4.5)
    expect(contrast(tokens.muted, tokens.surface)).toBeGreaterThanOrEqual(4.5)
    expect(contrast(tokens.muted, tokens['surface-soft'])).toBeGreaterThanOrEqual(4.5)
    expect(contrast(tokens.muted, tokens['accent-soft'])).toBeGreaterThanOrEqual(4.5)
    expect(contrast(tokens['focus-ring'], tokens.surface)).toBeGreaterThanOrEqual(3)
    expect(tokens['ambient-a']).toMatch(/^#[a-f\d]{6,8}$/i)
    expect(tokens['ambient-b']).toMatch(/^#[a-f\d]{6,8}$/i)
    expect(tokens['glass-surface']).toMatch(/^#[a-f\d]{6,8}$/i)
    expect(tokens['glass-surface-alpha']).toMatch(/^#[a-f\d]{8}$/i)
    expect(tokens['glass-border']).toMatch(/^#[a-f\d]{6,8}$/i)
  })
})
