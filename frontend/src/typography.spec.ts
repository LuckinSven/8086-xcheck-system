import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, expect, it } from 'vitest'

const styles = readFileSync(resolve(process.cwd(), 'src/styles.css'), 'utf8')

describe('readable typography and motion accessibility', () => {
  it('uses a 15px base with 14px controls and tables', () => {
    expect(styles).toMatch(/:root,[\s\S]*?font-size:\s*15px/)
    expect(styles).toMatch(/button, input, select, textarea\s*{[^}]*font-size:\s*14px/)
    expect(styles).toMatch(/table\s*{[^}]*font-size:\s*14px/)
  })

  it('never reduces explicit secondary text below 12px', () => {
    const pixelSizes = [...styles.matchAll(/font-size:\s*(\d+)px/g)].map((match) => Number(match[1]))
    expect(Math.min(...pixelSizes)).toBeGreaterThanOrEqual(12)
  })

  it('defines four motion levels and honors reduced-motion preferences', () => {
    for (const level of ['off', 'subtle', 'medium', 'strong']) {
      expect(styles).toContain(`:root[data-motion="${level}"]`)
    }
    expect(styles).toMatch(/@media\s*\(prefers-reduced-motion:\s*reduce\)/)
    expect(styles).toContain('--motion-factor: 0')
  })

  it('uses an opaque glass fallback before backdrop-filter enhancement', () => {
    expect(styles).toMatch(/\.panel\s*{[^}]*background:\s*var\(--glass-surface\)/)
    expect(styles).toMatch(/@supports\s*\(backdrop-filter:\s*blur\(1px\)\)/)
    expect(styles).toContain('background: var(--glass-surface-alpha)')
  })
})
