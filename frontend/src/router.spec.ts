import { describe, expect, it } from 'vitest'

import router from './router'
import ThreatbookWorkspace from './views/ThreatbookWorkspace.vue'

describe('ThreatBook workspace route', () => {
  it('resolves task ThreatBook URLs to the live workspace', () => {
    const resolved = router.resolve('/tasks/task-123/threatbook')
    expect(resolved.matched[0]?.components?.default).toBe(ThreatbookWorkspace)
  })
})
