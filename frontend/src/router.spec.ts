import { describe, expect, it } from 'vitest'

import router from './router'
import Dashboard from './views/Dashboard.vue'
import NewTask from './views/NewTask.vue'
import ThreatbookWorkspace from './views/ThreatbookWorkspace.vue'

describe('ThreatBook workspace route', () => {
  it('resolves task ThreatBook URLs to the live workspace', () => {
    const resolved = router.resolve('/tasks/task-123/threatbook')
    expect(resolved.matched[0]?.components?.default).toBe(ThreatbookWorkspace)
  })

  it('reserves the root route for Dashboard and moves query intake to /new', () => {
    expect(router.resolve('/').matched[0]?.components?.default).toBe(Dashboard)
    expect(router.resolve('/new').matched[0]?.components?.default).toBe(NewTask)
  })
})
