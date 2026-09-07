import { mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { beforeEach, describe, expect, it } from 'vitest'

import App from './App.vue'

describe('App shell', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
    localStorage.clear()
    document.documentElement.removeAttribute('data-theme')
  })

  async function mountApp() {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: '/', component: { template: '<div>Dashboard</div>' } },
        { path: '/new', component: { template: '<div>New Query</div>' } },
        { path: '/history', component: { template: '<div>历史</div>' } },
        { path: '/threatbook-history', component: { template: '<div>微步历史</div>' } },
        { path: '/settings', component: { template: '<div>设置</div>' } },
      ],
    })
    const wrapper = mount(App, { attachTo: document.body, global: { plugins: [router] } })
    await router.isReady()
    return wrapper
  }

  it('shows product identity and the primary navigation', async () => {
    const wrapper = await mountApp()

    expect(wrapper.text()).toContain('XCheck')
    expect(wrapper.get('a[href="/"]').text()).toContain('Dashboard')
    expect(wrapper.get('a[href="/new"]').text()).toContain('New Query')
    expect(wrapper.text()).toContain('Query History')
    expect(wrapper.get('a[href="/threatbook-history"]').text()).toContain('ThreatBook History')
    expect(wrapper.text()).toContain('System Settings')
  })

  it('keeps visual configuration out of the topbar', async () => {
    const wrapper = await mountApp()

    expect(wrapper.find('[data-testid="theme-trigger"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('Service connected')
  })
})
