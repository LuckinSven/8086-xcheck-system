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
        { path: '/', component: { template: '<div>首页</div>' } },
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
    expect(wrapper.text()).toContain('新建查询')
    expect(wrapper.text()).toContain('查询历史')
    expect(wrapper.get('a[href="/threatbook-history"]').text()).toContain('微步历史')
    expect(wrapper.text()).toContain('系统设置')
  })

  it('starts with ThreatBook red and exposes all six skins in the topbar', async () => {
    const wrapper = await mountApp()

    expect(document.documentElement.dataset.theme).toBe('threatbook-red')
    const trigger = wrapper.get('[data-testid="theme-trigger"]')
    expect(trigger.attributes('aria-label')).toBe('选择界面皮肤，当前微步社区红')
    await trigger.trigger('click')
    expect(wrapper.findAll('[data-testid="theme-option"]')).toHaveLength(6)
    expect(wrapper.get('[data-testid="theme-menu"]').attributes('role')).toBe('group')
    expect(wrapper.get('[data-theme-id="threatbook-red"]').attributes('aria-pressed')).toBe('true')
    expect(wrapper.text()).toContain('微步社区红')
    expect(wrapper.text()).toContain('护眼青绿')
  })

  it('closes on Escape and returns focus to the trigger', async () => {
    const wrapper = await mountApp()
    const trigger = wrapper.get('[data-testid="theme-trigger"]')
    await trigger.trigger('click')
    const option = wrapper.get('[data-theme-id="eye-care"]')
    ;(option.element as HTMLButtonElement).focus()

    await option.trigger('keydown', { key: 'Escape' })

    expect(wrapper.find('[data-testid="theme-menu"]').exists()).toBe(false)
    expect(document.activeElement).toBe(trigger.element)
  })

  it('dismisses the skin panel on an outside click', async () => {
    const wrapper = await mountApp()
    await wrapper.get('[data-testid="theme-trigger"]').trigger('click')

    document.body.click()
    await wrapper.vm.$nextTick()

    expect(wrapper.find('[data-testid="theme-menu"]').exists()).toBe(false)
  })

  it('switches skin immediately and remembers the selection', async () => {
    const wrapper = await mountApp()

    await wrapper.get('[data-testid="theme-trigger"]').trigger('click')
    await wrapper.get('[data-theme-id="intelligence-blue"]').trigger('click')

    expect(document.documentElement.dataset.theme).toBe('intelligence-blue')
    expect(localStorage.getItem('xcheck-theme')).toBe('intelligence-blue')
    expect(wrapper.find('[data-testid="theme-menu"]').exists()).toBe(false)
  })

  it('restores the saved skin on the next mount', async () => {
    localStorage.setItem('xcheck-theme', 'eye-care')

    const wrapper = await mountApp()

    expect(document.documentElement.dataset.theme).toBe('eye-care')
    expect(wrapper.get('[data-testid="theme-trigger"]').text()).toContain('护眼青绿')
  })
})
