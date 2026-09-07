import { mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it } from 'vitest'

import NewTask from './NewTask.vue'

describe('New task', () => {
  it('uses business names and does not restrict either log file chooser', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/', component: NewTask }],
    })
    const wrapper = mount(NewTask, { global: { plugins: [router] } })
    expect(wrapper.text()).toContain('Manual input')
    expect(wrapper.text()).toContain('Attack log')
    const buttons = wrapper.findAll('.mode-tabs button')
    expect(buttons.map((button) => button.text())).toEqual(['Manual input', 'Attack log', 'Access log'])

    await buttons[1].trigger('click')
    expect(wrapper.find('input[type="file"]').attributes('accept')).toBeUndefined()
    expect(wrapper.text()).toContain('CSV / XLS / XLSX / ZIP')

    await buttons[2].trigger('click')
    expect(wrapper.find('input[type="file"]').attributes('accept')).toBeUndefined()
  })
})
