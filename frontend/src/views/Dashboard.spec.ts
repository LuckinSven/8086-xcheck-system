import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { uiSettings } from '../ui-settings'
import Dashboard from './Dashboard.vue'

const apiMock = vi.hoisted(() => ({ get: vi.fn() }))

enableAutoUnmount(afterEach)

vi.mock('../api', () => ({
  api: apiMock,
  translateApiError: (reason: unknown) => reason instanceof Error ? reason.message : 'Request failed.',
}))

const base = {
  generated_at: '2026-09-07T01:02:03Z',
  summary: {},
  sections: {},
}

function mountDashboard() {
  return mount(Dashboard, {
    global: {
      stubs: { RouterLink: { template: '<a><slot /></a>' } },
    },
  })
}

describe('Dashboard', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    uiSettings.homepage_mode = 'overview'
    apiMock.get.mockReset()
  })

  afterEach(() => {
    Object.defineProperty(document, 'hidden', { configurable: true, value: false })
    vi.useRealTimers()
  })

  it('renders the bounded overview and refreshes it without changing routes', async () => {
    apiMock.get.mockResolvedValue({
      ...base,
      mode: 'overview',
      summary: { total_tasks: 12, total_unique_ips: 220, malicious_ips: 7, active_tasks: 2, failed_tasks: 1 },
      sections: {
        trend: { available: true, items: [{ date: '2026-09-07', tasks: 2, addresses: 22, malicious: 3 }] },
        recent_risks: { available: true, items: [{ task_id: 'risk-task', ip: '8.8.8.8', severity: 'high', labels: ['scanner'], country: 'China', province: 'Beijing', city: 'Beijing', created_at: '2026-09-07T01:00:00Z' }] },
        attention: { available: true, items: [{ task_id: 'failed-task', status: 'failed', current_step: 'threatbook_query', error_summary: 'safe failure', updated_at: '2026-09-07T01:00:00Z' }] },
      },
    })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(apiMock.get).toHaveBeenCalledWith('/api/dashboard?mode=overview')
    expect(wrapper.get('[data-dashboard="overview"]').text()).toContain('220')
    expect(wrapper.text()).toContain('8.8.8.8')
    expect(wrapper.text()).toContain('safe failure')

    await vi.advanceTimersByTimeAsync(15_000)
    expect(apiMock.get).toHaveBeenCalledTimes(2)
  })

  it('switches to the threat landscape selected in system settings', async () => {
    uiSettings.homepage_mode = 'landscape'
    apiMock.get.mockResolvedValue({
      ...base,
      mode: 'landscape',
      summary: { malicious_last_24h: 9, total_malicious: 90, affected_countries: 2 },
      sections: {
        countries: { available: true, items: [{ name: 'China', count: 6 }] },
        regions: { available: true, items: [{ name: 'China / Beijing', count: 4 }] },
        labels: { available: true, items: [{ name: 'scanner', count: 5 }] },
        severities: { available: true, items: [{ name: 'critical', count: 3 }] },
        trend: { available: true, items: [{ date: '2026-09-07', malicious: 9 }] },
      },
    })

    const wrapper = mountDashboard()
    await flushPromises()

    expect(apiMock.get).toHaveBeenCalledWith('/api/dashboard?mode=landscape')
    expect(wrapper.get('[data-dashboard="landscape"]').text()).toContain('scanner')
    expect(wrapper.find('[data-testid="threat-map"]').exists()).toBe(true)
    expect(wrapper.findAll('[data-map-marker]')).toHaveLength(1)
  })

  it('shows live operations progress, quota, integrations, and failed nodes', async () => {
    uiSettings.homepage_mode = 'operations'
    apiMock.get.mockResolvedValue({
      ...base,
      mode: 'operations',
      summary: {
        status_counts: { running: 1, failed: 1, completed: 4 }, backlog: 1,
        progress: { current: 40, total: 100, percent: 40 }, daily_usage: 125,
        daily_remaining: 9875, worker_status: 'ready', database_status: 'ready',
      },
      sections: {
        active_tasks: { available: true, items: [{ task_id: 'active-task', status: 'running', current_step: 'threatbook_query', unique_count: 100, current: 40, total: 100, created_at: '2026-09-07T01:00:00Z' }] },
        failed_nodes: { available: true, items: [{ task_id: 'failed-task', step: 'threatbook_query', error_summary: 'rate limited', current: 20, total: 100, started_at: '2026-09-07T01:00:00Z' }] },
        integration_health: { available: true, items: [{ name: 'whitelist', status: 'success', latency_ms: 12 }, { name: 'threatbook', status: 'untested', latency_ms: null }] },
        configuration: { available: true, items: [{ name: 'safe_rate', value: 800 }] },
      },
    })

    const wrapper = mountDashboard()
    await flushPromises()

    const operations = wrapper.get('[data-dashboard="operations"]')
    expect(operations.text()).toContain('40%')
    expect(operations.text()).toContain('9,875')
    expect(operations.text()).toContain('rate limited')
    expect(operations.text()).toContain('whitelist')
  })

  it('shows a translated retry state after a failed request', async () => {
    apiMock.get.mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce({
      ...base,
      mode: 'overview',
      summary: { total_tasks: 0, total_unique_ips: 0, malicious_ips: 0, active_tasks: 0, failed_tasks: 0 },
      sections: {
        trend: { available: true, items: [] },
        recent_risks: { available: true, items: [] },
        attention: { available: true, items: [] },
      },
    })
    const wrapper = mountDashboard()
    await flushPromises()

    expect(wrapper.text()).toContain('offline')
    await wrapper.get('[data-action="retry-dashboard"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-dashboard="overview"]').exists()).toBe(true)
  })

  it('pauses polling while hidden and refreshes when the page becomes visible', async () => {
    apiMock.get.mockResolvedValue({
      ...base,
      mode: 'overview',
      summary: { total_tasks: 0, total_unique_ips: 0, malicious_ips: 0, active_tasks: 0, failed_tasks: 0 },
      sections: {
        trend: { available: true, items: [] }, recent_risks: { available: true, items: [] },
        attention: { available: true, items: [] },
      },
    })
    Object.defineProperty(document, 'hidden', { configurable: true, value: true })
    const wrapper = mountDashboard()
    await flushPromises()

    await vi.advanceTimersByTimeAsync(30_000)
    expect(apiMock.get).toHaveBeenCalledTimes(1)

    Object.defineProperty(document, 'hidden', { configurable: true, value: false })
    document.dispatchEvent(new Event('visibilitychange'))
    await flushPromises()
    expect(apiMock.get).toHaveBeenCalledTimes(2)
    wrapper.unmount()
  })

  it('ignores a stale response when the configured home mode changes', async () => {
    let resolveOverview!: (value: unknown) => void
    const overview = new Promise((resolve) => { resolveOverview = resolve })
    apiMock.get.mockImplementation((path: string) => path.endsWith('overview')
      ? overview
      : Promise.resolve({
          ...base,
          mode: 'landscape',
          summary: { malicious_last_24h: 3, total_malicious: 8, affected_countries: 1 },
          sections: {
            countries: { available: true, items: [] }, regions: { available: true, items: [] },
            labels: { available: true, items: [] }, severities: { available: true, items: [] },
            trend: { available: true, items: [] },
          },
        }))
    const wrapper = mountDashboard()
    uiSettings.homepage_mode = 'landscape'
    await flushPromises()
    resolveOverview({
      ...base,
      mode: 'overview',
      summary: { total_tasks: 99, total_unique_ips: 99, malicious_ips: 99, active_tasks: 0, failed_tasks: 0 },
      sections: {
        trend: { available: true, items: [] }, recent_risks: { available: true, items: [] },
        attention: { available: true, items: [] },
      },
    })
    await flushPromises()

    expect(wrapper.find('[data-dashboard="landscape"]').exists()).toBe(true)
    expect(wrapper.text()).not.toContain('99')
  })
})
