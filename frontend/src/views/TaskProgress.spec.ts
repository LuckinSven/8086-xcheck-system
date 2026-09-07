import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, describe, expect, it, vi } from 'vitest'

import TaskProgress from './TaskProgress.vue'

const task = {
  id: 'task-123',
  status: 'waiting_threatbook_confirmation',
  input_type: 'manual',
  original_filename: null,
  current_step: 'whitelist_query',
  raw_count: 3,
  valid_count: 3,
  unique_count: 3,
  whitelist_removed_count: 0,
  threatbook_ready_count: 3,
  malicious_count: 0,
  high_confidence_count: 0,
  failed_count: 0,
  created_at: '2026-08-14T00:00:00Z',
  steps: [{ name: 'whitelist_query', status: 'completed', progress_current: 3, progress_total: 3, current_batch: 1, total_batches: 1, error_summary: null }],
}

const whitelist = {
  summary: { total: 3, hit: 1, clear: 1, error: 1 },
  total: 3,
  page: 1,
  page_size: 50,
  items: [
    { ip: '8.8.8.8', category: '当前名单', result_code: 'active', verdict: '当前条目', matches: [{ source: 'current' }], request_id: 'req-1' },
    { ip: '1.1.1.1', category: '未命中', result_code: 'not_found', verdict: '未命中条目', matches: [], request_id: 'req-2' },
  ],
}

function jsonResponse(payload: unknown, ok = true, status = 200) {
  return { ok, status, json: async () => payload } as Response
}

async function mountPage(fetchMock: ReturnType<typeof vi.fn>) {
  vi.stubGlobal('fetch', fetchMock)
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/tasks/:id', component: TaskProgress },
      { path: '/tasks/:id/threatbook', component: { template: '<div>微步工作台</div>' } },
      { path: '/history', component: { template: '<div>历史</div>' } },
    ],
  })
  await router.push('/tasks/task-123')
  await router.isReady()
  const wrapper = mount(TaskProgress, { global: { plugins: [router] } })
  await flushPromises()
  return { wrapper, router }
}

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('Task progress whitelist conclusions', () => {
  it('shows the paginated whitelist summary and human-readable conclusions after whitelist completion', async () => {
    const fetchMock = vi.fn((path: string) => {
      if (path === '/api/tasks/task-123') return Promise.resolve(jsonResponse(task))
      if (path === '/api/tasks/task-123/ips?page_size=100') return Promise.resolve(jsonResponse({ items: [] }))
      if (path === '/api/tasks/task-123/whitelist-results?page=1&page_size=50') return Promise.resolve(jsonResponse(whitelist))
      return Promise.reject(new Error(`Unexpected request: ${path}`))
    })

    const { wrapper } = await mountPage(fetchMock)

    expect(wrapper.text()).toContain('查白结论')
    expect(wrapper.text()).toContain('命中 1')
    expect(wrapper.text()).toContain('未命中 1')
    expect(wrapper.text()).toContain('异常 1')
    expect(wrapper.text()).toContain('当前名单')
    expect(wrapper.text()).toContain('当前条目')
    expect(wrapper.text()).toContain('req-1')
    expect(fetchMock).toHaveBeenCalledWith('/api/tasks/task-123/whitelist-results?page=1&page_size=50', undefined)
  })

  it('explains that zero whitelist hits have already advanced to the ThreatBook-ready next step', async () => {
    const zeroHitTask = { ...task, whitelist_removed_count: 3 }
    const fetchMock = vi.fn((path: string) => {
      if (path === '/api/tasks/task-123') return Promise.resolve(jsonResponse(zeroHitTask))
      if (path === '/api/tasks/task-123/ips?page_size=100') return Promise.resolve(jsonResponse({ items: [] }))
      if (path === '/api/tasks/task-123/whitelist-results?page=1&page_size=50') {
        return Promise.resolve(jsonResponse({ ...whitelist, summary: { total: 3, hit: 0, clear: 3, error: 0 } }))
      }
      return Promise.reject(new Error(`Unexpected request: ${path}`))
    })

    const { wrapper } = await mountPage(fetchMock)

    expect(wrapper.text()).toContain('没有白名单命中')
    expect(wrapper.text()).toContain('已自动进入微步待查集合')
  })

  it('requests filtered and paginated whitelist conclusions from the server and replaces the rendered rows', async () => {
    const filteredPage = {
      ...whitelist,
      total: 51,
      items: [{ ip: '1.1.1.1', category: '未命中', result_code: 'not_found', verdict: '筛选后的未命中条目', matches: [], request_id: 'req-filtered' }],
    }
    const secondPage = {
      ...filteredPage,
      page: 2,
      items: [{ ip: '9.9.9.9', category: '未命中', result_code: 'not_found', verdict: '第二页结论', matches: [], request_id: 'req-page-2' }],
    }
    const fetchMock = vi.fn((path: string) => {
      if (path === '/api/tasks/task-123') return Promise.resolve(jsonResponse(task))
      if (path === '/api/tasks/task-123/ips?page_size=100') return Promise.resolve(jsonResponse({ items: [] }))
      if (path === '/api/tasks/task-123/whitelist-results?page=1&page_size=50') return Promise.resolve(jsonResponse(whitelist))
      if (path === '/api/tasks/task-123/whitelist-results?page=1&page_size=50&verdict=%E6%9C%AA%E5%91%BD%E4%B8%AD') return Promise.resolve(jsonResponse(filteredPage))
      if (path === '/api/tasks/task-123/whitelist-results?page=2&page_size=50&verdict=%E6%9C%AA%E5%91%BD%E4%B8%AD') return Promise.resolve(jsonResponse(secondPage))
      return Promise.reject(new Error(`Unexpected request: ${path}`))
    })
    const { wrapper } = await mountPage(fetchMock)

    await wrapper.get('.whitelist-controls select').setValue('未命中')
    await flushPromises()
    expect(fetchMock).toHaveBeenCalledWith('/api/tasks/task-123/whitelist-results?page=1&page_size=50&verdict=%E6%9C%AA%E5%91%BD%E4%B8%AD', undefined)
    expect(wrapper.text()).toContain('筛选后的未命中条目')
    expect(wrapper.text()).not.toContain('当前条目')

    await wrapper.get('.pagination button:last-child').trigger('click')
    await flushPromises()
    expect(fetchMock).toHaveBeenCalledWith('/api/tasks/task-123/whitelist-results?page=2&page_size=50&verdict=%E6%9C%AA%E5%91%BD%E4%B8%AD', undefined)
    expect(wrapper.text()).toContain('第二页结论')
    expect(wrapper.text()).not.toContain('筛选后的未命中条目')
  })

  it('starts ThreatBook before navigating to its workspace and stays on the task page when the start fails', async () => {
    let startFails = true
    const fetchMock = vi.fn((path: string, init?: RequestInit) => {
      if (path === '/api/tasks/task-123') return Promise.resolve(jsonResponse(task))
      if (path === '/api/tasks/task-123/ips?page_size=100') return Promise.resolve(jsonResponse({ items: [] }))
      if (path === '/api/tasks/task-123/whitelist-results?page=1&page_size=50') return Promise.resolve(jsonResponse(whitelist))
      if (path === '/api/tasks/task-123/actions/start-threatbook' && init?.method === 'POST') {
        return Promise.resolve(startFails ? jsonResponse({ detail: '后端尚未配置微步 API Key' }, false, 409) : jsonResponse(task, true, 202))
      }
      return Promise.reject(new Error(`Unexpected request: ${path}`))
    })
    const { wrapper, router } = await mountPage(fetchMock)

    await wrapper.get('button.primary.danger').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe('/tasks/task-123')
    expect(wrapper.text()).toContain('后端尚未配置微步 API Key')

    startFails = false
    await wrapper.get('button.primary.danger').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe('/tasks/task-123/threatbook')
    expect(fetchMock.mock.calls.filter(([path, init]) => path === '/api/tasks/task-123/actions/start-threatbook' && init?.method === 'POST')).toHaveLength(2)
  })

  it('disables the start button while the start request is in flight so repeated clicks submit once', async () => {
    let resolveStart!: (response: Response) => void
    const startResponse = new Promise<Response>((resolve) => { resolveStart = resolve })
    const fetchMock = vi.fn((path: string, init?: RequestInit) => {
      if (path === '/api/tasks/task-123') return Promise.resolve(jsonResponse(task))
      if (path === '/api/tasks/task-123/ips?page_size=100') return Promise.resolve(jsonResponse({ items: [] }))
      if (path === '/api/tasks/task-123/whitelist-results?page=1&page_size=50') return Promise.resolve(jsonResponse(whitelist))
      if (path === '/api/tasks/task-123/actions/start-threatbook' && init?.method === 'POST') return startResponse
      return Promise.reject(new Error(`Unexpected request: ${path}`))
    })
    const { wrapper, router } = await mountPage(fetchMock)
    const startButton = wrapper.get('button.primary.danger')

    ;(startButton.element as HTMLButtonElement).click()
    ;(startButton.element as HTMLButtonElement).click()
    await wrapper.vm.$nextTick()
    expect((startButton.element as HTMLButtonElement).disabled).toBe(true)
    expect(fetchMock.mock.calls.filter(([path, init]) => path === '/api/tasks/task-123/actions/start-threatbook' && init?.method === 'POST')).toHaveLength(1)

    resolveStart(jsonResponse(task, true, 202))
    await flushPromises()
    expect(router.currentRoute.value.fullPath).toBe('/tasks/task-123/threatbook')
  })

  it('ignores an older whitelist filter response that resolves after the latest choice', async () => {
    let resolveOlder!: (response: Response) => void
    let resolveNewer!: (response: Response) => void
    const older = new Promise<Response>((resolve) => { resolveOlder = resolve })
    const newer = new Promise<Response>((resolve) => { resolveNewer = resolve })
    const fetchMock = vi.fn((path: string) => {
      if (path === '/api/tasks/task-123') return Promise.resolve(jsonResponse(task))
      if (path === '/api/tasks/task-123/ips?page_size=100') return Promise.resolve(jsonResponse({ items: [] }))
      if (path === '/api/tasks/task-123/whitelist-results?page=1&page_size=50') return Promise.resolve(jsonResponse(whitelist))
      if (path.endsWith('verdict=%E5%BD%93%E5%89%8D%E5%90%8D%E5%8D%95')) return older
      if (path.endsWith('verdict=%E6%9C%AA%E5%91%BD%E4%B8%AD')) return newer
      return Promise.reject(new Error(`Unexpected request: ${path}`))
    })
    const { wrapper } = await mountPage(fetchMock)

    await wrapper.get('.whitelist-controls select').setValue('当前名单')
    await wrapper.get('.whitelist-controls select').setValue('未命中')
    resolveNewer(jsonResponse({ ...whitelist, items: [{ ...whitelist.items[1], verdict: '最新筛选' }] }))
    await flushPromises()
    resolveOlder(jsonResponse({ ...whitelist, items: [{ ...whitelist.items[0], verdict: '过期筛选' }] }))
    await flushPromises()

    expect(wrapper.text()).toContain('最新筛选')
    expect(wrapper.text()).not.toContain('过期筛选')
  })

  it('does not schedule another poll when an in-flight load resolves after unmount', async () => {
    vi.useFakeTimers()
    let resolveTask!: (response: Response) => void
    const taskResponse = new Promise<Response>((resolve) => { resolveTask = resolve })
    const fetchMock = vi.fn((path: string) => {
      if (path === '/api/tasks/task-123') return taskResponse
      if (path === '/api/tasks/task-123/ips?page_size=100') return Promise.resolve(jsonResponse({ items: [] }))
      if (path === '/api/tasks/task-123/whitelist-results?page=1&page_size=50') return Promise.resolve(jsonResponse(whitelist))
      return Promise.reject(new Error(`Unexpected request: ${path}`))
    })
    const { wrapper } = await mountPage(fetchMock)

    wrapper.unmount()
    resolveTask(jsonResponse({ ...task, status: 'running' }))
    await flushPromises()
    await vi.advanceTimersByTimeAsync(1600)
    await flushPromises()

    expect(fetchMock.mock.calls.filter(([path]) => path === '/api/tasks/task-123')).toHaveLength(1)
  })
})
