import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, describe, expect, it, vi } from 'vitest'

import ThreatbookWorkspace from './ThreatbookWorkspace.vue'

enableAutoUnmount(afterEach)

const task = {
  id: 'task-123',
  status: 'running',
  input_type: 'manual',
  original_filename: null,
  current_step: 'threatbook_query',
  raw_count: 200,
  valid_count: 200,
  unique_count: 200,
  whitelist_removed_count: 0,
  threatbook_ready_count: 200,
  malicious_count: 7,
  high_confidence_count: 3,
  failed_count: 2,
  created_at: '2026-08-14T00:00:00Z',
  threatbook_config: {
    batch_size: 50,
    safe_ips_per_minute: 600,
    daily_budget: 10000,
    max_retries: 3,
    api_key: 'must-not-render',
  },
  steps: [
    {
      name: 'threatbook_query',
      status: 'running',
      progress_current: 50,
      progress_total: 200,
      current_batch: 1,
      total_batches: 4,
      error_summary: null,
      started_at: '2026-08-14T00:00:00Z',
      finished_at: null,
    },
  ],
}

const batches = {
  total: 2,
  page: 1,
  page_size: 20,
  items: [
    {
      id: 'batch-1',
      batch_number: 1,
      status: 'completed',
      address_count: 50,
      resolved_count: 48,
      unresolved_count: 2,
      attempt_count: 2,
      response_code: 0,
      response_message: '微步接口请求完成',
      created_at: '2026-08-14T00:01:00Z',
      finished_at: '2026-08-14T00:02:00Z',
    },
  ],
}

const results = {
  total: 51,
  page: 1,
  page_size: 50,
  items: [
    {
      id: 11,
      task_ip_id: 91,
      batch_id: 'batch-1',
      ip: '8.8.8.8',
      is_malicious: true,
      confidence_level: 'high',
      severity: 'critical',
      judgments: ['botnet', 'scanner'],
      country: '美国',
      province: '加利福尼亚',
      city: '山景城',
      carrier: 'Google',
      asn_number: 15169,
      asn_name: 'GOOGLE',
      scene: 'IDC',
      update_time: '2026-08-13 12:00:00',
      permalink: 'https://x.threatbook.com/v5/ip/8.8.8.8',
    },
  ],
}

function jsonResponse(payload: unknown, ok = true, status = 200) {
  return { ok, status, json: async () => payload } as Response
}

function baseFetch(overrides?: (path: string, init?: RequestInit) => Response | Promise<Response> | undefined) {
  return vi.fn((path: string, init?: RequestInit) => {
    const overridden = overrides?.(path, init)
    if (overridden) return Promise.resolve(overridden)
    if (path === '/api/tasks/task-123') return Promise.resolve(jsonResponse(task))
    if (path === '/api/tasks/task-123/threatbook/batches?page=1&page_size=20') return Promise.resolve(jsonResponse(batches))
    if (path === '/api/tasks/task-123/threatbook/results?page=1&page_size=50') return Promise.resolve(jsonResponse(results))
    return Promise.reject(new Error(`Unexpected request: ${path}`))
  })
}

async function mountPage(fetchMock = baseFetch(), path = '/tasks/task-123/threatbook') {
  vi.stubGlobal('fetch', fetchMock)
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/tasks/:id/threatbook', component: ThreatbookWorkspace },
      { path: '/tasks/:id', component: { template: '<div>任务详情</div>' } },
      { path: '/tasks/:id/ips/:ipId', component: { template: '<div>IP 排查</div>' } },
      { path: '/history', component: { template: '<div>任务历史</div>' } },
      { path: '/threatbook-history', component: { template: '<div>微步历史</div>' } },
    ],
  })
  await router.push(path)
  await router.isReady()
  const wrapper = mount(ThreatbookWorkspace, { global: { plugins: [router] } })
  await flushPromises()
  return { wrapper, router, fetchMock }
}

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('ThreatBook workspace', () => {
  it('renders persisted progress, batch evidence, safe execution settings, and intelligence fields', async () => {
    const { wrapper } = await mountPage()

    expect(wrapper.text()).toContain('ThreatBook Intelligence Workspace')
    const metrics = wrapper.findAll('.threatbook-stats article')
    expect(metrics[1].get('b').text()).toBe('50')
    expect(metrics[2].get('b').text()).toBe('150')
    expect(metrics[3].get('b').text()).toBe('2')
    expect(metrics[4].get('b').text()).toBe('7')
    expect(wrapper.text()).toContain('25%')
    expect(wrapper.text()).toContain('Current batch 1 / 4')
    expect(wrapper.text()).toContain('Batch size 50')
    expect(wrapper.text()).toContain('Safe rate 600 IPs/minute')
    expect(wrapper.text()).toContain('Daily budget 10000')
    expect(wrapper.text()).toContain('Maximum retries 3')
    expect(wrapper.text()).not.toContain('must-not-render')

    expect(wrapper.text()).toContain('微步接口请求完成')
    expect(wrapper.text()).toContain('48')
    expect(wrapper.text()).toContain('botnet, scanner')
    expect(wrapper.text()).toContain('美国 / 加利福尼亚 / 山景城')
    expect(wrapper.text()).toContain('Google')
    expect(wrapper.text()).toContain('AS15169 · GOOGLE')
    expect(wrapper.text()).toContain('IDC')
    expect(wrapper.get('a[href="/tasks/task-123/ips/91"]').text()).toContain('Investigate')
    expect(wrapper.get('a[href="https://x.threatbook.com/v5/ip/8.8.8.8"]').attributes('rel')).toContain('noopener')
  })

  it('sends result filters and pagination to the server without loading all IPs', async () => {
    const filtered = {
      ...results,
      total: 51,
      items: [{ ...results.items[0], id: 12, task_ip_id: 92, ip: '9.9.9.9', judgments: ['phishing'] }],
    }
    const secondPage = { ...filtered, page: 2, items: [{ ...filtered.items[0], id: 13, ip: '4.4.4.4' }] }
    const fetchMock = baseFetch((path) => {
      if (path === '/api/tasks/task-123/threatbook/results?q=9.9&malicious=true&judgment=phishing&country=%E4%B8%AD%E5%9B%BD&province=%E5%8C%97%E4%BA%AC&city=%E6%B5%B7%E6%B7%80&severity=high&confidence=high&page=1&page_size=50') return jsonResponse(filtered)
      if (path === '/api/tasks/task-123/threatbook/results?q=9.9&malicious=true&judgment=phishing&country=%E4%B8%AD%E5%9B%BD&province=%E5%8C%97%E4%BA%AC&city=%E6%B5%B7%E6%B7%80&severity=high&confidence=high&page=2&page_size=50') return jsonResponse(secondPage)
      return undefined
    })
    const { wrapper } = await mountPage(fetchMock)

    await wrapper.get('[aria-label="IP search"]').setValue('9.9')
    await wrapper.get('[aria-label="Malicious status"]').setValue('true')
    await wrapper.get('[aria-label="Threat label"]').setValue('phishing')
    await wrapper.get('[aria-label="Country"]').setValue('中国')
    await wrapper.get('[aria-label="Province"]').setValue('北京')
    await wrapper.get('[aria-label="City"]').setValue('海淀')
    await wrapper.get('[aria-label="Severity"]').setValue('high')
    await wrapper.get('[aria-label="Confidence"]').setValue('high')
    await wrapper.get('form.result-filters').trigger('submit')
    await flushPromises()

    const firstUrl = '/api/tasks/task-123/threatbook/results?q=9.9&malicious=true&judgment=phishing&country=%E4%B8%AD%E5%9B%BD&province=%E5%8C%97%E4%BA%AC&city=%E6%B5%B7%E6%B7%80&severity=high&confidence=high&page=1&page_size=50'
    expect(fetchMock).toHaveBeenCalledWith(firstUrl, undefined)
    expect(wrapper.text()).toContain('9.9.9.9')
    expect(wrapper.text()).not.toContain('8.8.8.8')

    await wrapper.get('[aria-label="Intelligence result pagination"] button:last-child').trigger('click')
    await flushPromises()
    expect(fetchMock).toHaveBeenCalledWith(firstUrl.replace('page=1', 'page=2'), undefined)
    expect(wrapper.text()).toContain('4.4.4.4')
  })

  it('polls task, batch, and result pages after 1.5 seconds only while active', async () => {
    vi.useFakeTimers()
    const fetchMock = baseFetch()
    await mountPage(fetchMock)
    expect(fetchMock).toHaveBeenCalledTimes(3)

    await vi.advanceTimersByTimeAsync(1499)
    expect(fetchMock).toHaveBeenCalledTimes(3)
    await vi.advanceTimersByTimeAsync(1)
    await flushPromises()

    expect(fetchMock).toHaveBeenCalledTimes(6)
  })

  it.each([
    'waiting_whitelist_confirmation',
    'waiting_threatbook_confirmation',
    'paused_quota',
    'failed',
    'partial_success',
    'completed',
  ])('does not poll ordinary waiting, terminal, or paused status %s', async (status) => {
    vi.useFakeTimers()
    const fetchMock = baseFetch((path) => path === '/api/tasks/task-123' ? jsonResponse({ ...task, status }) : undefined)
    await mountPage(fetchMock)
    const initialCalls = ['failed', 'partial_success', 'completed'].includes(status) ? 4 : 3
    expect(fetchMock).toHaveBeenCalledTimes(initialCalls)

    await vi.advanceTimersByTimeAsync(3000)
    await flushPromises()

    expect(fetchMock).toHaveBeenCalledTimes(initialCalls)
  })

  it('keeps successfully loaded sections visible and reports safe partial-load errors', async () => {
    const fetchMock = baseFetch((path) => {
      if (path.includes('/threatbook/batches')) return jsonResponse({ detail: '批次服务暂时不可用' }, false, 503)
      return undefined
    })
    const { wrapper } = await mountPage(fetchMock)

    expect(wrapper.text()).toContain('ThreatBook Intelligence Workspace')
    expect(wrapper.text()).toContain('8.8.8.8')
    expect(wrapper.text()).toContain('批次服务暂时不可用')
    expect(wrapper.text()).toContain('Batch details are unavailable')
  })

  it('keeps existing export and polls a successful retry through waiting and running', async () => {
    vi.useFakeTimers()
    const diagnostics = {
      task_id: 'task-123',
      status: 'failed',
      current_step: 'threatbook_query',
      error_summary: '上游超时',
      last_successful_checkpoint: 'filter_non_public',
      attempts: [],
      batches: [],
    }
    const taskStates = [
      { ...task, status: 'failed', error_summary: '上游超时' },
      { ...task, status: 'waiting_threatbook_confirmation', error_summary: null },
      { ...task, status: 'running', error_summary: null },
      { ...task, status: 'completed', error_summary: null },
    ]
    let taskReads = 0
    const fetchMock = baseFetch((path, init) => {
      if (path === '/api/tasks/task-123') return jsonResponse(taskStates[Math.min(taskReads++, taskStates.length - 1)])
      if (path.startsWith('/api/tasks/task-123/diagnostics')) return jsonResponse(diagnostics)
      if (path === '/api/tasks/task-123/steps/threatbook_query/retry' && init?.method === 'POST') return jsonResponse({ ...task, status: 'queued' }, true, 202)
      return undefined
    })
    const { wrapper } = await mountPage(fetchMock)

    expect(wrapper.get('a[href="/api/tasks/task-123/exports/threatbook_complete.xlsx"]')).toBeTruthy()
    expect(wrapper.text()).toContain('上游超时')
    await wrapper.get('button.retry-threatbook').trigger('click')
    await flushPromises()
    expect(fetchMock).toHaveBeenCalledWith('/api/tasks/task-123/steps/threatbook_query/retry', expect.objectContaining({ method: 'POST' }))
    expect(taskReads).toBe(2)

    await vi.advanceTimersByTimeAsync(1500)
    await flushPromises()
    expect(taskReads).toBe(3)

    await vi.advanceTimersByTimeAsync(1500)
    await flushPromises()
    expect(taskReads).toBe(4)
    await vi.advanceTimersByTimeAsync(3000)
    expect(taskReads).toBe(4)
  })

  it('requests a strictly bounded diagnostics summary for failed tasks', async () => {
    const diagnostics = {
      task_id: 'task-123', status: 'failed', current_step: 'threatbook_query', error_summary: '失败',
      last_successful_checkpoint: null, attempt_total: 0, batch_total: 0, attempt_limit: 50, batch_limit: 50,
      attempts: [], batches: [],
    }
    const fetchMock = baseFetch((path) => {
      if (path === '/api/tasks/task-123') return jsonResponse({ ...task, status: 'failed' })
      if (path === '/api/tasks/task-123/diagnostics?attempt_limit=50&batch_limit=50') return jsonResponse(diagnostics)
      return undefined
    })

    await mountPage(fetchMock)

    expect(fetchMock).toHaveBeenCalledWith('/api/tasks/task-123/diagnostics?attempt_limit=50&batch_limit=50', undefined)
  })

  it('ignores older result and batch responses that resolve after newer page choices', async () => {
    let resolveOldResults!: (response: Response) => void
    let resolveNewResults!: (response: Response) => void
    const oldResults = new Promise<Response>((resolve) => { resolveOldResults = resolve })
    const newResults = new Promise<Response>((resolve) => { resolveNewResults = resolve })
    const fetchMock = baseFetch((path) => {
      if (path.includes('/threatbook/results?q=old&')) return oldResults
      if (path.includes('/threatbook/results?q=new&')) return newResults
      return undefined
    })
    const { wrapper } = await mountPage(fetchMock)

    await wrapper.get('[aria-label="IP search"]').setValue('old')
    await wrapper.get('form.result-filters').trigger('submit')
    await wrapper.get('[aria-label="IP search"]').setValue('new')
    await wrapper.get('form.result-filters').trigger('submit')
    resolveNewResults(jsonResponse({ ...results, items: [{ ...results.items[0], id: 20, ip: '2.2.2.2' }] }))
    await flushPromises()
    resolveOldResults(jsonResponse({ ...results, items: [{ ...results.items[0], id: 21, ip: '1.1.1.1' }] }))
    await flushPromises()

    expect(wrapper.text()).toContain('2.2.2.2')
    expect(wrapper.text()).not.toContain('1.1.1.1')

    vi.useFakeTimers()
    let pageOneReads = 0
    let resolveOldBatch!: (response: Response) => void
    let resolvePageTwo!: (response: Response) => void
    const oldBatch = new Promise<Response>((resolve) => { resolveOldBatch = resolve })
    const pageTwo = new Promise<Response>((resolve) => { resolvePageTwo = resolve })
    const batchFetch = baseFetch((path) => {
      if (path === '/api/tasks/task-123/threatbook/batches?page=1&page_size=20') {
        pageOneReads += 1
        return pageOneReads === 1 ? jsonResponse({ ...batches, total: 21 }) : oldBatch
      }
      if (path === '/api/tasks/task-123/threatbook/batches?page=2&page_size=20') return pageTwo
      return undefined
    })
    const { wrapper: batchWrapper } = await mountPage(batchFetch)
    await vi.advanceTimersByTimeAsync(1500)
    await batchWrapper.get('[aria-label="Batch pagination"] button:last-child').trigger('click')
    resolvePageTwo(jsonResponse({ ...batches, total: 21, page: 2, items: [{ ...batches.items[0], id: 'batch-new', batch_number: 21 }] }))
    await flushPromises()
    resolveOldBatch(jsonResponse({ ...batches, total: 21, items: [{ ...batches.items[0], id: 'batch-old', batch_number: 1 }] }))
    await flushPromises()

    expect(batchWrapper.text()).toContain('#21')
    expect(batchWrapper.text()).not.toContain('#1completed')
  })

  it('polls with the applied filter snapshot instead of unsubmitted draft text', async () => {
    vi.useFakeTimers()
    const fetchMock = baseFetch()
    const { wrapper } = await mountPage(fetchMock)

    await wrapper.get('[aria-label="IP search"]').setValue('draft-only')
    await vi.advanceTimersByTimeAsync(1500)
    await flushPromises()

    const resultPaths = fetchMock.mock.calls
      .map(([path]) => path as string)
      .filter((path) => path.includes('/threatbook/results'))
    expect(resultPaths).toEqual([
      '/api/tasks/task-123/threatbook/results?page=1&page_size=50',
      '/api/tasks/task-123/threatbook/results?page=1&page_size=50',
    ])
  })

  it('shows persisted elapsed time and waits for an observed progress sample before ETA', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-08-14T00:01:00Z'))
    let taskReads = 0
    const fetchMock = baseFetch((path) => {
      if (path === '/api/tasks/task-123') {
        taskReads += 1
        return jsonResponse(taskReads === 1 ? task : {
          ...task,
          steps: [{ ...task.steps[0], progress_current: 80 }],
        })
      }
      return undefined
    })
    const { wrapper } = await mountPage(fetchMock)

    expect(wrapper.text()).toContain('Elapsed 1 min')
    expect(wrapper.text()).toContain('Estimated remaining Calculating')

    await vi.advanceTimersByTimeAsync(1500)
    await flushPromises()
    expect(wrapper.text()).toContain('Estimated remaining About 6 sec')
  })

  it('opens history detail in read-only mode without mutation controls', async () => {
    const diagnostics = {
      task_id: 'task-123', status: 'failed', current_step: 'threatbook_query', error_summary: '失败',
      last_successful_checkpoint: null, attempt_total: 0, batch_total: 0, attempt_limit: 50, batch_limit: 50,
      attempts: [], batches: [],
    }
    const fetchMock = baseFetch((path) => {
      if (path === '/api/tasks/task-123') return jsonResponse({ ...task, status: 'failed' })
      if (path.startsWith('/api/tasks/task-123/diagnostics')) return jsonResponse(diagnostics)
      return undefined
    })
    const { wrapper } = await mountPage(fetchMock, '/tasks/task-123/threatbook?mode=history')

    expect(wrapper.text()).toContain('Read-only history')
    expect(wrapper.find('button.retry-threatbook').exists()).toBe(false)
    expect(wrapper.get('a[href="/api/tasks/task-123/exports/threatbook_complete.xlsx"]')).toBeTruthy()
    expect(wrapper.get('a[href="/tasks/task-123/ips/91?mode=history"]')).toBeTruthy()
  })

  it.each(['failed', 'completed'])('links each failed batch to its bounded attempt diagnostics for %s tasks', async (status) => {
    const failedBatch = { ...batches.items[0], id: 'batch-failed', status: 'failed', attempt_count: 2, response_message: '微步接口请求失败' }
    const diagnostics = {
      task_id: 'task-123', status: 'failed', current_step: 'threatbook_query', error_summary: '失败',
      last_successful_checkpoint: null, attempt_total: 2, batch_total: 1, attempt_limit: 50, batch_limit: 50,
      attempts: [
        { id: 1, step_name: 'threatbook_query', batch_id: 'batch-failed', attempt_number: 1, status: 'failed', http_status: null, response_code: -1, error_type: 'RuntimeError', error_message: '安全错误', started_at: '2026-08-14T00:01:00Z', finished_at: '2026-08-14T00:01:01Z' },
        { id: 2, step_name: 'threatbook_query', batch_id: 'batch-failed', attempt_number: 2, status: 'failed', http_status: null, response_code: -1, error_type: 'RuntimeError', error_message: '仍然失败', started_at: '2026-08-14T00:01:02Z', finished_at: '2026-08-14T00:01:03Z' },
      ],
      batches: [],
    }
    const fetchMock = baseFetch((path) => {
      if (path === '/api/tasks/task-123') return jsonResponse({ ...task, status })
      if (path.includes('/threatbook/batches')) return jsonResponse({ ...batches, items: [failedBatch] })
      if (path.startsWith('/api/tasks/task-123/diagnostics')) return jsonResponse(diagnostics)
      return undefined
    })
    const { wrapper } = await mountPage(fetchMock)

    expect(fetchMock).toHaveBeenCalledWith('/api/tasks/task-123/diagnostics?attempt_limit=50&batch_limit=50', undefined)
    expect(wrapper.get('a[href="#batch-attempts-batch-failed"]').text()).toContain('2 attempts')
    expect(wrapper.get('#batch-attempts-batch-failed').text()).toContain('安全错误')
    expect(wrapper.get('#batch-attempts-batch-failed').text()).toContain('仍然失败')
  })
})
