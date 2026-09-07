import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, describe, expect, it, vi } from 'vitest'

import ThreatbookHistory from './ThreatbookHistory.vue'

const historyItems = [
  {
    task_id: 'task-alpha',
    source_name: 'alpha.xlsx',
    status: 'completed',
    ready_count: 120,
    completed_count: 118,
    failed_count: 2,
    malicious_count: 7,
    labels: ['botnet', 'scanner', 'phishing'],
    label_remaining_count: 1,
    regions: ['中国 / 北京 / 海淀', '美国 / 加利福尼亚'],
    region_remaining_count: 2,
    created_at: '2026-08-13T01:00:00Z',
    started_at: '2026-08-13T01:01:00Z',
    finished_at: '2026-08-13T01:03:00Z',
  },
  {
    task_id: 'task-beta',
    source_name: '手动输入',
    status: 'running',
    ready_count: 40,
    completed_count: 15,
    failed_count: 0,
    malicious_count: 1,
    labels: ['scanner'],
    label_remaining_count: 0,
    regions: ['新加坡'],
    region_remaining_count: 0,
    created_at: '2026-08-14T01:00:00Z',
    started_at: '2026-08-14T01:01:00Z',
    finished_at: null,
  },
]

const firstPage = {
  items: historyItems,
  total: 22,
  page: 1,
  page_size: 20,
}

const filterOptions = {
  labels: ['botnet', 'phishing', 'scanner'],
  countries: ['中国', '美国'],
  provinces: ['北京', '加利福尼亚'],
  cities: ['山景城', '海淀'],
  severities: ['critical-from-api', 'high-from-api'],
  confidence_levels: ['high-from-api', 'medium-from-api'],
}

function jsonResponse(payload: unknown, ok = true, status = 200) {
  return { ok, status, json: async () => payload } as Response
}

function baseFetch(
  override?: (path: string) => Response | Promise<Response> | undefined,
) {
  return vi.fn((path: string) => {
    const overridden = override?.(path)
    if (overridden) return Promise.resolve(overridden)
    if (path === '/api/threatbook/filter-options') return Promise.resolve(jsonResponse(filterOptions))
    if (path === '/api/threatbook/history?page=1&page_size=20') return Promise.resolve(jsonResponse(firstPage))
    return Promise.reject(new Error(`Unexpected request: ${path}`))
  })
}

async function mountPage(fetchMock = baseFetch()) {
  vi.stubGlobal('fetch', fetchMock)
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: '/threatbook-history', component: ThreatbookHistory },
      { path: '/tasks/:id/threatbook', component: { template: '<div>微步详情</div>' } },
    ],
  })
  await router.push('/threatbook-history')
  await router.isReady()
  const wrapper = mount(ThreatbookHistory, { global: { plugins: [router] } })
  await flushPromises()
  return { wrapper, fetchMock }
}

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('ThreatBook history', () => {
  it('renders exactly one row per task with aggregate metrics, primary tags, regions, and detail links', async () => {
    const { wrapper } = await mountPage()

    const rows = wrapper.findAll('tbody tr')
    expect(rows).toHaveLength(2)
    expect(rows[0].text()).toContain('alpha.xlsx')
    expect(rows[0].text()).toContain('120')
    expect(rows[0].text()).toContain('118')
    expect(rows[0].text()).toContain('botnet')
    expect(rows[0].text()).toContain('scanner')
    expect(rows[0].text()).toContain('phishing')
    expect(rows[0].text()).toContain('+1')
    expect(rows[0].text()).toContain('中国 / 北京 / 海淀')
    expect(rows[0].text()).toContain('美国 / 加利福尼亚')
    expect(rows[0].text()).toContain('+2')
    expect(rows[0].get('a[href="/tasks/task-alpha/threatbook?mode=history"]')).toBeTruthy()
    expect(rows[1].get('a[href="/tasks/task-beta/threatbook?mode=history"]')).toBeTruthy()
    expect(wrapper.get('th:nth-child(3)').text()).toBe('待查询总数')

    expect(wrapper.get('[aria-label="严重度筛选"]').text()).toContain('critical-from-api')
    expect(wrapper.get('[aria-label="可信度筛选"]').text()).toContain('medium-from-api')
    expect(wrapper.get('[aria-label="威胁标签筛选"]').text()).toContain('botnet')
    expect(wrapper.get('[aria-label="任务状态筛选"]').text()).toContain('等待移除白名单')
    expect(wrapper.get('[aria-label="任务状态筛选"]').text()).toContain('等待查询微步')
  })

  it('sends all submitted select and date filters to the server and clears them', async () => {
    const filteredUrl = '/api/threatbook/history?q=9.9&malicious=true&judgment=phishing&country=%E4%B8%AD%E5%9B%BD&province=%E5%8C%97%E4%BA%AC&city=%E6%B5%B7%E6%B7%80&severity=critical-from-api&confidence=high-from-api&status=completed&date_from=2026-08-01&date_to=2026-08-14&page=1&page_size=20'
    const fetchMock = baseFetch((path) => path === filteredUrl ? jsonResponse({ ...firstPage, items: [historyItems[0]], total: 1 }) : undefined)
    const { wrapper } = await mountPage(fetchMock)

    await wrapper.get('[aria-label="IP 搜索"]').setValue('9.9')
    await wrapper.get('[aria-label="恶意状态筛选"]').setValue('true')
    await wrapper.get('[aria-label="威胁标签筛选"]').setValue('phishing')
    await wrapper.get('[aria-label="国家筛选"]').setValue('中国')
    await wrapper.get('[aria-label="省份筛选"]').setValue('北京')
    await wrapper.get('[aria-label="城市筛选"]').setValue('海淀')
    await wrapper.get('[aria-label="严重度筛选"]').setValue('critical-from-api')
    await wrapper.get('[aria-label="可信度筛选"]').setValue('high-from-api')
    await wrapper.get('[aria-label="任务状态筛选"]').setValue('completed')
    await wrapper.get('[aria-label="开始日期"]').setValue('2026-08-01')
    await wrapper.get('[aria-label="结束日期"]').setValue('2026-08-14')
    await wrapper.get('form.history-filters').trigger('submit')
    await flushPromises()

    expect(fetchMock).toHaveBeenCalledWith(filteredUrl, undefined)
    expect(wrapper.findAll('tbody tr')).toHaveLength(1)

    await wrapper.get('button.clear-history-filters').trigger('click')
    await flushPromises()
    expect(fetchMock).toHaveBeenLastCalledWith('/api/threatbook/history?page=1&page_size=20', undefined)
    expect((wrapper.get('[aria-label="IP 搜索"]').element as HTMLInputElement).value).toBe('')
  })

  it('debounces IP searches and ignores an older response that finishes last', async () => {
    vi.useFakeTimers()
    let resolveOlder!: (response: Response) => void
    let resolveNewer!: (response: Response) => void
    const older = new Promise<Response>((resolve) => { resolveOlder = resolve })
    const newer = new Promise<Response>((resolve) => { resolveNewer = resolve })
    const fetchMock = baseFetch((path) => {
      if (path === '/api/threatbook/history?q=1.1&page=1&page_size=20') return older
      if (path === '/api/threatbook/history?q=2.2&page=1&page_size=20') return newer
      return undefined
    })
    const { wrapper } = await mountPage(fetchMock)

    await wrapper.get('[aria-label="IP 搜索"]').setValue('1.1')
    await vi.advanceTimersByTimeAsync(299)
    expect(fetchMock).not.toHaveBeenCalledWith('/api/threatbook/history?q=1.1&page=1&page_size=20', undefined)
    await vi.advanceTimersByTimeAsync(1)

    await wrapper.get('[aria-label="IP 搜索"]').setValue('2.2')
    await vi.advanceTimersByTimeAsync(300)
    resolveNewer(jsonResponse({ ...firstPage, items: [{ ...historyItems[1], source_name: 'newer.xlsx' }], total: 1 }))
    await flushPromises()
    expect(wrapper.text()).toContain('newer.xlsx')

    resolveOlder(jsonResponse({ ...firstPage, items: [{ ...historyItems[0], source_name: 'older.xlsx' }], total: 1 }))
    await flushPromises()
    expect(wrapper.text()).toContain('newer.xlsx')
    expect(wrapper.text()).not.toContain('older.xlsx')
  })

  it('invalidates an in-flight response as soon as IP input changes', async () => {
    vi.useFakeTimers()
    let resolveUnfiltered!: (response: Response) => void
    const unfiltered = new Promise<Response>((resolve) => { resolveUnfiltered = resolve })
    const fetchMock = baseFetch((path) => {
      if (path === '/api/threatbook/history?page=1&page_size=20') return unfiltered
      if (path === '/api/threatbook/history?q=3.3&page=1&page_size=20') {
        return jsonResponse({ ...firstPage, items: [{ ...historyItems[1], source_name: 'current-search.xlsx' }], total: 1 })
      }
      return undefined
    })
    const { wrapper } = await mountPage(fetchMock)

    await wrapper.get('[aria-label="IP 搜索"]').setValue('3.3')
    resolveUnfiltered(jsonResponse({ ...firstPage, items: [{ ...historyItems[0], source_name: 'older-unfiltered.xlsx' }], total: 1 }))
    await flushPromises()

    expect(wrapper.text()).not.toContain('older-unfiltered.xlsx')

    await vi.advanceTimersByTimeAsync(300)
    await flushPromises()
    expect(wrapper.text()).toContain('current-search.xlsx')
  })

  it('cancels a pending IP debounce before requesting another page', async () => {
    vi.useFakeTimers()
    const secondPageUrl = '/api/threatbook/history?q=4.4&page=2&page_size=20'
    const fetchMock = baseFetch((path) => {
      if (path === secondPageUrl) {
        return jsonResponse({ ...firstPage, page: 2, items: [{ ...historyItems[1], source_name: 'filtered-page-2.xlsx' }] })
      }
      if (path === '/api/threatbook/history?q=4.4&page=1&page_size=20') {
        return jsonResponse({ ...firstPage, items: [{ ...historyItems[0], source_name: 'delayed-page-1.xlsx' }] })
      }
      return undefined
    })
    const { wrapper } = await mountPage(fetchMock)

    await wrapper.get('[aria-label="IP 搜索"]').setValue('4.4')
    await wrapper.get('[aria-label="微步历史分页"] button:last-child').trigger('click')
    await flushPromises()
    expect(fetchMock).toHaveBeenCalledWith(secondPageUrl, undefined)
    expect(wrapper.text()).toContain('filtered-page-2.xlsx')

    await vi.advanceTimersByTimeAsync(300)
    await flushPromises()
    expect(fetchMock).not.toHaveBeenCalledWith('/api/threatbook/history?q=4.4&page=1&page_size=20', undefined)
    expect(wrapper.text()).toContain('filtered-page-2.xlsx')
  })

  it('requests and renders the next server page', async () => {
    const secondPageUrl = '/api/threatbook/history?page=2&page_size=20'
    const fetchMock = baseFetch((path) => path === secondPageUrl
      ? jsonResponse({ ...firstPage, page: 2, items: [{ ...historyItems[1], task_id: 'task-page-2', source_name: 'page-2.csv' }] })
      : undefined)
    const { wrapper } = await mountPage(fetchMock)

    await wrapper.get('[aria-label="微步历史分页"] button:last-child').trigger('click')
    await flushPromises()

    expect(fetchMock).toHaveBeenCalledWith(secondPageUrl, undefined)
    expect(wrapper.text()).toContain('page-2.csv')
    expect(wrapper.text()).toContain('第 2 / 2 页')
  })

  it('keeps current rows visible and exposes a busy state while updating', async () => {
    let resolveSecondPage!: (response: Response) => void
    const secondPage = new Promise<Response>((resolve) => { resolveSecondPage = resolve })
    const fetchMock = baseFetch((path) => path === '/api/threatbook/history?page=2&page_size=20' ? secondPage : undefined)
    const { wrapper } = await mountPage(fetchMock)

    await wrapper.get('[aria-label="微步历史分页"] button:last-child').trigger('click')

    expect(wrapper.get('.threatbook-history-panel').attributes('aria-busy')).toBe('true')
    expect(wrapper.text()).toContain('正在更新微步历史…')
    expect(wrapper.text()).toContain('alpha.xlsx')
    expect(wrapper.get('form.history-filters button[type="submit"]').attributes()).toHaveProperty('disabled')
    expect(wrapper.get('button.clear-history-filters').attributes()).toHaveProperty('disabled')
    expect(wrapper.get('[aria-label="微步历史分页"] button:last-child').attributes()).toHaveProperty('disabled')

    resolveSecondPage(jsonResponse({ ...firstPage, page: 2, items: [{ ...historyItems[1], source_name: 'updated.xlsx' }] }))
    await flushPromises()
    expect(wrapper.get('.threatbook-history-panel').attributes('aria-busy')).toBe('false')
    expect(wrapper.text()).not.toContain('正在更新微步历史…')
    expect(wrapper.text()).toContain('updated.xlsx')
  })

  it('shows an empty state when no task matches', async () => {
    const fetchMock = baseFetch((path) => path === '/api/threatbook/history?page=1&page_size=20'
      ? jsonResponse({ ...firstPage, items: [], total: 0 })
      : undefined)
    const { wrapper } = await mountPage(fetchMock)

    expect(wrapper.text()).toContain('没有符合筛选条件的微步任务')
    expect(wrapper.find('table').exists()).toBe(false)
  })

  it('shows a safe load error without rendering stale rows', async () => {
    const fetchMock = baseFetch((path) => path === '/api/threatbook/history?page=1&page_size=20'
      ? jsonResponse({ detail: '微步历史暂时不可用' }, false, 503)
      : undefined)
    const { wrapper } = await mountPage(fetchMock)

    expect(wrapper.text()).toContain('微步历史暂时不可用')
    expect(wrapper.find('tbody').exists()).toBe(false)
  })
})
