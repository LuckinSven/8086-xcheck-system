<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { RouterLink } from 'vue-router'

import { api } from '../api'
import type {
  Page,
  ThreatbookFilterOptions,
  ThreatbookHistoryItem,
} from '../types'

const pageSize = 20
const items = ref<ThreatbookHistoryItem[]>([])
const options = ref<ThreatbookFilterOptions>({
  labels: [],
  countries: [],
  provinces: [],
  cities: [],
  severities: [],
  confidence_levels: [],
})
const total = ref(0)
const page = ref(1)
const loading = ref(true)
const error = ref('')
const optionsError = ref('')

const emptyFilters = () => ({
  q: '',
  malicious: '',
  judgment: '',
  country: '',
  province: '',
  city: '',
  severity: '',
  confidence: '',
  status: '',
  date_from: '',
  date_to: '',
})
const filters = reactive(emptyFilters())

let searchTimer: ReturnType<typeof setTimeout> | undefined
let requestSerial = 0

const totalPages = computed(() => Math.max(1, Math.ceil(total.value / pageSize)))

const statusText: Record<string, string> = {
  queued: '排队中',
  running: '查询中',
  waiting_whitelist_confirmation: '等待移除白名单',
  waiting_threatbook_confirmation: '等待查询微步',
  paused_quota: '额度暂停',
  partial_success: '部分完成',
  failed: '失败',
  completed: '已完成',
}

const statusOptions = [
  ['queued', '排队中'],
  ['running', '查询中'],
  ['waiting_whitelist_confirmation', '等待移除白名单'],
  ['waiting_threatbook_confirmation', '等待查询微步'],
  ['paused_quota', '额度暂停'],
  ['partial_success', '部分完成'],
  ['failed', '失败'],
  ['completed', '已完成'],
]

function formatTime(value: string | null) {
  return value ? new Date(value).toLocaleString('zh-CN') : '—'
}

function queryPath(targetPage: number) {
  const params = new URLSearchParams()
  for (const name of [
    'q',
    'malicious',
    'judgment',
    'country',
    'province',
    'city',
    'severity',
    'confidence',
    'status',
    'date_from',
    'date_to',
  ] as const) {
    if (filters[name]) params.set(name, filters[name])
  }
  params.set('page', String(targetPage))
  params.set('page_size', String(pageSize))
  return `/api/threatbook/history?${params.toString()}`
}

async function loadHistory(targetPage = 1) {
  const currentRequest = ++requestSerial
  loading.value = true
  error.value = ''
  try {
    const payload = await api.get<Page<ThreatbookHistoryItem>>(queryPath(targetPage))
    if (currentRequest !== requestSerial) return
    items.value = payload.items
    total.value = payload.total
    page.value = payload.page
  } catch (caught) {
    if (currentRequest !== requestSerial) return
    items.value = []
    total.value = 0
    page.value = targetPage
    error.value = caught instanceof Error ? caught.message : '微步历史加载失败'
  } finally {
    if (currentRequest === requestSerial) loading.value = false
  }
}

async function loadOptions() {
  try {
    options.value = await api.get<ThreatbookFilterOptions>('/api/threatbook/filter-options')
  } catch (caught) {
    optionsError.value = caught instanceof Error ? caught.message : '筛选选项加载失败'
  }
}

function cancelSearch() {
  if (searchTimer !== undefined) {
    clearTimeout(searchTimer)
    searchTimer = undefined
  }
}

function scheduleIpSearch() {
  cancelSearch()
  requestSerial += 1
  searchTimer = setTimeout(() => {
    searchTimer = undefined
    void loadHistory(1)
  }, 300)
}

function submitFilters() {
  cancelSearch()
  void loadHistory(1)
}

function clearFilters() {
  cancelSearch()
  Object.assign(filters, emptyFilters())
  void loadHistory(1)
}

function changePage(targetPage: number) {
  cancelSearch()
  void loadHistory(targetPage)
}

onMounted(() => {
  void loadOptions()
  void loadHistory(1)
})

onBeforeUnmount(() => {
  cancelSearch()
  requestSerial += 1
})
</script>

<template>
  <section class="page-head threatbook-history-head">
    <div>
      <span class="kicker">THREATBOOK ARCHIVE</span>
      <h2>微步历史</h2>
      <p>每次用户提交只保留一条记录，筛选和翻页均由服务端完成。</p>
    </div>
    <div class="capacity"><b>{{ total }}</b><span>微步任务</span></div>
  </section>

  <section class="panel history-filter-panel">
    <form class="history-filters" @submit.prevent="submitFilters">
      <input
        v-model="filters.q"
        aria-label="IP 搜索"
        autocomplete="off"
        placeholder="搜索任务中的 IP"
        @input="scheduleIpSearch"
      >
      <select v-model="filters.malicious" aria-label="恶意状态筛选">
        <option value="">全部恶意状态</option>
        <option value="true">包含恶意</option>
        <option value="false">包含非恶意</option>
      </select>
      <select v-model="filters.judgment" aria-label="威胁标签筛选">
        <option value="">全部威胁标签</option>
        <option v-for="label in options.labels" :key="label" :value="label">{{ label }}</option>
      </select>
      <select v-model="filters.country" aria-label="国家筛选">
        <option value="">全部国家</option>
        <option v-for="country in options.countries" :key="country" :value="country">{{ country }}</option>
      </select>
      <select v-model="filters.province" aria-label="省份筛选">
        <option value="">全部省份</option>
        <option v-for="province in options.provinces" :key="province" :value="province">{{ province }}</option>
      </select>
      <select v-model="filters.city" aria-label="城市筛选">
        <option value="">全部城市</option>
        <option v-for="city in options.cities" :key="city" :value="city">{{ city }}</option>
      </select>
      <select v-model="filters.severity" aria-label="严重度筛选">
        <option value="">全部严重度</option>
        <option v-for="severity in options.severities" :key="severity" :value="severity">{{ severity }}</option>
      </select>
      <select v-model="filters.confidence" aria-label="可信度筛选">
        <option value="">全部可信度</option>
        <option v-for="confidence in options.confidence_levels" :key="confidence" :value="confidence">{{ confidence }}</option>
      </select>
      <select v-model="filters.status" aria-label="任务状态筛选">
        <option value="">全部任务状态</option>
        <option v-for="status in statusOptions" :key="status[0]" :value="status[0]">{{ status[1] }}</option>
      </select>
      <label><span>开始日期</span><input v-model="filters.date_from" aria-label="开始日期" type="date"></label>
      <label><span>结束日期</span><input v-model="filters.date_to" aria-label="结束日期" type="date"></label>
      <div class="history-filter-actions">
        <button class="primary" type="submit" :disabled="loading">应用筛选</button>
        <button class="button ghost clear-history-filters" type="button" :disabled="loading" @click="clearFilters">清空</button>
      </div>
    </form>
    <p v-if="optionsError" class="filter-options-error">筛选选项暂未完整加载：{{ optionsError }}</p>
  </section>

  <section class="panel table-panel threatbook-history-panel" :aria-busy="loading">
    <div v-if="loading && items.length" class="history-updating" role="status" aria-live="polite">正在更新微步历史…</div>
    <div v-if="error" class="error-banner">{{ error }}</div>
    <div v-else-if="loading && !items.length" class="empty">正在读取微步历史…</div>
    <div v-else-if="!items.length" class="empty">没有符合筛选条件的微步任务</div>
    <div v-else class="history-table-wrap">
      <table>
        <thead>
          <tr>
            <th>任务 / 来源</th><th>状态</th><th>待查询总数</th><th>完成</th><th>失败</th><th>恶意</th>
            <th>主要威胁标签</th><th>主要地区</th><th>开始 / 完成</th><th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in items" :key="item.task_id">
            <td><code>{{ item.task_id.slice(0, 8) }}</code><small>{{ item.source_name }}</small></td>
            <td><span class="status" :class="item.status">{{ statusText[item.status] || item.status }}</span></td>
            <td>{{ item.ready_count }}</td>
            <td>{{ item.completed_count }}</td>
            <td>{{ item.failed_count }}</td>
            <td class="danger-text">{{ item.malicious_count }}</td>
            <td>
              <div class="history-tags">
                <span v-for="label in item.labels" :key="label">{{ label }}</span>
                <b v-if="item.label_remaining_count">+{{ item.label_remaining_count }}</b>
                <i v-if="!item.labels.length">—</i>
              </div>
            </td>
            <td>
              <div class="history-regions">
                <span v-for="region in item.regions" :key="region">{{ region }}</span>
                <b v-if="item.region_remaining_count">+{{ item.region_remaining_count }}</b>
                <i v-if="!item.regions.length">—</i>
              </div>
            </td>
            <td class="history-times"><span>{{ formatTime(item.started_at) }}</span><span>{{ formatTime(item.finished_at) }}</span></td>
            <td><RouterLink class="text-link" :to="{ path: `/tasks/${item.task_id}/threatbook`, query: { mode: 'history' } }">查看微步详情 →</RouterLink></td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-if="total > 0" class="history-pagination" aria-label="微步历史分页">
      <span>第 {{ page }} / {{ totalPages }} 页 · 共 {{ total }} 条</span>
      <div class="pagination">
        <button class="button ghost" type="button" :disabled="loading || page <= 1" @click="changePage(page - 1)">上一页</button>
        <button class="button ghost" type="button" :disabled="loading || page >= totalPages" @click="changePage(page + 1)">下一页</button>
      </div>
    </div>
  </section>
</template>
