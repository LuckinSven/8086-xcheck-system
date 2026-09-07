<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { api, translateApiError } from '../api'
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
const { t, locale } = useI18n()

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

function statusText(status: string) {
  const key = `statuses.${status}`
  const translated = t(key)
  return translated === key ? status : translated
}

const statusOptions = ['queued', 'running', 'waiting_whitelist_confirmation',
  'waiting_threatbook_confirmation', 'paused_quota', 'partial_success', 'failed', 'completed']

function formatTime(value: string | null) {
  return value ? new Date(value).toLocaleString(locale.value, { hour12: false }) : '—'
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
    error.value = translateApiError(caught, t)
  } finally {
    if (currentRequest === requestSerial) loading.value = false
  }
}

async function loadOptions() {
  try {
    options.value = await api.get<ThreatbookFilterOptions>('/api/threatbook/filter-options')
  } catch (caught) {
    optionsError.value = translateApiError(caught, t)
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
      <h2>{{ t('common.threatbookHistory') }}</h2>
      <p>{{ t('threatbookHistory.description') }}</p>
    </div>
    <div class="capacity"><b>{{ total }}</b><span>{{ t('threatbookHistory.tasks') }}</span></div>
  </section>

  <section class="panel history-filter-panel">
    <form class="history-filters" @submit.prevent="submitFilters">
      <input
        v-model="filters.q"
        :aria-label="t('threatbookHistory.ipSearch')"
        autocomplete="off"
        :placeholder="t('threatbookHistory.searchPlaceholder')"
        @input="scheduleIpSearch"
      >
      <select v-model="filters.malicious" :aria-label="t('threatbookHistory.maliciousFilter')">
        <option value="">{{ t('threatbookHistory.allMalicious') }}</option>
        <option value="true">{{ t('threatbookHistory.containsMalicious') }}</option>
        <option value="false">{{ t('threatbookHistory.containsNonMalicious') }}</option>
      </select>
      <select v-model="filters.judgment" :aria-label="t('threatbookHistory.labelFilter')">
        <option value="">{{ t('threatbookHistory.allLabels') }}</option>
        <option v-for="label in options.labels" :key="label" :value="label">{{ label }}</option>
      </select>
      <select v-model="filters.country" :aria-label="t('threatbookHistory.countryFilter')">
        <option value="">{{ t('threatbookHistory.allCountries') }}</option>
        <option v-for="country in options.countries" :key="country" :value="country">{{ country }}</option>
      </select>
      <select v-model="filters.province" :aria-label="t('threatbookHistory.provinceFilter')">
        <option value="">{{ t('threatbookHistory.allProvinces') }}</option>
        <option v-for="province in options.provinces" :key="province" :value="province">{{ province }}</option>
      </select>
      <select v-model="filters.city" :aria-label="t('threatbookHistory.cityFilter')">
        <option value="">{{ t('threatbookHistory.allCities') }}</option>
        <option v-for="city in options.cities" :key="city" :value="city">{{ city }}</option>
      </select>
      <select v-model="filters.severity" :aria-label="t('threatbookHistory.severityFilter')">
        <option value="">{{ t('threatbookHistory.allSeverities') }}</option>
        <option v-for="severity in options.severities" :key="severity" :value="severity">{{ severity }}</option>
      </select>
      <select v-model="filters.confidence" :aria-label="t('threatbookHistory.confidenceFilter')">
        <option value="">{{ t('threatbookHistory.allConfidence') }}</option>
        <option v-for="confidence in options.confidence_levels" :key="confidence" :value="confidence">{{ confidence }}</option>
      </select>
      <select v-model="filters.status" :aria-label="t('threatbookHistory.statusFilter')">
        <option value="">{{ t('threatbookHistory.allStatuses') }}</option>
        <option v-for="status in statusOptions" :key="status" :value="status">{{ statusText(status) }}</option>
      </select>
      <label><span>{{ t('threatbookHistory.startDate') }}</span><input v-model="filters.date_from" :aria-label="t('threatbookHistory.startDate')" type="date"></label>
      <label><span>{{ t('threatbookHistory.endDate') }}</span><input v-model="filters.date_to" :aria-label="t('threatbookHistory.endDate')" type="date"></label>
      <div class="history-filter-actions">
        <button class="primary" type="submit" :disabled="loading">{{ t('common.applyFilters') }}</button>
        <button class="button ghost clear-history-filters" type="button" :disabled="loading" @click="clearFilters">{{ t('common.clear') }}</button>
      </div>
    </form>
    <p v-if="optionsError" class="filter-options-error">{{ t('threatbookHistory.optionsPartial') }}: {{ optionsError }}</p>
  </section>

  <section class="panel table-panel threatbook-history-panel" :aria-busy="loading">
    <div v-if="loading && items.length" class="history-updating" role="status" aria-live="polite">{{ t('threatbookHistory.updating') }}</div>
    <div v-if="error" class="error-banner">{{ error }}</div>
    <div v-else-if="loading && !items.length" class="empty">{{ t('threatbookHistory.loading') }}</div>
    <div v-else-if="!items.length" class="empty">{{ t('threatbookHistory.empty') }}</div>
    <div v-else class="history-table-wrap">
      <table>
        <thead>
          <tr>
            <th>{{ t('threatbookHistory.taskSource') }}</th><th>{{ t('task.status') }}</th><th>{{ t('threatbookHistory.readyTotal') }}</th><th>{{ t('statuses.completed') }}</th><th>{{ t('statuses.failed') }}</th><th>{{ t('common.malicious') }}</th>
            <th>{{ t('threatbookHistory.primaryLabels') }}</th><th>{{ t('threatbookHistory.primaryRegions') }}</th><th>{{ t('threatbookHistory.startFinish') }}</th><th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in items" :key="item.task_id">
            <td><code>{{ item.task_id.slice(0, 8) }}</code><small>{{ item.source_name }}</small></td>
            <td><span class="status" :class="item.status">{{ statusText(item.status) }}</span></td>
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
            <td><RouterLink class="text-link" :to="{ path: `/tasks/${item.task_id}/threatbook`, query: { mode: 'history' } }">{{ t('threatbookHistory.viewDetails') }} →</RouterLink></td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-if="total > 0" class="history-pagination" :aria-label="t('threatbookHistory.pagination')">
      <span>{{ t('task.pageSummary', { page, pages: totalPages, total }) }}</span>
      <div class="pagination">
        <button class="button ghost" type="button" :disabled="loading || page <= 1" @click="changePage(page - 1)">{{ t('common.previous') }}</button>
        <button class="button ghost" type="button" :disabled="loading || page >= totalPages" @click="changePage(page + 1)">{{ t('common.next') }}</button>
      </div>
    </div>
  </section>
</template>
