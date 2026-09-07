<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { api, translateApiError } from '../api'
import type { Page, Step, TaskDiagnostics, TaskSummary, ThreatbookBatch, ThreatbookResult } from '../types'

const route = useRoute()
const { t, locale } = useI18n()
const taskId = route.params.id as string
const task = ref<TaskSummary | null>(null)
const batches = ref<Page<ThreatbookBatch> | null>(null)
const results = ref<Page<ThreatbookResult> | null>(null)
const diagnostics = ref<TaskDiagnostics | null>(null)
const batchPage = ref(1)
const resultPage = ref(1)
const loading = ref(true)
const retrying = ref(false)
const retryHandoff = ref(false)
const loadErrors = reactive({ task: '', batches: '', results: '', diagnostics: '', action: '' })
const filters = reactive({ q: '', malicious: '', judgment: '', country: '', province: '', city: '', severity: '', confidence: '' })
const appliedFilters = reactive({ q: '', malicious: '', judgment: '', country: '', province: '', city: '', severity: '', confidence: '' })
let timer: number | undefined
let disposed = false
let workspaceGeneration = 0
let taskGeneration = 0
let batchGeneration = 0
let resultGeneration = 0
let diagnosticsGeneration = 0
let lastRateSample: { progress: number; sampledAt: number; startedAt: string | null } | null = null
const observedRate = ref<number | null>(null)

const threatbookStep = computed<Step | undefined>(() => task.value?.steps?.find((step) => step.name === 'threatbook_query'))
const progressTotal = computed(() => threatbookStep.value?.progress_total || task.value?.threatbook_ready_count || 0)
const progressCurrent = computed(() => Math.min(threatbookStep.value?.progress_current || 0, progressTotal.value))
const remaining = computed(() => Math.max(0, progressTotal.value - progressCurrent.value))
const progressPercent = computed(() => progressTotal.value ? Math.round(progressCurrent.value / progressTotal.value * 100) : 0)
const active = computed(() => task.value ? ['queued', 'running'].includes(task.value.status) : false)
const shouldPoll = computed(() => active.value || (
  retryHandoff.value && task.value?.status === 'waiting_threatbook_confirmation'
))
const readOnlyHistory = computed(() => route.query.mode === 'history')
const canRetry = computed(() => !readOnlyHistory.value && (task.value ? ['failed', 'partial_success'].includes(task.value.status) : false))
const batchPages = computed(() => batches.value ? Math.max(1, Math.ceil(batches.value.total / batches.value.page_size)) : 1)
const resultPages = computed(() => results.value ? Math.max(1, Math.ceil(results.value.total / results.value.page_size)) : 1)
const visibleErrors = computed(() => Object.values(loadErrors).filter(Boolean))

function sectionError(labelKey: string, reason: unknown) {
  return `${t(labelKey)}: ${translateApiError(reason, t)}`
}

function batchUrl(page: number) {
  return `/api/tasks/${taskId}/threatbook/batches?page=${page}&page_size=20`
}

type ResultFilters = typeof filters

function filterSnapshot(source: ResultFilters): Record<keyof ResultFilters, string> {
  return { ...source }
}

function resultUrl(page: number, snapshot: Record<keyof ResultFilters, string>) {
  const params = new URLSearchParams()
  for (const key of ['q', 'malicious', 'judgment', 'country', 'province', 'city', 'severity', 'confidence'] as const) {
    if (snapshot[key]) params.set(key, snapshot[key])
  }
  params.set('page', String(page))
  params.set('page_size', '50')
  return `/api/tasks/${taskId}/threatbook/results?${params}`
}

async function loadDiagnostics(currentTask: TaskSummary) {
  const generation = ++diagnosticsGeneration
  if (!['failed', 'partial_success', 'completed'].includes(currentTask.status)) {
    if (!disposed && generation === diagnosticsGeneration) {
      diagnostics.value = null
      loadErrors.diagnostics = ''
    }
    return
  }
  try {
    const payload = await api.get<TaskDiagnostics>(`/api/tasks/${taskId}/diagnostics?attempt_limit=50&batch_limit=50`)
    if (disposed || generation !== diagnosticsGeneration) return
    diagnostics.value = payload
    loadErrors.diagnostics = ''
  } catch (reason) {
    if (disposed || generation !== diagnosticsGeneration) return
    loadErrors.diagnostics = sectionError('threatbook.diagnostics', reason)
  }
}

function acceptTask(payload: TaskSummary) {
  const step = payload.steps?.find((item) => item.name === 'threatbook_query')
  const progress = step?.progress_current || 0
  const startedAt = step?.started_at || null
  const now = Date.now()
  if (!lastRateSample || lastRateSample.startedAt !== startedAt || progress < lastRateSample.progress) {
    observedRate.value = null
    lastRateSample = { progress, sampledAt: now, startedAt }
  } else if (progress > lastRateSample.progress && now > lastRateSample.sampledAt) {
    observedRate.value = (progress - lastRateSample.progress) / ((now - lastRateSample.sampledAt) / 1000)
    lastRateSample = { progress, sampledAt: now, startedAt }
  }
  task.value = payload
}

async function loadTask() {
  const generation = ++taskGeneration
  try {
    const payload = await api.get<TaskSummary>(`/api/tasks/${taskId}`)
    if (disposed || generation !== taskGeneration) return
    acceptTask(payload)
    if (retryHandoff.value && !['waiting_threatbook_confirmation', 'queued', 'running'].includes(payload.status)) {
      retryHandoff.value = false
    }
    loadErrors.task = ''
    await loadDiagnostics(payload)
  } catch (reason) {
    if (disposed || generation !== taskGeneration) return
    loadErrors.task = sectionError('threatbook.taskOverview', reason)
  }
}

async function loadBatches(page: number) {
  batchPage.value = page
  const generation = ++batchGeneration
  try {
    const payload = await api.get<Page<ThreatbookBatch>>(batchUrl(page))
    if (disposed || generation !== batchGeneration) return
    batches.value = payload
    batchPage.value = payload.page
    loadErrors.batches = ''
  } catch (reason) {
    if (disposed || generation !== batchGeneration) return
    loadErrors.batches = sectionError('threatbook.batchDetails', reason)
  }
}

async function loadResults(page: number, snapshot = filterSnapshot(appliedFilters)) {
  resultPage.value = page
  const generation = ++resultGeneration
  try {
    const payload = await api.get<Page<ThreatbookResult>>(resultUrl(page, snapshot))
    if (disposed || generation !== resultGeneration) return
    results.value = payload
    resultPage.value = payload.page
    loadErrors.results = ''
  } catch (reason) {
    if (disposed || generation !== resultGeneration) return
    loadErrors.results = sectionError('threatbook.intelligenceResults', reason)
  }
}

async function loadWorkspace() {
  const generation = ++workspaceGeneration
  if (timer !== undefined) {
    window.clearTimeout(timer)
    timer = undefined
  }
  await Promise.all([
    loadTask(),
    loadBatches(batchPage.value),
    loadResults(resultPage.value, filterSnapshot(appliedFilters)),
  ])
  if (disposed || generation !== workspaceGeneration) return
  loading.value = false
  if (shouldPoll.value) {
    timer = window.setTimeout(loadWorkspace, 1500)
  }
}

function submitFilters() {
  Object.assign(appliedFilters, filterSnapshot(filters))
  return loadResults(1, filterSnapshot(appliedFilters))
}

function clearFilters() {
  Object.assign(filters, { q: '', malicious: '', judgment: '', country: '', province: '', city: '', severity: '', confidence: '' })
  Object.assign(appliedFilters, filterSnapshot(filters))
  return loadResults(1, filterSnapshot(appliedFilters))
}

async function retryThreatbook() {
  if (retrying.value || readOnlyHistory.value) return
  retrying.value = true
  loadErrors.action = ''
  try {
    await api.post(`/api/tasks/${taskId}/steps/threatbook_query/retry`)
    retryHandoff.value = true
    await loadWorkspace()
  } catch (reason) {
    loadErrors.action = sectionError('threatbook.retryFailed', reason)
  } finally {
    retrying.value = false
  }
}

function locationText(result: ThreatbookResult) {
  return [result.country, result.province, result.city].filter(Boolean).join(' / ') || '—'
}

function asnText(result: ThreatbookResult) {
  const parts = [result.asn_number === null ? '' : `AS${result.asn_number}`, result.asn_name].filter(Boolean)
  return parts.join(' · ') || '—'
}

function dateText(value: string | null) {
  return value ? new Date(value).toLocaleString(locale.value, { hour12: false }) : '—'
}

function safePermalink(value: string | null) {
  if (!value) return null
  try {
    const parsed = new URL(value)
    return ['http:', 'https:'].includes(parsed.protocol) ? value : null
  } catch {
    return null
  }
}

function configValue(value: number | null | undefined, suffix = '') {
  return value === null || value === undefined ? t('threatbook.notProvided') : `${value}${suffix}`
}

function timestamp(value: string) {
  return Date.parse(/[zZ]|[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`)
}

function durationText(seconds: number) {
  const safeSeconds = Math.max(0, Math.round(seconds))
  if (safeSeconds < 60) return t('threatbook.seconds', { value: safeSeconds })
  const minutes = Math.floor(safeSeconds / 60)
  const remainder = safeSeconds % 60
  return remainder
    ? t('threatbook.minutesSeconds', { minutes, seconds: remainder })
    : t('threatbook.minutes', { value: minutes })
}

const elapsedText = computed(() => {
  const step = threatbookStep.value
  if (!step?.started_at) return '—'
  const end = step.finished_at ? timestamp(step.finished_at) : Date.now()
  return durationText((end - timestamp(step.started_at)) / 1000)
})

const etaText = computed(() => {
  if (!active.value || remaining.value <= 0) return null
  if (!observedRate.value || observedRate.value <= 0) return t('threatbook.calculating')
  return t('threatbook.approximately', { value: durationText(remaining.value / observedRate.value) })
})

function attemptsForBatch(batchId: string) {
  return diagnostics.value?.attempts.filter((attempt) => attempt.batch_id === batchId) || []
}

function diagnosticIpLink(ipId: number) {
  return readOnlyHistory.value
    ? { path: `/tasks/${taskId}/ips/${ipId}`, query: { mode: 'history' } }
    : `/tasks/${taskId}/ips/${ipId}`
}

onMounted(loadWorkspace)
onBeforeUnmount(() => {
  disposed = true
  workspaceGeneration += 1
  taskGeneration += 1
  batchGeneration += 1
  resultGeneration += 1
  diagnosticsGeneration += 1
  if (timer !== undefined) window.clearTimeout(timer)
})
</script>

<template>
  <div v-if="loading && !task" class="panel empty">{{ t('threatbook.loading') }}</div>
  <template v-else-if="task">
    <section class="page-head compact threatbook-head">
      <div><span class="kicker">THREATBOOK TASK {{ task.id.slice(0, 8) }}</span><h2>{{ t('threatbook.title') }}</h2><p>{{ task.original_filename || t('task.manualQuery') }} · {{ t('task.status') }}: {{ t(`statuses.${task.status}`) }}<b v-if="readOnlyHistory" class="history-readonly">{{ t('threatbook.readOnly') }}</b></p></div>
      <div class="task-actions"><a class="button ghost" :href="`/api/tasks/${taskId}/exports/threatbook_complete.xlsx`">{{ t('threatbook.exportResults') }}</a><RouterLink class="button ghost" :to="`/tasks/${taskId}`">{{ t('threatbook.backToTask') }}</RouterLink><RouterLink v-if="readOnlyHistory" class="button ghost" to="/threatbook-history">{{ t('threatbook.backToThreatbookHistory') }}</RouterLink><RouterLink v-else class="button ghost" to="/history">{{ t('task.backToHistory') }}</RouterLink></div>
    </section>

    <div v-if="visibleErrors.length" class="error-banner workspace-errors" role="alert"><span v-for="item in visibleErrors" :key="item">{{ item }}</span></div>

    <section class="stats-grid threatbook-stats" :aria-label="t('threatbook.progressMetrics')">
      <article><span>{{ t('threatbook.totalQueued') }}</span><b>{{ progressTotal }}</b></article>
      <article><span>{{ t('statuses.completed') }}</span><b>{{ progressCurrent }}</b></article>
      <article><span>{{ t('threatbook.remaining') }}</span><b>{{ remaining }}</b></article>
      <article><span>{{ t('statuses.failed') }}</span><b>{{ task.failed_count }}</b></article>
      <article class="danger-card"><span>{{ t('task.maliciousIps') }}</span><b>{{ task.malicious_count }}</b></article>
    </section>

    <section class="panel workspace-progress">
      <div class="section-title"><div><span class="kicker">LIVE EXECUTION</span><h3>{{ t('threatbook.liveProgress') }}</h3></div><span v-if="shouldPoll" class="live-dot">{{ t('threatbook.polling') }}</span></div>
      <div class="progress-copy"><b>{{ progressPercent }}%</b><span>{{ progressCurrent }} / {{ progressTotal }} IP</span></div>
      <div class="progress-track" role="progressbar" :aria-valuenow="progressPercent" aria-valuemin="0" aria-valuemax="100"><i :style="{ width: `${progressPercent}%` }"></i></div>
      <div class="execution-grid">
        <span>{{ t('threatbook.currentBatch') }} <b>{{ threatbookStep?.current_batch || 0 }} / {{ threatbookStep?.total_batches || 0 }}</b></span>
        <span>{{ t('threatbook.batchSize') }} <b>{{ configValue(task.threatbook_config?.batch_size) }}</b></span>
        <span>{{ t('threatbook.safeRate') }} <b>{{ configValue(task.threatbook_config?.safe_ips_per_minute, ` ${t('threatbook.ipsPerMinute')}`) }}</b></span>
        <span>{{ t('threatbook.dailyBudget') }} <b>{{ configValue(task.threatbook_config?.daily_budget) }}</b></span>
        <span>{{ t('threatbook.maxRetries') }} <b>{{ configValue(task.threatbook_config?.max_retries) }}</b></span>
        <span>{{ t('threatbook.elapsed') }} <b>{{ elapsedText }}</b></span>
        <span v-if="etaText">{{ t('threatbook.estimatedRemaining') }} <b>{{ etaText }}</b></span>
      </div>
      <div v-if="canRetry || (readOnlyHistory && ['failed', 'partial_success'].includes(task.status))" class="failure-detail compact-failure">
        <div><b>{{ diagnostics?.error_summary || task.error_summary || t('threatbook.incomplete') }}</b><span>{{ t('task.lastCheckpoint') }}: {{ diagnostics?.last_successful_checkpoint || t('common.none') }}</span></div>
        <button v-if="canRetry" class="primary retry-threatbook" :disabled="retrying" @click="retryThreatbook">{{ t(retrying ? 'threatbook.retrying' : 'threatbook.retryStep') }}</button>
      </div>
    </section>

    <section class="panel table-panel">
      <div class="section-title"><div><span class="kicker">BATCH DIAGNOSTICS</span><h3>{{ t('threatbook.executionBatches') }}</h3></div><span v-if="batches" class="muted">{{ t('threatbook.batchPageSummary', { page: batches.page, pages: batchPages, total: batches.total }) }}</span></div>
      <table v-if="batches?.items.length"><thead><tr><th>{{ t('task.batch') }}</th><th>{{ t('task.status') }}</th><th>{{ t('threatbook.ipCount') }}</th><th>{{ t('threatbook.resolved') }}</th><th>{{ t('threatbook.unresolved') }}</th><th>{{ t('task.attempt') }}</th><th>{{ t('threatbook.responseCode') }}</th><th>{{ t('threatbook.responseMessage') }}</th><th>{{ t('threatbook.startedAt') }}</th><th>{{ t('threatbook.finishedAt') }}</th><th>{{ t('threatbook.diagnostics') }}</th></tr></thead><tbody><tr v-for="batch in batches.items" :key="batch.id"><td>#{{ batch.batch_number }}</td><td><span class="status" :class="batch.status">{{ t(`statuses.${batch.status}`) }}</span></td><td>{{ batch.address_count }}</td><td>{{ batch.resolved_count }}</td><td>{{ batch.unresolved_count }}</td><td>{{ batch.attempt_count }}</td><td>{{ batch.response_code ?? '—' }}</td><td>{{ batch.response_message || '—' }}</td><td>{{ dateText(batch.created_at) }}</td><td>{{ dateText(batch.finished_at) }}</td><td><a v-if="batch.status === 'failed' && attemptsForBatch(batch.id).length" class="text-link" :href="`#batch-attempts-${batch.id}`">{{ t('threatbook.attemptCount', { value: attemptsForBatch(batch.id).length }) }}</a><span v-else-if="batch.status === 'failed'">{{ t('threatbook.notInDiagnosticWindow') }}</span><span v-else>—</span></td></tr></tbody></table>
      <p v-else class="empty-row muted">{{ t(loadErrors.batches ? 'threatbook.batchUnavailable' : 'threatbook.noBatches') }}</p>
      <div v-if="batches" class="pagination workspace-pagination" :aria-label="t('threatbook.batchPagination')"><button class="button ghost" :disabled="batches.page <= 1" @click="loadBatches(batches.page - 1)">{{ t('common.previous') }}</button><button class="button ghost" :disabled="batches.page >= batchPages" @click="loadBatches(batches.page + 1)">{{ t('common.next') }}</button></div>
      <div v-if="diagnostics?.attempts.length" class="batch-attempt-diagnostics">
        <section v-for="batch in batches?.items.filter((item) => attemptsForBatch(item.id).length)" :id="`batch-attempts-${batch.id}`" :key="`attempts-${batch.id}`">
          <h4>{{ t('threatbook.batchAttemptDiagnostics', { value: batch.batch_number }) }}</h4>
          <p class="muted">{{ t('threatbook.diagnosticWindow', { limit: diagnostics.attempt_limit, count: attemptsForBatch(batch.id).length }) }}</p>
          <table><thead><tr><th>{{ t('task.attempt') }}</th><th>{{ t('task.status') }}</th><th>{{ t('threatbook.responseCode') }}</th><th>{{ t('task.errorType') }}</th><th>{{ t('task.errorMessage') }}</th><th>{{ t('threatbook.finishedAt') }}</th></tr></thead><tbody><tr v-for="attempt in attemptsForBatch(batch.id)" :key="attempt.id"><td>#{{ attempt.attempt_number }}</td><td>{{ t(`statuses.${attempt.status}`) }}</td><td>{{ attempt.response_code ?? '—' }}</td><td>{{ attempt.error_type || '—' }}</td><td>{{ attempt.error_message || '—' }}</td><td>{{ dateText(attempt.finished_at) }}</td></tr></tbody></table>
        </section>
      </div>
    </section>

    <section class="panel table-panel intelligence-panel">
      <div class="section-title"><div><span class="kicker">IP INTELLIGENCE</span><h3>{{ t('threatbook.intelligenceResults') }}</h3></div><span v-if="results" class="muted">{{ t('task.pageSummary', { page: results.page, pages: resultPages, total: results.total }) }}</span></div>
      <form class="result-filters" @submit.prevent="submitFilters">
        <input v-model.trim="filters.q" :aria-label="t('threatbook.ipSearch')" :placeholder="t('threatbook.searchIp')">
        <select v-model="filters.malicious" :aria-label="t('threatbook.maliciousStatus')"><option value="">{{ t('threatbook.allMalicious') }}</option><option value="true">{{ t('common.malicious') }}</option><option value="false">{{ t('common.notMalicious') }}</option></select>
        <input v-model.trim="filters.judgment" :aria-label="t('threatbook.threatLabel')" :placeholder="t('threatbook.threatLabel')">
        <input v-model.trim="filters.country" :aria-label="t('threatbook.country')" :placeholder="t('threatbook.country')">
        <input v-model.trim="filters.province" :aria-label="t('threatbook.province')" :placeholder="t('threatbook.province')">
        <input v-model.trim="filters.city" :aria-label="t('threatbook.city')" :placeholder="t('threatbook.city')">
        <input v-model.trim="filters.severity" :aria-label="t('diagnostics.severity')" :placeholder="t('diagnostics.severity')">
        <input v-model.trim="filters.confidence" :aria-label="t('diagnostics.confidence')" :placeholder="t('diagnostics.confidence')">
        <button class="primary" type="submit">{{ t('common.applyFilters') }}</button><button class="button ghost" type="button" @click="clearFilters">{{ t('common.clear') }}</button>
      </form>
      <table v-if="results?.items.length"><thead><tr><th>IP</th><th>{{ t('common.malicious') }}</th><th>{{ t('diagnostics.confidence') }}</th><th>{{ t('diagnostics.severity') }}</th><th>{{ t('threatbook.threatLabel') }}</th><th>{{ t('threatbook.location') }}</th><th>{{ t('threatbook.carrier') }}</th><th>ASN</th><th>{{ t('threatbook.scene') }}</th><th>{{ t('threatbook.updatedAt') }}</th><th>{{ t('threatbook.link') }}</th><th>{{ t('task.investigate') }}</th></tr></thead><tbody><tr v-for="result in results.items" :key="result.id"><td><code>{{ result.ip }}</code></td><td :class="result.is_malicious ? 'danger-text' : 'ok-text'">{{ t(result.is_malicious ? 'common.malicious' : 'common.notMalicious') }}</td><td>{{ result.confidence_level || '—' }}</td><td>{{ result.severity || '—' }}</td><td>{{ result.judgments.join(', ') || '—' }}</td><td>{{ locationText(result) }}</td><td>{{ result.carrier || '—' }}</td><td>{{ asnText(result) }}</td><td>{{ result.scene || '—' }}</td><td>{{ result.update_time || '—' }}</td><td><a v-if="safePermalink(result.permalink)" class="text-link" :href="safePermalink(result.permalink)!" target="_blank" rel="noopener noreferrer">{{ t('threatbook.viewIntelligence') }}</a><span v-else>—</span></td><td><RouterLink class="text-link" :to="diagnosticIpLink(result.task_ip_id)">{{ t('task.investigate') }} →</RouterLink></td></tr></tbody></table>
      <p v-else class="empty-row muted">{{ t(loadErrors.results ? 'threatbook.resultsUnavailable' : 'threatbook.noResults') }}</p>
      <div v-if="results" class="pagination workspace-pagination" :aria-label="t('threatbook.resultsPagination')"><button class="button ghost" :disabled="results.page <= 1" @click="loadResults(results.page - 1)">{{ t('common.previous') }}</button><button class="button ghost" :disabled="results.page >= resultPages" @click="loadResults(results.page + 1)">{{ t('common.next') }}</button></div>
    </section>
  </template>
  <section v-else class="panel empty"><p v-for="item in visibleErrors" :key="item" class="error-banner">{{ item }}</p><RouterLink class="button ghost" :to="`/tasks/${taskId}`">{{ t('threatbook.backToTask') }}</RouterLink></section>
</template>
