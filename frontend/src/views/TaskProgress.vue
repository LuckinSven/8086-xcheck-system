<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { api, translateApiError } from '../api'
import type { IpItem, TaskSummary, WhitelistResultsPage } from '../types'

const route = useRoute()
const router = useRouter()
const { t } = useI18n()
const taskId = route.params.id as string
const task = ref<TaskSummary | null>(null)
const ips = ref<IpItem[]>([])
const whitelist = ref<WhitelistResultsPage | null>(null)
const whitelistPage = ref(1)
const whitelistVerdict = ref('')
const diagnostics = ref<Record<string, any> | null>(null)
const error = ref('')
const startingThreatbook = ref(false)
let timer: number | undefined
let disposed = false
let loadGeneration = 0
let whitelistGeneration = 0

const active = computed(() => task.value && ['queued', 'running'].includes(task.value.status))
const canRemove = computed(() => task.value?.status === 'waiting_whitelist_confirmation')
const canStart = computed(() => task.value?.status === 'waiting_threatbook_confirmation' || task.value?.status === 'paused_quota')
const whitelistCompleted = computed(() => task.value?.steps?.some((step) => step.name === 'whitelist_query' && step.status === 'completed') ?? false)
const whitelistPages = computed(() => whitelist.value ? Math.max(1, Math.ceil(whitelist.value.total / whitelist.value.page_size)) : 1)

function whitelistUrl(page: number, verdict: string) {
  const params = new URLSearchParams({ page: String(page), page_size: '50' })
  if (verdict) params.set('verdict', verdict)
  return `/api/tasks/${taskId}/whitelist-results?${params}`
}

async function loadWhitelist(page = whitelistPage.value, verdict = whitelistVerdict.value) {
  const generation = ++whitelistGeneration
  if (!whitelistCompleted.value) {
    if (!disposed && generation === whitelistGeneration) whitelist.value = null
    return
  }
  try {
    const payload = await api.get<WhitelistResultsPage>(whitelistUrl(page, verdict))
    if (disposed || generation !== whitelistGeneration) return
    whitelist.value = payload
    whitelistPage.value = payload.page
    error.value = ''
  } catch (reason) {
    if (disposed || generation !== whitelistGeneration) return
    throw reason
  }
}

async function load() {
  const generation = ++loadGeneration
  if (timer !== undefined) {
    window.clearTimeout(timer)
    timer = undefined
  }
  try {
    const taskPayload = await api.get<TaskSummary>(`/api/tasks/${taskId}`)
    if (disposed || generation !== loadGeneration) return
    task.value = taskPayload
    const ipPayload = await api.get<{ items: IpItem[] }>(`/api/tasks/${taskId}/ips?page_size=100`)
    if (disposed || generation !== loadGeneration) return
    ips.value = ipPayload.items
    await loadWhitelist(whitelistPage.value, whitelistVerdict.value)
    if (disposed || generation !== loadGeneration) return
    if (['failed', 'partial_success'].includes(taskPayload.status)) {
      const diagnosticPayload = await api.get<Record<string, any>>(`/api/tasks/${taskId}/diagnostics`)
      if (disposed || generation !== loadGeneration) return
      diagnostics.value = diagnosticPayload
    }
  } catch (reason) {
    if (!disposed && generation === loadGeneration) {
      error.value = translateApiError(reason, t)
    }
  }
  if (!disposed && generation === loadGeneration && active.value) {
    timer = window.setTimeout(load, 1500)
  }
}

async function action(name: string) {
  error.value = ''
  try {
    await api.post(`/api/tasks/${taskId}/actions/${name}`)
    await load()
  } catch (reason) {
    error.value = translateApiError(reason, t)
  }
}

async function startThreatbook() {
  if (startingThreatbook.value) return
  error.value = ''
  startingThreatbook.value = true
  try {
    await api.post(`/api/tasks/${taskId}/actions/start-threatbook`)
    await router.push(`/tasks/${taskId}/threatbook`)
  } catch (reason) {
    error.value = translateApiError(reason, t)
  } finally {
    startingThreatbook.value = false
  }
}

async function changeWhitelistFilter() {
  whitelistPage.value = 1
  try {
    await loadWhitelist(1, whitelistVerdict.value)
  } catch (reason) {
    error.value = translateApiError(reason, t)
  }
}

async function changeWhitelistPage(page: number) {
  whitelistPage.value = page
  try {
    await loadWhitelist(page, whitelistVerdict.value)
  } catch (reason) {
    error.value = translateApiError(reason, t)
  }
}

function matchesText(matches: unknown[]) {
  return matches.length ? JSON.stringify(matches) : '—'
}

function exportUrl(stage: string, format: string) {
  return `/api/tasks/${taskId}/exports/${stage}.${format}`
}

function statusText(status: string) {
  const key = `statuses.${status}`
  const value = t(key)
  return value === key ? status : value
}

function stepText(step: string) {
  const key = `steps.${step}`
  const value = t(key)
  return value === key ? step : value
}

onMounted(load)
onBeforeUnmount(() => {
  disposed = true
  loadGeneration += 1
  whitelistGeneration += 1
  if (timer !== undefined) {
    window.clearTimeout(timer)
    timer = undefined
  }
})
</script>

<template>
  <div v-if="!task" class="panel empty">{{ t('task.loading') }}</div>
  <template v-else>
    <section class="page-head compact"><div><span class="kicker">TASK {{ task.id.slice(0, 8) }}</span><h2>{{ task.original_filename || t('task.manualQuery') }}</h2><p>{{ t('task.currentStep') }}: {{ stepText(task.current_step) }} · {{ t('task.status') }}: {{ statusText(task.status) }}</p></div>
      <div class="task-actions"><a v-if="task.original_filename" class="button ghost" :href="`/api/tasks/${taskId}/original`">{{ t('task.downloadOriginal') }}</a><a class="button ghost" :href="exportUrl('deduplicated', 'xlsx')">{{ t('task.exportDeduplicated') }}</a><RouterLink class="button ghost" to="/history">{{ t('task.backToHistory') }}</RouterLink></div>
    </section>
    <p v-if="error" class="error-banner">{{ error }}</p>
    <section class="stats-grid">
      <article><span>{{ t('task.rawRecords') }}</span><b>{{ task.raw_count }}</b></article><article><span>{{ t('task.validIps') }}</span><b>{{ task.valid_count }}</b></article>
      <article><span>{{ t('task.afterDeduplication') }}</span><b>{{ task.unique_count }}</b></article><article><span>{{ t('task.whitelistRemoved') }}</span><b>{{ task.whitelist_removed_count }}</b></article>
      <article><span>{{ t('task.threatbookReady') }}</span><b>{{ task.threatbook_ready_count }}</b></article><article class="danger-card"><span>{{ t('task.maliciousIps') }}</span><b>{{ task.malicious_count }}</b></article>
    </section>
    <section class="panel">
      <div class="section-title"><div><span class="kicker">PIPELINE</span><h3>{{ t('task.pipelineTitle') }}</h3></div><span class="live-dot" v-if="active">{{ t('task.live') }}</span></div>
      <div class="timeline">
        <div v-for="(step, index) in task.steps" :key="step.name" class="step" :class="step.status">
          <div class="step-icon">{{ step.status === 'completed' ? '✓' : step.status === 'failed' ? '!' : index + 1 }}</div>
          <div><b>{{ stepText(step.name) }}</b><span>{{ statusText(step.status) }}<template v-if="step.total_batches"> · {{ t('task.batchProgress', { current: step.current_batch, total: step.total_batches }) }}</template></span><p v-if="step.error_summary">{{ step.error_summary }}</p></div>
        </div>
      </div>
      <div class="gate" v-if="canRemove"><div><b>{{ t('task.whitelistComplete') }}</b><span>{{ t('task.whitelistRemovalHint') }}</span></div><button class="primary" @click="action('remove-whitelist')">{{ t('task.removeWhitelist') }}</button></div>
      <div class="gate" v-if="canStart"><div><b>{{ t('task.querySetReady') }}</b><span v-if="whitelist?.summary.hit === 0">{{ t('task.noWhitelistHits') }}</span><span v-else>{{ t('task.defaultLimits') }}</span></div><button class="primary danger" :disabled="startingThreatbook" @click="startThreatbook">{{ t(startingThreatbook ? 'task.startingThreatbook' : 'task.startThreatbook') }}</button></div>
      <div class="failure-detail" v-if="diagnostics">
        <div class="section-title"><div><span class="kicker">FAILURE EVIDENCE</span><h3>{{ t('task.failureDiagnostics') }}</h3></div><button class="primary" @click="api.post(`/api/tasks/${taskId}/steps/${diagnostics.current_step}/retry`).then(load)">{{ t('task.retryCurrentStep') }}</button></div>
        <p><b>{{ diagnostics.current_step }}</b> · {{ diagnostics.error_summary }}</p>
        <p class="muted">{{ t('task.lastCheckpoint') }}: {{ diagnostics.last_successful_checkpoint ? stepText(diagnostics.last_successful_checkpoint) : t('common.none') }}</p>
        <table v-if="diagnostics.attempts.length"><thead><tr><th>{{ t('task.step') }}</th><th>{{ t('task.batch') }}</th><th>{{ t('task.attempt') }}</th><th>{{ t('task.errorType') }}</th><th>{{ t('task.errorMessage') }}</th></tr></thead><tbody><tr v-for="attempt in diagnostics.attempts" :key="attempt.id"><td>{{ stepText(attempt.step_name) }}</td><td>{{ attempt.batch_id || '-' }}</td><td>{{ attempt.attempt_number }}</td><td>{{ attempt.error_type || '-' }}</td><td>{{ attempt.error_message || '-' }}</td></tr></tbody></table>
      </div>
    </section>
    <section v-if="whitelist" class="panel table-panel whitelist-panel">
      <div class="section-title"><div><span class="kicker">WHITELIST CONCLUSIONS</span><h3>{{ t('task.whitelistConclusions') }}</h3></div><span class="muted">{{ t('task.pageSummary', { page: whitelist.page, pages: whitelistPages, total: whitelist.total }) }}</span></div>
      <div class="whitelist-summary" :aria-label="t('task.whitelistSummary')"><span>{{ t('task.total') }} <b>{{ whitelist.summary.total }}</b></span><span class="hit">{{ t('task.hits') }} <b>{{ whitelist.summary.hit }}</b></span><span class="clear">{{ t('task.clear') }} <b>{{ whitelist.summary.clear }}</b></span><span class="error">{{ t('task.errors') }} <b>{{ whitelist.summary.error }}</b></span></div>
      <div class="whitelist-controls"><label>{{ t('task.verdictFilter') }}<select v-model="whitelistVerdict" @change="changeWhitelistFilter"><option value="">{{ t('task.allVerdicts') }}</option><option value="当前名单">{{ t('task.currentList') }}</option><option value="历史名单">{{ t('task.historicalList') }}</option><option value="失效名单">{{ t('task.inactiveList') }}</option><option value="未命中">{{ t('task.notFound') }}</option><option value="异常">{{ t('task.exception') }}</option></select></label><div class="pagination"><button class="button ghost" :disabled="whitelist.page <= 1" @click="changeWhitelistPage(whitelist.page - 1)">{{ t('common.previous') }}</button><button class="button ghost" :disabled="whitelist.page >= whitelistPages" @click="changeWhitelistPage(whitelist.page + 1)">{{ t('common.next') }}</button></div></div>
      <table><thead><tr><th>IP</th><th>{{ t('task.verdictType') }}</th><th>{{ t('task.verdict') }}</th><th>{{ t('task.resultCode') }}</th><th>{{ t('task.matchDetails') }}</th><th>Request ID</th></tr></thead><tbody><tr v-for="result in whitelist.items" :key="`${result.ip}-${result.request_id}`"><td><code>{{ result.ip }}</code></td><td><span class="stage-tag">{{ result.category }}</span></td><td>{{ result.verdict }}</td><td><code>{{ result.result_code }}</code></td><td class="matches">{{ matchesText(result.matches) }}</td><td>{{ result.request_id || '—' }}</td></tr><tr v-if="!whitelist.items.length"><td colspan="6" class="empty-row">{{ t('task.noWhitelistResults') }}</td></tr></tbody></table>
    </section>
    <section class="panel table-panel">
      <div class="section-title"><div><span class="kicker">IP EVIDENCE</span><h3>{{ t('task.ipDetails') }}</h3></div><div class="export-links"><a :href="exportUrl('whitelist_hits','txt')">{{ t('task.whitelistTxt') }}</a><a :href="exportUrl('threatbook_complete','xlsx')">{{ t('task.threatbookExcel') }}</a></div></div>
      <table><thead><tr><th>IP</th><th>{{ t('task.version') }}</th><th>{{ t('task.occurrences') }}</th><th>{{ t('task.public') }}</th><th>{{ t('task.classification') }}</th><th>{{ t('task.sourcePosition') }}</th><th></th></tr></thead>
        <tbody><tr v-for="ip in ips" :key="ip.id"><td><code>{{ ip.ip }}</code></td><td>IPv{{ ip.ip_version }}</td><td>{{ ip.occurrence_count }}</td><td>{{ t(ip.is_public ? 'common.yes' : 'common.no') }}</td><td><span class="stage-tag">{{ ip.stage }}</span></td><td>{{ ip.first_position }}</td><td><RouterLink class="text-link" :to="`/tasks/${taskId}/ips/${ip.id}`">{{ t('task.investigate') }} →</RouterLink></td></tr></tbody>
      </table>
    </section>
  </template>
</template>
