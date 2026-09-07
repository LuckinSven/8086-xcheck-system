<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { api } from '../api'
import type { Page, Step, TaskDiagnostics, TaskSummary, ThreatbookBatch, ThreatbookResult } from '../types'

const route = useRoute()
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

function message(reason: unknown, fallback: string) {
  return reason instanceof Error ? reason.message : fallback
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
    loadErrors.diagnostics = `诊断信息：${message(reason, '暂时无法加载')}`
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
    loadErrors.task = `任务概况：${message(reason, '暂时无法加载')}`
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
    loadErrors.batches = `批次明细：${message(reason, '暂时无法加载')}`
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
    loadErrors.results = `情报结果：${message(reason, '暂时无法加载')}`
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
    loadErrors.action = `重试失败：${message(reason, '请求未完成')}`
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
  return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '—'
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
  return value === null || value === undefined ? '未提供' : `${value}${suffix}`
}

function timestamp(value: string) {
  return Date.parse(/[zZ]|[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`)
}

function durationText(seconds: number) {
  const safeSeconds = Math.max(0, Math.round(seconds))
  if (safeSeconds < 60) return `${safeSeconds} 秒`
  const minutes = Math.floor(safeSeconds / 60)
  const remainder = safeSeconds % 60
  return remainder ? `${minutes} 分 ${remainder} 秒` : `${minutes} 分钟`
}

const elapsedText = computed(() => {
  const step = threatbookStep.value
  if (!step?.started_at) return '—'
  const end = step.finished_at ? timestamp(step.finished_at) : Date.now()
  return durationText((end - timestamp(step.started_at)) / 1000)
})

const etaText = computed(() => {
  if (!active.value || remaining.value <= 0) return null
  if (!observedRate.value || observedRate.value <= 0) return '计算中'
  return `约 ${durationText(remaining.value / observedRate.value)}`
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
  <div v-if="loading && !task" class="panel empty">正在加载微步工作台…</div>
  <template v-else-if="task">
    <section class="page-head compact threatbook-head">
      <div><span class="kicker">THREATBOOK TASK {{ task.id.slice(0, 8) }}</span><h2>微步情报工作台</h2><p>{{ task.original_filename || '手动 IP 查询' }} · 状态：{{ task.status }}<b v-if="readOnlyHistory" class="history-readonly">历史只读</b></p></div>
      <div class="task-actions"><a class="button ghost" :href="`/api/tasks/${taskId}/exports/threatbook_complete.xlsx`">导出微步结果</a><RouterLink class="button ghost" :to="`/tasks/${taskId}`">返回任务详情</RouterLink><RouterLink v-if="readOnlyHistory" class="button ghost" to="/threatbook-history">返回微步历史</RouterLink><RouterLink v-else class="button ghost" to="/history">返回任务历史</RouterLink></div>
    </section>

    <div v-if="visibleErrors.length" class="error-banner workspace-errors" role="alert"><span v-for="item in visibleErrors" :key="item">{{ item }}</span></div>

    <section class="stats-grid threatbook-stats" aria-label="微步进度指标">
      <article><span>总待查</span><b>{{ progressTotal }}</b></article>
      <article><span>已完成</span><b>{{ progressCurrent }}</b></article>
      <article><span>剩余</span><b>{{ remaining }}</b></article>
      <article><span>失败</span><b>{{ task.failed_count }}</b></article>
      <article class="danger-card"><span>恶意 IP</span><b>{{ task.malicious_count }}</b></article>
    </section>

    <section class="panel workspace-progress">
      <div class="section-title"><div><span class="kicker">LIVE EXECUTION</span><h3>实时执行进度</h3></div><span v-if="shouldPoll" class="live-dot">每 1.5 秒更新</span></div>
      <div class="progress-copy"><b>{{ progressPercent }}%</b><span>{{ progressCurrent }} / {{ progressTotal }} IP</span></div>
      <div class="progress-track" role="progressbar" :aria-valuenow="progressPercent" aria-valuemin="0" aria-valuemax="100"><i :style="{ width: `${progressPercent}%` }"></i></div>
      <div class="execution-grid">
        <span>当前批次 <b>{{ threatbookStep?.current_batch || 0 }} / {{ threatbookStep?.total_batches || 0 }}</b></span>
        <span>批大小 <b>{{ configValue(task.threatbook_config?.batch_size) }}</b></span>
        <span>安全速率 <b>{{ configValue(task.threatbook_config?.safe_ips_per_minute, ' IP/分钟') }}</b></span>
        <span>每日预算 <b>{{ configValue(task.threatbook_config?.daily_budget) }}</b></span>
        <span>最大重试 <b>{{ configValue(task.threatbook_config?.max_retries) }}</b></span>
        <span>已用时间 <b>{{ elapsedText }}</b></span>
        <span v-if="etaText">预计剩余 <b>{{ etaText }}</b></span>
      </div>
      <div v-if="canRetry || (readOnlyHistory && ['failed', 'partial_success'].includes(task.status))" class="failure-detail compact-failure">
        <div><b>{{ diagnostics?.error_summary || task.error_summary || '微步查询未全部完成' }}</b><span>最后成功检查点：{{ diagnostics?.last_successful_checkpoint || '无' }}</span></div>
        <button v-if="canRetry" class="primary retry-threatbook" :disabled="retrying" @click="retryThreatbook">{{ retrying ? '正在重试…' : '重试微步节点' }}</button>
      </div>
    </section>

    <section class="panel table-panel">
      <div class="section-title"><div><span class="kicker">BATCH DIAGNOSTICS</span><h3>执行批次</h3></div><span v-if="batches" class="muted">第 {{ batches.page }} / {{ batchPages }} 页，共 {{ batches.total }} 批</span></div>
      <table v-if="batches?.items.length"><thead><tr><th>批次</th><th>状态</th><th>IP 数</th><th>已解析</th><th>未解析</th><th>尝试</th><th>响应码</th><th>响应信息</th><th>开始时间</th><th>完成时间</th><th>诊断</th></tr></thead><tbody><tr v-for="batch in batches.items" :key="batch.id"><td>#{{ batch.batch_number }}</td><td><span class="status" :class="batch.status">{{ batch.status }}</span></td><td>{{ batch.address_count }}</td><td>{{ batch.resolved_count }}</td><td>{{ batch.unresolved_count }}</td><td>{{ batch.attempt_count }}</td><td>{{ batch.response_code ?? '—' }}</td><td>{{ batch.response_message || '—' }}</td><td>{{ dateText(batch.created_at) }}</td><td>{{ dateText(batch.finished_at) }}</td><td><a v-if="batch.status === 'failed' && attemptsForBatch(batch.id).length" class="text-link" :href="`#batch-attempts-${batch.id}`">{{ attemptsForBatch(batch.id).length }} 条尝试</a><span v-else-if="batch.status === 'failed'">最近诊断窗口未包含</span><span v-else>—</span></td></tr></tbody></table>
      <p v-else class="empty-row muted">{{ loadErrors.batches ? '批次明细暂未加载' : '尚无微步执行批次。' }}</p>
      <div v-if="batches" class="pagination workspace-pagination" aria-label="批次分页"><button class="button ghost" :disabled="batches.page <= 1" @click="loadBatches(batches.page - 1)">上一页</button><button class="button ghost" :disabled="batches.page >= batchPages" @click="loadBatches(batches.page + 1)">下一页</button></div>
      <div v-if="diagnostics?.attempts.length" class="batch-attempt-diagnostics">
        <section v-for="batch in batches?.items.filter((item) => attemptsForBatch(item.id).length)" :id="`batch-attempts-${batch.id}`" :key="`attempts-${batch.id}`">
          <h4>批次 #{{ batch.batch_number }} 尝试诊断</h4>
          <p class="muted">显示最近 {{ diagnostics.attempt_limit }} 条诊断窗口中的 {{ attemptsForBatch(batch.id).length }} 条相关尝试</p>
          <table><thead><tr><th>尝试</th><th>状态</th><th>响应码</th><th>错误类型</th><th>错误信息</th><th>完成时间</th></tr></thead><tbody><tr v-for="attempt in attemptsForBatch(batch.id)" :key="attempt.id"><td>#{{ attempt.attempt_number }}</td><td>{{ attempt.status }}</td><td>{{ attempt.response_code ?? '—' }}</td><td>{{ attempt.error_type || '—' }}</td><td>{{ attempt.error_message || '—' }}</td><td>{{ dateText(attempt.finished_at) }}</td></tr></tbody></table>
        </section>
      </div>
    </section>

    <section class="panel table-panel intelligence-panel">
      <div class="section-title"><div><span class="kicker">IP INTELLIGENCE</span><h3>情报结果</h3></div><span v-if="results" class="muted">第 {{ results.page }} / {{ resultPages }} 页，共 {{ results.total }} 条</span></div>
      <form class="result-filters" @submit.prevent="submitFilters">
        <input v-model.trim="filters.q" aria-label="IP 搜索" placeholder="搜索 IP">
        <select v-model="filters.malicious" aria-label="恶意状态"><option value="">全部恶意状态</option><option value="true">恶意</option><option value="false">非恶意</option></select>
        <input v-model.trim="filters.judgment" aria-label="威胁标签" placeholder="威胁标签">
        <input v-model.trim="filters.country" aria-label="国家" placeholder="国家">
        <input v-model.trim="filters.province" aria-label="省份" placeholder="省份">
        <input v-model.trim="filters.city" aria-label="城市" placeholder="城市">
        <input v-model.trim="filters.severity" aria-label="严重度" placeholder="严重度">
        <input v-model.trim="filters.confidence" aria-label="可信度" placeholder="可信度">
        <button class="primary" type="submit">应用筛选</button><button class="button ghost" type="button" @click="clearFilters">清空</button>
      </form>
      <table v-if="results?.items.length"><thead><tr><th>IP</th><th>恶意</th><th>可信度</th><th>严重度</th><th>威胁标签</th><th>国家 / 省 / 市</th><th>运营商</th><th>ASN</th><th>场景</th><th>更新时间</th><th>微步链接</th><th>排查</th></tr></thead><tbody><tr v-for="result in results.items" :key="result.id"><td><code>{{ result.ip }}</code></td><td :class="result.is_malicious ? 'danger-text' : 'ok-text'">{{ result.is_malicious ? '恶意' : '非恶意' }}</td><td>{{ result.confidence_level || '—' }}</td><td>{{ result.severity || '—' }}</td><td>{{ result.judgments.join('、') || '—' }}</td><td>{{ locationText(result) }}</td><td>{{ result.carrier || '—' }}</td><td>{{ asnText(result) }}</td><td>{{ result.scene || '—' }}</td><td>{{ result.update_time || '—' }}</td><td><a v-if="safePermalink(result.permalink)" class="text-link" :href="safePermalink(result.permalink)!" target="_blank" rel="noopener noreferrer">查看情报</a><span v-else>—</span></td><td><RouterLink class="text-link" :to="diagnosticIpLink(result.task_ip_id)">排查 →</RouterLink></td></tr></tbody></table>
      <p v-else class="empty-row muted">{{ loadErrors.results ? '情报结果暂未加载' : '没有符合条件的情报结果。' }}</p>
      <div v-if="results" class="pagination workspace-pagination" aria-label="情报结果分页"><button class="button ghost" :disabled="results.page <= 1" @click="loadResults(results.page - 1)">上一页</button><button class="button ghost" :disabled="results.page >= resultPages" @click="loadResults(results.page + 1)">下一页</button></div>
    </section>
  </template>
  <section v-else class="panel empty"><p v-for="item in visibleErrors" :key="item" class="error-banner">{{ item }}</p><RouterLink class="button ghost" :to="`/tasks/${taskId}`">返回任务详情</RouterLink></section>
</template>
