<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'

import { api } from '../api'
import type { IpItem, TaskSummary, WhitelistResultsPage } from '../types'

const route = useRoute()
const router = useRouter()
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
      error.value = reason instanceof Error ? reason.message : '读取任务失败'
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
    error.value = reason instanceof Error ? reason.message : '操作失败'
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
    error.value = reason instanceof Error ? reason.message : '启动微步查询失败'
  } finally {
    startingThreatbook.value = false
  }
}

async function changeWhitelistFilter() {
  whitelistPage.value = 1
  try {
    await loadWhitelist(1, whitelistVerdict.value)
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '读取查白结论失败'
  }
}

async function changeWhitelistPage(page: number) {
  whitelistPage.value = page
  try {
    await loadWhitelist(page, whitelistVerdict.value)
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '读取查白结论失败'
  }
}

function matchesText(matches: unknown[]) {
  return matches.length ? JSON.stringify(matches) : '—'
}

function exportUrl(stage: string, format: string) {
  return `/api/tasks/${taskId}/exports/${stage}.${format}`
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
  <div v-if="!task" class="panel empty">正在读取任务…</div>
  <template v-else>
    <section class="page-head compact"><div><span class="kicker">TASK {{ task.id.slice(0, 8) }}</span><h2>{{ task.original_filename || '手动 IP 查询' }}</h2><p>当前节点：{{ task.current_step }} · 状态：{{ task.status }}</p></div>
      <div class="task-actions"><a v-if="task.original_filename" class="button ghost" :href="`/api/tasks/${taskId}/original`">下载原文件</a><a class="button ghost" :href="exportUrl('deduplicated', 'xlsx')">导出去重结果</a><RouterLink class="button ghost" to="/history">返回历史</RouterLink></div>
    </section>
    <p v-if="error" class="error-banner">{{ error }}</p>
    <section class="stats-grid">
      <article><span>原始记录</span><b>{{ task.raw_count }}</b></article><article><span>有效 IP</span><b>{{ task.valid_count }}</b></article>
      <article><span>去重后</span><b>{{ task.unique_count }}</b></article><article><span>白名单移除</span><b>{{ task.whitelist_removed_count }}</b></article>
      <article><span>微步待查</span><b>{{ task.threatbook_ready_count }}</b></article><article class="danger-card"><span>恶意 IP</span><b>{{ task.malicious_count }}</b></article>
    </section>
    <section class="panel">
      <div class="section-title"><div><span class="kicker">PIPELINE</span><h3>处理进度与节点排查</h3></div><span class="live-dot" v-if="active">实时更新</span></div>
      <div class="timeline">
        <div v-for="(step, index) in task.steps" :key="step.name" class="step" :class="step.status">
          <div class="step-icon">{{ step.status === 'completed' ? '✓' : step.status === 'failed' ? '!' : index + 1 }}</div>
          <div><b>{{ step.name }}</b><span>{{ step.status }}<template v-if="step.total_batches"> · {{ step.current_batch }}/{{ step.total_batches }} 批</template></span><p v-if="step.error_summary">{{ step.error_summary }}</p></div>
        </div>
      </div>
      <div class="gate" v-if="canRemove"><div><b>查白已经完成</b><span>当前、历史及失效名单命中都会从本次微步队列移除。</span></div><button class="primary" @click="action('remove-whitelist')">一键移除白名单</button></div>
      <div class="gate" v-if="canStart"><div><b>待查集合已经准备好</b><span v-if="whitelist?.summary.hit === 0">没有白名单命中，已自动进入微步待查集合。</span><span v-else>默认每批 100、800 IP/分钟、每日预算 10,000。</span></div><button class="primary danger" :disabled="startingThreatbook" @click="startThreatbook">{{ startingThreatbook ? '正在启动微步…' : '开始查询微步' }}</button></div>
      <div class="failure-detail" v-if="diagnostics">
        <div class="section-title"><div><span class="kicker">FAILURE EVIDENCE</span><h3>失败节点排查</h3></div><button class="primary" @click="api.post(`/api/tasks/${taskId}/steps/${diagnostics.current_step}/retry`).then(load)">重试当前节点</button></div>
        <p><b>{{ diagnostics.current_step }}</b> · {{ diagnostics.error_summary }}</p>
        <p class="muted">最后成功检查点：{{ diagnostics.last_successful_checkpoint || '无' }}</p>
        <table v-if="diagnostics.attempts.length"><thead><tr><th>节点</th><th>批次</th><th>尝试</th><th>错误类型</th><th>错误信息</th></tr></thead><tbody><tr v-for="attempt in diagnostics.attempts" :key="attempt.id"><td>{{ attempt.step_name }}</td><td>{{ attempt.batch_id || '-' }}</td><td>{{ attempt.attempt_number }}</td><td>{{ attempt.error_type || '-' }}</td><td>{{ attempt.error_message || '-' }}</td></tr></tbody></table>
      </div>
    </section>
    <section v-if="whitelist" class="panel table-panel whitelist-panel">
      <div class="section-title"><div><span class="kicker">WHITELIST CONCLUSIONS</span><h3>查白结论</h3></div><span class="muted">第 {{ whitelist.page }} / {{ whitelistPages }} 页，共 {{ whitelist.total }} 条</span></div>
      <div class="whitelist-summary" aria-label="查白汇总"><span>总计 <b>{{ whitelist.summary.total }}</b></span><span class="hit">命中 <b>{{ whitelist.summary.hit }}</b></span><span class="clear">未命中 <b>{{ whitelist.summary.clear }}</b></span><span class="error">异常 <b>{{ whitelist.summary.error }}</b></span></div>
      <div class="whitelist-controls"><label>结论筛选<select v-model="whitelistVerdict" @change="changeWhitelistFilter"><option value="">全部结论</option><option value="当前名单">当前名单</option><option value="历史名单">历史名单</option><option value="失效名单">失效名单</option><option value="未命中">未命中</option><option value="异常">异常</option></select></label><div class="pagination"><button class="button ghost" :disabled="whitelist.page <= 1" @click="changeWhitelistPage(whitelist.page - 1)">上一页</button><button class="button ghost" :disabled="whitelist.page >= whitelistPages" @click="changeWhitelistPage(whitelist.page + 1)">下一页</button></div></div>
      <table><thead><tr><th>IP</th><th>结论类型</th><th>结论说明</th><th>结果码</th><th>匹配信息</th><th>请求 ID</th></tr></thead><tbody><tr v-for="result in whitelist.items" :key="`${result.ip}-${result.request_id}`"><td><code>{{ result.ip }}</code></td><td><span class="stage-tag">{{ result.category }}</span></td><td>{{ result.verdict }}</td><td><code>{{ result.result_code }}</code></td><td class="matches">{{ matchesText(result.matches) }}</td><td>{{ result.request_id || '—' }}</td></tr><tr v-if="!whitelist.items.length"><td colspan="6" class="empty-row">没有符合筛选条件的查白结论。</td></tr></tbody></table>
    </section>
    <section class="panel table-panel">
      <div class="section-title"><div><span class="kicker">IP EVIDENCE</span><h3>IP 处理明细（前 100 条）</h3></div><div class="export-links"><a :href="exportUrl('whitelist_hits','txt')">白名单 TXT</a><a :href="exportUrl('threatbook_complete','xlsx')">微步 Excel</a></div></div>
      <table><thead><tr><th>IP</th><th>版本</th><th>次数</th><th>公网</th><th>当前归类</th><th>来源位置</th><th></th></tr></thead>
        <tbody><tr v-for="ip in ips" :key="ip.id"><td><code>{{ ip.ip }}</code></td><td>IPv{{ ip.ip_version }}</td><td>{{ ip.occurrence_count }}</td><td>{{ ip.is_public ? '是' : '否' }}</td><td><span class="stage-tag">{{ ip.stage }}</span></td><td>{{ ip.first_position }}</td><td><RouterLink class="text-link" :to="`/tasks/${taskId}/ips/${ip.id}`">排查 →</RouterLink></td></tr></tbody>
      </table>
    </section>
  </template>
</template>
