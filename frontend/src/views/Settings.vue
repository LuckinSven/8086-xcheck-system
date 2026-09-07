<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'

import { api } from '../api'

interface SettingsPayload {
  whitelist_api_url: string
  threatbook_api_url: string
  threatbook_api_key?: string
  clear_threatbook_api_key?: boolean
  threatbook_api_key_configured?: boolean
  upload_max_bytes?: number
  threatbook_batch_size: number
  threatbook_safe_ips_per_minute: number
  threatbook_daily_budget: number
  threatbook_max_retries: number
}

interface ProbeResult {
  ok: boolean
  message: string
  latency_ms: number
}

const form = reactive<SettingsPayload>({
  whitelist_api_url: '',
  threatbook_api_url: '',
  threatbook_api_key: '',
  clear_threatbook_api_key: false,
  threatbook_batch_size: 100,
  threatbook_safe_ips_per_minute: 800,
  threatbook_daily_budget: 10000,
  threatbook_max_retries: 3,
})
const extra = ref<SettingsPayload | null>(null)
const message = ref('')
const error = ref('')
const busy = ref('')
const probeResult = reactive<Record<string, ProbeResult | null>>({ whitelist: null, threatbook: null })

function applyLoaded(value: SettingsPayload) {
  form.whitelist_api_url = value.whitelist_api_url
  form.threatbook_api_url = value.threatbook_api_url
  form.threatbook_batch_size = value.threatbook_batch_size
  form.threatbook_safe_ips_per_minute = value.threatbook_safe_ips_per_minute
  form.threatbook_daily_budget = value.threatbook_daily_budget
  form.threatbook_max_retries = value.threatbook_max_retries
  form.threatbook_api_key = ''
  form.clear_threatbook_api_key = false
  extra.value = value
}

onMounted(async () => {
  try {
    applyLoaded(await api.get<SettingsPayload>('/api/settings'))
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '配置读取失败'
  }
})

async function save(showMessage = true) {
  busy.value = 'save'
  error.value = ''
  if (showMessage) message.value = ''
  try {
    const value = await api.put<SettingsPayload>('/api/settings', { ...form })
    applyLoaded(value)
    if (showMessage) message.value = '配置已保存；后续任务将使用新参数。'
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '配置保存失败'
  } finally {
    busy.value = ''
  }
}

async function probe(target: 'whitelist' | 'threatbook') {
  busy.value = target
  error.value = ''
  probeResult[target] = null
  try {
    probeResult[target] = await api.post<ProbeResult>(`/api/settings/test-${target}`)
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '接口测试失败'
  } finally {
    busy.value = ''
  }
}
</script>

<template>
  <section class="page-head">
    <div><span class="kicker">INTEGRATION CONTROL</span><h2>系统设置</h2><p>直接配置内网查白与微步接口，并在保存后发起真实认证测试。</p></div>
    <div class="capacity"><b :class="extra?.threatbook_api_key_configured ? 'ok-text' : 'danger-text'">{{ extra?.threatbook_api_key_configured ? '认证就绪' : '等待配置' }}</b><span>微步 API</span></div>
  </section>

  <section class="settings-stack">
    <div class="integration-grid">
      <article class="panel integration-card">
        <div class="integration-heading"><div class="integration-icon">W</div><div><span class="kicker">WHITELIST API</span><h3>白名单接口</h3></div></div>
        <label class="field-label">查询地址<input v-model.trim="form.whitelist_api_url" name="whitelist_api_url" type="url" placeholder="http://服务器IP:8085/api/v1/whitelist/query" /></label>
        <button class="button ghost" data-action="test-whitelist" :disabled="!!busy" @click="probe('whitelist')">{{ busy === 'whitelist' ? '正在测试…' : '测试白名单连接' }}</button>
        <p v-if="probeResult.whitelist" class="probe-result"><i></i>{{ probeResult.whitelist.message }} · {{ probeResult.whitelist.latency_ms }} ms</p>
      </article>

      <article class="panel integration-card">
        <div class="integration-heading"><div class="integration-icon blue">T</div><div><span class="kicker">THREATBOOK API</span><h3>微步接口与认证</h3></div></div>
        <label class="field-label">查询地址<input v-model.trim="form.threatbook_api_url" name="threatbook_api_url" type="url" placeholder="https://api.threatbook.cn/v3/scene/ip_reputation" /></label>
        <label class="field-label">API Key<input v-model="form.threatbook_api_key" type="password" autocomplete="new-password" :placeholder="extra?.threatbook_api_key_configured ? '已配置；留空表示不修改' : '请输入微步 API Key'" /></label>
        <label v-if="extra?.threatbook_api_key_configured" class="check-label"><input v-model="form.clear_threatbook_api_key" type="checkbox" /> 清除当前密钥</label>
        <button class="button ghost" data-action="test-threatbook" :disabled="!!busy" @click="probe('threatbook')">{{ busy === 'threatbook' ? '正在认证…' : '测试微步认证' }}</button>
        <p v-if="probeResult.threatbook" class="probe-result"><i></i>{{ probeResult.threatbook.message }} · {{ probeResult.threatbook.latency_ms }} ms</p>
      </article>
    </div>

    <article class="panel limit-panel">
      <div class="section-title"><div><span class="kicker">QUERY GUARDRAILS</span><h3>微步批量查询限制</h3></div><span class="muted">单并发 · 保存后对后续任务生效</span></div>
      <div class="form-grid"><label>每批 IP 数<input v-model.number="form.threatbook_batch_size" type="number" min="1" max="100" /></label><label>安全速度（IP/分钟）<input v-model.number="form.threatbook_safe_ips_per_minute" type="number" min="1" max="1000" /></label><label>本地每日预算<input v-model.number="form.threatbook_daily_budget" type="number" min="1" /></label><label>最大重试次数<input v-model.number="form.threatbook_max_retries" type="number" min="0" max="3" /></label></div>
      <div class="settings-actions"><button class="primary" data-action="save-settings" :disabled="!!busy" @click="save()">{{ busy === 'save' ? '正在保存…' : '保存全部配置' }}</button><span>接口测试使用最近一次保存的配置 · 上传上限 {{ Math.round((extra?.upload_max_bytes || 0) / 1024 / 1024) }} MB</span></div>
    </article>
  </section>
  <p v-if="message" class="success-banner settings-message">{{ message }}</p>
  <p v-if="error" class="error-banner settings-message">{{ error }}</p>
</template>
