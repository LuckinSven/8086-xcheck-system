<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'

import { api, translateApiError } from '../api'
import { themes } from '../theme'
import type { DisplaySettings, SystemSettings } from '../types'
import { applyUiSettings, DEFAULT_DISPLAY_SETTINGS } from '../ui-settings'

interface SettingsForm extends DisplaySettings {
  whitelist_api_url: string
  threatbook_api_url: string
  threatbook_api_key: string
  clear_threatbook_api_key: boolean
  threatbook_batch_size: number
  threatbook_safe_ips_per_minute: number
  threatbook_daily_budget: number
  threatbook_max_retries: number
}

interface ProbeResult {
  ok: boolean
  code: string
  fallback: string
  params: Record<string, string | number>
  latency_ms: number
}

const { t } = useI18n()
const form = reactive<SettingsForm>({
  whitelist_api_url: '',
  threatbook_api_url: '',
  threatbook_api_key: '',
  clear_threatbook_api_key: false,
  threatbook_batch_size: 100,
  threatbook_safe_ips_per_minute: 800,
  threatbook_daily_budget: 10000,
  threatbook_max_retries: 3,
  ...DEFAULT_DISPLAY_SETTINGS,
})
const extra = ref<SystemSettings | null>(null)
const message = ref('')
const error = ref('')
const busy = ref('')
const probeResult = reactive<Record<'whitelist' | 'threatbook', ProbeResult | null>>({
  whitelist: null,
  threatbook: null,
})

function applyLoaded(value: SystemSettings) {
  form.whitelist_api_url = value.whitelist_api_url
  form.threatbook_api_url = value.threatbook_api_url
  form.threatbook_batch_size = value.threatbook_batch_size
  form.threatbook_safe_ips_per_minute = value.threatbook_safe_ips_per_minute
  form.threatbook_daily_budget = value.threatbook_daily_budget
  form.threatbook_max_retries = value.threatbook_max_retries
  form.ui_language = value.ui_language
  form.theme_id = value.theme_id
  form.homepage_mode = value.homepage_mode
  form.motion_intensity = value.motion_intensity
  form.threatbook_api_key = ''
  form.clear_threatbook_api_key = false
  extra.value = value
}

function translatedProbe(result: ProbeResult) {
  const key = `messages.${result.code}`
  const translated = t(key, result.params)
  return translated === key ? result.fallback : translated
}

onMounted(async () => {
  try {
    applyLoaded(await api.get<SystemSettings>('/api/settings'))
  } catch (reason) {
    error.value = translateApiError(reason, t)
  }
})

async function save(showMessage = true) {
  busy.value = 'save'
  error.value = ''
  if (showMessage) message.value = ''
  try {
    const value = await api.put<SystemSettings>('/api/settings', { ...form })
    applyLoaded(value)
    applyUiSettings(value)
    if (showMessage) message.value = t('settings.saved')
  } catch (reason) {
    error.value = translateApiError(reason, t)
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
    error.value = translateApiError(reason, t)
  } finally {
    busy.value = ''
  }
}
</script>

<template>
  <section class="page-head">
    <div><span class="kicker">SYSTEM CONTROL</span><h2>{{ t('common.systemSettings') }}</h2><p>{{ t('settings.description') }}</p></div>
    <div class="capacity"><b :class="extra?.threatbook_api_key_configured ? 'ok-text' : 'danger-text'">{{ t(extra?.threatbook_api_key_configured ? 'settings.authReady' : 'settings.awaitingConfiguration') }}</b><span>ThreatBook API</span></div>
  </section>

  <section class="settings-stack">
    <article class="panel appearance-panel">
      <div class="section-title"><div><span class="kicker">APPEARANCE &amp; LANGUAGE</span><h3>{{ t('settings.appearanceAndLanguage') }}</h3></div><span class="muted">{{ t('settings.appearanceHint') }}</span></div>
      <div class="form-grid appearance-grid">
        <label>{{ t('settings.language') }}<select v-model="form.ui_language" name="ui_language"><option value="en-US">English</option><option value="zh-CN">简体中文</option></select></label>
        <label>{{ t('settings.theme') }}<select v-model="form.theme_id" name="theme_id"><option v-for="theme in themes" :key="theme.id" :value="theme.id">{{ t(`themes.${theme.id}.name`) }}</option></select></label>
        <label>{{ t('settings.homepage') }}<select v-model="form.homepage_mode" name="homepage_mode"><option value="overview">{{ t('settings.homeModes.overview') }}</option><option value="landscape">{{ t('settings.homeModes.landscape') }}</option><option value="operations">{{ t('settings.homeModes.operations') }}</option></select></label>
        <label>{{ t('settings.motion') }}<select v-model="form.motion_intensity" name="motion_intensity"><option value="off">{{ t('settings.motionModes.off') }}</option><option value="subtle">{{ t('settings.motionModes.subtle') }}</option><option value="medium">{{ t('settings.motionModes.medium') }}</option><option value="strong">{{ t('settings.motionModes.strong') }}</option></select></label>
      </div>
      <div class="theme-swatches" aria-hidden="true"><span v-for="theme in themes" :key="theme.id" :class="{ active: theme.id === form.theme_id }"><i v-for="color in theme.swatches" :key="color" :style="{ background: color }"></i></span></div>
    </article>

    <div class="integration-grid">
      <article class="panel integration-card">
        <div class="integration-heading"><div class="integration-icon">W</div><div><span class="kicker">WHITELIST API</span><h3>{{ t('settings.whitelistApi') }}</h3></div></div>
        <label class="field-label">{{ t('settings.endpoint') }}<input v-model.trim="form.whitelist_api_url" name="whitelist_api_url" type="url" placeholder="http://server-ip:8085/api/v1/whitelist/query" /></label>
        <button class="button ghost" data-action="test-whitelist" :disabled="!!busy" @click="probe('whitelist')">{{ t(busy === 'whitelist' ? 'settings.testing' : 'settings.testWhitelist') }}</button>
        <p v-if="probeResult.whitelist" class="probe-result"><i></i>{{ translatedProbe(probeResult.whitelist) }} · {{ probeResult.whitelist.latency_ms }} ms</p>
      </article>

      <article class="panel integration-card">
        <div class="integration-heading"><div class="integration-icon blue">T</div><div><span class="kicker">THREATBOOK API</span><h3>{{ t('settings.threatbookApi') }}</h3></div></div>
        <label class="field-label">{{ t('settings.endpoint') }}<input v-model.trim="form.threatbook_api_url" name="threatbook_api_url" type="url" placeholder="https://api.threatbook.cn/v3/scene/ip_reputation" /></label>
        <label class="field-label">API Key<input v-model="form.threatbook_api_key" type="password" autocomplete="new-password" :placeholder="t(extra?.threatbook_api_key_configured ? 'settings.keyConfigured' : 'settings.enterKey')" /></label>
        <label v-if="extra?.threatbook_api_key_configured" class="check-label"><input v-model="form.clear_threatbook_api_key" type="checkbox" /> {{ t('settings.clearKey') }}</label>
        <button class="button ghost" data-action="test-threatbook" :disabled="!!busy" @click="probe('threatbook')">{{ t(busy === 'threatbook' ? 'settings.authenticating' : 'settings.testThreatbook') }}</button>
        <p v-if="probeResult.threatbook" class="probe-result"><i></i>{{ translatedProbe(probeResult.threatbook) }} · {{ probeResult.threatbook.latency_ms }} ms</p>
      </article>
    </div>

    <article class="panel limit-panel">
      <div class="section-title"><div><span class="kicker">QUERY GUARDRAILS</span><h3>{{ t('settings.queryLimits') }}</h3></div><span class="muted">{{ t('settings.limitHint') }}</span></div>
      <div class="form-grid"><label>{{ t('settings.batchSize') }}<input v-model.number="form.threatbook_batch_size" type="number" min="1" max="100" /></label><label>{{ t('settings.safeRate') }}<input v-model.number="form.threatbook_safe_ips_per_minute" type="number" min="1" max="1000" /></label><label>{{ t('settings.dailyBudget') }}<input v-model.number="form.threatbook_daily_budget" type="number" min="1" /></label><label>{{ t('settings.maxRetries') }}<input v-model.number="form.threatbook_max_retries" type="number" min="0" max="3" /></label></div>
      <div class="settings-actions"><button class="primary" data-action="save-settings" :disabled="!!busy" @click="save()">{{ t(busy === 'save' ? 'settings.saving' : 'settings.saveAll') }}</button><span>{{ t('settings.probeUsesSaved') }} · {{ t('settings.uploadLimit', { value: Math.round((extra?.upload_max_bytes || 0) / 1024 / 1024) }) }}</span></div>
    </article>
  </section>
  <p v-if="message" class="success-banner settings-message">{{ message }}</p>
  <p v-if="error" class="error-banner settings-message">{{ error }}</p>
</template>
