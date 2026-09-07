<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'

import { api, translateApiError } from '../api'
import OverviewDashboard from '../components/dashboard/OverviewDashboard.vue'
import OperationsDashboard from '../components/dashboard/OperationsDashboard.vue'
import ThreatLandscapeDashboard from '../components/dashboard/ThreatLandscapeDashboard.vue'
import type {
  DashboardPayload,
  LandscapeDashboard as LandscapeDashboardPayload,
  OperationsDashboard as OperationsDashboardPayload,
  OverviewDashboard as OverviewDashboardPayload,
} from '../types'
import { uiSettings } from '../ui-settings'

const { t, d } = useI18n()
const dashboard = ref<DashboardPayload | null>(null)
const loading = ref(true)
const refreshing = ref(false)
const error = ref('')
let timer: ReturnType<typeof setInterval> | undefined
let requestVersion = 0
let activeMode: string | null = null

const mode = computed(() => uiSettings.homepage_mode)
const modeTitle = computed(() => t(`settings.homeModes.${mode.value}`))

async function load(silent = false) {
  const requestedMode = mode.value
  if (silent && activeMode === requestedMode) return
  const version = ++requestVersion
  activeMode = requestedMode
  if (silent) refreshing.value = true
  else loading.value = true
  error.value = ''
  try {
    const result = await api.get<DashboardPayload>(`/api/dashboard?mode=${requestedMode}`)
    if (version === requestVersion && mode.value === requestedMode) dashboard.value = result
  } catch (reason) {
    if (version === requestVersion && (!silent || !dashboard.value)) {
      error.value = translateApiError(reason, t)
    }
  } finally {
    if (version === requestVersion) {
      activeMode = null
      loading.value = false
      refreshing.value = false
    }
  }
}

watch(mode, () => {
  dashboard.value = null
  load()
}, { immediate: true })

function handleVisibilityChange() {
  if (!document.hidden) load(true)
}

onMounted(() => {
  document.addEventListener('visibilitychange', handleVisibilityChange)
  timer = setInterval(() => {
    if (!document.hidden) load(true)
  }, 15_000)
})

onUnmounted(() => {
  requestVersion += 1
  if (timer) clearInterval(timer)
  document.removeEventListener('visibilitychange', handleVisibilityChange)
})
</script>

<template>
  <div class="dashboard-stage">
    <section class="page-head dashboard-head">
      <div><span class="kicker">LIVE SECURITY INTELLIGENCE</span><h2>{{ modeTitle }}</h2><p>{{ t(`dashboard.descriptions.${mode}`) }}</p></div>
      <div class="dashboard-updated">
        <span :class="{ refreshing }"><i></i>{{ refreshing ? t('dashboard.refreshing') : t('dashboard.live') }}</span>
        <small v-if="dashboard">{{ t('dashboard.updatedAt') }} {{ d(new Date(dashboard.generated_at), 'short') }}</small>
      </div>
    </section>

    <section v-if="loading && !dashboard" class="dashboard-skeleton" aria-busy="true">
      <span v-for="item in 8" :key="item"></span>
    </section>
    <section v-else-if="error && !dashboard" class="panel dashboard-error">
      <span>!</span><h3>{{ t('dashboard.unavailable') }}</h3><p>{{ error }}</p>
      <button class="primary" data-action="retry-dashboard" @click="load()">{{ t('common.retry') }}</button>
    </section>
    <template v-else-if="dashboard">
      <OverviewDashboard v-if="dashboard.mode === 'overview'" :dashboard="dashboard as OverviewDashboardPayload" />
      <ThreatLandscapeDashboard v-else-if="dashboard.mode === 'landscape'" :dashboard="dashboard as LandscapeDashboardPayload" />
      <OperationsDashboard v-else :dashboard="dashboard as OperationsDashboardPayload" />
      <p v-if="error" class="error-banner dashboard-refresh-error">{{ error }}</p>
    </template>
  </div>
</template>
