<script setup lang="ts">
import { useI18n } from 'vue-i18n'

import type { OverviewDashboard } from '../../types'
import DashboardSparkline from './DashboardSparkline.vue'

defineProps<{ dashboard: OverviewDashboard }>()
const { t, n } = useI18n()

function location(item: OverviewDashboard['sections']['recent_risks']['items'][number]) {
  return [item.country, item.province, item.city].filter(Boolean).join(' / ') || t('common.none')
}
</script>

<template>
  <div class="dashboard-layout" data-dashboard="overview">
    <section class="dashboard-metrics overview-metrics">
      <article><span>{{ t('dashboard.metrics.totalTasks') }}</span><b>{{ n(dashboard.summary.total_tasks) }}</b><i>01</i></article>
      <article><span>{{ t('dashboard.metrics.uniqueIps') }}</span><b>{{ n(dashboard.summary.total_unique_ips) }}</b><i>02</i></article>
      <article class="risk-metric"><span>{{ t('dashboard.metrics.maliciousIps') }}</span><b>{{ n(dashboard.summary.malicious_ips) }}</b><i>03</i></article>
      <article><span>{{ t('dashboard.metrics.activeTasks') }}</span><b>{{ n(dashboard.summary.active_tasks) }}</b><i>04</i></article>
      <article><span>{{ t('dashboard.metrics.failedTasks') }}</span><b>{{ n(dashboard.summary.failed_tasks) }}</b><i>05</i></article>
    </section>

    <section class="dashboard-grid overview-grid">
      <article class="panel dashboard-card trend-card">
        <header><div><span class="kicker">7 DAY SIGNAL</span><h3>{{ t('dashboard.sevenDayTrend') }}</h3></div><span class="signal-live">{{ t('dashboard.live') }}</span></header>
        <DashboardSparkline
          :values="dashboard.sections.trend.items.map((item) => item.malicious)"
          :labels="dashboard.sections.trend.items.map((item) => item.date)"
        />
        <div class="trend-legend">
          <span><i class="red"></i>{{ t('dashboard.metrics.maliciousIps') }}</span>
          <b>{{ n(dashboard.sections.trend.items.reduce((sum, item) => sum + item.malicious, 0)) }}</b>
        </div>
      </article>

      <article class="panel dashboard-card risk-feed">
        <header><div><span class="kicker">LATEST INTELLIGENCE</span><h3>{{ t('dashboard.recentRisks') }}</h3></div><RouterLink to="/threatbook-history">{{ t('dashboard.viewAll') }} →</RouterLink></header>
        <div v-if="dashboard.sections.recent_risks.items.length" class="dashboard-list">
          <RouterLink v-for="item in dashboard.sections.recent_risks.items" :key="`${item.task_id}-${item.ip}`" :to="`/tasks/${item.task_id}/threatbook`" class="risk-row">
            <span class="threat-pulse"></span>
            <div><code>{{ item.ip }}</code><small>{{ location(item) }}</small></div>
            <div class="risk-labels"><span v-for="label in item.labels.slice(0, 2)" :key="label">{{ label }}</span></div>
            <b :class="`severity ${item.severity || ''}`">{{ item.severity || t('common.none') }}</b>
          </RouterLink>
        </div>
        <p v-else class="dashboard-empty">{{ t('dashboard.emptyRisks') }}</p>
      </article>

      <article class="panel dashboard-card attention-card">
        <header><div><span class="kicker">ACTION REQUIRED</span><h3>{{ t('dashboard.attention') }}</h3></div><span class="attention-count">{{ dashboard.sections.attention.items.length }}</span></header>
        <div v-if="dashboard.sections.attention.items.length" class="dashboard-list">
          <RouterLink v-for="item in dashboard.sections.attention.items" :key="item.task_id" :to="`/tasks/${item.task_id}`" class="attention-row">
            <span class="attention-icon">!</span>
            <div><code>{{ item.task_id.slice(0, 10) }}</code><small>{{ t(`steps.${item.current_step}`) }}</small></div>
            <p>{{ item.error_summary || t(`statuses.${item.status}`) }}</p>
            <span>→</span>
          </RouterLink>
        </div>
        <p v-else class="dashboard-empty ok-empty">✓ {{ t('dashboard.emptyAttention') }}</p>
      </article>
    </section>
  </div>
</template>
