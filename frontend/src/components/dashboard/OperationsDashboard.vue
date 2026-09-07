<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

import type { OperationsDashboard } from '../../types'

const props = defineProps<{ dashboard: OperationsDashboard }>()
const { t, n } = useI18n()

const dailyBudget = computed(() => props.dashboard.summary.daily_usage + props.dashboard.summary.daily_remaining)
const usagePercent = computed(() => dailyBudget.value
  ? Math.min(100, Math.round(props.dashboard.summary.daily_usage * 100 / dailyBudget.value))
  : 0)
</script>

<template>
  <div class="dashboard-layout operations-layout" data-dashboard="operations">
    <section class="ops-health-strip">
      <article class="panel"><span class="health-orb ok"></span><div><small>{{ t('dashboard.worker') }}</small><b>{{ t(`dashboard.health.${dashboard.summary.worker_status}`) }}</b></div></article>
      <article class="panel"><span class="health-orb ok"></span><div><small>{{ t('dashboard.database') }}</small><b>{{ t(`dashboard.health.${dashboard.summary.database_status}`) }}</b></div></article>
      <article class="panel"><span class="health-orb"></span><div><small>{{ t('dashboard.backlog') }}</small><b>{{ n(dashboard.summary.backlog) }}</b></div></article>
      <article class="panel"><span class="health-orb danger"></span><div><small>{{ t('dashboard.failedNodes') }}</small><b>{{ n(dashboard.sections.failed_nodes.items.length) }}</b></div></article>
    </section>

    <section class="operations-grid">
      <article class="panel dashboard-card ops-progress-card">
        <header><div><span class="kicker">PIPELINE VELOCITY</span><h3>{{ t('dashboard.queueProgress') }}</h3></div><b>{{ dashboard.summary.progress.percent }}%</b></header>
        <div class="ops-main-progress"><i :style="{ width: `${dashboard.summary.progress.percent}%` }"></i></div>
        <p>{{ n(dashboard.summary.progress.current) }} / {{ n(dashboard.summary.progress.total) }} {{ t('dashboard.processed') }}</p>
        <div class="status-distribution">
          <span v-for="(count, status) in dashboard.summary.status_counts" :key="status"><i :class="String(status)"></i>{{ t(`statuses.${status}`) }}<b>{{ n(count) }}</b></span>
        </div>
      </article>

      <article class="panel dashboard-card quota-card">
        <header><div><span class="kicker">DAILY GUARDRAIL</span><h3>{{ t('dashboard.dailyQuota') }}</h3></div></header>
        <div class="quota-ring" :style="{ '--usage': `${usagePercent * 3.6}deg` }"><div><b>{{ usagePercent }}%</b><span>{{ t('dashboard.used') }}</span></div></div>
        <dl><div><dt>{{ t('dashboard.used') }}</dt><dd>{{ n(dashboard.summary.daily_usage) }}</dd></div><div><dt>{{ t('threatbook.remaining') }}</dt><dd>{{ n(dashboard.summary.daily_remaining) }}</dd></div></dl>
      </article>

      <article class="panel dashboard-card active-tasks-card">
        <header><div><span class="kicker">ACTIVE WORKLOAD</span><h3>{{ t('dashboard.activeTaskQueue') }}</h3></div><RouterLink to="/history">{{ t('dashboard.viewAll') }} →</RouterLink></header>
        <div v-if="dashboard.sections.active_tasks.items.length" class="ops-task-list">
          <RouterLink v-for="item in dashboard.sections.active_tasks.items" :key="item.task_id" :to="`/tasks/${item.task_id}`">
            <div><code>{{ item.task_id.slice(0, 12) }}</code><span class="status running">{{ t(`statuses.${item.status}`) }}</span></div>
            <small>{{ t(`steps.${item.current_step}`) }} · {{ n(item.unique_count) }} IP</small>
            <div class="mini-progress"><i :style="{ width: `${item.total ? item.current * 100 / item.total : 0}%` }"></i></div>
            <b>{{ n(item.current) }} / {{ n(item.total) }}</b>
          </RouterLink>
        </div>
        <p v-else class="dashboard-empty">{{ t('dashboard.emptyActiveTasks') }}</p>
      </article>

      <article class="panel dashboard-card failed-nodes-card">
        <header><div><span class="kicker">NODE DIAGNOSTICS</span><h3>{{ t('dashboard.failedNodes') }}</h3></div></header>
        <div v-if="dashboard.sections.failed_nodes.items.length" class="failed-node-list">
          <RouterLink v-for="item in dashboard.sections.failed_nodes.items" :key="`${item.task_id}-${item.step}`" :to="`/tasks/${item.task_id}`"><span>!</span><div><code>{{ item.task_id.slice(0, 12) }}</code><b>{{ t(`steps.${item.step}`) }}</b><small>{{ item.error_summary || t('statuses.failed') }}</small></div><i>→</i></RouterLink>
        </div>
        <p v-else class="dashboard-empty ok-empty">✓ {{ t('dashboard.emptyFailedNodes') }}</p>
      </article>

      <article class="panel dashboard-card integration-health-card">
        <header><div><span class="kicker">INTEGRATIONS</span><h3>{{ t('dashboard.integrationHealth') }}</h3></div><RouterLink to="/settings">{{ t('common.systemSettings') }} →</RouterLink></header>
        <div class="integration-health-list"><div v-for="item in dashboard.sections.integration_health.items" :key="item.name"><span :class="`health-orb ${item.status}`"></span><div><b>{{ item.name }}</b><small>{{ t(`dashboard.integrationStatus.${item.status}`) }}<template v-if="item.latency_ms !== null"> · {{ item.latency_ms }} ms</template></small></div></div></div>
        <div class="ops-config"><span v-for="item in dashboard.sections.configuration.items" :key="item.name"><small>{{ t(`dashboard.configuration.${item.name}`) }}</small><b>{{ n(item.value) }}</b></span></div>
      </article>
    </section>
  </div>
</template>
