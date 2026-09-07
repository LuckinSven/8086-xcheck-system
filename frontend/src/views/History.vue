<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { api } from '../api'
import type { TaskSummary } from '../types'

const tasks = ref<TaskSummary[]>([])
const total = ref(0)
const loading = ref(true)
const { t, locale } = useI18n()

onMounted(async () => {
  try {
    const payload = await api.get<{ items: TaskSummary[]; total: number }>('/api/tasks?page=1&page_size=100')
    tasks.value = payload.items
    total.value = payload.total
  } finally {
    loading.value = false
  }
})

function statusText(status: string) {
  const key = `statuses.${status}`
  const translated = t(key)
  return translated === key ? status : translated
}

function dateText(value: string) {
  return new Date(value).toLocaleString(locale.value, { hour12: false })
}
</script>

<template>
  <section class="page-head"><div><span class="kicker">ARCHIVE</span><h2>{{ t('common.queryHistory') }}</h2><p>{{ t('history.description') }}</p></div><div class="capacity"><b>{{ total }}</b><span>{{ t('history.totalTasks') }}</span></div></section>
  <section class="panel table-panel">
    <div v-if="loading" class="empty">{{ t('history.loading') }}</div>
    <div v-else-if="!tasks.length" class="empty">{{ t('history.empty') }}</div>
    <table v-else>
      <thead><tr><th>{{ t('history.task') }}</th><th>{{ t('history.source') }}</th><th>{{ t('history.progress') }}</th><th>{{ t('history.uniqueIps') }}</th><th>{{ t('history.whitelistRemoved') }}</th><th>{{ t('common.malicious') }}</th><th>{{ t('history.createdAt') }}</th><th></th></tr></thead>
      <tbody><tr v-for="task in tasks" :key="task.id">
        <td><code>{{ task.id.slice(0, 8) }}</code></td>
        <td>{{ task.original_filename || (task.input_type === 'manual' ? t('common.manualInput') : task.input_type) }}</td>
        <td><span class="status" :class="task.status">{{ statusText(task.status) }}</span></td>
        <td>{{ task.unique_count }}</td><td>{{ task.whitelist_removed_count }}</td><td class="danger-text">{{ task.malicious_count }}</td>
        <td>{{ dateText(task.created_at) }}</td>
        <td><RouterLink class="text-link" :to="`/tasks/${task.id}`">{{ t('history.viewContinue') }} →</RouterLink></td>
      </tr></tbody>
    </table>
  </section>
</template>
