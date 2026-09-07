<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'

import { api } from '../api'
import type { TaskSummary } from '../types'

const tasks = ref<TaskSummary[]>([])
const total = ref(0)
const loading = ref(true)

onMounted(async () => {
  try {
    const payload = await api.get<{ items: TaskSummary[]; total: number }>('/api/tasks?page=1&page_size=100')
    tasks.value = payload.items
    total.value = payload.total
  } finally {
    loading.value = false
  }
})

const statusText: Record<string, string> = {
  queued: '排队中', running: '处理中', waiting_whitelist_confirmation: '等待移除白名单',
  waiting_threatbook_confirmation: '等待查询微步', paused_quota: '额度暂停', partial_success: '部分完成',
  failed: '失败', completed: '已完成',
}
</script>

<template>
  <section class="page-head"><div><span class="kicker">ARCHIVE</span><h2>查询历史</h2><p>所有任务、原文件、节点和结果永久保存。</p></div><div class="capacity"><b>{{ total }}</b><span>累计任务</span></div></section>
  <section class="panel table-panel">
    <div v-if="loading" class="empty">正在读取历史…</div>
    <div v-else-if="!tasks.length" class="empty">还没有查询任务</div>
    <table v-else>
      <thead><tr><th>任务</th><th>来源</th><th>进度</th><th>唯一 IP</th><th>白名单移除</th><th>恶意</th><th>创建时间</th><th></th></tr></thead>
      <tbody><tr v-for="task in tasks" :key="task.id">
        <td><code>{{ task.id.slice(0, 8) }}</code></td>
        <td>{{ task.original_filename || (task.input_type === 'manual' ? '手动输入' : task.input_type) }}</td>
        <td><span class="status" :class="task.status">{{ statusText[task.status] || task.status }}</span></td>
        <td>{{ task.unique_count }}</td><td>{{ task.whitelist_removed_count }}</td><td class="danger-text">{{ task.malicious_count }}</td>
        <td>{{ new Date(task.created_at).toLocaleString('zh-CN') }}</td>
        <td><RouterLink class="text-link" :to="`/tasks/${task.id}`">查看 / 继续 →</RouterLink></td>
      </tr></tbody>
    </table>
  </section>
</template>

