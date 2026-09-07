<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'

import { api } from '../api'
import type { TaskSummary } from '../types'

const router = useRouter()
const mode = ref<'manual' | 'attack' | 'access'>('manual')
const text = ref('')
const file = ref<File | null>(null)
const busy = ref(false)
const error = ref('')

function selectFile(event: Event) {
  file.value = (event.target as HTMLInputElement).files?.[0] || null
}

async function submit() {
  busy.value = true
  error.value = ''
  try {
    let task: TaskSummary
    if (mode.value === 'manual') {
      task = await api.post<TaskSummary>('/api/tasks/manual', { text: text.value })
    } else {
      if (!file.value) throw new Error('请选择需要处理的文件')
      task = await api.upload<TaskSummary>(`/api/tasks/upload?input_type=${mode.value}`, file.value)
    }
    await router.push(`/tasks/${task.id}`)
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '创建任务失败'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section class="page-head">
    <div><span class="kicker">NEW INVESTIGATION</span><h2>创建 IP 排查任务</h2><p>输入 IP 或上传日志，系统将依次去重、查白并查询微步。</p></div>
    <div class="capacity"><b>20 万行</b><span>CSV 容量基线</span></div>
  </section>
  <section class="panel intake-panel">
    <div class="mode-tabs" role="tablist">
      <button :class="{ active: mode === 'manual' }" @click="mode = 'manual'">手动输入</button>
      <button :class="{ active: mode === 'attack' }" @click="mode = 'attack'">攻击日志</button>
      <button :class="{ active: mode === 'access' }" @click="mode = 'access'">访问日志</button>
    </div>
    <div v-if="mode === 'manual'" class="input-block">
      <label for="ips">待查询 IP</label>
      <textarea id="ips" v-model="text" placeholder="支持换行、空格、逗号或分号分隔&#10;例如：8.8.8.8&#10;2001:4860:4860::8888"></textarea>
      <small>自动校验 IPv4 / IPv6，并统计重复出现次数。</small>
    </div>
    <div v-else class="upload-zone">
      <input type="file" @change="selectFile" />
      <b>{{ file?.name || '点击选择或拖入文件' }}</b>
      <span v-if="mode === 'attack'">攻击日志读取 srcAddress 字段</span>
      <span v-else>访问日志读取“访问源 IP”字段</span>
      <small>CSV / XLS / XLSX / ZIP / LOG / JSONL · 最大 500 MB · 原文件永久存档</small>
    </div>
    <p v-if="error" class="error-banner">{{ error }}</p>
    <div class="form-footer">
      <div class="flow-hint"><span>提取</span><i>→</i><span>去重</span><i>→</i><span>查白</span><i>→</i><span>微步</span></div>
      <button class="primary" :disabled="busy || (mode === 'manual' ? !text.trim() : !file)" @click="submit">
        {{ busy ? '正在创建…' : '创建并开始处理' }}
      </button>
    </div>
  </section>
</template>
