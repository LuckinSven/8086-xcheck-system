<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { api, translateApiError } from '../api'
import type { TaskSummary } from '../types'

const router = useRouter()
const { t } = useI18n()
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
      if (!file.value) throw new Error(t('newTask.selectFileError'))
      task = await api.upload<TaskSummary>(`/api/tasks/upload?input_type=${mode.value}`, file.value)
    }
    await router.push(`/tasks/${task.id}`)
  } catch (reason) {
    error.value = translateApiError(reason, t)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section class="page-head">
    <div><span class="kicker">NEW INVESTIGATION</span><h2>{{ t('newTask.title') }}</h2><p>{{ t('newTask.description') }}</p></div>
    <div class="capacity"><b>200,000</b><span>{{ t('newTask.capacity') }}</span></div>
  </section>
  <section class="panel intake-panel">
    <div class="mode-tabs" role="tablist">
      <button :class="{ active: mode === 'manual' }" @click="mode = 'manual'">{{ t('newTask.manual') }}</button>
      <button :class="{ active: mode === 'attack' }" @click="mode = 'attack'">{{ t('newTask.attackLog') }}</button>
      <button :class="{ active: mode === 'access' }" @click="mode = 'access'">{{ t('newTask.accessLog') }}</button>
    </div>
    <div v-if="mode === 'manual'" class="input-block">
      <label for="ips">{{ t('newTask.addresses') }}</label>
      <textarea id="ips" v-model="text" :placeholder="t('newTask.placeholder')"></textarea>
      <small>{{ t('newTask.validationHint') }}</small>
    </div>
    <div v-else class="upload-zone">
      <input type="file" @change="selectFile" />
      <b>{{ file?.name || t('newTask.chooseFile') }}</b>
      <span v-if="mode === 'attack'">{{ t('newTask.attackFieldHint') }}</span>
      <span v-else>{{ t('newTask.accessFieldHint') }}</span>
      <small>{{ t('newTask.fileHint') }}</small>
    </div>
    <p v-if="error" class="error-banner">{{ error }}</p>
    <div class="form-footer">
      <div class="flow-hint"><span>{{ t('newTask.extract') }}</span><i>→</i><span>{{ t('newTask.deduplicate') }}</span><i>→</i><span>{{ t('newTask.whitelist') }}</span><i>→</i><span>ThreatBook</span></div>
      <button class="primary" :disabled="busy || (mode === 'manual' ? !text.trim() : !file)" @click="submit">
        {{ t(busy ? 'newTask.creating' : 'newTask.create') }}
      </button>
    </div>
  </section>
</template>
