<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { api } from '../api'

const route = useRoute()
const data = ref<Record<string, any> | null>(null)
onMounted(async () => { data.value = await api.get(`/api/tasks/${route.params.id}/ips/${route.params.ipId}`) })
</script>

<template>
  <div v-if="!data" class="panel empty">正在加载证据链…</div>
  <template v-else>
    <section class="page-head compact"><div><span class="kicker">IP INVESTIGATION</span><h2>{{ data.ip }}</h2><p>IPv{{ data.ip_version }} · {{ data.is_public ? '公网地址' : '非公网地址' }} · {{ data.stage }}</p></div><RouterLink class="button ghost" :to="`/tasks/${route.params.id}`">← 返回任务</RouterLink></section>
    <section class="evidence-grid">
      <article class="panel"><span class="kicker">SOURCE</span><h3>来源证据</h3><dl><dt>出现次数</dt><dd>{{ data.occurrence_count }}</dd><dt>首次位置</dt><dd>{{ data.first_position }}</dd><dt>最后位置</dt><dd>{{ data.last_position }}</dd><dt>样本位置</dt><dd>{{ data.sample_positions.join('、') }}</dd></dl></article>
      <article class="panel"><span class="kicker">WHITELIST</span><h3>白名单快照</h3><div v-if="data.whitelist"><strong>{{ data.whitelist.result_code }}</strong><p>{{ data.whitelist.verdict }}</p><code>{{ data.whitelist.request_id }}</code></div><p v-else class="muted">尚无查白结果</p></article>
      <article class="panel wide"><span class="kicker">THREATBOOK</span><h3>微步研判</h3><div v-if="data.threatbook" class="threat-grid"><div><span>是否恶意</span><b>{{ data.threatbook.is_malicious ? '恶意' : '非恶意' }}</b></div><div><span>可信度</span><b>{{ data.threatbook.confidence_level || '-' }}</b></div><div><span>严重度</span><b>{{ data.threatbook.severity || '-' }}</b></div><div><span>威胁类型</span><b>{{ data.threatbook.judgments.join('、') || '-' }}</b></div></div><p v-else class="muted">该 IP 未查询微步或尚未完成</p></article>
    </section>
  </template>
</template>

