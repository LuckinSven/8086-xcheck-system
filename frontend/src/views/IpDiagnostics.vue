<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'

import { api } from '../api'

const route = useRoute()
const { t } = useI18n()
const data = ref<Record<string, any> | null>(null)
onMounted(async () => { data.value = await api.get(`/api/tasks/${route.params.id}/ips/${route.params.ipId}`) })
</script>

<template>
  <div v-if="!data" class="panel empty">{{ t('diagnostics.loading') }}</div>
  <template v-else>
    <section class="page-head compact"><div><span class="kicker">IP INVESTIGATION</span><h2>{{ data.ip }}</h2><p>IPv{{ data.ip_version }} · {{ t(data.is_public ? 'diagnostics.public' : 'diagnostics.private') }} · {{ data.stage }}</p></div><RouterLink class="button ghost" :to="`/tasks/${route.params.id}`">← {{ t('diagnostics.backToTask') }}</RouterLink></section>
    <section class="evidence-grid">
      <article class="panel"><span class="kicker">SOURCE</span><h3>{{ t('diagnostics.sourceEvidence') }}</h3><dl><dt>{{ t('diagnostics.occurrences') }}</dt><dd>{{ data.occurrence_count }}</dd><dt>{{ t('diagnostics.firstPosition') }}</dt><dd>{{ data.first_position }}</dd><dt>{{ t('diagnostics.lastPosition') }}</dt><dd>{{ data.last_position }}</dd><dt>{{ t('diagnostics.samplePositions') }}</dt><dd>{{ data.sample_positions.join(', ') }}</dd></dl></article>
      <article class="panel"><span class="kicker">WHITELIST</span><h3>{{ t('diagnostics.whitelistSnapshot') }}</h3><div v-if="data.whitelist"><strong>{{ data.whitelist.result_code }}</strong><p>{{ data.whitelist.verdict }}</p><code>{{ data.whitelist.request_id }}</code></div><p v-else class="muted">{{ t('diagnostics.noWhitelist') }}</p></article>
      <article class="panel wide"><span class="kicker">THREATBOOK</span><h3>{{ t('diagnostics.threatbookVerdict') }}</h3><div v-if="data.threatbook" class="threat-grid"><div><span>{{ t('diagnostics.maliciousStatus') }}</span><b>{{ t(data.threatbook.is_malicious ? 'common.malicious' : 'common.notMalicious') }}</b></div><div><span>{{ t('diagnostics.confidence') }}</span><b>{{ data.threatbook.confidence_level || '-' }}</b></div><div><span>{{ t('diagnostics.severity') }}</span><b>{{ data.threatbook.severity || '-' }}</b></div><div><span>{{ t('diagnostics.threatTypes') }}</span><b>{{ data.threatbook.judgments.join(', ') || '-' }}</b></div></div><p v-else class="muted">{{ t('diagnostics.noThreatbook') }}</p></article>
    </section>
  </template>
</template>
