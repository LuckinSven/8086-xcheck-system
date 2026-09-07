<script setup lang="ts">
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
</script>

<template>
  <section class="page-head">
    <div><span class="kicker">SECURITY OVERVIEW</span><h2>{{ t('dashboard.title') }}</h2><p>{{ t('dashboard.loadingDescription') }}</p></div>
  </section>
  <section class="panel empty">{{ t('common.loading') }}</section>
</template>
