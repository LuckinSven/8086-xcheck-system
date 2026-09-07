<script setup lang="ts">
import { RouterLink, RouterView } from 'vue-router'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">XC</div>
        <div><strong>XCheck</strong><small>{{ t('shell.productSubtitle') }}</small></div>
      </div>
      <nav :aria-label="t('shell.primaryNavigation')">
        <RouterLink to="/"><span>⌂</span>{{ t('common.dashboard') }}</RouterLink>
        <RouterLink to="/new"><span>＋</span>{{ t('common.newQuery') }}</RouterLink>
        <RouterLink to="/history"><span>◫</span>{{ t('common.queryHistory') }}</RouterLink>
        <RouterLink to="/threatbook-history"><span>◎</span>{{ t('common.threatbookHistory') }}</RouterLink>
        <RouterLink to="/settings"><span>⚙</span>{{ t('common.systemSettings') }}</RouterLink>
      </nav>
      <div class="sidebar-note">
        <b>{{ t('shell.lanMode') }}</b>
        <span>{{ t('shell.pipeline') }}</span>
      </div>
    </aside>
    <main class="content">
      <header class="topbar">
        <div><span class="eyebrow">SECURITY OPERATIONS</span><h1>{{ t('shell.workbench') }}</h1></div>
        <div class="topbar-actions">
          <div class="health"><i></i>{{ t('shell.serviceConnected') }}</div>
        </div>
      </header>
      <RouterView />
    </main>
  </div>
</template>
