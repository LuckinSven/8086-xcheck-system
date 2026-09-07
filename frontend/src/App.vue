<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import { RouterLink, RouterView } from 'vue-router'

import { applyTheme, persistTheme, readStoredTheme, themes, type ThemeId } from './theme'

const selectedTheme = ref<ThemeId>(readStoredTheme())
const themeOpen = ref(false)
const themePicker = ref<HTMLElement | null>(null)
const themeTrigger = ref<HTMLButtonElement | null>(null)
const activeTheme = computed(() => themes.find((theme) => theme.id === selectedTheme.value) ?? themes[0])

applyTheme(selectedTheme.value)

async function closeThemePicker(restoreFocus = false) {
  themeOpen.value = false
  if (restoreFocus) {
    await nextTick()
    themeTrigger.value?.focus()
  }
}

function onDocumentClick(event: MouseEvent) {
  if (themeOpen.value && !themePicker.value?.contains(event.target as Node)) {
    void closeThemePicker()
  }
}

function selectTheme(themeId: ThemeId) {
  selectedTheme.value = themeId
  applyTheme(themeId)
  persistTheme(themeId)
  void closeThemePicker(true)
}

onMounted(() => document.addEventListener('click', onDocumentClick))
onBeforeUnmount(() => document.removeEventListener('click', onDocumentClick))
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark">XC</div>
        <div><strong>XCheck</strong><small>IP 信誉查询系统</small></div>
      </div>
      <nav aria-label="主要导航">
        <RouterLink to="/"><span>＋</span>新建查询</RouterLink>
        <RouterLink to="/history"><span>◫</span>查询历史</RouterLink>
        <RouterLink to="/threatbook-history"><span>◎</span>微步历史</RouterLink>
        <RouterLink to="/settings"><span>⚙</span>系统设置</RouterLink>
      </nav>
      <div class="sidebar-note">
        <b>局域网模式</b>
        <span>白名单过滤 → 微步查询</span>
      </div>
    </aside>
    <main class="content">
      <header class="topbar">
        <div><span class="eyebrow">SECURITY OPERATIONS</span><h1>威胁情报工作台</h1></div>
        <div class="topbar-actions">
          <div class="health"><i></i>服务已连接</div>
          <div ref="themePicker" class="theme-picker" @keydown.esc.stop="closeThemePicker(true)">
            <button
              ref="themeTrigger"
              class="theme-trigger"
              type="button"
              data-testid="theme-trigger"
              :aria-label="`选择界面皮肤，当前${activeTheme.name}`"
              :aria-expanded="themeOpen"
              @click="themeOpen = !themeOpen"
            >
              <span class="palette-icon" aria-hidden="true">◐</span>
              <span class="theme-trigger-label"><small>皮肤</small><b>{{ activeTheme.name }}</b></span>
              <span class="theme-preview" aria-hidden="true">
                <i v-for="color in activeTheme.swatches" :key="color" :style="{ background: color }"></i>
              </span>
              <span class="theme-chevron" aria-hidden="true">⌄</span>
            </button>
            <div v-if="themeOpen" class="theme-menu" data-testid="theme-menu" role="group" aria-label="选择界面皮肤">
              <div class="theme-menu-head"><b>界面皮肤</b><span>选择后自动保存</span></div>
              <button
                v-for="theme in themes"
                :key="theme.id"
                class="theme-option"
                :class="{ active: theme.id === selectedTheme }"
                type="button"
                data-testid="theme-option"
                :data-theme-id="theme.id"
                :aria-pressed="theme.id === selectedTheme"
                @click="selectTheme(theme.id)"
              >
                <span class="theme-card-swatches" aria-hidden="true">
                  <i v-for="color in theme.swatches" :key="color" :style="{ background: color }"></i>
                </span>
                <span class="theme-option-copy"><b>{{ theme.name }}</b><small>{{ theme.description }}</small></span>
                <span class="theme-check" aria-hidden="true">{{ theme.id === selectedTheme ? '✓' : '' }}</span>
              </button>
            </div>
          </div>
        </div>
      </header>
      <RouterView />
    </main>
  </div>
</template>
