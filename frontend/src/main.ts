import { createPinia } from 'pinia'
import { createApp } from 'vue'

import App from './App.vue'
import { i18n } from './i18n'
import router from './router'
import { applyUiSettings, DEFAULT_DISPLAY_SETTINGS, loadUiSettings } from './ui-settings'
import './styles.css'

applyUiSettings(DEFAULT_DISPLAY_SETTINGS)
createApp(App).use(createPinia()).use(i18n).use(router).mount('#app')
void loadUiSettings()
