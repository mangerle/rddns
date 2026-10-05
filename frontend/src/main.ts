// ==========================================
// 前端应用初始化主入口 (Vue 3 + Vite + TS)
// ==========================================

import { createPinia } from 'pinia'
import { createApp } from 'vue'
import App from './App.vue'
import { i18n } from './i18n'
import './style.css'

const app = createApp(App)
const pinia = createPinia()

app.use(pinia)
app.use(i18n)

app.mount('#app')
