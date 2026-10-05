// ==========================================
// 主题切换管理 Store (Dark / Light)
// ==========================================

import { defineStore } from 'pinia'
import { ref } from 'vue'

export const useThemeStore = defineStore('theme', () => {
  const saved = localStorage.getItem('rddns_theme')
  const isDark = ref<boolean>(saved ? saved === 'dark' : true)

  function applyTheme(dark: boolean) {
    isDark.value = dark
    localStorage.setItem('rddns_theme', dark ? 'dark' : 'light')
    if (dark) {
      document.documentElement.classList.add('dark')
      document.documentElement.setAttribute('data-theme', 'dark')
    }
    else {
      document.documentElement.classList.remove('dark')
      document.documentElement.setAttribute('data-theme', 'light')
    }
  }

  function toggleTheme() {
    applyTheme(!isDark.value)
  }

  // 初始化主题设置
  applyTheme(isDark.value)

  return {
    isDark,
    toggleTheme,
    applyTheme,
  }
})
