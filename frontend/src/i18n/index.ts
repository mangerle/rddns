// ==========================================
// vue-i18n 初始化与语言切换支持
// ==========================================

import { createI18n } from 'vue-i18n'
import enUS from './en-US'
import zhCN from './zh-CN'

const savedLocale = localStorage.getItem('rddns_locale') || (
  navigator.language.startsWith('zh') ? 'zh-CN' : 'en-US'
)

export const i18n = createI18n({
  legacy: false,
  locale: savedLocale,
  fallbackLocale: 'zh-CN',
  messages: {
    'zh-CN': zhCN,
    'en-US': enUS,
  },
})

export function setLocale(locale: 'zh-CN' | 'en-US') {
  i18n.global.locale.value = locale
  localStorage.setItem('rddns_locale', locale)
  document.documentElement.setAttribute('lang', locale)
}

export function getLocale(): 'zh-CN' | 'en-US' {
  return (i18n.global.locale.value as 'zh-CN' | 'en-US') || 'zh-CN'
}
