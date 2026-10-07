// ==========================================
// 认证与会话状态管理 Store
// ==========================================

import { defineStore } from 'pinia'
import { ref } from 'vue'
import { authApi } from '@/api'
import { onUnauthorized } from '@/api/client'
import { i18n } from '@/i18n'
import { useLogStore } from './log'
import { useToastStore } from './toast'

// UTF-8 安全的 Basic Auth Base64 编码（防止非 ASCII 用户名或密码调用 btoa 抛出异常）
export function encodeBasicAuth(user: string, pass: string): string {
  const bytes = new TextEncoder().encode(`${user}:${pass}`)
  let binary = ''
  for (const b of bytes) {
    binary += String.fromCharCode(b)
  }
  return btoa(binary)
}

// 从已保存的 Basic Auth 凭据中安全解码原密码（供仅修改用户名时更新会话使用）
export function decodeBasicAuthPassword(encoded: string): string | null {
  try {
    const binary = atob(encoded)
    const bytes = new Uint8Array(binary.length)
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i)
    }
    const decoded = new TextDecoder().decode(bytes)
    const colonIdx = decoded.indexOf(':')
    if (colonIdx === -1) {
      return null
    }
    return decoded.slice(colonIdx + 1)
  }
  catch {
    return null
  }
}

export const useAuthStore = defineStore('auth', () => {
  const toast = useToastStore()
  const t = i18n.global.t

  const currentView = ref<'loading' | 'login' | 'init' | 'app'>('loading')
  const username = ref<string>('')
  const isAuthenticated = ref<boolean>(!!sessionStorage.getItem('rddns_auth'))

  // 监听 401 拦截事件
  onUnauthorized(() => {
    sessionStorage.removeItem('rddns_auth')
    isAuthenticated.value = false
    currentView.value = 'login'
    useLogStore().closeSSE()
  })

  // 检查账号状态（是否需要初始化、已保存的用户名）
  async function checkAuthStatus() {
    try {
      const res = await authApi.getStatus()
      if (res.success) {
        if (res.data.need_init) {
          currentView.value = 'init'
          return
        }
        if (res.data.username) {
          username.value = res.data.username
        }
      }
      if (sessionStorage.getItem('rddns_auth')) {
        isAuthenticated.value = true
        currentView.value = 'app'
      }
      else {
        currentView.value = 'login'
      }
    }
    catch {
      currentView.value = 'login'
    }
  }

  // 提交初始化账号
  async function submitInit(user: string, pass: string): Promise<boolean> {
    try {
      const res = await authApi.init({ username: user, password: pass })
      if (res.success) {
        const authKey = encodeBasicAuth(user, pass)
        sessionStorage.setItem('rddns_auth', authKey)
        isAuthenticated.value = true
        username.value = user
        currentView.value = 'app'
        toast.success(t('auth.initSuccess'))
        return true
      }
      else {
        toast.error(t('auth.initFailed', { message: res.message }))
        return false
      }
    }
    catch (e: unknown) {
      const errMsg = e instanceof Error ? e.message : String(e)
      toast.error(t('common.requestError', { error: errMsg }))
      return false
    }
  }

  // 提交登录认证
  async function submitLogin(user: string, pass: string): Promise<boolean> {
    try {
      const res = await authApi.login({ username: user, password: pass })
      if (res.success) {
        const authKey = encodeBasicAuth(user, pass)
        sessionStorage.setItem('rddns_auth', authKey)
        isAuthenticated.value = true
        username.value = user
        currentView.value = 'app'
        toast.success(t('auth.loginSuccess'))
        return true
      }
      else {
        toast.error(t('auth.loginFailed', { message: res.message }))
        return false
      }
    }
    catch (e: unknown) {
      const errMsg = e instanceof Error ? e.message : String(e)
      toast.error(t('common.requestError', { error: errMsg }))
      return false
    }
  }

  // 退出登录
  function logout() {
    sessionStorage.removeItem('rddns_auth')
    isAuthenticated.value = false
    currentView.value = 'login'
    useLogStore().closeSSE()
    toast.info(t('common.logoutSuccess'))
  }

  return {
    currentView,
    username,
    isAuthenticated,
    checkAuthStatus,
    submitInit,
    submitLogin,
    logout,
  }
})
