// ==========================================
// 全局 Toast 提示通知 Store
// ==========================================

import { defineStore } from 'pinia'
import { ref } from 'vue'

export interface ToastItem {
  id: number
  message: string
  type: 'info' | 'success' | 'warning' | 'error'
  duration: number
}

export const useToastStore = defineStore('toast', () => {
  const toasts = ref<ToastItem[]>([])
  let seed = 0

  function show(message: string, type: 'info' | 'success' | 'warning' | 'error' = 'info', duration = 3000) {
    const id = ++seed
    toasts.value.push({ id, message, type, duration })
    setTimeout(() => {
      remove(id)
    }, duration)
  }

  function remove(id: number) {
    const idx = toasts.value.findIndex(t => t.id === id)
    if (idx !== -1) {
      toasts.value.splice(idx, 1)
    }
  }

  return {
    toasts,
    show,
    remove,
    success: (msg: string, dur?: number) => show(msg, 'success', dur),
    error: (msg: string, dur?: number) => show(msg, 'error', dur),
    info: (msg: string, dur?: number) => show(msg, 'info', dur),
    warning: (msg: string, dur?: number) => show(msg, 'warning', dur),
  }
})
