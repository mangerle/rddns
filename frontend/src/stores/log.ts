// ==========================================
// 系统实时日志与 SSE 推流管理 Store
// ==========================================

import type { LogEntry } from '@/types/log'
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { authApi } from '@/api'
import { i18n } from '@/i18n'
import { useToastStore } from './toast'

export const useLogStore = defineStore('log', () => {
  const toast = useToastStore()
  const t = i18n.global.t

  const isModalOpen = ref<boolean>(false)
  const logs = ref<LogEntry[]>([])
  const isConnected = ref<boolean>(false)

  let activeEventSource: EventSource | null = null
  const logListeners: ((entry: LogEntry) => void)[] = []

  function onLogReceived(cb: (entry: LogEntry) => void) {
    logListeners.push(cb)
    return () => {
      const idx = logListeners.indexOf(cb)
      if (idx !== -1)
        logListeners.splice(idx, 1)
    }
  }

  function appendLog(entry: LogEntry) {
    logs.value.push(entry)
    if (logs.value.length > 1000) {
      logs.value.shift()
    }
    logListeners.forEach((cb) => {
      try {
        cb(entry)
      }
      catch {}
    })
  }

  function clearLogs() {
    logs.value = []
    toast.info(t('modal.logsCleared'))
  }

  async function initSSE() {
    if (activeEventSource) {
      try {
        activeEventSource.close()
      }
      catch {}
      activeEventSource = null
    }

    let sseUrl = '/api/v1/logs/sse'
    const auth = sessionStorage.getItem('rddns_auth')

    if (auth) {
      try {
        const resp = await authApi.getSseTicket()
        if (resp.success && resp.data?.ticket) {
          sseUrl = `/api/v1/logs/sse?ticket=${encodeURIComponent(resp.data.ticket)}`
        }
      }
      catch (e) {
        console.warn('获取 SSE 临时 Ticket 失败，尝试免 Ticket 连接:', e)
      }
    }

    try {
      const es = new EventSource(sseUrl)
      activeEventSource = es

      es.onopen = () => {
        isConnected.value = true
      }

      es.onmessage = (e) => {
        try {
          const entry: LogEntry = JSON.parse(e.data)
          appendLog(entry)
        }
        catch (err) {
          console.error('解析 SSE 日志失败:', err)
        }
      }

      es.onerror = () => {
        isConnected.value = false
        es.close()
        if (activeEventSource === es) {
          activeEventSource = null
        }
        // 5秒后自动重连
        setTimeout(initSSE, 5000)
      }
    }
    catch (e) {
      console.error('初始化 SSE 异常:', e)
    }
  }

  return {
    isModalOpen,
    logs,
    isConnected,
    onLogReceived,
    appendLog,
    clearLogs,
    initSSE,
  }
})
