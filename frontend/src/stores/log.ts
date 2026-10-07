// ==========================================
// 系统实时日志与 SSE 推流管理 Store
// ==========================================

import type { LogEntry } from '@/types/log'
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { authApi, systemApi } from '@/api'
import { i18n } from '@/i18n'
import { useToastStore } from './toast'

export const useLogStore = defineStore('log', () => {
  const toast = useToastStore()
  const t = i18n.global.t

  const isModalOpen = ref<boolean>(false)
  const logs = ref<LogEntry[]>([])
  const isConnected = ref<boolean>(false)

  let activeEventSource: EventSource | null = null
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null
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
    // 按唯一 id 去重；无 id 时按时间戳、模块与内容去重，防止快照与流并发重复
    const exists = entry.id != null
      ? logs.value.some(l => l.id === entry.id)
      : logs.value.some(
          l =>
            l.timestamp === entry.timestamp
            && l.target === entry.target
            && l.message === entry.message,
        )
    if (exists) {
      return
    }

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

  // 主动拉取服务端的最新历史日志快照
  async function fetchHistoryLogs() {
    try {
      const res = await systemApi.getLogs()
      if (res.success && Array.isArray(res.data)) {
        for (const entry of res.data) {
          appendLog(entry)
        }
      }
    }
    catch (e) {
      console.warn('拉取历史日志快照失败:', e)
    }
  }

  function clearLogs() {
    logs.value = []
    toast.info(t('modal.logsCleared'))
  }

  function closeSSE() {
    if (reconnectTimer) {
      clearTimeout(reconnectTimer)
      reconnectTimer = null
    }
    if (activeEventSource) {
      try {
        activeEventSource.close()
      }
      catch {}
      activeEventSource = null
    }
    isConnected.value = false
  }

  async function initSSE() {
    closeSSE()

    // 建立推流连接前，先拉取服务端的历史日志快照
    await fetchHistoryLogs()

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
        // 仅在仍持有登录态时 5 秒后自动重连
        if (sessionStorage.getItem('rddns_auth')) {
          if (reconnectTimer) {
            clearTimeout(reconnectTimer)
          }
          reconnectTimer = setTimeout(initSSE, 5000)
        }
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
    closeSSE,
    initSSE,
    fetchHistoryLogs,
  }
})
