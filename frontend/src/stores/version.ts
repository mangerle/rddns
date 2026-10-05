// ==========================================
// 版本检查与在线自动升级管理 Store
// ==========================================

import type { VersionInfo } from '@/types/config'
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { systemApi } from '@/api'
import { i18n } from '@/i18n'
import { useLogStore } from './log'
import { useToastStore } from './toast'

export function normalizeVersion(v?: string) {
  if (!v)
    return ''
  return String(v).trim().replace(/^v+/i, '')
}

export const useVersionStore = defineStore('version', () => {
  const logStore = useLogStore()
  const toast = useToastStore()
  const t = i18n.global.t

  const versionInfo = ref<VersionInfo | null>(null)
  const isChecking = ref<boolean>(false)
  const isModalOpen = ref<boolean>(false)

  // 升级流程内部状态
  const isUpgrading = ref<boolean>(false)
  const upgradeStep = ref<'download' | 'install' | 'restart'>('download')
  const progressPercent = ref<number>(0)
  const transferredText = ref<string>('0 MB / 0 MB')
  const statusTitle = ref<string>('')
  const statusSub = ref<string>('')
  const showManualReload = ref<boolean>(false)

  let reconnectTimer: ReturnType<typeof setInterval> | null = null

  // 注册 SSE 日志监听器解析自更新进度
  logStore.onLogReceived((entry) => {
    if (!isUpgrading.value || !entry.message)
      return
    const msg = entry.message

    // 1. 下载进度
    const progressMatch = msg.match(/下载进度:\s*([\d.]+)%\s*\(([^)]+)\)/)
    if (progressMatch) {
      progressPercent.value = Number.parseFloat(progressMatch[1])
      transferredText.value = progressMatch[2]
      statusTitle.value = t('update.downloading')
      statusSub.value = `正在下载更新资产包 (${transferredText.value})...`
      return
    }

    // 2. 校验与安装热替换
    if (msg.includes('更新包校验通过') || msg.includes('正在执行程序安全替换')) {
      upgradeStep.value = 'install'
      progressPercent.value = 100
      transferredText.value = '校验完成'
      statusTitle.value = t('update.installing')
      statusSub.value = '安装包哈希与签名通过，正在安全执行热替换...'
      return
    }

    // 3. 替换完成，调度平滑重启
    if (msg.includes('自动更新完成，正在平滑重启服务') || msg.includes('正在调度平滑重启服务')) {
      upgradeStep.value = 'restart'
      progressPercent.value = 100
      transferredText.value = '准备就绪'
      startRestartPolling()
      return
    }

    // 4. 异常提示
    if (msg.includes('在线自动更新失败') || msg.includes('执行程序替换失败')) {
      isUpgrading.value = false
      statusTitle.value = '升级遇到异常'
      statusSub.value = msg
      toast.error(msg)
    }
  })

  // 启动重启探测并在新服务拉起后自动刷新
  function startRestartPolling() {
    if (reconnectTimer)
      return
    let pollAttempts = 0
    statusTitle.value = t('update.restarting')
    statusSub.value = '服务正在平滑重启，准备自动重连...'

    reconnectTimer = setInterval(async () => {
      pollAttempts++
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 1500)

      try {
        const resp = await fetch('/api/v1/auth/status', {
          cache: 'no-store',
          signal: controller.signal,
        })
        clearTimeout(timeoutId)

        if (resp.ok) {
          if (reconnectTimer) {
            clearInterval(reconnectTimer)
            reconnectTimer = null
          }
          statusTitle.value = t('update.upgradeComplete')
          statusSub.value = '新版本已就绪，正在自动进入控制台...'
          toast.success(t('update.upgradeComplete'))
          setTimeout(() => {
            window.location.reload()
          }, 600)
          return
        }
      }
      catch {
        clearTimeout(timeoutId)
      }

      if (pollAttempts >= 5) {
        showManualReload.value = true
        statusSub.value = '正在等待新版本服务就绪...'
      }
    }, 800)
  }

  // 检查版本
  async function checkVersion(isManual = false) {
    if (isManual) {
      isChecking.value = true
      toast.info(t('common.checkingUpdate'))
    }
    try {
      const res = await systemApi.getVersion()
      if (res.success && res.data) {
        versionInfo.value = res.data
        if (res.data.has_update) {
          if (isManual) {
            isModalOpen.value = true
          }
        }
        else if (isManual) {
          toast.success(
            t('common.latestVersionAlert', {
              version: normalizeVersion(res.data.current_version),
            }),
          )
        }
      }
    }
    catch (e: unknown) {
      if (isManual) {
        const errMsg = e instanceof Error ? e.message : String(e)
        toast.error(t('common.checkUpdateFailed', { error: errMsg }))
      }
    }
    finally {
      if (isManual)
        isChecking.value = false
    }
  }

  // 开始执行自动升级
  async function startUpgrade() {
    if (isUpgrading.value)
      return
    isUpgrading.value = true
    upgradeStep.value = 'download'
    progressPercent.value = 0
    transferredText.value = '0 MB / 0 MB'
    statusTitle.value = t('update.downloading')
    statusSub.value = '正在连接更新发布源...'

    try {
      const res = await systemApi.upgrade()
      if (!res.success) {
        isUpgrading.value = false
        toast.error(t('common.upgradeFailed', { message: res.message }))
        statusTitle.value = '升级失败'
        statusSub.value = res.message
      }
    }
    catch (e: unknown) {
      isUpgrading.value = false
      const errMsg = e instanceof Error ? e.message : String(e)
      toast.error(t('common.upgradeFailed', { message: errMsg }))
      statusTitle.value = '网络请求异常'
      statusSub.value = errMsg
    }
  }

  return {
    versionInfo,
    isChecking,
    isModalOpen,
    isUpgrading,
    upgradeStep,
    progressPercent,
    transferredText,
    statusTitle,
    statusSub,
    showManualReload,
    checkVersion,
    startUpgrade,
  }
})
