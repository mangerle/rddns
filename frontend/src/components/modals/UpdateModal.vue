<script setup lang="ts">
import { CheckCircle, Download, RefreshCw, Sparkles, X } from 'lucide-vue-next'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { normalizeVersion, useVersionStore } from '@/stores/version'

const versionStore = useVersionStore()
const { t } = useI18n()

const currentVer = computed(() =>
  normalizeVersion(versionStore.versionInfo?.current_version),
)
const latestVer = computed(() =>
  normalizeVersion(versionStore.versionInfo?.latest_version),
)

function closeModal() {
  if (versionStore.isUpgrading)
    return
  versionStore.isModalOpen = false
}
</script>

<template>
  <div
    v-if="versionStore.isModalOpen"
    class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/75 backdrop-blur-sm"
    @click.self="closeModal"
  >
    <div class="w-full max-w-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col animate-in fade-in zoom-in-95 duration-150">
      <!-- 头部 -->
      <div class="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/90 shrink-0">
        <div class="flex items-center gap-3">
          <div class="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-500 dark:text-indigo-400">
            <Sparkles class="w-4 h-4" />
          </div>
          <span class="text-sm font-semibold text-slate-900 dark:text-slate-100">{{ t('update.title') }}</span>
          <span class="text-xs font-mono px-2 py-0.5 rounded-full bg-indigo-50 dark:bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-500/20">
            v{{ latestVer }}
          </span>
        </div>

        <button
          v-if="!versionStore.isUpgrading"
          type="button"
          class="cursor-pointer p-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 transition"
          @click="closeModal"
        >
          <X class="w-4 h-4" />
        </button>
      </div>

      <!-- 视图 1：更新提示与更新日志 -->
      <div v-if="!versionStore.isUpgrading" class="p-6 flex flex-col gap-5">
        <div class="flex items-center justify-between p-3.5 rounded-xl bg-slate-100 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800/80 text-xs">
          <div class="flex items-center gap-2">
            <span class="text-slate-500 dark:text-slate-400">{{ t('update.currentVer') }}</span>
            <span class="font-mono text-slate-800 dark:text-slate-200">v{{ currentVer }}</span>
          </div>
          <span class="text-slate-400 dark:text-slate-500">→</span>
          <div class="flex items-center gap-2">
            <span class="text-slate-500 dark:text-slate-400">{{ t('update.targetVer') }}</span>
            <span class="font-mono text-emerald-600 dark:emerald-400 font-semibold">v{{ latestVer }}</span>
          </div>
        </div>

        <div class="flex flex-col gap-2">
          <div class="text-xs font-semibold text-slate-700 dark:text-slate-300">
            {{ t('update.changelog') }}
          </div>
          <div class="max-h-60 overflow-y-auto p-4 rounded-xl bg-slate-100 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800/80 text-xs leading-relaxed text-slate-700 dark:text-slate-300 whitespace-pre-wrap font-mono">
            {{ versionStore.versionInfo?.release_notes || t('update.regularImprovements') }}
          </div>
        </div>

        <div class="flex items-center justify-end gap-3 pt-2">
          <button
            type="button"
            class="cursor-pointer px-4 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs text-slate-700 dark:text-slate-300 transition"
            @click="closeModal"
          >
            {{ t('update.cancel') }}
          </button>
          <button
            type="button"
            class="cursor-pointer flex items-center gap-2 px-5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-xs text-white font-medium shadow-lg shadow-indigo-600/20 transition"
            @click="versionStore.startUpgrade"
          >
            <Download class="w-3.5 h-3.5" />
            <span>{{ t('update.upgradeNow') }}</span>
          </button>
        </div>
      </div>

      <!-- 视图 2：下载安装进度条与重启探针 -->
      <div v-else class="p-6 flex flex-col gap-6">
        <div class="flex flex-col gap-2 text-center items-center py-2">
          <div class="text-sm font-semibold text-slate-900 dark:text-slate-100">
            {{ versionStore.statusTitle }}
          </div>
          <div class="text-xs text-slate-500 dark:text-slate-400">
            {{ versionStore.statusSub }}
          </div>
        </div>

        <!-- 进度条 -->
        <div class="flex flex-col gap-2">
          <div class="w-full bg-slate-200 dark:bg-slate-800 h-2.5 rounded-full overflow-hidden">
            <div
              class="bg-indigo-500 h-full transition-all duration-300 rounded-full"
              :style="{ width: `${versionStore.progressPercent}%` }"
            />
          </div>
          <div class="flex justify-between text-[11px] text-slate-500 dark:text-slate-400 font-mono">
            <span>{{ versionStore.progressPercent.toFixed(1) }}%</span>
            <span>{{ versionStore.transferredText }}</span>
          </div>
        </div>

        <!-- 步骤指示 -->
        <div class="flex flex-col gap-3 p-4 rounded-xl bg-slate-100 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800/80 text-xs">
          <div
            class="flex items-center gap-3 transition"
            :class="versionStore.upgradeStep === 'download' ? 'text-indigo-600 dark:text-indigo-400 font-medium' : 'text-emerald-600 dark:text-emerald-400'"
          >
            <CheckCircle v-if="versionStore.upgradeStep !== 'download'" class="w-4 h-4 shrink-0" />
            <RefreshCw v-else class="w-4 h-4 animate-spin shrink-0" />
            <span>{{ t('update.stepDownload') }}</span>
          </div>

          <div
            class="flex items-center gap-3 transition"
            :class="versionStore.upgradeStep === 'install' ? 'text-indigo-600 dark:text-indigo-400 font-medium' : (versionStore.upgradeStep === 'restart' ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-400 dark:text-slate-500')"
          >
            <CheckCircle v-if="versionStore.upgradeStep === 'restart'" class="w-4 h-4 shrink-0" />
            <RefreshCw v-else-if="versionStore.upgradeStep === 'install'" class="w-4 h-4 animate-spin shrink-0" />
            <div v-else class="w-4 h-4 rounded-full border border-slate-300 dark:border-slate-700 shrink-0" />
            <span>{{ t('update.stepInstall') }}</span>
          </div>

          <div
            class="flex items-center gap-3 transition"
            :class="versionStore.upgradeStep === 'restart' ? 'text-indigo-600 dark:text-indigo-400 font-medium' : 'text-slate-400 dark:text-slate-500'"
          >
            <RefreshCw v-if="versionStore.upgradeStep === 'restart'" class="w-4 h-4 animate-spin shrink-0" />
            <div v-else class="w-4 h-4 rounded-full border border-slate-300 dark:border-slate-700 shrink-0" />
            <span>{{ t('update.stepRestart') }}</span>
          </div>
        </div>

        <!-- 极端网络兜底刷新按钮 -->
        <div v-if="versionStore.showManualReload" class="flex justify-center pt-2">
          <button
            type="button"
            onclick="window.location.reload()"
            class="cursor-pointer px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-xs text-white font-medium transition"
          >
            {{ t('update.manualReload') }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
