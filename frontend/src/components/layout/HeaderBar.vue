<script setup lang="ts">
import {
  Globe,
  LogOut,
  Moon,
  Radio,
  RefreshCw,
  Save,
  Sparkles,
  Sun,
  Terminal,
} from 'lucide-vue-next'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { getLocale, setLocale } from '@/i18n'
import { useAuthStore } from '@/stores/auth'
import { useConfigStore } from '@/stores/config'
import { useLogStore } from '@/stores/log'
import { useThemeStore } from '@/stores/theme'
import { normalizeVersion, useVersionStore } from '@/stores/version'

const configStore = useConfigStore()
const logStore = useLogStore()
const versionStore = useVersionStore()
const themeStore = useThemeStore()
const authStore = useAuthStore()
const { t } = useI18n()

const currentVer = computed(() =>
  normalizeVersion(versionStore.versionInfo?.current_version),
)
const hasUpdate = computed(() => !!versionStore.versionInfo?.has_update)
const latestVer = computed(() =>
  normalizeVersion(versionStore.versionInfo?.latest_version),
)

function toggleLang() {
  const cur = getLocale()
  setLocale(cur === 'zh-CN' ? 'en-US' : 'zh-CN')
}
</script>

<template>
  <header class="h-16 px-6 border-b border-slate-200 dark:border-slate-800 bg-white/80 dark:bg-slate-900/90 backdrop-blur-md flex items-center justify-between shrink-0 z-30 select-none transition-colors duration-150">
    <!-- 左侧 Logo 与应用信息 -->
    <div class="flex items-center gap-4">
      <div class="flex items-center gap-3">
        <div class="w-9 h-9 rounded-xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-600 dark:text-indigo-400 font-bold text-lg shadow-xs">
          R
        </div>
        <div class="flex flex-col">
          <div class="flex items-center gap-2">
            <span class="font-bold text-slate-900 dark:text-slate-100 text-sm tracking-wide">rddns</span>
            <!-- 运行状态指示徽标 -->
            <div
              class="flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-mono border cursor-pointer transition hover:opacity-80"
              :class="hasUpdate ? 'bg-amber-500/10 text-amber-500 dark:text-amber-400 border-amber-500/30' : 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20'"
              :title="hasUpdate ? t('common.newVersionFound', { version: latestVer }) : t('common.checkingUpdate')"
              @click="versionStore.checkVersion(true)"
            >
              <span class="w-1.5 h-1.5 rounded-full" :class="hasUpdate ? 'bg-amber-500 dark:bg-amber-400 animate-ping' : 'bg-emerald-500 dark:bg-emerald-400'" />
              <span>v{{ currentVer || '0.11.0' }}</span>
              <span v-if="hasUpdate" class="text-[10px] text-amber-600 dark:text-amber-300 font-sans flex items-center gap-1 ml-0.5">
                <Sparkles class="w-2.5 h-2.5" />
                <span>{{ t('update.title') }}</span>
              </span>
            </div>
          </div>
          <span class="text-[10px] text-slate-500 dark:text-slate-400">{{ t('common.brandSubtitle') }} · {{ t('common.brandTitle') }}</span>
        </div>
      </div>
    </div>

    <!-- 右侧操作栏 -->
    <div class="flex items-center gap-3">
      <!-- 立即全量同步 -->
      <button
        type="button"
        :disabled="configStore.isSyncing"
        class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs text-slate-700 dark:text-slate-200 transition cursor-pointer"
        @click="configStore.triggerSync"
      >
        <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': configStore.isSyncing }" />
        <span>{{ configStore.isSyncing ? t('common.syncing') : t('common.syncAll') }}</span>
      </button>

      <!-- 保存配置 -->
      <button
        type="button"
        :disabled="configStore.isSaving"
        class="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 text-xs text-white font-medium shadow-md shadow-indigo-600/20 transition disabled:opacity-50 cursor-pointer"
        @click="configStore.saveConfig()"
      >
        <Save class="w-3.5 h-3.5" :class="{ 'animate-pulse': configStore.isSaving }" />
        <span>{{ configStore.isSaving ? t('common.saving') : t('common.saveConfig') }}</span>
      </button>

      <div class="h-4 w-px bg-slate-200 dark:bg-slate-800 mx-1" />

      <!-- 实时日志弹窗按钮 -->
      <button
        type="button"
        class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50 hover:bg-slate-100 dark:hover:bg-slate-750 text-xs text-slate-700 dark:text-slate-300 transition cursor-pointer"
        @click="logStore.isModalOpen = true"
      >
        <Terminal class="w-3.5 h-3.5 text-indigo-500 dark:text-indigo-400" />
        <span>{{ t('common.viewLogs') }}</span>
        <Radio v-if="logStore.isConnected" class="w-2.5 h-2.5 text-emerald-500 dark:text-emerald-400 animate-pulse ml-0.5" />
      </button>

      <!-- 语言切换 -->
      <button
        type="button"
        class="flex items-center gap-1 px-2.5 py-1.5 rounded-lg border border-slate-300 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 hover:bg-slate-100 dark:hover:bg-slate-800 text-xs text-slate-700 dark:text-slate-300 transition cursor-pointer"
        :title="t('common.langToggle')"
        @click="toggleLang"
      >
        <Globe class="w-3.5 h-3.5" />
        <span>{{ getLocale() === 'zh-CN' ? 'EN' : '中' }}</span>
      </button>

      <!-- 主题切换 -->
      <button
        type="button"
        class="p-2 rounded-lg border border-slate-300 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 transition cursor-pointer"
        :title="t('common.themeToggle')"
        @click="themeStore.toggleTheme"
      >
        <Sun v-if="themeStore.isDark" class="w-3.5 h-3.5 text-amber-400" />
        <Moon v-else class="w-3.5 h-3.5 text-indigo-600" />
      </button>

      <!-- 退出登录 -->
      <button
        type="button"
        class="p-2 rounded-lg border border-slate-300 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/60 hover:bg-rose-50 dark:hover:bg-rose-500/10 hover:border-rose-300 dark:hover:border-rose-500/30 text-slate-600 hover:text-rose-600 dark:text-slate-400 dark:hover:text-rose-400 transition cursor-pointer"
        :title="t('common.logout')"
        @click="authStore.logout"
      >
        <LogOut class="w-3.5 h-3.5" />
      </button>
    </div>
  </header>
</template>
