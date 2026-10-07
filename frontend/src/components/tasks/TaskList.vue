<script setup lang="ts">
import type { DnsTaskConfig } from '@/types/task'
import { Plus } from 'lucide-vue-next'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useConfigStore } from '@/stores/config'
import { PROVIDER_DISPLAY_NAMES } from '@/types/provider'

const configStore = useConfigStore()
const { t } = useI18n()

const taskCount = computed(() => configStore.config.dns_tasks.length)

function getDomainSummary(task: DnsTaskConfig): string {
  if (task.ipv4?.domains && task.ipv4.domains.length > 0) {
    const first = task.ipv4.domains[0]
    const more = task.ipv4.domains.length - 1
    return more > 0 ? `${first} (+${more})` : first
  }
  if (task.ipv6?.domains && task.ipv6.domains.length > 0) {
    const first = task.ipv6.domains[0]
    const more = task.ipv6.domains.length - 1
    return more > 0 ? `${first} (+${more})` : first
  }
  return t('task.noDomainConfigured')
}

function getProviderName(task: DnsTaskConfig): string {
  const pType = task.provider?.type
  return PROVIDER_DISPLAY_NAMES[pType] || pType || t('task.noProviderConfigured')
}

function getTaskState(task: DnsTaskConfig) {
  return task.name ? configStore.taskStates[task.name] : undefined
}

function getTaskDotClass(task: DnsTaskConfig): string {
  if (task.enabled === false) {
    return 'bg-slate-400 dark:bg-slate-600'
  }
  const st = getTaskState(task)
  if (st && st.consecutive_failures > 0) {
    return 'bg-rose-500 shadow-xs shadow-rose-500/50'
  }
  return 'bg-emerald-500 shadow-xs shadow-emerald-500/50'
}
</script>

<template>
  <div class="w-72 border-r border-slate-200 dark:border-slate-800 bg-white/50 dark:bg-slate-900/30 flex flex-col shrink-0 select-none transition-colors">
    <!-- 头部栏 -->
    <div class="p-4 border-b border-slate-200 dark:border-slate-800/80 flex items-center justify-between">
      <div class="flex items-center gap-2">
        <span class="text-xs font-bold text-slate-800 dark:text-slate-200 tracking-wide">{{ t('task.listTitle') }}</span>
        <span class="px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-[10px] font-mono text-slate-600 dark:text-slate-400 border border-slate-200 dark:border-slate-700">
          {{ taskCount }}
        </span>
      </div>
      <button
        type="button"
        class="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-indigo-50 dark:bg-indigo-600/20 hover:bg-indigo-100 dark:hover:bg-indigo-600/30 border border-indigo-200 dark:border-indigo-500/30 text-indigo-700 dark:text-indigo-300 text-xs font-medium transition cursor-pointer"
        @click="configStore.addTask"
      >
        <Plus class="w-3.5 h-3.5" />
        <span>{{ t('task.newBtn') }}</span>
      </button>
    </div>

    <!-- 任务卡片列表 -->
    <div class="flex-1 overflow-y-auto p-3 flex flex-col gap-2">
      <div
        v-if="configStore.config.dns_tasks.length === 0"
        class="text-center py-12 text-slate-400 dark:text-slate-500 text-xs"
      >
        {{ t('task.emptyList') }}
      </div>

      <div
        v-for="(task, idx) in configStore.config.dns_tasks"
        :key="idx"
        class="p-3 rounded-xl border transition-all cursor-pointer flex flex-col gap-1.5"
        :class="
          configStore.currentTaskIndex === idx
            ? 'bg-indigo-50 dark:bg-indigo-500/10 border-indigo-300 dark:border-indigo-500/40 shadow-xs ring-1 ring-indigo-500/20'
            : 'bg-white dark:bg-slate-900/40 border-slate-200 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/40 hover:border-slate-300 dark:hover:border-slate-700'
        "
        @click="configStore.currentTaskIndex = idx"
      >
        <div class="flex items-center justify-between gap-2">
          <div class="flex items-center gap-2 min-w-0">
            <span
              class="w-2 h-2 rounded-full shrink-0 transition"
              :class="getTaskDotClass(task)"
            />
            <span class="text-xs font-semibold truncate text-slate-900 dark:text-slate-100">
              {{ task.name || t('task.unnamedTask') }}
            </span>
          </div>
          <span class="text-[10px] font-medium px-2 py-0.5 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-750 shrink-0">
            {{ getProviderName(task) }}
          </span>
        </div>

        <div class="text-[11px] font-mono text-slate-500 dark:text-slate-400 truncate pl-4">
          {{ getDomainSummary(task) }}
        </div>

        <div
          v-if="getTaskState(task) && (getTaskState(task)?.last_ipv4 || getTaskState(task)?.last_ipv6 || getTaskState(task)?.last_error)"
          class="pl-4 flex items-center justify-between gap-2 text-[10px] font-mono"
        >
          <span
            v-if="getTaskState(task)?.consecutive_failures"
            class="text-rose-600 dark:text-rose-400 truncate"
          >
            {{ getTaskState(task)?.last_error || t('task.statusFailed', { count: getTaskState(task)?.consecutive_failures }) }}
          </span>
          <span
            v-else
            class="text-emerald-600 dark:text-emerald-400 truncate"
          >
            {{ getTaskState(task)?.last_ipv4 || getTaskState(task)?.last_ipv6 }}
          </span>
          <span
            v-if="getTaskState(task)?.last_sync_time"
            class="text-slate-400 dark:text-slate-500 shrink-0"
          >
            {{ getTaskState(task)?.last_sync_time?.slice(11, 19) }}
          </span>
        </div>
      </div>
    </div>
  </div>
</template>
