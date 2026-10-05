<script setup lang="ts">
import { Terminal, Trash2, X } from 'lucide-vue-next'
import { nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useLogStore } from '@/stores/log'

const logStore = useLogStore()
const { t } = useI18n()
const logScrollEl = ref<HTMLElement | null>(null)

function scrollToBottom() {
  nextTick(() => {
    if (logScrollEl.value) {
      logScrollEl.value.scrollTop = logScrollEl.value.scrollHeight
    }
  })
}

watch(() => logStore.logs.length, () => {
  if (logStore.isModalOpen) {
    scrollToBottom()
  }
})

watch(() => logStore.isModalOpen, (open) => {
  if (open) {
    scrollToBottom()
  }
})

function handleKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape' && logStore.isModalOpen) {
    logStore.isModalOpen = false
  }
}

onMounted(() => {
  window.addEventListener('keydown', handleKeydown)
})

onUnmounted(() => {
  window.removeEventListener('keydown', handleKeydown)
})
</script>

<template>
  <div
    v-if="logStore.isModalOpen"
    class="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-slate-900/50 dark:bg-slate-950/75 backdrop-blur-xs transition-colors"
    @click.self="logStore.isModalOpen = false"
  >
    <div class="w-full max-w-4xl h-[80vh] flex flex-col bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
      <!-- 头部 -->
      <div class="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/90 dark:bg-slate-900/90 shrink-0">
        <div class="flex items-center gap-3">
          <div class="w-2.5 h-2.5 rounded-full bg-emerald-500 shadow-xs shadow-emerald-500/50 animate-pulse" />
          <span class="text-sm font-semibold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            <Terminal class="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
            {{ t('modal.logTitle') }}
          </span>
          <span class="text-[11px] font-mono px-2 py-0.5 rounded-full bg-indigo-500/10 text-indigo-600 dark:text-indigo-400 border border-indigo-500/20">
            {{ t('modal.sseTag') }}
          </span>
        </div>

        <div class="flex items-center gap-2">
          <button
            type="button"
            class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs text-slate-700 dark:text-slate-300 transition cursor-pointer"
            @click="logStore.clearLogs"
          >
            <Trash2 class="w-3.5 h-3.5" />
            <span>{{ t('modal.clearLogs') }}</span>
          </button>
          <button
            type="button"
            class="p-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 transition cursor-pointer"
            :title="t('modal.closeLogs')"
            @click="logStore.isModalOpen = false"
          >
            <X class="w-4 h-4" />
          </button>
        </div>
      </div>

      <!-- 日志列表主体 -->
      <div
        ref="logScrollEl"
        class="flex-1 p-4 bg-slate-950/80 overflow-y-auto font-mono text-xs leading-relaxed flex flex-col gap-1 select-text"
      >
        <div v-if="logStore.logs.length === 0" class="h-full flex items-center justify-center text-slate-500 select-none">
          暂无实时日志记录
        </div>
        <div
          v-for="(log, idx) in logStore.logs"
          :key="idx"
          class="flex items-start gap-2 hover:bg-slate-900/50 px-2 py-0.5 rounded transition"
        >
          <span class="text-slate-500 shrink-0">[{{ log.timestamp }}]</span>
          <span
            class="shrink-0 font-bold px-1.5 py-0.2 rounded text-[10px]"
            :class="{
              'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20': log.level === 'INFO',
              'bg-amber-500/10 text-amber-400 border border-amber-500/20': log.level === 'WARN',
              'bg-rose-500/10 text-rose-400 border border-rose-500/20': log.level === 'ERROR',
              'bg-slate-700/30 text-slate-400': log.level === 'DEBUG' || log.level === 'TRACE',
            }"
          >
            {{ log.level }}
          </span>
          <span class="text-indigo-400 shrink-0">[{{ log.target }}]</span>
          <span class="text-slate-200 break-all">{{ log.message }}</span>
        </div>
      </div>
    </div>
  </div>
</template>
