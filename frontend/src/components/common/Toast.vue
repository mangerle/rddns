<script setup lang="ts">
import { AlertCircle, AlertTriangle, CheckCircle, Info, X } from 'lucide-vue-next'
import { useToastStore } from '@/stores/toast'

const toastStore = useToastStore()
</script>

<template>
  <div class="fixed top-5 right-5 z-50 flex flex-col gap-2 pointer-events-none">
    <transition-group
      enter-active-class="transform ease-out duration-250 transition"
      enter-from-class="translate-y-[-10px] opacity-0 scale-95"
      enter-to-class="translate-y-0 opacity-100 scale-100"
      leave-active-class="transition ease-in duration-200"
      leave-from-class="opacity-100 scale-100"
      leave-to-class="opacity-0 scale-95"
    >
      <div
        v-for="toast in toastStore.toasts"
        :key="toast.id"
        class="pointer-events-auto flex items-center gap-3 min-w-[280px] max-w-[420px] px-4 py-3 rounded-lg shadow-xl border backdrop-blur-md text-sm font-medium transition-all"
        :class="{
          'bg-white/95 dark:bg-slate-900/95 border-emerald-500/40 text-emerald-600 dark:text-emerald-300': toast.type === 'success',
          'bg-white/95 dark:bg-slate-900/95 border-rose-500/40 text-rose-600 dark:text-rose-300': toast.type === 'error',
          'bg-white/95 dark:bg-slate-900/95 border-amber-500/40 text-amber-600 dark:text-amber-300': toast.type === 'warning',
          'bg-white/95 dark:bg-slate-900/95 border-indigo-500/40 text-indigo-600 dark:text-indigo-300': toast.type === 'info',
        }"
      >
        <span class="shrink-0">
          <CheckCircle v-if="toast.type === 'success'" class="w-4 h-4 text-emerald-500 dark:text-emerald-400" />
          <AlertCircle v-else-if="toast.type === 'error'" class="w-4 h-4 text-rose-500 dark:text-rose-400" />
          <AlertTriangle v-else-if="toast.type === 'warning'" class="w-4 h-4 text-amber-500 dark:text-amber-400" />
          <Info v-else class="w-4 h-4 text-indigo-500 dark:text-indigo-400" />
        </span>
        <span class="flex-1 text-slate-800 dark:text-slate-100">{{ toast.message }}</span>
        <button
          type="button"
          class="cursor-pointer shrink-0 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition p-1"
          @click="toastStore.remove(toast.id)"
        >
          <X class="w-3.5 h-3.5" />
        </button>
      </div>
    </transition-group>
  </div>
</template>
