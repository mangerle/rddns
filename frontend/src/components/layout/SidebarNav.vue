<script setup lang="ts">
import { Bell, Network, Settings } from 'lucide-vue-next'
import { useI18n } from 'vue-i18n'
import { useConfigStore } from '@/stores/config'

const configStore = useConfigStore()
const { t } = useI18n()

const navItems = [
  {
    id: 'tab-dns',
    icon: Network,
    title: 'nav.dnsTitle',
    desc: 'nav.dnsDesc',
  },
  {
    id: 'tab-notify',
    icon: Bell,
    title: 'nav.notifyTitle',
    desc: 'nav.notifyDesc',
  },
  {
    id: 'tab-system',
    icon: Settings,
    title: 'nav.systemTitle',
    desc: 'nav.systemDesc',
  },
] as const
</script>

<template>
  <aside class="w-64 border-r border-slate-200 dark:border-slate-800 bg-white/70 dark:bg-slate-900/40 backdrop-blur-sm p-4 flex flex-col gap-2 shrink-0 select-none transition-colors duration-150">
    <div class="text-[11px] font-semibold tracking-wider text-slate-400 dark:text-slate-500 uppercase px-3 py-1">
      Navigation
    </div>
    <button
      v-for="item in navItems"
      :key="item.id"
      type="button"
      class="flex items-start gap-3 p-3 rounded-xl border text-left transition-all group cursor-pointer"
      :class="
        configStore.activeTab === item.id
          ? 'bg-indigo-50 dark:bg-indigo-500/10 border-indigo-200 dark:border-indigo-500/30 text-indigo-700 dark:text-indigo-300 shadow-xs'
          : 'bg-transparent border-transparent text-slate-600 dark:text-slate-400 hover:bg-slate-100/80 dark:hover:bg-slate-800/50 hover:text-slate-900 dark:hover:text-slate-200'
      "
      @click="configStore.activeTab = item.id"
    >
      <component
        :is="item.icon"
        class="w-5 h-5 shrink-0 mt-0.5 transition"
        :class="configStore.activeTab === item.id ? 'text-indigo-600 dark:text-indigo-400' : 'text-slate-400 dark:text-slate-500 group-hover:text-slate-600 dark:group-hover:text-slate-300'"
      />
      <div class="flex flex-col gap-0.5">
        <span
          class="text-xs font-semibold transition-colors"
          :class="configStore.activeTab === item.id ? 'text-slate-900 dark:text-slate-100 font-bold' : 'text-slate-700 dark:text-slate-300'"
        >
          {{ t(item.title) }}
        </span>
        <span class="text-[11px] line-clamp-1 opacity-75">
          {{ t(item.desc) }}
        </span>
      </div>
    </button>
  </aside>
</template>
