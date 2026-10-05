<script setup lang="ts">
import type { DnsTaskConfig } from '@/types/task'
import { Copy, Sliders, Trash2 } from 'lucide-vue-next'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useConfigStore } from '@/stores/config'
import DnsProviderForm from './DnsProviderForm.vue'
import IpSourceForm from './IpSourceForm.vue'

const props = defineProps<{
  task: DnsTaskConfig
}>()

const configStore = useConfigStore()
const { t } = useI18n()

// TTL 联动选择
const ttlOptions = [
  { label: 'dns.ttlAuto', value: '' },
  { label: 'dns.ttl1s', value: '1' },
  { label: 'dns.ttl1m', value: '60' },
  { label: 'dns.ttl2m', value: '120' },
  { label: 'dns.ttl10m', value: '600' },
  { label: 'dns.ttl30m', value: '1800' },
  { label: 'dns.ttl1h', value: '3600' },
  { label: 'dns.ttl1d', value: '86400' },
]

const selectedTtl = computed({
  get: () => {
    if (props.task.ttl === null || props.task.ttl === undefined || props.task.ttl === 0) {
      return ''
    }
    const str = String(props.task.ttl)
    return ttlOptions.some(o => o.value === str) ? str : '__custom__'
  },
  set: (val: string) => {
    if (val === '') {
      props.task.ttl = null
    }
    else if (val !== '__custom__') {
      props.task.ttl = parseInt(val) || null
    }
  },
})
</script>

<template>
  <div class="flex-1 overflow-y-auto p-6 flex flex-col gap-6">
    <!-- 任务操作顶栏 -->
    <div class="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-5 flex flex-wrap items-center justify-between gap-4 shadow-xs transition-colors">
      <div class="flex items-center gap-4 flex-1 min-w-[280px]">
        <label class="relative inline-flex items-center cursor-pointer">
          <input
            v-model="task.enabled"
            type="checkbox"
            class="sr-only peer"
          >
          <div class="w-9 h-5 bg-slate-300 dark:bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-indigo-600" />
        </label>

        <div class="flex flex-col gap-1 flex-1">
          <input
            v-model="task.name"
            type="text"
            :placeholder="t('task.namePlaceholder')"
            class="bg-transparent border-b border-transparent hover:border-slate-300 dark:hover:border-slate-700 focus:border-indigo-500 font-bold text-base text-slate-900 dark:text-slate-100 px-1 py-0.5 transition-all outline-none"
          >
          <span class="text-[11px] text-slate-500 dark:text-slate-400 pl-1">
            {{ task.enabled ? t('task.enableTask') : t('common.disable') }}
          </span>
        </div>
      </div>

      <div class="flex items-center gap-2">
        <button
          type="button"
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs text-slate-700 dark:text-slate-300 transition cursor-pointer"
          @click="configStore.cloneTask"
        >
          <Copy class="w-3.5 h-3.5" />
          <span>{{ t('common.copy') }}</span>
        </button>
        <button
          type="button"
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 hover:bg-rose-50 dark:hover:bg-rose-500/10 hover:border-rose-300 dark:hover:border-rose-500/30 text-xs text-rose-600 dark:text-rose-400 transition cursor-pointer"
          @click="configStore.deleteTask"
        >
          <Trash2 class="w-3.5 h-3.5" />
          <span>{{ t('common.delete') }}</span>
        </button>
      </div>
    </div>

    <!-- 高级网络与 TTL 参数卡片 -->
    <div class="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col gap-5 shadow-xs transition-colors">
      <div class="flex items-center gap-2.5 pb-4 border-b border-slate-100 dark:border-slate-800/80">
        <div class="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-600 dark:text-indigo-400">
          <Sliders class="w-4 h-4" />
        </div>
        <div>
          <h2 class="text-sm font-bold text-slate-800 dark:text-slate-100">
            解析高级策略
          </h2>
          <p class="text-[11px] text-slate-500 dark:text-slate-400">
            配置 TTL 记录缓存时间与 HTTP 物理网卡出站出口
          </p>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
        <!-- TTL 设置 -->
        <div class="flex flex-col gap-2">
          <div class="flex items-center justify-between">
            <label class="text-xs font-semibold text-slate-700 dark:text-slate-300">{{ t('dns.ttlLabel') }}</label>
            <span class="text-[11px] text-slate-500">{{ t('dns.ttlHint') }}</span>
          </div>
          <select
            v-model="selectedTtl"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all cursor-pointer"
          >
            <option
              v-for="opt in ttlOptions"
              :key="opt.value"
              :value="opt.value"
            >
              {{ t(opt.label) }}
            </option>
            <option value="__custom__">
              {{ t('dns.ttlCustom') }}
            </option>
          </select>
          <input
            v-if="selectedTtl === '__custom__'"
            :value="task.ttl || ''"
            type="number"
            min="1"
            :placeholder="t('dns.ttlCustomPlaceholder')"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all font-mono"
            @input="task.ttl = parseInt(($event.target as HTMLInputElement).value) || null"
          >
        </div>

        <!-- 出站网卡设置 -->
        <div class="flex flex-col gap-2">
          <div class="flex items-center justify-between">
            <label class="text-xs font-semibold text-slate-700 dark:text-slate-300">{{ t('dns.httpInterfaceLabel') }}</label>
            <span class="text-[11px] text-slate-500">{{ t('dns.httpInterfaceHint') }}</span>
          </div>
          <select
            v-model="task.http_interface"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all cursor-pointer"
          >
            <option :value="null">
              {{ t('dns.httpInterfaceDefault') }}
            </option>
            <option
              v-for="iface in configStore.networkInterfaces"
              :key="iface.name"
              :value="iface.name"
            >
              {{ iface.display_name || iface.name }}
            </option>
            <option
              v-if="task.http_interface && !configStore.networkInterfaces.some((i) => i.name === task.http_interface)"
              :value="task.http_interface"
            >
              {{ t('dns.httpInterfaceOffline', { name: task.http_interface }) }}
            </option>
          </select>
          <p class="text-[11px] text-slate-500 dark:text-slate-400">
            {{ t('dns.httpInterfaceTip') }}
          </p>
        </div>
      </div>
    </div>

    <!-- DNS 服务商凭证配置表单 -->
    <DnsProviderForm :task="task" />

    <!-- IPv4 策略与域名配置 -->
    <IpSourceForm type="ipv4" :config="task.ipv4" />

    <!-- IPv6 策略与域名配置 -->
    <IpSourceForm type="ipv6" :config="task.ipv6" />
  </div>
</template>
