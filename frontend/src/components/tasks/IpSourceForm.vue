<script setup lang="ts">
import type { IpFetchConfig } from '@/types/task'
import { AlertCircle, Check, Globe, RefreshCw } from 'lucide-vue-next'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { taskApi } from '@/api'
import { STUN_PRESETS_V4, STUN_PRESETS_V6 } from '@/constants'
import { useConfigStore } from '@/stores/config'

import { useToastStore } from '@/stores/toast'

const props = defineProps<{
  type: 'ipv4' | 'ipv6'
  config: IpFetchConfig
}>()

const configStore = useConfigStore()
const toast = useToastStore()
const { t } = useI18n()

const isV4 = computed(() => props.type === 'ipv4')
const typeUpper = computed(() => props.type.toUpperCase())

// STUN 预设集群选项
const stunPresets = computed(() =>
  isV4.value
    ? [{ label: t('dns.stunDefaultPool'), value: '' }, ...STUN_PRESETS_V4]
    : [{ label: t('dns.stunDefaultPoolV6'), value: '' }, ...STUN_PRESETS_V6],
)

// 探测测试状态
const isProbing = ref(false)
const probeResult = ref<{ success: boolean, ip?: string, error?: string } | null>(null)

// 域名列表转换
const domainsText = computed({
  get: () => (props.config.domains || []).join('\n'),
  set: (val: string) => {
    props.config.domains = val
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean)
  },
})

// URL 列表逗号转换
const urlsText = computed({
  get: () => (props.config.url_endpoints || []).join(', '),
  set: (val: string) => {
    props.config.url_endpoints = val
      .split(',')
      .map(s => s.trim())
      .filter(Boolean)
  },
})

// STUN 选择联动
const selectedStunPreset = computed({
  get: () => {
    const cur = props.config.stun_server || ''
    const found = stunPresets.value.find(p => p.value === cur)
    return found ? cur : '__custom__'
  },
  set: (val: string) => {
    if (val !== '__custom__') {
      props.config.stun_server = val || null
    }
  },
})

// 网卡设备选择联动
const selectedNetIf = computed({
  get: () => {
    const cur = props.config.net_interface || ''
    const found = configStore.networkInterfaces.find(i => i.name === cur)
    return found ? cur : (cur ? '__custom__' : '')
  },
  set: (val: string) => {
    if (val !== '__custom__') {
      props.config.net_interface = val || null
    }
  },
})

// 测试探测 IP
async function runProbeTest() {
  isProbing.value = true
  probeResult.value = null
  try {
    const res = await taskApi.testIp({
      ip_type: props.type,
      http_interface: configStore.currentTask?.http_interface || null,
      ...props.config,
    })
    if (res.success && res.data) {
      const fetchedIp = isV4.value ? res.data.ipv4 : res.data.ipv6
      if (fetchedIp) {
        probeResult.value = { success: true, ip: fetchedIp }
        toast.success(t('dns.probeToastSuccess', { type: typeUpper.value, ip: fetchedIp }))
      }
      else {
        probeResult.value = { success: false, error: t('dns.probeNone', { type: typeUpper.value }) }
        toast.error(t('dns.probeToastNone', { type: typeUpper.value }))
      }
    }
    else {
      probeResult.value = { success: false, error: res.message }
      toast.error(t('dns.probeFailed', { message: res.message }))
    }
  }
  catch (e: unknown) {
    const errMsg = e instanceof Error ? e.message : String(e)
    probeResult.value = { success: false, error: errMsg }
    toast.error(t('common.requestError', { error: errMsg }))
  }
  finally {
    isProbing.value = false
  }
}
</script>

<template>
  <div class="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col gap-6 shadow-xs transition-colors">
    <!-- 头部勾选与即时探测 -->
    <div class="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800/80">
      <div class="flex items-center gap-3">
        <label class="relative inline-flex items-center cursor-pointer">
          <input
            v-model="config.enabled"
            type="checkbox"
            class="sr-only peer"
          >
          <div class="w-9 h-5 bg-slate-300 dark:bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-indigo-600" />
        </label>
        <div>
          <h2 class="text-sm font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            <Globe class="w-4 h-4 text-indigo-600 dark:text-indigo-400" />
            {{ isV4 ? t('dns.enableIpv4') : t('dns.enableIpv6') }}
          </h2>
          <p class="text-[11px] text-slate-500 dark:text-slate-400">
            {{ isV4 ? '配置公网 IPv4 获取策略与解析域名' : '配置公网 IPv6 获取策略与解析域名' }}
          </p>
        </div>
      </div>

      <div class="flex items-center gap-2">
        <!-- 探测结果高亮徽标 -->
        <div
          v-if="probeResult"
          class="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono border animate-in fade-in duration-200"
          :class="probeResult.success ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30' : 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/30'"
        >
          <Check v-if="probeResult.success" class="w-3.5 h-3.5" />
          <AlertCircle v-else class="w-3.5 h-3.5" />
          <span>{{ probeResult.success ? probeResult.ip : probeResult.error }}</span>
        </div>

        <button
          type="button"
          :disabled="isProbing || !config.enabled"
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs text-slate-700 dark:text-slate-200 transition disabled:opacity-50 cursor-pointer"
          @click="runProbeTest"
        >
          <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': isProbing }" />
          <span>{{ isProbing ? t('dns.probing') : (isV4 ? t('dns.probeBtnV4') : t('dns.probeBtnV6')) }}</span>
        </button>
      </div>
    </div>

    <!-- 字段内容 (仅在启用时展示或可编辑) -->
    <div :class="{ 'opacity-50 pointer-events-none': !config.enabled }" class="flex flex-col gap-5 transition-opacity">
      <!-- 途径选择 -->
      <div class="flex flex-col gap-1.5">
        <label class="text-xs font-semibold text-slate-700 dark:text-slate-300">
          {{ isV4 ? t('dns.sourceTypeLabelV4') : t('dns.sourceTypeLabelV6') }}
        </label>
        <select
          v-model="config.source_type"
          class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all cursor-pointer"
        >
          <option value="url">
            {{ isV4 ? t('dns.sourceUrl') : t('dns.sourceUrlV6') }}
          </option>
          <option value="net_interface">
            {{ isV4 ? t('dns.sourceNetIf') : t('dns.sourceNetIfV6') }}
          </option>
          <option value="stun">
            {{ isV4 ? t('dns.sourceStun') : t('dns.sourceStunV6') }}
          </option>
          <option value="command">
            {{ t('dns.sourceCmd') }}
          </option>
        </select>
      </div>

      <!-- 1. URL 探测途径 -->
      <div v-if="config.source_type === 'url'" class="flex flex-col gap-1.5">
        <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('dns.probeUrlLabel') }}</label>
        <input
          v-model="urlsText"
          type="text"
          class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
        >
      </div>

      <!-- 2. 网卡直读途径 -->
      <div v-else-if="config.source_type === 'net_interface'" class="flex flex-col gap-3">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('dns.netIfSelectLabel') }}</label>
          <select
            v-model="selectedNetIf"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all cursor-pointer"
          >
            <option value="">
              {{ t('dns.netIfSelectPlaceholder') }}
            </option>
            <option
              v-for="iface in configStore.networkInterfaces"
              :key="iface.name"
              :value="iface.name"
            >
              {{ iface.display_name || iface.name }}
            </option>
            <option value="__custom__">
              {{ t('dns.netIfCustomOption') }}
            </option>
          </select>
        </div>
        <input
          v-if="selectedNetIf === '__custom__'"
          v-model="config.net_interface"
          type="text"
          :placeholder="t('dns.netIfCustomPlaceholder')"
          class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
        >
      </div>

      <!-- 3. STUN 协议途径 -->
      <div v-else-if="config.source_type === 'stun'" class="flex flex-col gap-3">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('dns.stunServerSelectLabel') }}</label>
          <select
            v-model="selectedStunPreset"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all cursor-pointer"
          >
            <option
              v-for="p in stunPresets"
              :key="p.value"
              :value="p.value"
            >
              {{ p.label }}
            </option>
            <option value="__custom__">
              {{ t('dns.stunCustomOption') }}
            </option>
          </select>
        </div>
        <input
          v-if="selectedStunPreset === '__custom__'"
          v-model="config.stun_server"
          type="text"
          :placeholder="t('dns.stunCustomPlaceholder')"
          class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
        >
      </div>

      <!-- 4. 命令提取途径 -->
      <div v-else-if="config.source_type === 'command'" class="flex flex-col gap-1.5">
        <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('dns.cmdLabel') }}</label>
        <input
          v-model="config.cmd"
          type="text"
          :placeholder="t('dns.cmdPlaceholder')"
          class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 font-mono focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
        >
      </div>

      <!-- 正则表达式 / 匹配语法 -->
      <div class="flex flex-col gap-1.5">
        <div class="flex items-center justify-between">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">
            {{ isV4 ? t('dns.regexLabel') : t('dns.regexV6Label') }}
          </label>
          <span class="text-[11px] text-slate-500">
            {{ isV4 ? t('dns.regexHint') : t('dns.regexV6Tip') }}
          </span>
        </div>
        <input
          v-model="config.regex"
          type="text"
          :placeholder="isV4 ? t('dns.regexPlaceholder') : t('dns.regexV6Placeholder')"
          class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 font-mono focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
        >
      </div>

      <!-- 域名列表 -->
      <div class="flex flex-col gap-1.5">
        <div class="flex items-center justify-between">
          <label class="text-xs font-semibold text-slate-700 dark:text-slate-300">
            {{ isV4 ? t('dns.domainsLabelV4') : t('dns.domainsLabelV6') }}
          </label>
          <span class="text-[11px] text-slate-500">{{ t('dns.domainsHint') }}</span>
        </div>
        <textarea
          v-model="domainsText"
          rows="4"
          :placeholder="isV4 ? t('dns.domainsPlaceholderV4') : t('dns.domainsPlaceholderV6')"
          class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg p-3 text-sm text-slate-800 dark:text-slate-100 font-mono focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all resize-y"
        />
      </div>
    </div>
  </div>
</template>
