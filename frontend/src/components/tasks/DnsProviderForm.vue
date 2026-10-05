<script setup lang="ts">
import type { ProviderType } from '@/types/provider'
import type { DnsTaskConfig } from '@/types/task'
import { Shield } from 'lucide-vue-next'
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import PasswordInput from '@/components/common/PasswordInput.vue'
import { PROVIDER_DISPLAY_NAMES } from '@/types/provider'

const props = defineProps<{
  task: DnsTaskConfig
}>()

const { t } = useI18n()

const providerType = computed<ProviderType>({
  get: () => props.task.provider?.type || 'cloudflare',
  set: (val: ProviderType) => {
    switchProvider(val)
  },
})

function switchProvider(newType: ProviderType) {
  if (props.task.provider?.type === newType)
    return
  // 保留基本字段结构
  const p: Record<string, unknown> = { type: newType }
  if (newType === 'cloudflare') {
    p.api_token = ''
    p.api_key = ''
    p.email = ''
  }
  else if (newType === 'ali_dns' || newType === 'aliesa') {
    p.access_key_id = ''
    p.access_key_secret = ''
    p.endpoint = null
  }
  else if (newType === 'tencent_cloud' || newType === 'edgeone') {
    p.secret_id = ''
    p.secret_key = ''
  }
  else if (newType === 'huawei_cloud') {
    p.access_key_id = ''
    p.secret_access_key = ''
    p.endpoint = null
  }
  else if (newType === 'porkbun') {
    p.api_key = ''
    p.secret_key = ''
  }
  else if (newType === 'godaddy' || newType === 'spaceship' || newType === 'dnsla') {
    p.api_key = ''
    p.api_secret = ''
  }
  else if (newType === 'dynv6') {
    p.token = ''
  }
  else if (newType === 'baidu_cloud' || newType === 'traffic_route') {
    p.access_key_id = ''
    p.secret_access_key = ''
  }
  else if (newType === 'namecheap' || newType === 'dynadot') {
    p.password = ''
  }
  else if (newType === 'namesilo' || newType === 'gcore' || newType === 'nsone') {
    p.api_key = ''
  }
  else if (newType === 'vercel') {
    p.token = ''
    p.team_id = null
  }
  else if (newType === 'rainyun') {
    p.api_key = ''
    p.domain_id = null
  }
  else if (newType === 'cloudns') {
    p.auth_id = ''
    p.auth_password = ''
  }
  else if (newType === 'name_com') {
    p.username = ''
    p.api_token = ''
  }
  else if (newType === 'nowcn' || newType === 'eranet' || newType === 'tnethk') {
    p.id = ''
    p.secret = ''
  }
  else if (newType === 'hipm_dnsmgr') {
    p.api_token = ''
    p.endpoint = null
  }
  else if (newType === 'callback') {
    p.url = ''
    p.method = 'GET'
    p.headers = null
    p.body = null
  }
  props.task.provider = p as unknown as typeof props.task.provider
}

// 通配类型访问辅助
const p = computed<Record<string, unknown>>(() => (props.task.provider || {}) as unknown as Record<string, unknown>)

function onCallbackHeadersInput(e: Event) {
  const val = (e.target as HTMLInputElement).value?.trim()
  if (!val) {
    p.value.headers = null
    return
  }
  try {
    p.value.headers = JSON.parse(val)
  }
  catch {}
}
</script>

<template>
  <div class="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col gap-6 shadow-xs transition-colors">
    <div class="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800/80">
      <div class="flex items-center gap-2.5">
        <div class="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-600 dark:text-indigo-400">
          <Shield class="w-4 h-4" />
        </div>
        <div>
          <h2 class="text-sm font-bold text-slate-800 dark:text-slate-100">
            {{ t('dns.cardTitle') }}
          </h2>
          <p class="text-[11px] text-slate-500 dark:text-slate-400">
            选择域名托管服务商并配置 API 鉴权密钥
          </p>
        </div>
      </div>
      <span class="text-[11px] font-mono px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20">
        {{ t('dns.nativeBadge') }}
      </span>
    </div>

    <!-- 服务商下拉选择 -->
    <div class="flex flex-col gap-2">
      <label class="text-xs font-semibold text-slate-700 dark:text-slate-300">{{ t('dns.providerSelectLabel') }}</label>
      <select
        v-model="providerType"
        class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all cursor-pointer"
      >
        <option
          v-for="(name, typeKey) in PROVIDER_DISPLAY_NAMES"
          :key="typeKey"
          :value="typeKey"
        >
          {{ name }}
        </option>
      </select>
    </div>

    <!-- 动态凭证表单字段 -->
    <div class="flex flex-col gap-4">
      <!-- 1. Cloudflare -->
      <template v-if="providerType === 'cloudflare'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">API Token ({{ t('common.recommended') }})</label>
            <PasswordInput v-model="p.api_token" placeholder="Cloudflare API Token" />
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Global API Key</label>
            <PasswordInput v-model="p.api_key" placeholder="Global API Key" />
          </div>
        </div>
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Account Email</label>
          <input
            v-model="p.email"
            type="text"
            placeholder="your_email@example.com"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
          >
        </div>
      </template>

      <!-- 2. AliDNS -->
      <template v-else-if="providerType === 'ali_dns'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">AccessKey ID</label>
            <input
              v-model="p.access_key_id"
              type="text"
              placeholder="Aliyun RAM AccessKey ID"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">AccessKey Secret</label>
            <PasswordInput v-model="p.access_key_secret" placeholder="Aliyun RAM AccessKey Secret" />
          </div>
        </div>
      </template>

      <!-- 3. Tencent Cloud DNSPod -->
      <template v-else-if="providerType === 'tencent_cloud'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">SecretId</label>
            <input
              v-model="p.secret_id"
              type="text"
              placeholder="Tencent Cloud API SecretId"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">SecretKey</label>
            <PasswordInput v-model="p.secret_key" placeholder="Tencent Cloud API SecretKey" />
          </div>
        </div>
      </template>

      <!-- 4. Huawei Cloud -->
      <template v-else-if="providerType === 'huawei_cloud'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">AccessKey ID (AK)</label>
            <input
              v-model="p.access_key_id"
              type="text"
              placeholder="Huawei Cloud AK"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Secret Access Key (SK)</label>
            <PasswordInput v-model="p.secret_access_key" placeholder="Huawei Cloud SK" />
          </div>
        </div>
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Endpoint ({{ t('common.optional') }})</label>
          <input
            v-model="p.endpoint"
            type="text"
            placeholder="https://dns.myhuaweicloud.com"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
          >
        </div>
      </template>

      <!-- 5. Porkbun -->
      <template v-else-if="providerType === 'porkbun'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">API Key</label>
            <input
              v-model="p.api_key"
              type="text"
              placeholder="pk1_..."
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Secret Key</label>
            <PasswordInput v-model="p.secret_key" placeholder="sk1_..." />
          </div>
        </div>
      </template>

      <!-- 6. GoDaddy -->
      <template v-else-if="providerType === 'godaddy'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">API Key</label>
            <input
              v-model="p.api_key"
              type="text"
              placeholder="GoDaddy API Key"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">API Secret</label>
            <PasswordInput v-model="p.api_secret" placeholder="GoDaddy API Secret" />
          </div>
        </div>
      </template>

      <!-- 7. Dynv6 -->
      <template v-else-if="providerType === 'dynv6'">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">HTTP Token</label>
          <PasswordInput v-model="p.token" placeholder="Dynv6 API Token" />
        </div>
      </template>

      <!-- 8. Baidu Cloud -->
      <template v-else-if="providerType === 'baidu_cloud'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">AccessKey (AK)</label>
            <input
              v-model="p.access_key_id"
              type="text"
              placeholder="Baidu Cloud AK"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">SecretKey (SK)</label>
            <PasswordInput v-model="p.secret_access_key" placeholder="Baidu Cloud SK" />
          </div>
        </div>
      </template>

      <!-- 9. TrafficRoute (火山引擎) -->
      <template v-else-if="providerType === 'traffic_route'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">AccessKey ID (AK)</label>
            <input
              v-model="p.access_key_id"
              type="text"
              placeholder="Volcengine AK"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Secret Access Key (SK)</label>
            <PasswordInput v-model="p.secret_access_key" placeholder="Volcengine SK" />
          </div>
        </div>
      </template>

      <!-- 10. Namecheap -->
      <template v-else-if="providerType === 'namecheap'">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Dynamic DNS Password</label>
          <PasswordInput v-model="p.password" placeholder="Namecheap Dynamic DNS Password" />
        </div>
      </template>

      <!-- 11. NameSilo -->
      <template v-else-if="providerType === 'namesilo'">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">API Key</label>
          <PasswordInput v-model="p.api_key" placeholder="NameSilo API Key" />
        </div>
      </template>

      <!-- 12. Spaceship -->
      <template v-else-if="providerType === 'spaceship'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">API Key (X-API-Key)</label>
            <input
              v-model="p.api_key"
              type="text"
              placeholder="Spaceship API Key"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">API Secret (X-API-Secret)</label>
            <PasswordInput v-model="p.api_secret" placeholder="Spaceship API Secret" />
          </div>
        </div>
      </template>

      <!-- 13. Dynadot -->
      <template v-else-if="providerType === 'dynadot'">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Dynamic DNS Password</label>
          <PasswordInput v-model="p.password" placeholder="Dynadot Dynamic DNS Password" />
        </div>
      </template>

      <!-- 14. Vercel -->
      <template v-else-if="providerType === 'vercel'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Vercel Token</label>
            <PasswordInput v-model="p.token" placeholder="Vercel Access Token" />
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Team ID ({{ t('common.optional') }})</label>
            <input
              v-model="p.team_id"
              type="text"
              placeholder="team_xxxx"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
        </div>
      </template>

      <!-- 15. RainYun -->
      <template v-else-if="providerType === 'rainyun'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">API Key (x-api-key)</label>
            <PasswordInput v-model="p.api_key" placeholder="Rainyun API Key" />
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Domain ID ({{ t('common.optional') }})</label>
            <input
              v-model="p.domain_id"
              type="text"
              placeholder="Domain ID"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
        </div>
      </template>

      <!-- 16. ClouDNS -->
      <template v-else-if="providerType === 'cloudns'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Auth ID</label>
            <input
              v-model="p.auth_id"
              type="text"
              placeholder="ClouDNS Auth ID"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Auth Password</label>
            <PasswordInput v-model="p.auth_password" placeholder="ClouDNS API Password" />
          </div>
        </div>
      </template>

      <!-- 17. Gcore -->
      <template v-else-if="providerType === 'gcore'">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Permanent API Key</label>
          <PasswordInput v-model="p.api_key" placeholder="APIKey xxx" />
        </div>
      </template>

      <!-- 18. Name.com -->
      <template v-else-if="providerType === 'name_com'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Username</label>
            <input
              v-model="p.username"
              type="text"
              placeholder="Name.com Username"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">API Token</label>
            <PasswordInput v-model="p.api_token" placeholder="Name.com API Token" />
          </div>
        </div>
      </template>

      <!-- 19. DNS.LA -->
      <template v-else-if="providerType === 'dnsla'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">API ID</label>
            <input
              v-model="p.api_id"
              type="text"
              placeholder="DNS.LA API ID"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">API Secret</label>
            <PasswordInput v-model="p.api_secret" placeholder="DNS.LA API Secret" />
          </div>
        </div>
      </template>

      <!-- 20. AliESA -->
      <template v-else-if="providerType === 'aliesa'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">AccessKey ID</label>
            <input
              v-model="p.access_key_id"
              type="text"
              placeholder="Aliyun AccessKey ID"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">AccessKey Secret</label>
            <PasswordInput v-model="p.access_key_secret" placeholder="Aliyun AccessKey Secret" />
          </div>
        </div>
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">ESA Endpoint ({{ t('common.optional') }})</label>
          <input
            v-model="p.endpoint"
            type="text"
            placeholder="https://esa.cn-hangzhou.aliyuncs.com"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
          >
        </div>
      </template>

      <!-- 21. EdgeOne -->
      <template v-else-if="providerType === 'edgeone'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">SecretId</label>
            <input
              v-model="p.secret_id"
              type="text"
              placeholder="Tencent Cloud API SecretId"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">SecretKey</label>
            <PasswordInput v-model="p.secret_key" placeholder="Tencent Cloud API SecretKey" />
          </div>
        </div>
      </template>

      <!-- 22. NowCn / 23. Eranet / 24. TNetHK -->
      <template v-else-if="providerType === 'nowcn' || providerType === 'eranet' || providerType === 'tnethk'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">AccessInstanceID</label>
            <input
              v-model="p.id"
              type="text"
              placeholder="AccessInstanceID"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">SecretKey</label>
            <PasswordInput v-model="p.secret" placeholder="SecretKey" />
          </div>
        </div>
      </template>

      <!-- 25. NS1 (IBM NS1) -->
      <template v-else-if="providerType === 'nsone'">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">API Key (Secret)</label>
          <PasswordInput v-model="p.api_key" placeholder="IBM NS1 Connect API Key" />
        </div>
      </template>

      <!-- 26. HiPM DNSMgr -->
      <template v-else-if="providerType === 'hipm_dnsmgr'">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">API Token</label>
            <PasswordInput v-model="p.api_token" placeholder="HiPM DNSMgr API Token" />
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">DNSMgr Endpoint ({{ t('common.optional') }})</label>
            <input
              v-model="p.endpoint"
              type="text"
              placeholder="https://dnsmgr.example.com"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
          </div>
        </div>
      </template>

      <!-- 27. Callback (自定义 Webhook) -->
      <template v-else-if="providerType === 'callback'">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">Callback URL (支持 #{ip}, #{domain}, #{recordType})</label>
          <input
            v-model="p.url"
            type="text"
            placeholder="https://api.myprovider.com/update?ip=#{ip}&domain=#{domain}"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 font-mono focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
          >
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">HTTP 请求方法</label>
            <select
              v-model="p.method"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            >
              <option value="GET">
                GET
              </option>
              <option value="POST">
                POST
              </option>
              <option value="PUT">
                PUT
              </option>
            </select>
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">自定义 Headers (JSON 格式，可选)</label>
            <input
              :value="p.headers ? JSON.stringify(p.headers) : ''"
              type="text"
              placeholder="{&quot;Authorization&quot;: &quot;Bearer token&quot;}"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 font-mono focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
              @input="onCallbackHeadersInput"
            >
          </div>
        </div>
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">请求体 (可选，支持 #{ip}, #{domain}, #{recordType})</label>
          <textarea
            v-model="p.body"
            rows="2"
            placeholder="{&quot;ip&quot;: &quot;#{ip}&quot;, &quot;domain&quot;: &quot;#{domain}&quot;}"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg p-3 text-xs text-slate-800 dark:text-slate-100 font-mono focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
          />
        </div>
      </template>
    </div>
  </div>
</template>
