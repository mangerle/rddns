<script setup lang="ts">
import { Clock, Lock } from 'lucide-vue-next'
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import PasswordInput from '@/components/common/PasswordInput.vue'
import { useConfigStore } from '@/stores/config'

const configStore = useConfigStore()
const { t } = useI18n()

const newPassword = ref('')

// 确保 auth 对象存在
if (!configStore.config.auth) {
  configStore.config.auth = { username: 'admin' }
}
</script>

<template>
  <div class="flex-1 overflow-y-auto p-6 flex flex-col gap-6">
    <!-- 运行与同步参数 -->
    <div class="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col gap-5 shadow-xs transition-colors">
      <div class="flex items-center gap-2.5 pb-4 border-b border-slate-100 dark:border-slate-800/80">
        <div class="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-600 dark:text-indigo-400">
          <Clock class="w-4 h-4" />
        </div>
        <div>
          <h2 class="text-sm font-bold text-slate-800 dark:text-slate-100">
            {{ t('system.runTitle') }}
          </h2>
          <p class="text-[11px] text-slate-500 dark:text-slate-400">
            调整后台常驻探测心跳、缓存校对周期及网络隔离
          </p>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-semibold text-slate-700 dark:text-slate-300">{{ t('system.intervalLabel') }}</label>
          <input
            v-model.number="configStore.config.interval_secs"
            type="number"
            min="5"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 font-mono focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
          >
          <span class="text-[11px] text-slate-500 dark:text-slate-400">{{ t('system.intervalTip') }}</span>
        </div>

        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-semibold text-slate-700 dark:text-slate-300">{{ t('system.cacheTimesLabel') }}</label>
          <input
            v-model.number="configStore.config.cache_times"
            type="number"
            min="1"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 font-mono focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
          >
          <span class="text-[11px] text-slate-500 dark:text-slate-400">{{ t('system.cacheTimesTip') }}</span>
        </div>
      </div>

      <!-- 禁止 WAN 访问 -->
      <label class="flex items-center gap-3 p-4 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800/80 cursor-pointer hover:border-slate-300 dark:hover:border-slate-700 transition">
        <input
          v-model="configStore.config.not_allow_wan_access"
          type="checkbox"
          class="rounded border-slate-300 dark:border-slate-700 text-indigo-600 focus:ring-indigo-500 bg-white dark:bg-slate-900"
        >
        <div class="flex flex-col">
          <span class="text-xs font-semibold text-slate-800 dark:text-slate-200">{{ t('system.notAllowWan') }}</span>
          <span class="text-[11px] text-slate-500 dark:text-slate-400">仅允许局域网私有网段 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) 访问控制台</span>
        </div>
      </label>

      <!-- 自定义公共 DNS 服务器 -->
      <div class="flex flex-col gap-1.5">
        <div class="flex items-center justify-between">
          <label class="text-xs font-semibold text-slate-700 dark:text-slate-300">{{ t('system.dnsServerLabel') }}</label>
          <span class="text-[11px] text-slate-500">{{ t('system.dnsServerHint') }}</span>
        </div>
        <input
          v-model="configStore.config.dns_server"
          type="text"
          :placeholder="t('system.dnsServerPlaceholder')"
          class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 font-mono focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
        >
        <span class="text-[11px] text-slate-500 dark:text-slate-400">{{ t('system.dnsServerTip') }}</span>
      </div>
    </div>

    <!-- Web 管理员身份认证 (Basic Auth) -->
    <div class="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col gap-5 shadow-xs transition-colors">
      <div class="flex items-center gap-2.5 pb-4 border-b border-slate-100 dark:border-slate-800/80">
        <div class="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-600 dark:text-indigo-400">
          <Lock class="w-4 h-4" />
        </div>
        <div>
          <h2 class="text-sm font-bold text-slate-800 dark:text-slate-100">
            {{ t('system.authTitle') }}
          </h2>
          <p class="text-[11px] text-slate-500 dark:text-slate-400">
            {{ t('system.authTip') }}
          </p>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-5">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-semibold text-slate-700 dark:text-slate-300">{{ t('system.authUsernameLabel') }}</label>
          <input
            v-if="configStore.config.auth"
            v-model="configStore.config.auth.username"
            type="text"
            :placeholder="t('system.authUsernamePlaceholder')"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
          >
        </div>

        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-semibold text-slate-700 dark:text-slate-300">{{ t('system.authPasswordLabel') }}</label>
          <PasswordInput
            v-model="newPassword"
            :placeholder="t('system.authPasswordPlaceholder')"
          />
        </div>
      </div>
    </div>
  </div>
</template>
