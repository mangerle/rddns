<script setup lang="ts">
import { ArrowRight, Globe, Moon, Sparkles, Sun } from 'lucide-vue-next'
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import PasswordInput from '@/components/common/PasswordInput.vue'
import { getLocale, setLocale } from '@/i18n'
import { useAuthStore } from '@/stores/auth'
import { useConfigStore } from '@/stores/config'
import { useLogStore } from '@/stores/log'
import { useThemeStore } from '@/stores/theme'
import { useToastStore } from '@/stores/toast'
import { useVersionStore } from '@/stores/version'

const authStore = useAuthStore()
const configStore = useConfigStore()
const logStore = useLogStore()
const versionStore = useVersionStore()
const themeStore = useThemeStore()
const toast = useToastStore()
const { t } = useI18n()

const username = ref('admin')
const password = ref('')
const confirmPassword = ref('')
const isSubmitting = ref(false)

async function handleInit() {
  if (!username.value.trim()) {
    toast.error(t('auth.usernameEmpty'))
    return
  }
  if (!password.value || password.value.length < 4) {
    toast.error(t('auth.passwordMinLength'))
    return
  }
  if (password.value !== confirmPassword.value) {
    toast.error(t('auth.passwordMismatch'))
    return
  }

  isSubmitting.value = true
  const ok = await authStore.submitInit(username.value.trim(), password.value)
  isSubmitting.value = false
  if (ok) {
    await configStore.loadConfig()
    await configStore.loadNetworkInterfaces()
    logStore.initSSE()
    versionStore.loadVersion()
  }
}

function toggleLang() {
  const current = getLocale()
  setLocale(current === 'zh-CN' ? 'en-US' : 'zh-CN')
}
</script>

<template>
  <div class="h-screen w-screen flex flex-col justify-center items-center bg-slate-100 dark:bg-slate-950 text-slate-800 dark:text-slate-100 p-6 relative overflow-hidden select-none transition-colors duration-150">
    <div class="absolute top-6 right-6 flex items-center gap-3">
      <button
        type="button"
        class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/60 hover:bg-slate-50 dark:hover:bg-slate-800 text-xs text-slate-700 dark:text-slate-300 transition cursor-pointer"
        @click="toggleLang"
      >
        <Globe class="w-3.5 h-3.5" />
        <span>{{ getLocale() === 'zh-CN' ? 'EN' : '中' }}</span>
      </button>
      <button
        type="button"
        class="p-2 rounded-lg border border-slate-300 dark:border-slate-800 bg-white dark:bg-slate-900/60 hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 transition cursor-pointer"
        @click="themeStore.toggleTheme"
      >
        <Sun v-if="themeStore.isDark" class="w-3.5 h-3.5 text-amber-400" />
        <Moon v-else class="w-3.5 h-3.5 text-indigo-600" />
      </button>
    </div>

    <div class="w-full max-w-[440px] bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 rounded-2xl p-8 shadow-xl dark:shadow-2xl backdrop-blur-xl flex flex-col gap-6 transition-colors">
      <div class="flex flex-col items-center text-center gap-2">
        <div class="w-14 h-14 rounded-2xl bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-600 dark:text-indigo-400 mb-2">
          <Sparkles class="w-8 h-8" />
        </div>
        <h1 class="text-xl font-bold text-slate-900 dark:text-slate-100 tracking-tight">
          {{ t('auth.initTitle') }}
        </h1>
        <p class="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
          {{ t('auth.initDesc') }}
        </p>
      </div>

      <form class="flex flex-col gap-4" @submit.prevent="handleInit">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-semibold text-slate-700 dark:text-slate-300">{{ t('auth.usernameLabel') }}</label>
          <input
            v-model="username"
            type="text"
            :placeholder="t('auth.usernamePlaceholder')"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
            required
          >
        </div>

        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-semibold text-slate-700 dark:text-slate-300">{{ t('auth.initPasswordLabel') }}</label>
          <PasswordInput
            v-model="password"
            :placeholder="t('auth.initPasswordPlaceholder')"
          />
        </div>

        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-semibold text-slate-700 dark:text-slate-300">{{ t('auth.initConfirmPasswordLabel') }}</label>
          <PasswordInput
            v-model="confirmPassword"
            :placeholder="t('auth.initConfirmPasswordPlaceholder')"
          />
        </div>

        <button
          type="submit"
          :disabled="isSubmitting || !username.trim() || !password || !confirmPassword"
          class="w-full mt-2 flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-500 active:bg-indigo-700 text-white font-medium py-2.5 px-4 rounded-lg shadow-lg shadow-indigo-600/20 transition disabled:opacity-50 cursor-pointer"
        >
          <span>{{ isSubmitting ? t('common.saving') : t('auth.initBtn') }}</span>
          <ArrowRight class="w-4 h-4" />
        </button>
      </form>
    </div>
  </div>
</template>
