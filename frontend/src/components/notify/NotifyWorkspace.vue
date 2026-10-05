<script setup lang="ts">
import {
  Bell,
  Bot,
  Globe,
  Mail,
  MessageSquare,
  Radio,
  RefreshCw,
  Send,
  Smartphone,
} from 'lucide-vue-next'
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { notifyApi } from '@/api'
import PasswordInput from '@/components/common/PasswordInput.vue'
import { EMAIL_PRESETS } from '@/constants'
import { useConfigStore } from '@/stores/config'

import { useToastStore } from '@/stores/toast'

const configStore = useConfigStore()
const toast = useToastStore()
const { t } = useI18n()

const testingChannel = ref<string | null>(null)
const isTestingAll = ref(false)

// 保持深度响应式的 notifications 计算属性
const notifications = computed(() => configStore.notifications)

function applyEmailPreset(e: Event) {
  const val = (e.target as HTMLSelectElement).value
  if (val && EMAIL_PRESETS[val] && notifications.value.email) {
    const p = EMAIL_PRESETS[val]
    notifications.value.email.smtp_server = p.server
    notifications.value.email.smtp_port = p.port
    notifications.value.email.use_ssl = p.ssl
  }
}

// 邮件收件人逗号分割转换
function getEmailToText(): string {
  return (notifications.value.email?.to_addresses || []).join(', ')
}
function setEmailToText(val: string) {
  if (notifications.value.email) {
    notifications.value.email.to_addresses = val
      .split(',')
      .map(s => s.trim())
      .filter(Boolean)
  }
}

// 发送单渠道测试通知
async function runSingleTest(channel: string) {
  testingChannel.value = channel
  toast.info(t('notify.testing'))
  try {
    const res = await notifyApi.testNotify({
      channel,
      config: notifications.value,
    })
    if (res.success) {
      toast.success(t('notify.testSent'))
    }
    else {
      toast.error(t('notify.testFailed', { message: res.message }))
    }
  }
  catch (e: unknown) {
    const errMsg = e instanceof Error ? e.message : String(e)
    toast.error(t('common.requestError', { error: errMsg }))
  }
  finally {
    testingChannel.value = null
  }
}

// 测试全部启用的渠道
async function runTestAll() {
  isTestingAll.value = true
  toast.info(t('notify.testing'))
  try {
    const res = await notifyApi.testNotify({
      config: notifications.value,
    })
    if (res.success) {
      toast.success(t('notify.testAllSent'))
    }
    else {
      toast.error(t('notify.testFailed', { message: res.message }))
    }
  }
  catch (e: unknown) {
    const errMsg = e instanceof Error ? e.message : String(e)
    toast.error(t('common.requestError', { error: errMsg }))
  }
  finally {
    isTestingAll.value = false
  }
}

function onWebhookHeadersInput(e: Event) {
  const val = (e.target as HTMLInputElement).value?.trim()
  if (!val) {
    if (notifications.value.webhook)
      notifications.value.webhook.headers = null
    return
  }
  try {
    if (notifications.value.webhook)
      notifications.value.webhook.headers = JSON.parse(val)
  }
  catch {}
}
</script>

<template>
  <div class="flex-1 overflow-y-auto p-6 flex flex-col gap-6">
    <!-- 全局通知触发策略 -->
    <div class="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col gap-5 shadow-xs transition-colors">
      <div class="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800/80">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-600 dark:text-indigo-400">
            <Bell class="w-4 h-4" />
          </div>
          <div>
            <h2 class="text-sm font-bold text-slate-800 dark:text-slate-100">
              {{ t('notify.policyTitle') }}
            </h2>
            <p class="text-[11px] text-slate-500 dark:text-slate-400">
              设定何时向已配置的通信终端发送变动或告警消息
            </p>
          </div>
        </div>

        <button
          type="button"
          :disabled="isTestingAll"
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs text-slate-700 dark:text-slate-200 transition cursor-pointer"
          @click="runTestAll"
        >
          <Send class="w-3.5 h-3.5" :class="{ 'animate-spin': isTestingAll }" />
          <span>{{ t('notify.testAllBtn') }}</span>
        </button>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <label class="flex items-center gap-3 p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800/80 cursor-pointer hover:border-slate-300 dark:hover:border-slate-700 transition">
          <input
            v-model="notifications.on_success"
            type="checkbox"
            class="rounded border-slate-300 dark:border-slate-700 text-indigo-600 focus:ring-indigo-500 bg-white dark:bg-slate-900"
          >
          <span class="text-xs font-medium text-slate-800 dark:text-slate-200">{{ t('notify.onSuccess') }}</span>
        </label>

        <label class="flex items-center gap-3 p-3.5 rounded-xl bg-slate-50 dark:bg-slate-950/60 border border-slate-200 dark:border-slate-800/80 cursor-pointer hover:border-slate-300 dark:hover:border-slate-700 transition">
          <input
            v-model="notifications.on_failure"
            type="checkbox"
            class="rounded border-slate-300 dark:border-slate-700 text-indigo-600 focus:ring-indigo-500 bg-white dark:bg-slate-900"
          >
          <span class="text-xs font-medium text-slate-800 dark:text-slate-200">{{ t('notify.onFailure') }}</span>
        </label>
      </div>
    </div>

    <!-- 1. 微信公众号 -->
    <div class="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col gap-5 shadow-xs transition-colors">
      <div class="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800/80">
        <div class="flex items-center gap-3">
          <label class="relative inline-flex items-center cursor-pointer">
            <input
              v-model="notifications.wechat_official.enabled"
              type="checkbox"
              class="sr-only peer"
            >
            <div class="w-9 h-5 bg-slate-300 dark:bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-indigo-600" />
          </label>
          <span class="text-sm font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            <Radio class="w-4 h-4 text-emerald-500" />
            {{ t('notify.wechatOfficialTitle') }}
          </span>
        </div>

        <button
          type="button"
          :disabled="testingChannel === 'wechat_official' || !notifications.wechat_official.enabled"
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs text-slate-700 dark:text-slate-200 transition disabled:opacity-50 cursor-pointer"
          @click="runSingleTest('wechat_official')"
        >
          <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': testingChannel === 'wechat_official' }" />
          <span>{{ t('notify.testChannelBtn') }}</span>
        </button>
      </div>

      <div :class="{ 'opacity-50 pointer-events-none': !notifications.wechat_official.enabled }" class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.wxAppId') }}</label>
          <input v-model="notifications.wechat_official.app_id" type="text" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
        </div>
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.wxAppSecret') }}</label>
          <PasswordInput v-model="notifications.wechat_official.app_secret" />
        </div>
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.wxTemplateId') }}</label>
          <input v-model="notifications.wechat_official.template_id" type="text" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
        </div>
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.wxToUser') }}</label>
          <input v-model="notifications.wechat_official.to_user" type="text" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
        </div>
      </div>
    </div>

    <!-- 2. 企业微信 -->
    <div class="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col gap-5 shadow-xs transition-colors">
      <div class="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800/80">
        <div class="flex items-center gap-3">
          <label class="relative inline-flex items-center cursor-pointer">
            <input
              v-model="notifications.wecom.enabled"
              type="checkbox"
              class="sr-only peer"
            >
            <div class="w-9 h-5 bg-slate-300 dark:bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-indigo-600" />
          </label>
          <span class="text-sm font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            <MessageSquare class="w-4 h-4 text-blue-500" />
            {{ t('notify.wecomTitle') }}
          </span>
        </div>

        <button
          type="button"
          :disabled="testingChannel === 'wecom' || !notifications.wecom.enabled"
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs text-slate-700 dark:text-slate-200 transition disabled:opacity-50 cursor-pointer"
          @click="runSingleTest('wecom')"
        >
          <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': testingChannel === 'wecom' }" />
          <span>{{ t('notify.testChannelBtn') }}</span>
        </button>
      </div>

      <div :class="{ 'opacity-50 pointer-events-none': !notifications.wecom.enabled }" class="flex flex-col gap-4">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-semibold text-slate-700 dark:text-slate-300">{{ t('notify.wecomMode') }}</label>
          <select
            v-model="notifications.wecom.mode"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all cursor-pointer"
          >
            <option value="bot">
              {{ t('notify.wecomModeBot') }}
            </option>
            <option value="app">
              {{ t('notify.wecomModeApp') }}
            </option>
          </select>
        </div>

        <div v-if="notifications.wecom.mode === 'bot'" class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.wecomWebhookUrl') }}</label>
          <input v-model="notifications.wecom.webhook_url" type="text" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 font-mono focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
        </div>

        <div v-else class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.wecomCorpId') }}</label>
            <input v-model="notifications.wecom.corp_id" type="text" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.wecomCorpSecret') }}</label>
            <PasswordInput v-model="notifications.wecom.corp_secret" />
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.wecomAgentId') }}</label>
            <input
              :value="notifications.wecom.agent_id || ''"
              type="number"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
              @input="notifications.wecom.agent_id = parseInt(($event.target as HTMLInputElement).value) || null"
            >
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.wecomToUser') }}</label>
            <input v-model="notifications.wecom.to_user" type="text" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
          </div>
        </div>
      </div>
    </div>

    <!-- 3. SMTP 邮件通知 -->
    <div class="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col gap-5 shadow-xs transition-colors">
      <div class="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800/80">
        <div class="flex items-center gap-3">
          <label class="relative inline-flex items-center cursor-pointer">
            <input
              v-model="notifications.email.enabled"
              type="checkbox"
              class="sr-only peer"
            >
            <div class="w-9 h-5 bg-slate-300 dark:bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-indigo-600" />
          </label>
          <span class="text-sm font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            <Mail class="w-4 h-4 text-purple-500" />
            {{ t('notify.emailTitle') }}
          </span>
        </div>

        <button
          type="button"
          :disabled="testingChannel === 'email' || !notifications.email.enabled"
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs text-slate-700 dark:text-slate-200 transition disabled:opacity-50 cursor-pointer"
          @click="runSingleTest('email')"
        >
          <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': testingChannel === 'email' }" />
          <span>{{ t('notify.testChannelBtn') }}</span>
        </button>
      </div>

      <div :class="{ 'opacity-50 pointer-events-none': !notifications.email.enabled }" class="flex flex-col gap-4">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-semibold text-slate-700 dark:text-slate-300">{{ t('notify.emailPreset') }}</label>
          <select
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all cursor-pointer"
            @change="applyEmailPreset"
          >
            <option value="">
              {{ t('notify.emailPresetCustom') }}
            </option>
            <option value="qq">
              {{ t('notify.emailPresetQq') }}
            </option>
            <option value="163">
              {{ t('notify.emailPreset163') }}
            </option>
            <option value="126">
              {{ t('notify.emailPreset126') }}
            </option>
            <option value="qq_enterprise">
              {{ t('notify.emailPresetQqEnt') }}
            </option>
            <option value="aliyun">
              {{ t('notify.emailPresetAliyun') }}
            </option>
            <option value="gmail">
              {{ t('notify.emailPresetGmail') }}
            </option>
            <option value="outlook">
              {{ t('notify.emailPresetOutlook') }}
            </option>
            <option value="139">
              {{ t('notify.emailPreset139') }}
            </option>
          </select>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.emailServer') }}</label>
            <input v-model="notifications.email.smtp_server" type="text" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.emailPort') }}</label>
            <input v-model.number="notifications.email.smtp_port" type="number" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.emailUsername') }}</label>
            <input v-model="notifications.email.username" type="text" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.emailPassword') }}</label>
            <PasswordInput v-model="notifications.email.password" />
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.emailFrom') }}</label>
            <input v-model="notifications.email.from_address" type="text" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.emailTo') }}</label>
            <input :value="getEmailToText()" type="text" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all" @input="setEmailToText(($event.target as HTMLInputElement).value)">
          </div>
        </div>

        <label class="flex items-center gap-2 cursor-pointer pt-1">
          <input v-model="notifications.email.use_ssl" type="checkbox" class="rounded border-slate-300 dark:border-slate-700 text-indigo-600 focus:ring-indigo-500 bg-white dark:bg-slate-900">
          <span class="text-xs text-slate-700 dark:text-slate-300">{{ t('notify.emailSsl') }}</span>
        </label>
      </div>
    </div>

    <!-- 4. 钉钉机器人 -->
    <div class="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col gap-5 shadow-xs transition-colors">
      <div class="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800/80">
        <div class="flex items-center gap-3">
          <label class="relative inline-flex items-center cursor-pointer">
            <input
              v-model="notifications.dingtalk.enabled"
              type="checkbox"
              class="sr-only peer"
            >
            <div class="w-9 h-5 bg-slate-300 dark:bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-indigo-600" />
          </label>
          <span class="text-sm font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            <Bot class="w-4 h-4 text-cyan-500" />
            {{ t('notify.dingtalkTitle') }}
          </span>
        </div>

        <button
          type="button"
          :disabled="testingChannel === 'dingtalk' || !notifications.dingtalk.enabled"
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs text-slate-700 dark:text-slate-200 transition disabled:opacity-50 cursor-pointer"
          @click="runSingleTest('dingtalk')"
        >
          <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': testingChannel === 'dingtalk' }" />
          <span>{{ t('notify.testChannelBtn') }}</span>
        </button>
      </div>

      <div :class="{ 'opacity-50 pointer-events-none': !notifications.dingtalk.enabled }" class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.dingtalkToken') }}</label>
          <input v-model="notifications.dingtalk.access_token" type="text" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 font-mono focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
        </div>
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.dingtalkSecret') }}</label>
          <PasswordInput v-model="notifications.dingtalk.secret" :placeholder="t('notify.dingtalkSecretPlaceholder')" />
        </div>
      </div>
    </div>

    <!-- 5. 飞书机器人 -->
    <div class="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col gap-5 shadow-xs transition-colors">
      <div class="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800/80">
        <div class="flex items-center gap-3">
          <label class="relative inline-flex items-center cursor-pointer">
            <input
              v-model="notifications.feishu.enabled"
              type="checkbox"
              class="sr-only peer"
            >
            <div class="w-9 h-5 bg-slate-300 dark:bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-indigo-600" />
          </label>
          <span class="text-sm font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            <Send class="w-4 h-4 text-emerald-500" />
            {{ t('notify.feishuTitle') }}
          </span>
        </div>

        <button
          type="button"
          :disabled="testingChannel === 'feishu' || !notifications.feishu.enabled"
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs text-slate-700 dark:text-slate-200 transition disabled:opacity-50 cursor-pointer"
          @click="runSingleTest('feishu')"
        >
          <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': testingChannel === 'feishu' }" />
          <span>{{ t('notify.testChannelBtn') }}</span>
        </button>
      </div>

      <div :class="{ 'opacity-50 pointer-events-none': !notifications.feishu.enabled }" class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.feishuWebhook') }}</label>
          <input v-model="notifications.feishu.webhook_url" type="text" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 font-mono focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
        </div>
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.feishuSecret') }}</label>
          <PasswordInput v-model="notifications.feishu.secret" :placeholder="t('notify.feishuSecretPlaceholder')" />
        </div>
      </div>
    </div>

    <!-- 6. Telegram -->
    <div class="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col gap-5 shadow-xs transition-colors">
      <div class="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800/80">
        <div class="flex items-center gap-3">
          <label class="relative inline-flex items-center cursor-pointer">
            <input
              v-model="notifications.telegram.enabled"
              type="checkbox"
              class="sr-only peer"
            >
            <div class="w-9 h-5 bg-slate-300 dark:bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-indigo-600" />
          </label>
          <span class="text-sm font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            <Bot class="w-4 h-4 text-sky-500" />
            {{ t('notify.telegramTitle') }}
          </span>
        </div>

        <button
          type="button"
          :disabled="testingChannel === 'telegram' || !notifications.telegram.enabled"
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs text-slate-700 dark:text-slate-200 transition disabled:opacity-50 cursor-pointer"
          @click="runSingleTest('telegram')"
        >
          <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': testingChannel === 'telegram' }" />
          <span>{{ t('notify.testChannelBtn') }}</span>
        </button>
      </div>

      <div :class="{ 'opacity-50 pointer-events-none': !notifications.telegram.enabled }" class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.telegramToken') }}</label>
          <PasswordInput v-model="notifications.telegram.bot_token" />
        </div>
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.telegramChatId') }}</label>
          <input v-model="notifications.telegram.chat_id" type="text" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
        </div>
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.telegramProxy') }}</label>
          <input v-model="notifications.telegram.api_proxy" type="text" placeholder="https://api.telegram.org" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
        </div>
      </div>
    </div>

    <!-- 7. Bark -->
    <div class="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col gap-5 shadow-xs transition-colors">
      <div class="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800/80">
        <div class="flex items-center gap-3">
          <label class="relative inline-flex items-center cursor-pointer">
            <input
              v-model="notifications.bark.enabled"
              type="checkbox"
              class="sr-only peer"
            >
            <div class="w-9 h-5 bg-slate-300 dark:bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-indigo-600" />
          </label>
          <span class="text-sm font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            <Smartphone class="w-4 h-4 text-orange-500" />
            {{ t('notify.barkTitle') }}
          </span>
        </div>

        <button
          type="button"
          :disabled="testingChannel === 'bark' || !notifications.bark.enabled"
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs text-slate-700 dark:text-slate-200 transition disabled:opacity-50 cursor-pointer"
          @click="runSingleTest('bark')"
        >
          <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': testingChannel === 'bark' }" />
          <span>{{ t('notify.testChannelBtn') }}</span>
        </button>
      </div>

      <div :class="{ 'opacity-50 pointer-events-none': !notifications.bark.enabled }" class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.barkServer') }}</label>
          <input v-model="notifications.bark.server_url" type="text" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
        </div>
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.barkKey') }}</label>
          <PasswordInput v-model="notifications.bark.device_key" />
        </div>
      </div>
    </div>

    <!-- 8. 通用 Webhook -->
    <div class="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col gap-5 shadow-xs transition-colors">
      <div class="flex items-center justify-between pb-4 border-b border-slate-100 dark:border-slate-800/80">
        <div class="flex items-center gap-3">
          <label class="relative inline-flex items-center cursor-pointer">
            <input
              v-model="notifications.webhook.enabled"
              type="checkbox"
              class="sr-only peer"
            >
            <div class="w-9 h-5 bg-slate-300 dark:bg-slate-800 peer-focus:outline-none rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:bg-indigo-600" />
          </label>
          <span class="text-sm font-bold text-slate-800 dark:text-slate-100 flex items-center gap-2">
            <Globe class="w-4 h-4 text-emerald-500" />
            {{ t('notify.webhookTitle') }}
          </span>
        </div>

        <button
          type="button"
          :disabled="testingChannel === 'webhook' || !notifications.webhook.enabled"
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs text-slate-700 dark:text-slate-200 transition disabled:opacity-50 cursor-pointer"
          @click="runSingleTest('webhook')"
        >
          <RefreshCw class="w-3.5 h-3.5" :class="{ 'animate-spin': testingChannel === 'webhook' }" />
          <span>{{ t('notify.testChannelBtn') }}</span>
        </button>
      </div>

      <div :class="{ 'opacity-50 pointer-events-none': !notifications.webhook.enabled }" class="flex flex-col gap-4">
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.webhookUrl') }}</label>
          <input v-model="notifications.webhook.url" type="text" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 font-mono focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all">
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.webhookMethod') }}</label>
            <select v-model="notifications.webhook.method" class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all cursor-pointer">
              <option value="POST">
                POST
              </option>
              <option value="GET">
                GET
              </option>
              <option value="PUT">
                PUT
              </option>
            </select>
          </div>
          <div class="flex flex-col gap-1.5">
            <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.webhookHeaders') }}</label>
            <input
              :value="notifications.webhook.headers ? JSON.stringify(notifications.webhook.headers) : ''"
              type="text"
              placeholder="{&quot;Authorization&quot;: &quot;Bearer xxx&quot;}"
              class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 text-sm text-slate-800 dark:text-slate-100 font-mono focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
              @input="onWebhookHeadersInput"
            >
          </div>
        </div>
        <div class="flex flex-col gap-1.5">
          <label class="text-xs font-medium text-slate-700 dark:text-slate-300">{{ t('notify.webhookBody') }}</label>
          <textarea
            v-model="notifications.webhook.body"
            rows="2"
            placeholder="{&quot;status&quot;: &quot;#{status}&quot;, &quot;ipv4&quot;: &quot;#{ipv4}&quot;, &quot;domains&quot;: &quot;#{domains}&quot;}"
            class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg p-3 text-xs text-slate-800 dark:text-slate-100 font-mono focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all"
          />
        </div>
      </div>
    </div>
  </div>
</template>
