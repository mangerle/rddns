<script setup lang="ts">
import { onMounted } from 'vue'
import InitPage from '@/components/auth/InitPage.vue'
import LoginPage from '@/components/auth/LoginPage.vue'
import Toast from '@/components/common/Toast.vue'
import HeaderBar from '@/components/layout/HeaderBar.vue'
import SidebarNav from '@/components/layout/SidebarNav.vue'
import LogModal from '@/components/modals/LogModal.vue'
import UpdateModal from '@/components/modals/UpdateModal.vue'
import NotifyWorkspace from '@/components/notify/NotifyWorkspace.vue'
import SystemWorkspace from '@/components/system/SystemWorkspace.vue'
import DnsWorkspace from '@/components/tasks/DnsWorkspace.vue'
import { useAuthStore } from '@/stores/auth'
import { useConfigStore } from '@/stores/config'
import { useLogStore } from '@/stores/log'
import { useVersionStore } from '@/stores/version'

const authStore = useAuthStore()
const configStore = useConfigStore()
const logStore = useLogStore()
const versionStore = useVersionStore()

onMounted(async () => {
  await authStore.checkAuthStatus()
  if (authStore.currentView === 'app') {
    await configStore.loadConfig()
    await configStore.loadNetworkInterfaces()
    logStore.initSSE()
    versionStore.checkVersion(false)
  }
})
</script>

<template>
  <div class="h-full w-full flex flex-col bg-slate-100 dark:bg-slate-950 text-slate-800 dark:text-slate-100 antialiased font-sans overflow-hidden transition-colors duration-150">
    <!-- 全局轻量 Toast 容器 -->
    <Toast />

    <!-- 模态弹窗 -->
    <LogModal />
    <UpdateModal />

    <!-- 1. 加载等待中 -->
    <div
      v-if="authStore.currentView === 'loading'"
      class="h-full w-full flex items-center justify-center bg-slate-100 dark:bg-slate-950"
    >
      <div class="flex flex-col items-center gap-3">
        <div class="w-8 h-8 rounded-full border-2 border-indigo-500 border-t-transparent animate-spin" />
        <span class="text-xs text-slate-500 dark:text-slate-400 font-mono">正在连接 rddns 控制台...</span>
      </div>
    </div>

    <!-- 2. 账号初始化向导 -->
    <InitPage v-else-if="authStore.currentView === 'init'" />

    <!-- 3. 管理员登录页 -->
    <LoginPage v-else-if="authStore.currentView === 'login'" />

    <!-- 4. 主控制台 -->
    <div v-else-if="authStore.currentView === 'app'" class="h-full w-full flex flex-col overflow-hidden">
      <!-- 吸顶 Header 导航栏 -->
      <HeaderBar />

      <!-- 主工作区：左侧 SidebarNav + 右侧动态 Tab 内容 -->
      <main class="flex-1 flex overflow-hidden">
        <SidebarNav />

        <!-- 选项卡内容区 -->
        <div class="flex-1 flex overflow-hidden">
          <!-- 选项卡 1: DNS 任务与解析 -->
          <DnsWorkspace v-if="configStore.activeTab === 'tab-dns'" />

          <!-- 选项卡 2: 通知与告警 -->
          <NotifyWorkspace v-else-if="configStore.activeTab === 'tab-notify'" />

          <!-- 选项卡 3: 系统与安全 -->
          <SystemWorkspace v-else-if="configStore.activeTab === 'tab-system'" />
        </div>
      </main>
    </div>
  </div>
</template>
