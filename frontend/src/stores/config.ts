// ==========================================
// 系统与多任务配置状态管理 Store (Master-Detail)
// ==========================================

import type { AppConfig, NetworkInterface } from '@/types/config'
import type { DnsTaskConfig } from '@/types/task'
import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { configApi, systemApi } from '@/api'
import { i18n } from '@/i18n'
import { useToastStore } from './toast'

export const useConfigStore = defineStore('config', () => {
  const toast = useToastStore()
  const t = i18n.global.t

  const activeTab = ref<'tab-dns' | 'tab-notify' | 'tab-system'>('tab-dns')
  const isLoading = ref<boolean>(false)
  const isSaving = ref<boolean>(false)
  const isSyncing = ref<boolean>(false)
  const restartRequired = ref<string[]>([])

  // 创建默认通知配置结构，杜绝 null 导致的运行时访问异常
  function createDefaultNotifications(): AppConfig['notifications'] {
    return {
      on_ip_change_only: true,
      on_success: true,
      on_failure: true,
      wechat_official: {
        enabled: false,
        app_id: '',
        app_secret: '',
        template_id: '',
        to_user: '',
        url: null,
        template_data: null,
      },
      wecom: {
        enabled: false,
        mode: 'bot',
        webhook_url: null,
        corp_id: null,
        corp_secret: null,
        agent_id: null,
        to_user: '@all',
      },
      email: {
        enabled: false,
        smtp_server: '',
        smtp_port: 465,
        use_ssl: true,
        username: '',
        password: '',
        from_address: '',
        to_addresses: [],
      },
      dingtalk: {
        enabled: false,
        access_token: '',
        secret: null,
      },
      feishu: {
        enabled: false,
        webhook_url: '',
        secret: null,
      },
      telegram: {
        enabled: false,
        bot_token: '',
        chat_id: '',
        api_proxy: null,
      },
      bark: {
        enabled: false,
        server_url: 'https://api.day.app',
        device_key: '',
        group: null,
        sound: null,
      },
      webhook: {
        enabled: false,
        url: '',
        method: 'POST',
        headers: null,
        body: null,
      },
    }
  }

  // 全局配置对象
  const config = ref<AppConfig>({
    listen_port: 9876,
    interval_secs: 300,
    cache_times: 10,
    not_allow_wan_access: false,
    dns_server: null,
    auth: { username: 'admin' },
    notifications: createDefaultNotifications(),
    dns_tasks: [],
  })

  // 安全计算属性：通知配置
  const notifications = computed(() => {
    if (!config.value.notifications) {
      config.value.notifications = createDefaultNotifications()
    }
    return config.value.notifications
  })

  // 当前选中的任务索引 (Master-Detail)
  const currentTaskIndex = ref<number>(0)

  // 系统网卡设备列表
  const networkInterfaces = ref<NetworkInterface[]>([])

  // 计算属性：当前任务
  const currentTask = computed<DnsTaskConfig | null>(() => {
    if (!config.value.dns_tasks || config.value.dns_tasks.length === 0) {
      return null
    }
    return config.value.dns_tasks[currentTaskIndex.value] || config.value.dns_tasks[0]
  })

  // 创建默认任务对象
  function createDefaultTask(index: number): DnsTaskConfig {
    return {
      name: `${t('task.nameLabel')} ${index}`,
      enabled: true,
      ttl: null,
      http_interface: null,
      provider: {
        type: 'cloudflare',
        api_token: '',
        api_key: '',
        email: '',
      },
      ipv4: {
        enabled: true,
        source_type: 'url',
        url_endpoints: [
          'https://api.ipify.org',
          'https://myip.ipip.net/ip',
          'https://ddns.oray.com/checkip',
        ],
        stun_server: null,
        net_interface: null,
        cmd: null,
        regex: null,
        domains: [],
      },
      ipv6: {
        enabled: true,
        source_type: 'net_interface',
        url_endpoints: [
          'https://api64.ipify.org',
          'https://speed.neu6.edu.cn/getIP.php',
          'https://6.ipw.cn',
        ],
        stun_server: null,
        net_interface: null,
        cmd: null,
        regex: null,
        domains: [],
      },
    }
  }

  // 安全规范化配置结构，杜绝 null 字段引发运行时空指针异常
  function normalizeConfig(cfg: AppConfig): AppConfig {
    if (!cfg.dns_tasks || cfg.dns_tasks.length === 0) {
      cfg.dns_tasks = [createDefaultTask(1)]
    }

    // 规范化多任务字段
    cfg.dns_tasks.forEach((task, idx) => {
      if (!task.name)
        task.name = `${t('task.nameLabel')} ${idx + 1}`
      if (task.enabled === undefined)
        task.enabled = true
      if (!task.provider)
        task.provider = { type: 'cloudflare', api_token: '' }
      if (!task.ipv4) {
        task.ipv4 = {
          enabled: true,
          source_type: 'url',
          url_endpoints: ['https://api.ipify.org'],
          domains: [],
        }
      }
      if (!task.ipv4.url_endpoints)
        task.ipv4.url_endpoints = []
      if (!task.ipv4.domains)
        task.ipv4.domains = []

      if (!task.ipv6) {
        task.ipv6 = {
          enabled: false,
          source_type: 'net_interface',
          url_endpoints: [],
          domains: [],
        }
      }
      if (!task.ipv6.url_endpoints)
        task.ipv6.url_endpoints = []
      if (!task.ipv6.domains)
        task.ipv6.domains = []
    })

    // 规范化通知渠道对象，绝不保留 null
    if (!cfg.notifications) {
      cfg.notifications = createDefaultNotifications()
    }
    const notif = cfg.notifications
    notif.on_success = notif.on_success !== false
    notif.on_failure = notif.on_failure !== false

    if (!notif.wechat_official) {
      notif.wechat_official = {
        enabled: false,
        app_id: '',
        app_secret: '',
        template_id: '',
        to_user: '',
        url: null,
        template_data: null,
      }
    }
    if (!notif.wecom) {
      notif.wecom = {
        enabled: false,
        mode: 'bot',
        webhook_url: null,
        corp_id: null,
        corp_secret: null,
        agent_id: null,
        to_user: '@all',
      }
    }
    if (!notif.email) {
      notif.email = {
        enabled: false,
        smtp_server: '',
        smtp_port: 465,
        use_ssl: true,
        username: '',
        password: '',
        from_address: '',
        to_addresses: [],
      }
    }
    if (!notif.dingtalk) {
      notif.dingtalk = {
        enabled: false,
        access_token: '',
        secret: null,
      }
    }
    if (!notif.feishu) {
      notif.feishu = {
        enabled: false,
        webhook_url: '',
        secret: null,
      }
    }
    if (!notif.telegram) {
      notif.telegram = {
        enabled: false,
        bot_token: '',
        chat_id: '',
        api_proxy: null,
      }
    }
    if (!notif.bark) {
      notif.bark = {
        enabled: false,
        server_url: 'https://api.day.app',
        device_key: '',
        group: null,
        sound: null,
      }
    }
    if (!notif.webhook) {
      notif.webhook = {
        enabled: false,
        url: '',
        method: 'POST',
        headers: null,
        body: null,
      }
    }

    // 规范化 auth 对象
    if (!cfg.auth) {
      cfg.auth = { username: '' }
    }

    return cfg
  }

  // 加载配置
  async function loadConfig() {
    isLoading.value = true
    try {
      const res = await configApi.getConfig()
      if (res.success && res.data) {
        config.value = normalizeConfig(res.data)
        restartRequired.value = res.data.restart_required || []
        if (currentTaskIndex.value >= config.value.dns_tasks.length) {
          currentTaskIndex.value = 0
        }
      }
    }
    catch (e: unknown) {
      console.error('加载系统配置失败:', e)
    }
    finally {
      isLoading.value = false
    }
  }

  // 加载系统网卡
  async function loadNetworkInterfaces() {
    try {
      const res = await systemApi.getNetworkInterfaces()
      if (res.success && Array.isArray(res.data)) {
        networkInterfaces.value = res.data
      }
    }
    catch (e: unknown) {
      console.warn('获取网卡列表失败:', e)
    }
  }

  // 保存全局配置
  async function saveConfig(newPassword?: string) {
    isSaving.value = true
    try {
      const res = await configApi.saveConfig({
        config: config.value,
        new_password: newPassword || null,
      })
      if (res.success) {
        toast.success(t('common.saveSuccess'))
        if (newPassword && config.value.auth?.username) {
          const authKey = btoa(`${config.value.auth.username}:${newPassword}`)
          sessionStorage.setItem('rddns_auth', authKey)
        }
        return true
      }
      else {
        toast.error(t('common.saveFailed', { message: res.message }))
        return false
      }
    }
    catch (e: unknown) {
      const errMsg = e instanceof Error ? e.message : String(e)
      toast.error(t('common.requestError', { error: errMsg }))
      return false
    }
    finally {
      isSaving.value = false
    }
  }

  // 触发立即全量同步
  async function triggerSync() {
    isSyncing.value = true
    try {
      const res = await systemApi.syncAll()
      if (res.success) {
        toast.success(res.message)
      }
      else {
        toast.error(res.message)
      }
    }
    catch (e: unknown) {
      const errMsg = e instanceof Error ? e.message : String(e)
      toast.error(t('common.syncTriggerFailed', { error: errMsg }))
    }
    finally {
      isSyncing.value = false
    }
  }

  // 新增任务
  function addTask() {
    const nextNum = config.value.dns_tasks.length + 1
    const newTask = createDefaultTask(nextNum)
    config.value.dns_tasks.push(newTask)
    currentTaskIndex.value = config.value.dns_tasks.length - 1
    toast.success(t('task.newSuccess', { name: newTask.name }))
  }

  // 克隆当前任务
  function cloneTask() {
    if (!currentTask.value)
      return
    const cloned: DnsTaskConfig = JSON.parse(JSON.stringify(currentTask.value))
    cloned.name = `${cloned.name || t('task.unnamedTask')} - ${t('task.cloneSuffix')}`
    config.value.dns_tasks.push(cloned)
    currentTaskIndex.value = config.value.dns_tasks.length - 1
    toast.success(t('task.cloneSuccess', { name: cloned.name }))
  }

  // 删除当前任务
  function deleteTask() {
    if (config.value.dns_tasks.length <= 1) {
      toast.warning(t('task.deleteMinWarning'))
      return
    }
    const taskName = currentTask.value?.name || t('task.unnamedTask')
    config.value.dns_tasks.splice(currentTaskIndex.value, 1)
    if (currentTaskIndex.value >= config.value.dns_tasks.length) {
      currentTaskIndex.value = config.value.dns_tasks.length - 1
    }
    toast.success(t('task.deleteSuccess', { name: taskName }))
  }

  return {
    activeTab,
    isLoading,
    isSaving,
    isSyncing,
    restartRequired,
    config,
    notifications,
    currentTaskIndex,
    currentTask,
    networkInterfaces,
    loadConfig,
    loadNetworkInterfaces,
    saveConfig,
    triggerSync,
    addTask,
    cloneTask,
    deleteTask,
  }
})
