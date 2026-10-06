// ==========================================
// 系统全局配置与接口响应类型定义
// ==========================================

import type { NotificationConfig } from './notify'
import type { DnsTaskConfig } from './task'

export interface UserAuthConfig {
  username: string
}

export interface AppConfig {
  listen_port: number
  interval_secs: number
  cache_times: number
  not_allow_wan_access: boolean
  dns_server?: string | null
  auth?: UserAuthConfig | null
  notifications: NotificationConfig
  dns_tasks: DnsTaskConfig[]
  restart_required?: string[]
}

export interface SaveConfigPayload {
  config: AppConfig
  new_password?: string | null
}

export interface NetworkInterface {
  name: string
  display_name?: string
  ips: string[]
}

export interface VersionInfo {
  current_version: string
  latest_version: string
  has_update: boolean
  release_notes?: string
  download_url?: string
}

export interface AuthStatus {
  need_init: boolean
  username?: string | null
}

export interface ApiResult<T = any> {
  success: boolean
  message: string
  data: T
}
