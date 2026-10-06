// ==========================================
// 域名解析任务与 IP 探测类型定义
// ==========================================

import type { ProviderConfig } from './provider'

export type IpSourceType = 'url' | 'net_interface' | 'stun' | 'command'

export interface IpFetchConfig {
  enabled: boolean
  source_type: IpSourceType
  url_endpoints: string[]
  stun_server?: string | null
  net_interface?: string | null
  cmd?: string | null
  regex?: string | null
  domains: string[]
}

export interface DnsTaskConfig {
  name: string
  enabled: boolean
  ttl?: number | null
  http_interface?: string | null
  provider: ProviderConfig
  ipv4: IpFetchConfig
  ipv6: IpFetchConfig
}

export interface TaskRuntimeState {
  last_ipv4?: string | null
  last_ipv6?: string | null
  ipv4_fail_count: number
  ipv6_fail_count: number
  consecutive_failures: number
  check_counter: number
  last_sync_time?: string | null
  last_error?: string | null
  synced_domains?: Record<string, string>
}
