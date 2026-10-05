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
