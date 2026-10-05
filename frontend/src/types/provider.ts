// ==========================================
// DNS 服务商类型定义 (与 Rust ProviderConfig 对应)
// ==========================================

export type ProviderType
  = | 'cloudflare'
    | 'ali_dns'
    | 'tencent_cloud'
    | 'huawei_cloud'
    | 'porkbun'
    | 'godaddy'
    | 'dynv6'
    | 'baidu_cloud'
    | 'traffic_route'
    | 'namecheap'
    | 'namesilo'
    | 'spaceship'
    | 'dynadot'
    | 'vercel'
    | 'rainyun'
    | 'cloudns'
    | 'gcore'
    | 'name_com'
    | 'dnsla'
    | 'aliesa'
    | 'edgeone'
    | 'nowcn'
    | 'eranet'
    | 'tnethk'
    | 'nsone'
    | 'hipm_dnsmgr'
    | 'callback'

export interface CloudflareConfig {
  type: 'cloudflare'
  api_token?: string | null
  api_key?: string | null
  email?: string | null
}

export interface AliDnsConfig {
  type: 'ali_dns'
  access_key_id: string
  access_key_secret: string
  endpoint?: string | null
}

export interface TencentCloudConfig {
  type: 'tencent_cloud'
  secret_id: string
  secret_key: string
}

export interface HuaweiCloudConfig {
  type: 'huawei_cloud'
  access_key_id: string
  secret_access_key: string
  region?: string | null
  endpoint?: string | null
}

export interface PorkbunConfig {
  type: 'porkbun'
  api_key: string
  secret_key: string
}

export interface GoDaddyConfig {
  type: 'godaddy'
  api_key: string
  api_secret: string
}

export interface Dynv6Config {
  type: 'dynv6'
  token: string
}

export interface BaiduCloudConfig {
  type: 'baidu_cloud'
  access_key_id: string
  secret_access_key: string
}

export interface TrafficRouteConfig {
  type: 'traffic_route'
  access_key_id: string
  secret_access_key: string
}

export interface NamecheapConfig {
  type: 'namecheap'
  password: string
}

export interface NameSiloConfig {
  type: 'namesilo'
  api_key: string
}

export interface SpaceshipConfig {
  type: 'spaceship'
  api_key: string
  api_secret: string
}

export interface DynadotConfig {
  type: 'dynadot'
  password: string
}

export interface VercelConfig {
  type: 'vercel'
  token: string
  team_id?: string | null
}

export interface RainYunConfig {
  type: 'rainyun'
  api_key: string
  domain_id?: string | null
}

export interface ClouDnsConfig {
  type: 'cloudns'
  auth_id: string
  auth_password: string
}

export interface GcoreConfig {
  type: 'gcore'
  api_key: string
}

export interface NameComConfig {
  type: 'name_com'
  username: string
  api_token: string
}

export interface DnsLaConfig {
  type: 'dnsla'
  api_id: string
  api_secret: string
}

export interface AliEsaConfig {
  type: 'aliesa'
  access_key_id: string
  access_key_secret: string
  endpoint?: string | null
}

export interface EdgeOneConfig {
  type: 'edgeone'
  secret_id: string
  secret_key: string
}

export interface NowCnConfig {
  type: 'nowcn'
  id: string
  secret: string
}

export interface EranetConfig {
  type: 'eranet'
  id: string
  secret: string
}

export interface TNetHkConfig {
  type: 'tnethk'
  id: string
  secret: string
}

export interface NsOneConfig {
  type: 'nsone'
  api_key: string
}

export interface HipmDnsMgrConfig {
  type: 'hipm_dnsmgr'
  api_token: string
  endpoint?: string | null
}

export interface CallbackConfig {
  type: 'callback'
  url: string
  method?: string
  headers?: Record<string, string> | null
  body?: string | null
}

export type ProviderConfig
  = | CloudflareConfig
    | AliDnsConfig
    | TencentCloudConfig
    | HuaweiCloudConfig
    | PorkbunConfig
    | GoDaddyConfig
    | Dynv6Config
    | BaiduCloudConfig
    | TrafficRouteConfig
    | NamecheapConfig
    | NameSiloConfig
    | SpaceshipConfig
    | DynadotConfig
    | VercelConfig
    | RainYunConfig
    | ClouDnsConfig
    | GcoreConfig
    | NameComConfig
    | DnsLaConfig
    | AliEsaConfig
    | EdgeOneConfig
    | NowCnConfig
    | EranetConfig
    | TNetHkConfig
    | NsOneConfig
    | HipmDnsMgrConfig
    | CallbackConfig

export const PROVIDER_DISPLAY_NAMES: Record<ProviderType, string> = {
  cloudflare: 'Cloudflare',
  ali_dns: '阿里云 AliDNS',
  tencent_cloud: '腾讯云 DNSPod',
  huawei_cloud: '华为云',
  porkbun: 'Porkbun',
  godaddy: 'GoDaddy',
  dynv6: 'Dynv6',
  baidu_cloud: '百度智能云',
  traffic_route: '火山引擎',
  namecheap: 'Namecheap',
  namesilo: 'NameSilo',
  spaceship: 'Spaceship',
  dynadot: 'Dynadot',
  vercel: 'Vercel',
  rainyun: '雨云',
  cloudns: 'ClouDNS',
  gcore: 'Gcore',
  name_com: 'Name.com',
  dnsla: 'DNS.LA',
  aliesa: '阿里 ESA',
  edgeone: '腾讯 EdgeOne',
  nowcn: '时代互联',
  eranet: 'Eranet 国际',
  tnethk: 'TNetHK',
  nsone: 'IBM NS1',
  hipm_dnsmgr: 'HiPM DNSMgr',
  callback: '自定义 Callback',
}
