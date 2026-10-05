// ==========================================
// 业务静态预设与全局常量配置
// ==========================================

export interface OptionItem<T = string | number> {
  label: string
  value: T
}

export interface EmailPresetConfig {
  server: string
  port: number
  ssl: boolean
}

// 支持的 DNS 服务商选项列表
export const DNS_PROVIDER_OPTIONS: OptionItem<string>[] = [
  { value: 'Cloudflare', label: 'Cloudflare' },
  { value: 'Aliyun', label: '阿里云 (Aliyun DNS)' },
  { value: 'TencentCloud', label: '腾讯云 (DNSPod / TencentCloud)' },
  { value: 'HuaweiCloud', label: '华为云 (Huawei Cloud)' },
  { value: 'BaiduCloud', label: '百度智能云 (Baidu Cloud)' },
  { value: 'Volcengine', label: '火山引擎 (Volcengine)' },
  { value: 'Dnspod', label: 'DNSPod (Token 鉴权)' },
  { value: 'DuckDns', label: 'DuckDNS' },
  { value: 'Dynv6', label: 'Dynv6' },
  { value: 'Rfc2136', label: 'RFC2136 (BIND / 自建 DNS TSIG)' },
  { value: 'Custom', label: '自定义 API Webhook' },
]

// 常用 SMTP 邮件服务商预设
export const EMAIL_PRESETS: Record<string, EmailPresetConfig> = {
  qq: { server: 'smtp.qq.com', port: 465, ssl: true },
  163: { server: 'smtp.163.com', port: 465, ssl: true },
  126: { server: 'smtp.126.com', port: 465, ssl: true },
  qq_enterprise: { server: 'smtp.exmail.qq.com', port: 465, ssl: true },
  aliyun: { server: 'smtp.aliyun.com', port: 465, ssl: true },
  gmail: { server: 'smtp.gmail.com', port: 465, ssl: true },
  outlook: { server: 'smtp.office365.com', port: 587, ssl: false },
  139: { server: 'smtp.139.com', port: 465, ssl: true },
}

// 常用 STUN 节点预设
export const STUN_PRESETS_V4: OptionItem<string>[] = [
  { label: '小米 (stun.miwifi.com:3478)', value: 'stun.miwifi.com:3478' },
  { label: '腾讯云 (stun.qq.com:3478)', value: 'stun.qq.com:3478' },
  { label: '哔哩哔哩 (stun.chat.bilibili.com:3478)', value: 'stun.chat.bilibili.com:3478' },
  { label: '百度 (stun.baidu.com:3478)', value: 'stun.baidu.com:3478' },
  { label: 'Cloudflare (stun.cloudflare.com:3478)', value: 'stun.cloudflare.com:3478' },
  { label: 'Google (stun.l.google.com:19302)', value: 'stun.l.google.com:19302' },
  { label: '群晖 (stun.synology.com:3478)', value: 'stun.synology.com:3478' },
]

export const STUN_PRESETS_V6: OptionItem<string>[] = [
  { label: 'Nextcloud (stun.nextcloud.com:3478)', value: 'stun.nextcloud.com:3478' },
  { label: 'Google (stun.l.google.com:19302)', value: 'stun.l.google.com:19302' },
  { label: 'FreeSWITCH (stun.freeswitch.org:3478)', value: 'stun.freeswitch.org:3478' },
  { label: 'Sipgate (stun.sipgate.net:3478)', value: 'stun.sipgate.net:3478' },
]
