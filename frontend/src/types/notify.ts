// ==========================================
// 告警通知渠道类型定义
// ==========================================

export interface WechatOfficialConfig {
  enabled: boolean
  app_id: string
  app_secret: string
  template_id: string
  to_user: string
  url?: string | null
  template_data?: string | null
}

export interface WeComConfig {
  enabled: boolean
  mode: 'bot' | 'app'
  webhook_url?: string | null
  corp_id?: string | null
  corp_secret?: string | null
  agent_id?: number | null
  to_user?: string | null
}

export interface TelegramConfig {
  enabled: boolean
  bot_token: string
  chat_id: string
  api_proxy?: string | null
}

export interface DingTalkConfig {
  enabled: boolean
  access_token: string
  secret?: string | null
}

export interface FeishuConfig {
  enabled: boolean
  webhook_url: string
  secret?: string | null
}

export interface BarkConfig {
  enabled: boolean
  server_url?: string | null
  device_key: string
  group?: string | null
  sound?: string | null
}

export interface EmailConfig {
  enabled: boolean
  smtp_server: string
  smtp_port: number
  use_ssl: boolean
  username: string
  password: string
  from_address: string
  to_addresses: string[]
}

export interface WebhookConfig {
  enabled: boolean
  url: string
  method?: string
  headers?: Record<string, string> | null
  body?: string | null
}

export interface NotificationConfig {
  on_ip_change_only: boolean
  on_success: boolean
  on_failure: boolean
  wechat_official?: WechatOfficialConfig | null
  wecom?: WeComConfig | null
  telegram?: TelegramConfig | null
  dingtalk?: DingTalkConfig | null
  feishu?: FeishuConfig | null
  bark?: BarkConfig | null
  email?: EmailConfig | null
  webhook?: WebhookConfig | null
}
