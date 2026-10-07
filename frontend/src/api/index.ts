// ==========================================
// 业务 API 聚合导出
// ==========================================

import type {
  AppConfig,
  AuthStatus,
  NetworkInterface,
  SaveConfigPayload,
  VersionInfo,
} from '@/types/config'
import type { LogEntry } from '@/types/log'
import type { ChannelDeliveryStatus, NotificationConfig } from '@/types/notify'
import type { IpFetchConfig, TaskRuntimeState } from '@/types/task'
import { api } from './client'

export const authApi = {
  // 检查账号初始化状态
  getStatus: () => api.get<AuthStatus>('/api/v1/auth/status'),
  // 首次初始化
  init: (payload: { username: string, password: string }) =>
    api.post<{ token?: string }>('/api/v1/auth/init', payload),
  // 登录认证
  login: (payload: { username: string, password: string }) =>
    api.post<{ token?: string }>('/api/v1/auth/login', payload),
  // 获取 SSE 日志单次消费凭据
  getSseTicket: () => api.post<{ ticket: string }>('/api/v1/auth/sse-ticket'),
}

export const configApi = {
  // 拉取全局配置
  getConfig: () => api.get<AppConfig>('/api/v1/config'),
  // 保存全局配置 (含任务、通知与安全设置)
  saveConfig: (payload: SaveConfigPayload) =>
    api.post<null>('/api/v1/config', payload),
}

export const taskApi = {
  // 获取全部任务运行时状态快照 (P2-7)
  getStatus: () =>
    api.get<Record<string, TaskRuntimeState>>('/api/v1/tasks/status'),
  // 测试探测 IP
  testIp: (payload: { ip_type: 'ipv4' | 'ipv6' } & IpFetchConfig) =>
    api.post<{ ipv4?: string, ipv6?: string }>('/api/v1/test/ip', payload),
}

export const notifyApi = {
  // 获取各通知渠道投递状态快照 (P2-7)
  getStatus: () =>
    api.get<Record<string, ChannelDeliveryStatus>>('/api/v1/notifications/status'),
  // 单渠道或全量发送测试通知
  testNotify: (payload: { channel?: string, config: NotificationConfig }) =>
    api.post<null>('/api/v1/test/notify', payload),
}

export const systemApi = {
  // 立即触发全量解析同步
  syncAll: () => api.post<null>('/api/v1/sync'),
  // 读取当前生效版本信息 (仅本地与启动预检缓存，不会出站访问 GitHub)
  getVersion: () => api.get<VersionInfo>('/api/v1/version'),
  // 强制检查远端新版本 (绕过缓存直连发布源，仅由用户手动点击触发)
  checkVersion: () => api.post<VersionInfo>('/api/v1/version/check'),
  // 触发在线自更新
  upgrade: () => api.post<null>('/api/v1/upgrade'),
  // 枚举物理与虚拟网卡
  getNetworkInterfaces: () =>
    api.get<NetworkInterface[]>('/api/v1/network-interfaces'),
  // 获取最近操作日志快照
  getLogs: () => api.get<LogEntry[]>('/api/v1/logs'),
}
