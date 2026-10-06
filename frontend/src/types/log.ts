// ==========================================
// 日志条目类型定义 (SSE 实时推流)
// ==========================================

export interface LogEntry {
  id?: number
  timestamp: string
  level: 'TRACE' | 'DEBUG' | 'INFO' | 'WARN' | 'ERROR'
  target: string
  message: string
}
