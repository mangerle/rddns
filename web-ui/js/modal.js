// ==========================================
// 模态日志控制与 SSE 实时推流
// ==========================================

import { showToast } from './toast.js';
import { t } from './i18n/index.js';
import { escapeHtml } from './tasks.js';

let activeEventSource = null;

// 模态日志控制
export function openLogModal() {
  const modal = document.getElementById('logModal');
  if (modal) modal.style.display = 'flex';
  const container = document.getElementById('logContainer');
  if (container) container.scrollTop = container.scrollHeight;
}

export function closeLogModal() {
  const modal = document.getElementById('logModal');
  if (modal) modal.style.display = 'none';
}

export function handleBackdropClick(e) {
  if (e.target.id === 'logModal') {
    closeLogModal();
  }
}

// 监听 Escape 按键关闭弹窗
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    closeLogModal();
  }
});

// 日志追加与渲染 (经 HTML 转义防范 XSS)
export function appendLog(entry) {
  const container = document.getElementById('logContainer');
  if (!container) return;
  const div = document.createElement('div');
  div.className = 'log-line';
  div.innerHTML = `<span class="log-time">[${escapeHtml(entry.timestamp)}]</span> <span class="log-lvl-${escapeHtml(entry.level)}">[${escapeHtml(entry.level)}]</span> <span class="log-target">[${escapeHtml(entry.target)}]</span> ${escapeHtml(entry.message)}`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

export function clearLogs() {
  const container = document.getElementById('logContainer');
  if (container) container.innerHTML = '';
  showToast(t('modal.logsCleared'), 'info');
}

export async function initSSE() {
  if (activeEventSource) {
    try { activeEventSource.close(); } catch (_) {}
    activeEventSource = null;
  }
  const auth = sessionStorage.getItem('rddns_auth');
  let sseUrl = '/api/v1/logs/sse';

  if (auth) {
    try {
      const resp = await fetch('/api/v1/auth/sse-ticket', {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${auth}`
        }
      });
      if (resp.status === 401) {
        console.warn('SSE 鉴权失败 (401)，已停止自动重连');
        return;
      }
      if (resp.ok) {
        const json = await resp.json();
        if (json.data && json.data.ticket) {
          sseUrl = `/api/v1/logs/sse?ticket=${encodeURIComponent(json.data.ticket)}`;
        }
      }
    } catch (e) {
      console.warn('获取 SSE Ticket 失败，降级重试:', e);
    }
  }

  const es = new EventSource(sseUrl);
  activeEventSource = es;

  es.onmessage = function(e) {
    try {
      const entry = JSON.parse(e.data);
      appendLog(entry);
    } catch (err) {
      console.error('解析 SSE 日志异常:', err);
    }
  };
  es.onerror = function() {
    es.close();
    if (activeEventSource === es) {
      activeEventSource = null;
    }
    setTimeout(initSSE, 5000);
  };
}
