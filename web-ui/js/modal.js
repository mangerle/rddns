// ==========================================
// 模态日志控制与 SSE 实时推流
// ==========================================

import { showToast } from './toast.js';

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

// 日志追加与渲染
export function appendLog(entry) {
  const container = document.getElementById('logContainer');
  if (!container) return;
  const div = document.createElement('div');
  div.className = 'log-line';
  div.innerHTML = `<span class="log-time">[${entry.timestamp}]</span> <span class="log-lvl-${entry.level}">[${entry.level}]</span> <span class="log-target">[${entry.target}]</span> ${entry.message}`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

export function clearLogs() {
  const container = document.getElementById('logContainer');
  if (container) container.innerHTML = '';
  showToast('日志已清空', 'info');
}

export function initSSE() {
  if (activeEventSource) {
    try { activeEventSource.close(); } catch (_) {}
    activeEventSource = null;
  }
  const auth = sessionStorage.getItem('rddns_auth');
  const sseUrl = auth ? `/api/v1/logs/sse?auth=${encodeURIComponent(auth)}` : '/api/v1/logs/sse';
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
    setTimeout(initSSE, 3000);
  };
}
