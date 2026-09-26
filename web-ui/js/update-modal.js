// ==========================================
// 版本更新与下载进度控制模块
// ==========================================

import { apiFetch } from './api.js';
import { showToast } from './toast.js';
import { t } from './i18n/index.js';
import { escapeHtml } from './tasks.js';
import { onLog } from './modal.js';

let isUpgrading = false;
let currentUpdateInfo = null;
let reconnectTimer = null;

// 清理版本号前缀，避免出现 vv0.8.2 等重复前缀
export function normalizeVersion(v) {
  if (!v) return '';
  return String(v).trim().replace(/^v+/i, '');
}

// 简易 Markdown 更新日志渲染器（安全无依赖）
function renderReleaseNotes(notes) {
  if (!notes || !notes.trim()) {
    return `<p style="color:var(--text-muted);">${escapeHtml(t('update.regularImprovements'))}</p>`;
  }

  const lines = notes.split(/\r?\n/);
  const htmlParts = [];
  let inList = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      if (inList) {
        htmlParts.push('</ul>');
        inList = false;
      }
      continue;
    }

    if (trimmed.startsWith('### ')) {
      if (inList) {
        htmlParts.push('</ul>');
        inList = false;
      }
      const title = trimmed.replace(/^###\s+/, '');
      htmlParts.push(`<h3>${formatInline(title)}</h3>`);
    } else if (trimmed.startsWith('## ')) {
      if (inList) {
        htmlParts.push('</ul>');
        inList = false;
      }
      const title = trimmed.replace(/^##\s+/, '');
      htmlParts.push(`<h3>${formatInline(title)}</h3>`);
    } else if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
      if (!inList) {
        htmlParts.push('<ul>');
        inList = true;
      }
      const item = trimmed.replace(/^[-*]\s+/, '');
      htmlParts.push(`<li>${formatInline(item)}</li>`);
    } else {
      if (inList) {
        htmlParts.push('</ul>');
        inList = false;
      }
      htmlParts.push(`<p>${formatInline(trimmed)}</p>`);
    }
  }

  if (inList) {
    htmlParts.push('</ul>');
  }

  return htmlParts.join('');
}

// 格式化加粗等行内语法
function formatInline(str) {
  let safe = escapeHtml(str);
  // 加粗 **text**
  safe = safe.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  // 行内代码 `code`
  safe = safe.replace(/`([^`]+)`/g, '<code style="background:var(--bg-card);padding:2px 4px;border-radius:4px;border:1px solid var(--border);">$1</code>');
  return safe;
}

// 打开版本更新模态框
export function openUpdateModal(info) {
  currentUpdateInfo = info;
  const modal = document.getElementById('updateModal');
  if (!modal) return;

  const cleanCurrent = normalizeVersion(info.current_version);
  const cleanTarget = normalizeVersion(info.latest_version);

  // 绑定元数据展示
  const tagEl = document.getElementById('updateModalVersionTag');
  if (tagEl) tagEl.innerText = `v${cleanTarget}`;

  const curVerEl = document.getElementById('updateCurrentVer');
  if (curVerEl) curVerEl.innerText = `v${cleanCurrent}`;

  const targetVerEl = document.getElementById('updateTargetVer');
  if (targetVerEl) targetVerEl.innerText = `v${cleanTarget}`;

  const notesEl = document.getElementById('updateNotesContainer');
  if (notesEl) {
    notesEl.innerHTML = renderReleaseNotes(info.release_notes);
  }

  // 重置视图与状态
  const promptView = document.getElementById('updatePromptView');
  const progressView = document.getElementById('updateProgressView');
  const closeBtn = document.getElementById('closeUpdateModalBtn');

  if (promptView) promptView.style.display = 'flex';
  if (progressView) progressView.style.display = 'none';
  if (closeBtn) closeBtn.style.display = 'inline-flex';

  modal.style.display = 'flex';
}

// 关闭模态框
export function closeUpdateModal() {
  if (isUpgrading) {
    // 升级中禁止直接关闭，防止用户中断进程
    return;
  }
  const modal = document.getElementById('updateModal');
  if (modal) modal.style.display = 'none';
}

// 遮罩点击
export function handleUpdateModalBackdropClick(e) {
  if (e.target.id === 'updateModal' && !isUpgrading) {
    closeUpdateModal();
  }
}

// 开始自动升级
export async function startWebUpgrade() {
  if (isUpgrading) return;
  isUpgrading = true;

  // 切换为进度视图
  const promptView = document.getElementById('updatePromptView');
  const progressView = document.getElementById('updateProgressView');
  const closeBtn = document.getElementById('closeUpdateModalBtn');

  if (promptView) promptView.style.display = 'none';
  if (progressView) progressView.style.display = 'flex';
  if (closeBtn) closeBtn.style.display = 'none';

  // 重置各步骤状态
  setStepState('stepDownload', 'active');
  setStepState('stepInstall', 'pending');
  setStepState('stepRestart', 'pending');

  updateProgress(0, '0 MB / 0 MB');
  setStatusText(t('update.downloading'), '正在连接更新发布源...');

  try {
    const res = await apiFetch('/api/v1/upgrade', { method: 'POST' });
    const json = await res.json();
    if (!json.success) {
      isUpgrading = false;
      if (closeBtn) closeBtn.style.display = 'inline-flex';
      showToast(t('common.upgradeFailed', { message: json.message }), 'error');
      setStatusText(t('common.upgradeFailed', { message: json.message }), '升级任务启动异常，请检查系统日志');
    }
  } catch (err) {
    isUpgrading = false;
    if (closeBtn) closeBtn.style.display = 'inline-flex';
    showToast(t('common.upgradeFailed', { message: err.message }), 'error');
    setStatusText(t('common.upgradeFailed', { message: err.message }), '网络请求异常');
  }
}

// 设置步骤指示器状态
function setStepState(stepId, state) {
  const el = document.getElementById(stepId);
  if (!el) return;
  el.className = `update-step-item ${state}`;
}

// 更新进度条与数据
function updateProgress(percent, transferredText) {
  const bar = document.getElementById('updateProgressBar');
  const percentText = document.getElementById('updateProgressPercent');
  const transText = document.getElementById('updateProgressTransferred');

  const p = Math.min(Math.max(percent, 0), 100);
  if (bar) bar.style.width = `${p}%`;
  if (percentText) percentText.innerText = `${p.toFixed(1)}%`;
  if (transText && transferredText) transText.innerText = transferredText;
}

// 设置状态标题与副文案
function setStatusText(title, sub) {
  const titleEl = document.getElementById('updateStatusTitle');
  const subEl = document.getElementById('updateStatusSub');
  if (titleEl && title) titleEl.innerText = title;
  if (subEl && sub) subEl.innerText = sub;
}

// 启动重启探测并在新服务就绪后全自动刷新页面
function startRestartPolling() {
  if (reconnectTimer) return;
  let pollAttempts = 0;

  setStatusText(t('update.restarting'), '服务正在平滑重启，准备自动重连...');

  const interval = setInterval(async () => {
    pollAttempts++;

    // 采用 1.5 秒超时的无阻塞探针，防止旧套接字挂起
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 1500);

    try {
      // 访问免鉴权公开状态接口，服务拉起后必定立即返回 200 OK
      const resp = await fetch('/api/v1/auth/status', {
        cache: 'no-store',
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (resp.ok) {
        clearInterval(interval);
        reconnectTimer = null;
        setStepState('stepRestart', 'done');
        setStatusText(t('update.upgradeComplete'), '新版本已就绪，正在自动进入控制台...');
        showToast(t('update.upgradeComplete'), 'success');
        setTimeout(() => {
          window.location.reload();
        }, 500);
        return;
      }
    } catch (_) {
      clearTimeout(timeoutId);
      // 网络处于进程平滑切换间隙，继续下一轮探测
    }

    // 持续探测超过 5 次（约 4 秒）后呈现手动刷新按钮作为极端环境兜底
    if (pollAttempts >= 5) {
      const manualBtn = document.getElementById('restartManualAction');
      if (manualBtn) manualBtn.style.display = 'flex';
      setStatusText(t('update.restarting'), '正在等待新版本服务就绪...');
    }
  }, 800);

  reconnectTimer = interval;
}

// 注册全局 SSE 日志监听器以解析升级进度
onLog((entry) => {
  if (!isUpgrading || !entry || !entry.message) return;
  const msg = entry.message;

  // 1. 匹配下载进度：例如 "下载进度: 45.2% (12.3 MB / 27.2 MB)"
  const progressMatch = msg.match(/下载进度:\s*([\d.]+)%\s*\(([^)]+)\)/);
  if (progressMatch) {
    const percent = parseFloat(progressMatch[1]);
    const trans = progressMatch[2];
    updateProgress(percent, trans);
    setStatusText(t('update.downloading'), `正在下载更新资产包 (${trans})...`);
    return;
  }

  // 2. 匹配下载与验签通过，开始安装替换
  if (msg.includes('更新包校验通过') || msg.includes('正在执行程序安全替换')) {
    setStepState('stepDownload', 'done');
    setStepState('stepInstall', 'active');
    updateProgress(100, '校验完成');
    setStatusText(t('update.installing'), '安装包哈希与签名通过，正在安全执行热替换...');
    return;
  }

  // 3. 匹配自更新完成，准备平滑重启
  if (msg.includes('自动更新完成，正在平滑重启服务') || msg.includes('正在调度平滑重启服务')) {
    setStepState('stepInstall', 'done');
    setStepState('stepRestart', 'active');
    updateProgress(100, '准备就绪');
    startRestartPolling();
    return;
  }

  // 4. 异常提示
  if (msg.includes('在线自动更新失败') || msg.includes('执行程序替换失败')) {
    isUpgrading = false;
    const closeBtn = document.getElementById('closeUpdateModalBtn');
    if (closeBtn) closeBtn.style.display = 'inline-flex';
    setStatusText('升级遇到异常', msg);
    showToast(msg, 'error');
  }
});

// 挂载至全局 window 供 HTML 事件绑定
window.openUpdateModal = openUpdateModal;
window.closeUpdateModal = closeUpdateModal;
window.handleUpdateModalBackdropClick = handleUpdateModalBackdropClick;
window.startWebUpgrade = startWebUpgrade;
