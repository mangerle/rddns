// ==========================================
// rddns 前端应用主调度与初始化入口
// ==========================================

import { apiFetch } from './api.js';
import { initTheme, toggleTheme } from './theme.js';
import { showToast } from './toast.js';
import { openLogModal, closeLogModal, clearLogs, handleBackdropClick, initSSE } from './modal.js';
import {
  t,
  initI18n,
  setLocale,
  getLocale,
  onLocaleChange
} from './i18n/index.js';
import {
  showLoginPage,
  showInitPage,
  showMainApp,
  updateLogoutBtn,
  logout,
  submitInitAuth,
  submitLogin,
  initPasswordToggles,
  setOnLoginSuccess
} from './auth.js';
import {
  globalConfig,
  currentTaskIndex,
  setGlobalConfig,
  setCurrentTaskIndex,
  loadNetworkInterfaces,
  handleNetIfSelect,
  handleStunSelect,
  handleTtlSelect,
  renderProviderFields,
  renderIpFields,
  renderTaskList,
  populateCurrentTaskForm,
  collectCurrentTaskFromForm,
  switchTask,
  addNewTask,
  deleteCurrentTask,
  cloneCurrentTask,
  onTaskNameChange,
  onTaskEnabledChange,
  testIp
} from './tasks.js';
import {
  EMAIL_PRESETS,
  applyEmailPreset,
  autoFillFromAddress,
  toggleWecomMode,
  collectNotificationConfig,
  testSingleNotify,
  testNotifyAll
} from './notify.js';

let currentActiveTab = 'tab-dns';

// 获取当前模块的标题与描述
export function getSectionInfo(tabId) {
  const sections = {
    'tab-dns': {
      title: t('nav.dnsTitle'),
      desc: t('nav.dnsDesc')
    },
    'tab-notify': {
      title: t('nav.notifyTitle'),
      desc: t('nav.notifyDesc')
    },
    'tab-system': {
      title: t('nav.systemTitle'),
      desc: t('nav.systemDesc')
    }
  };
  return sections[tabId] || sections['tab-dns'];
}

export function switchNav(tabId) {
  currentActiveTab = tabId;
  document.querySelectorAll('.tab-content').forEach(el => el.style.display = 'none');
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  
  const activeTab = document.getElementById(tabId);
  if (activeTab) activeTab.style.display = 'block';
  
  const navItem = document.getElementById(`nav-${tabId}`);
  if (navItem) navItem.classList.add('active');

  const dnsSubSidebar = document.getElementById('dnsSubSidebar');
  if (dnsSubSidebar) {
    dnsSubSidebar.style.display = (tabId === 'tab-dns') ? 'flex' : 'none';
  }

  // 控制工作台吸顶 Header 展示内容 (DNS 模式展示任务栏，其它模式展示模块标题)
  const headerDnsTaskBar = document.getElementById('headerDnsTaskBar');
  const headerStandardBar = document.getElementById('headerStandardBar');
  const titleEl = document.getElementById('currentSectionTitle');
  const descEl = document.getElementById('currentSectionDesc');

  if (tabId === 'tab-dns') {
    if (headerDnsTaskBar) headerDnsTaskBar.style.display = 'flex';
    if (headerStandardBar) headerStandardBar.style.display = 'none';
  } else {
    if (headerDnsTaskBar) headerDnsTaskBar.style.display = 'none';
    if (headerStandardBar) headerStandardBar.style.display = 'flex';
    const info = getSectionInfo(tabId);
    if (info) {
      if (titleEl) titleEl.innerText = info.title;
      if (descEl) descEl.innerText = info.desc;
    }
  }

  // 切换标签页时将工作台滚动主体重置回顶部
  const workspaceBody = document.querySelector('.workspace-body');
  if (workspaceBody) workspaceBody.scrollTop = 0;
}

// 切换语言
export function toggleLanguage() {
  const current = getLocale();
  const next = current === 'zh-CN' ? 'en-US' : 'zh-CN';
  setLocale(next);
  updateLangBtnText();
  showToast(next === 'zh-CN' ? '已切换至简体中文' : 'Switched to English', 'info');
}

export function updateLangBtnText() {
  const current = getLocale();
  const text = current === 'zh-CN' ? 'EN' : '中';
  ['langBtnText', 'loginLangBtnText', 'initLangBtnText'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerText = text;
  });
}

// 全局回显配置 (首次加载或刷新配置时触发)
export function populateForm(conf) {
  const sysIntervalEl = document.getElementById('sysInterval');
  if (sysIntervalEl) sysIntervalEl.value = conf.interval_secs || 300;
  const sysCacheTimesEl = document.getElementById('sysCacheTimes');
  if (sysCacheTimesEl) sysCacheTimesEl.value = conf.cache_times || 10;
  const sysNotAllowWanEl = document.getElementById('sysNotAllowWan');
  if (sysNotAllowWanEl) sysNotAllowWanEl.checked = conf.not_allow_wan_access;
  const sysDnsServerEl = document.getElementById('sysDnsServer');
  if (sysDnsServerEl) sysDnsServerEl.value = conf.dns_server || '';

  if (conf.auth && document.getElementById('sysUsername')) {
    document.getElementById('sysUsername').value = conf.auth.username;
  }

  // 如果任务列表为空，自动补全默认任务
  if (!conf.dns_tasks || conf.dns_tasks.length === 0) {
    conf.dns_tasks = [{
      name: `${t('task.nameLabel')} 1`,
      enabled: true,
      provider: { type: 'cloudflare', api_token: '' },
      ttl: null,
      ipv4: { enabled: true, source_type: 'url', url_endpoints: ['https://api.ipify.org'], net_interface: null, cmd: null, regex: null, domains: [] },
      ipv6: { enabled: true, source_type: 'net_interface', url_endpoints: [], net_interface: null, cmd: null, regex: null, domains: [] }
    }];
  }

  setCurrentTaskIndex(0);
  renderTaskList();
  populateCurrentTaskForm(conf.dns_tasks[currentTaskIndex]);

  // Notifications 回显
  if (conf.notifications) {
    const notif = conf.notifications;
    const onSuccessEl = document.getElementById('notifyOnSuccess');
    if (onSuccessEl) onSuccessEl.checked = notif.on_success !== false;
    const onFailureEl = document.getElementById('notifyOnFailure');
    if (onFailureEl) onFailureEl.checked = notif.on_failure !== false;

    if (notif.wechat_official) {
      const wx = notif.wechat_official;
      if (document.getElementById('wxOfficialEnable')) document.getElementById('wxOfficialEnable').checked = wx.enabled;
      if (document.getElementById('wxOfficialAppId')) document.getElementById('wxOfficialAppId').value = wx.app_id || '';
      if (document.getElementById('wxOfficialAppSecret')) document.getElementById('wxOfficialAppSecret').value = wx.app_secret || '';
      if (document.getElementById('wxOfficialTemplateId')) document.getElementById('wxOfficialTemplateId').value = wx.template_id || '';
      if (document.getElementById('wxOfficialToUser')) document.getElementById('wxOfficialToUser').value = wx.to_user || '';
      if (document.getElementById('wxOfficialUrl')) document.getElementById('wxOfficialUrl').value = wx.url || '';
      if (document.getElementById('wxOfficialTmplData')) document.getElementById('wxOfficialTmplData').value = wx.template_data || '';
    }
    if (notif.wecom) {
      const wc = notif.wecom;
      if (document.getElementById('wecomEnable')) document.getElementById('wecomEnable').checked = wc.enabled;
      if (document.getElementById('wecomMode')) document.getElementById('wecomMode').value = wc.mode || 'bot';
      toggleWecomMode();
      if (document.getElementById('wecomWebhookUrl')) document.getElementById('wecomWebhookUrl').value = wc.webhook_url || '';
      if (document.getElementById('wecomCorpId')) document.getElementById('wecomCorpId').value = wc.corp_id || '';
      if (document.getElementById('wecomCorpSecret')) document.getElementById('wecomCorpSecret').value = wc.corp_secret || '';
      if (document.getElementById('wecomAgentId')) document.getElementById('wecomAgentId').value = wc.agent_id || '';
      if (document.getElementById('wecomToUser')) document.getElementById('wecomToUser').value = wc.to_user || '';
    }
    if (notif.email) {
      const em = notif.email;
      if (document.getElementById('emailEnable')) document.getElementById('emailEnable').checked = em.enabled;
      if (document.getElementById('emailSmtpServer')) document.getElementById('emailSmtpServer').value = em.smtp_server || '';
      if (document.getElementById('emailSmtpPort')) document.getElementById('emailSmtpPort').value = em.smtp_port || 465;
      if (document.getElementById('emailUsername')) document.getElementById('emailUsername').value = em.username || '';
      if (document.getElementById('emailPassword')) document.getElementById('emailPassword').value = em.password || '';
      if (document.getElementById('emailFrom')) document.getElementById('emailFrom').value = em.from_address || '';
      if (document.getElementById('emailTo')) document.getElementById('emailTo').value = (em.to_addresses || []).join(', ');
      if (document.getElementById('emailUseSsl')) document.getElementById('emailUseSsl').checked = em.use_ssl !== false;

      let matchedPreset = 'custom';
      for (const [key, preset] of Object.entries(EMAIL_PRESETS)) {
        if (preset.server.toLowerCase() === (em.smtp_server || '').toLowerCase()) {
          matchedPreset = key;
          break;
        }
      }
      if (document.getElementById('emailPreset')) document.getElementById('emailPreset').value = matchedPreset;
    }
    if (notif.dingtalk) {
      const dt = notif.dingtalk;
      if (document.getElementById('dingtalkEnable')) document.getElementById('dingtalkEnable').checked = dt.enabled;
      if (document.getElementById('dingtalkAccessToken')) document.getElementById('dingtalkAccessToken').value = dt.access_token || '';
      if (document.getElementById('dingtalkSecret')) document.getElementById('dingtalkSecret').value = dt.secret || '';
    }
    if (notif.feishu) {
      const fs = notif.feishu;
      if (document.getElementById('feishuEnable')) document.getElementById('feishuEnable').checked = fs.enabled;
      if (document.getElementById('feishuWebhookUrl')) document.getElementById('feishuWebhookUrl').value = fs.webhook_url || '';
      if (document.getElementById('feishuSecret')) document.getElementById('feishuSecret').value = fs.secret || '';
    }
    if (notif.telegram) {
      const tg = notif.telegram;
      if (document.getElementById('telegramEnable')) document.getElementById('telegramEnable').checked = tg.enabled;
      if (document.getElementById('telegramBotToken')) document.getElementById('telegramBotToken').value = tg.bot_token || '';
      if (document.getElementById('telegramChatId')) document.getElementById('telegramChatId').value = tg.chat_id || '';
      if (document.getElementById('telegramApiProxy')) document.getElementById('telegramApiProxy').value = tg.api_proxy || '';
    }
    if (notif.bark) {
      const bk = notif.bark;
      if (document.getElementById('barkEnable')) document.getElementById('barkEnable').checked = bk.enabled;
      if (document.getElementById('barkServerUrl')) document.getElementById('barkServerUrl').value = bk.server_url || 'https://api.day.app';
      if (document.getElementById('barkDeviceKey')) document.getElementById('barkDeviceKey').value = bk.device_key || '';
      if (document.getElementById('barkGroup')) document.getElementById('barkGroup').value = bk.group || '';
      if (document.getElementById('barkSound')) document.getElementById('barkSound').value = bk.sound || '';
    }
    if (notif.webhook) {
      const wh = notif.webhook;
      if (document.getElementById('webhookEnable')) document.getElementById('webhookEnable').checked = wh.enabled;
      if (document.getElementById('webhookUrl')) document.getElementById('webhookUrl').value = wh.url || '';
      if (document.getElementById('webhookMethod')) document.getElementById('webhookMethod').value = wh.method || 'POST';
      if (document.getElementById('webhookHeaders')) document.getElementById('webhookHeaders').value = wh.headers ? JSON.stringify(wh.headers) : '';
      if (document.getElementById('webhookBody')) document.getElementById('webhookBody').value = wh.body || '';
    }
  }
  initPasswordToggles();
}

// 加载配置
export async function loadConfig() {
  try {
    const res = await apiFetch('/api/v1/config');
    if (res.status === 401) {
      showLoginPage();
      return;
    }
    const json = await res.json();
    if (json.success) {
      setGlobalConfig(json.data);
      populateForm(globalConfig);
      showMainApp();
    }
  } catch (e) {
    console.error('加载配置异常:', e);
  }
}

// 保存全局配置 (包含所有多任务与系统通知)
export async function saveConfig() {
  collectCurrentTaskFromForm(currentTaskIndex);

  const notifications = collectNotificationConfig();

  const payload = {
    config: {
      listen_port: globalConfig?.listen_port || 9876,
      interval_secs: parseInt(document.getElementById('sysInterval')?.value) || 300,
      cache_times: parseInt(document.getElementById('sysCacheTimes')?.value) || 10,
      not_allow_wan_access: document.getElementById('sysNotAllowWan')?.checked ?? false,
      auth: document.getElementById('sysUsername')?.value ? {
        username: document.getElementById('sysUsername').value
      } : null,
      dns_server: document.getElementById('sysDnsServer')?.value?.trim() || null,
      dns_tasks: globalConfig?.dns_tasks || [],
      notifications
    },
    new_password: document.getElementById('sysPassword')?.value || null
  };

  try {
    const res = await apiFetch('/api/v1/config', {
      method: 'POST',
      body: payload
    });
    const json = await res.json();
    if (json.success) {
      showToast(t('common.saveSuccess'), 'success');
      const newUsername = document.getElementById('sysUsername')?.value.trim();
      const newPassword = document.getElementById('sysPassword')?.value;
      if (newPassword) {
        sessionStorage.setItem('rddns_auth', btoa(newUsername + ':' + newPassword));
        updateLogoutBtn();
      }
      if (document.getElementById('sysPassword')) {
        document.getElementById('sysPassword').value = '';
      }
      renderTaskList();
    } else {
      showToast(t('common.saveFailed', { message: json.message }), 'error');
    }
  } catch (e) {
    showToast(t('common.requestError', { error: e }), 'error');
  }
}

// 立即触发全量同步
export async function triggerSync() {
  try {
    const res = await apiFetch('/api/v1/sync', { method: 'POST' });
    const json = await res.json();
    showToast(json.message, json.success ? 'success' : 'error');
  } catch (e) {
    showToast(t('common.syncTriggerFailed', { error: e }), 'error');
  }
}

// 检查版本更新 (仅在手动点击时触发)
export async function checkAppVersion(isManual = true) {
  if (isManual) {
    showToast(t('common.checkingUpdate') || '正在检查更新...', 'info');
  }
  try {
    const res = await apiFetch('/api/v1/version');
    const json = await res.json();
    if (json.success && json.data) {
      const info = json.data;
      const verTextEl = document.getElementById('versionText');
      if (verTextEl) {
        verTextEl.dataset.version = info.current_version;
        verTextEl.innerText = t('common.connected', { version: `v${info.current_version}` });
      }
      const updateNoticeEl = document.getElementById('updateNotice');
      if (info.has_update) {
        if (updateNoticeEl) {
          updateNoticeEl.style.display = 'block';
          updateNoticeEl.innerHTML = `<span>${t('common.newVersionFound', { version: `v${info.latest_version}` })}</span>`;
        }
        if (isManual) {
          if (confirm(t('common.newVersionUpgradePrompt', { version: info.latest_version, notes: info.release_notes || 'Regular improvements' }))) {
            triggerWebUpgrade();
          }
        }
      } else if (isManual) {
        showToast(t('common.latestVersionAlert', { version: info.current_version }), 'success');
      }
    }
  } catch (e) {
    if (isManual) showToast(t('common.checkUpdateFailed', { error: e.message }), 'error');
  }
}

// 触发在线升级
export async function triggerWebUpgrade() {
  if (!confirm(t('common.upgradeConfirm'))) return;
  try {
    const res = await apiFetch('/api/v1/upgrade', { method: 'POST' });
    const json = await res.json();
    if (json.success) {
      showToast(t('common.upgradeSuccess', { message: json.message }), 'success');
    } else {
      showToast(t('common.upgradeFailed', { message: json.message }), 'error');
    }
  } catch (e) {
    showToast(t('common.upgradeFailed', { message: e.message }), 'error');
  }
}

// 监听语言切换，同步更新顶部状态栏和当前模块标题
onLocaleChange(() => {
  updateLangBtnText();
  if (currentActiveTab !== 'tab-dns') {
    const titleEl = document.getElementById('currentSectionTitle');
    const descEl = document.getElementById('currentSectionDesc');
    const info = getSectionInfo(currentActiveTab);
    if (info) {
      if (titleEl) titleEl.innerText = info.title;
      if (descEl) descEl.innerText = info.desc;
    }
  }
  const verTextEl = document.getElementById('versionText');
  if (verTextEl) {
    const currentVer = verTextEl.dataset.version;
    if (currentVer) {
      verTextEl.innerText = t('common.connected', { version: `v${currentVer}` });
    } else {
      verTextEl.innerText = t('common.connectedFallback');
    }
  }
});

// 初始化应用生命周期
async function initApp() {
  initI18n();
  initTheme();
  updateLangBtnText();
  renderProviderFields();
  renderIpFields('ipv4');
  renderIpFields('ipv6');

  // 静默异步获取系统真实版本号并绑定至顶部徽标
  checkAppVersion(false);

  // 设置登录成功回调
  setOnLoginSuccess(() => {
    loadConfig();
    loadNetworkInterfaces();
    initSSE();
    checkAppVersion(false);
  });

  // 1. 检查后端是否需要初始化管理员账号
  try {
    const statusRes = await fetch('/api/v1/auth/status');
    const statusJson = await statusRes.json();
    if (statusJson.success) {
      if (statusJson.data.need_init) {
        showInitPage();
        return;
      }
      if (statusJson.data.username && document.getElementById('loginUsername')) {
        document.getElementById('loginUsername').value = statusJson.data.username;
      }
    }
  } catch (e) {
    console.error('检查认证状态异常:', e);
  }

  // 2. 如果已完成初始化，检查本地凭据
  const auth = sessionStorage.getItem('rddns_auth');
  if (!auth) {
    showLoginPage();
    return;
  }

  // 3. 携带本地凭据拉取配置
  const configRes = await apiFetch('/api/v1/config');
  if (configRes.status === 401) {
    showLoginPage();
    return;
  }
  const configJson = await configRes.json();
  if (configJson.success) {
    setGlobalConfig(configJson.data);
    populateForm(globalConfig);
    showMainApp();
    loadNetworkInterfaces();
    initSSE();
  } else {
    showLoginPage();
  }
}

// 挂载所有供 HTML 内联事件调用的方法到全局 window 对象
Object.assign(window, {
  toggleTheme,
  toggleLanguage,
  openLogModal,
  closeLogModal,
  clearLogs,
  handleBackdropClick,
  showLoginPage,
  showInitPage,
  showMainApp,
  logout,
  submitInitAuth,
  submitLogin,
  switchNav,
  applyEmailPreset,
  autoFillFromAddress,
  toggleWecomMode,
  handleNetIfSelect,
  handleStunSelect,
  handleTtlSelect,
  renderProviderFields,
  renderIpFields,
  switchTask,
  addNewTask,
  deleteCurrentTask,
  cloneCurrentTask,
  onTaskNameChange,
  onTaskEnabledChange,
  saveConfig,
  triggerSync,
  testIp,
  testSingleNotify,
  testNotifyAll: () => testNotifyAll(saveConfig),
  checkAppVersion,
  triggerWebUpgrade
});

// 启动应用
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initApp);
} else {
  initApp();
}
