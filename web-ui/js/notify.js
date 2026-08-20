// ==========================================
// 通知渠道配置与测试通知模块
// ==========================================

import { apiFetch } from './api.js';
import { showToast } from './toast.js';

// 常用邮箱预设数据字典
export const EMAIL_PRESETS = {
  qq: { server: 'smtp.qq.com', port: 465, ssl: true },
  '163': { server: 'smtp.163.com', port: 465, ssl: true },
  '126': { server: 'smtp.126.com', port: 465, ssl: true },
  qq_enterprise: { server: 'smtp.exmail.qq.com', port: 465, ssl: true },
  aliyun: { server: 'smtp.aliyun.com', port: 465, ssl: true },
  gmail: { server: 'smtp.gmail.com', port: 465, ssl: true },
  outlook: { server: 'smtp.office365.com', port: 587, ssl: false },
  '139': { server: 'smtp.139.com', port: 465, ssl: true }
};

export function applyEmailPreset() {
  const val = document.getElementById('emailPreset')?.value;
  if (val && EMAIL_PRESETS[val]) {
    const p = EMAIL_PRESETS[val];
    const serverInput = document.getElementById('emailSmtpServer');
    const portInput = document.getElementById('emailSmtpPort');
    const sslCheck = document.getElementById('emailUseSsl');
    if (serverInput) serverInput.value = p.server;
    if (portInput) portInput.value = p.port;
    if (sslCheck) sslCheck.checked = p.ssl;
  }
}

export function autoFillFromAddress() {
  const username = document.getElementById('emailUsername')?.value.trim() || '';
  const fromInput = document.getElementById('emailFrom');
  if (fromInput && username.includes('@') && (!fromInput.value || fromInput.dataset.autofilled === "true")) {
    fromInput.value = username;
    fromInput.dataset.autofilled = "true";
  }
}

export function toggleWecomMode() {
  const mode = document.getElementById('wecomMode')?.value || 'bot';
  const botField = document.getElementById('wecomBotField');
  const appFields = document.getElementById('wecomAppFields');
  if (botField) botField.style.display = mode === 'bot' ? 'block' : 'none';
  if (appFields) appFields.style.display = mode === 'app' ? 'block' : 'none';
}

// 收集通知配置
export function collectNotificationConfig() {
  const cfg = {
    on_ip_change_only: true,
    on_success: document.getElementById('notifyOnSuccess')?.checked ?? true,
    on_failure: document.getElementById('notifyOnFailure')?.checked ?? true
  };

  const wxAppId = document.getElementById('wxOfficialAppId')?.value.trim();
  if (wxAppId) {
    cfg.wechat_official = {
      enabled: document.getElementById('wxOfficialEnable')?.checked ?? false,
      app_id: wxAppId,
      app_secret: document.getElementById('wxOfficialAppSecret')?.value.trim() || '',
      template_id: document.getElementById('wxOfficialTemplateId')?.value.trim() || '',
      to_user: document.getElementById('wxOfficialToUser')?.value.trim() || '',
      url: document.getElementById('wxOfficialUrl')?.value.trim() || null,
      template_data: document.getElementById('wxOfficialTmplData')?.value.trim() || null,
    };
  }

  const wecomMode = document.getElementById('wecomMode')?.value || 'bot';
  const wecomHook = document.getElementById('wecomWebhookUrl')?.value.trim();
  const wecomCorp = document.getElementById('wecomCorpId')?.value.trim();
  if (wecomHook || wecomCorp) {
    cfg.wecom = {
      enabled: document.getElementById('wecomEnable')?.checked ?? false,
      mode: wecomMode,
      webhook_url: wecomHook || null,
      corp_id: wecomCorp || null,
      corp_secret: document.getElementById('wecomCorpSecret')?.value.trim() || null,
      agent_id: parseInt(document.getElementById('wecomAgentId')?.value) || null,
      to_user: document.getElementById('wecomToUser')?.value.trim() || null
    };
  }

  const smtpServer = document.getElementById('emailSmtpServer')?.value.trim();
  if (smtpServer) {
    cfg.email = {
      enabled: document.getElementById('emailEnable')?.checked ?? false,
      smtp_server: smtpServer,
      smtp_port: parseInt(document.getElementById('emailSmtpPort')?.value) || 465,
      use_ssl: document.getElementById('emailUseSsl')?.checked ?? true,
      username: document.getElementById('emailUsername')?.value.trim() || '',
      password: document.getElementById('emailPassword')?.value.trim() || '',
      from_address: document.getElementById('emailFrom')?.value.trim() || '',
      to_addresses: (document.getElementById('emailTo')?.value || '').split(',').map(s => s.trim()).filter(Boolean)
    };
  }

  const dtToken = document.getElementById('dingtalkAccessToken')?.value.trim();
  if (dtToken) {
    cfg.dingtalk = {
      enabled: document.getElementById('dingtalkEnable')?.checked ?? false,
      access_token: dtToken,
      secret: document.getElementById('dingtalkSecret')?.value.trim() || null
    };
  }

  const fsHook = document.getElementById('feishuWebhookUrl')?.value.trim();
  if (fsHook) {
    cfg.feishu = {
      enabled: document.getElementById('feishuEnable')?.checked ?? false,
      webhook_url: fsHook,
      secret: document.getElementById('feishuSecret')?.value.trim() || null
    };
  }

  const tgToken = document.getElementById('telegramBotToken')?.value.trim();
  if (tgToken) {
    cfg.telegram = {
      enabled: document.getElementById('telegramEnable')?.checked ?? false,
      bot_token: tgToken,
      chat_id: document.getElementById('telegramChatId')?.value.trim() || '',
      api_proxy: document.getElementById('telegramApiProxy')?.value.trim() || null
    };
  }

  const barkKey = document.getElementById('barkDeviceKey')?.value.trim();
  if (barkKey) {
    cfg.bark = {
      enabled: document.getElementById('barkEnable')?.checked ?? false,
      server_url: document.getElementById('barkServerUrl')?.value.trim() || 'https://api.day.app',
      device_key: barkKey,
      group: document.getElementById('barkGroup')?.value.trim() || null,
      sound: document.getElementById('barkSound')?.value.trim() || null
    };
  }

  const whUrl = document.getElementById('webhookUrl')?.value.trim();
  if (whUrl) {
    let parsedHeaders = null;
    try {
      const hStr = document.getElementById('webhookHeaders')?.value.trim();
      if (hStr) parsedHeaders = JSON.parse(hStr);
    } catch (_) {}
    cfg.webhook = {
      enabled: document.getElementById('webhookEnable')?.checked ?? false,
      url: whUrl,
      method: document.getElementById('webhookMethod')?.value || 'POST',
      headers: parsedHeaders,
      body: document.getElementById('webhookBody')?.value.trim() || null
    };
  }

  return cfg;
}

// 发送单项渠道测试通知
export async function testSingleNotify(channelKey) {
  let notifPayload = {
    on_ip_change_only: false,
    on_success: true,
    on_failure: true
  };

  if (channelKey === 'wechat_official') {
    const appId = document.getElementById('wxOfficialAppId')?.value.trim();
    const appSecret = document.getElementById('wxOfficialAppSecret')?.value.trim();
    const templateId = document.getElementById('wxOfficialTemplateId')?.value.trim();
    const toUser = document.getElementById('wxOfficialToUser')?.value.trim();
    if (!appId || !appSecret || !templateId || !toUser) {
      showToast('请先完整填写微信公众号 AppID、AppSecret、模板ID 与 接收者 OpenID！', 'error');
      return;
    }
    notifPayload.wechat_official = {
      enabled: true,
      app_id: appId,
      app_secret: appSecret,
      template_id: templateId,
      to_user: toUser,
      url: document.getElementById('wxOfficialUrl')?.value.trim() || null,
      template_data: document.getElementById('wxOfficialTmplData')?.value.trim() || null,
    };
  } else if (channelKey === 'wecom') {
    const mode = document.getElementById('wecomMode')?.value;
    if (mode === 'bot') {
      const webhookUrl = document.getElementById('wecomWebhookUrl')?.value.trim();
      if (!webhookUrl) {
        showToast('请先填写企业微信群机器人 Webhook URL！', 'error');
        return;
      }
      notifPayload.wecom = {
        enabled: true,
        mode: 'bot',
        webhook_url: webhookUrl
      };
    } else {
      const corpId = document.getElementById('wecomCorpId')?.value.trim();
      const corpSecret = document.getElementById('wecomCorpSecret')?.value.trim();
      const agentId = parseInt(document.getElementById('wecomAgentId')?.value);
      if (!corpId || !corpSecret || !agentId) {
        showToast('请先完整填写企业微信 CorpID、CorpSecret 与 AgentID！', 'error');
        return;
      }
      notifPayload.wecom = {
        enabled: true,
        mode: 'app',
        corp_id: corpId,
        corp_secret: corpSecret,
        agent_id: agentId,
        to_user: document.getElementById('wecomToUser')?.value.trim() || '@all'
      };
    }
  } else if (channelKey === 'email') {
    const smtpServer = document.getElementById('emailSmtpServer')?.value.trim();
    const username = document.getElementById('emailUsername')?.value.trim();
    const password = document.getElementById('emailPassword')?.value.trim();
    const fromAddress = document.getElementById('emailFrom')?.value.trim();
    const toAddresses = (document.getElementById('emailTo')?.value || '').split(',').map(s => s.trim()).filter(Boolean);
    if (!smtpServer || !username || !password || !fromAddress || toAddresses.length === 0) {
      showToast('请先完整填写 SMTP 服务器、账号、密码/授权码、发件人及收件人邮箱！', 'error');
      return;
    }
    notifPayload.email = {
      enabled: true,
      smtp_server: smtpServer,
      smtp_port: parseInt(document.getElementById('emailSmtpPort')?.value) || 465,
      use_ssl: document.getElementById('emailUseSsl')?.checked ?? true,
      username,
      password,
      from_address: fromAddress,
      to_addresses: toAddresses
    };
  } else if (channelKey === 'dingtalk') {
    const token = document.getElementById('dingtalkAccessToken')?.value.trim();
    if (!token) {
      showToast('请先填写钉钉机器人的 AccessToken 或 Webhook 地址！', 'error');
      return;
    }
    notifPayload.dingtalk = {
      enabled: true,
      access_token: token,
      secret: document.getElementById('dingtalkSecret')?.value.trim() || null
    };
  } else if (channelKey === 'feishu') {
    const hook = document.getElementById('feishuWebhookUrl')?.value.trim();
    if (!hook) {
      showToast('请先填写飞书群机器人的 Webhook URL！', 'error');
      return;
    }
    notifPayload.feishu = {
      enabled: true,
      webhook_url: hook,
      secret: document.getElementById('feishuSecret')?.value.trim() || null
    };
  } else if (channelKey === 'telegram') {
    const token = document.getElementById('telegramBotToken')?.value.trim();
    const chatId = document.getElementById('telegramChatId')?.value.trim();
    if (!token || !chatId) {
      showToast('请先填写 Telegram Bot Token 与 Chat ID！', 'error');
      return;
    }
    notifPayload.telegram = {
      enabled: true,
      bot_token: token,
      chat_id: chatId,
      api_proxy: document.getElementById('telegramApiProxy')?.value.trim() || null
    };
  } else if (channelKey === 'bark') {
    const devKey = document.getElementById('barkDeviceKey')?.value.trim();
    if (!devKey) {
      showToast('请先填写 Bark 设备 Key！', 'error');
      return;
    }
    notifPayload.bark = {
      enabled: true,
      server_url: document.getElementById('barkServerUrl')?.value.trim() || 'https://api.day.app',
      device_key: devKey,
      group: document.getElementById('barkGroup')?.value.trim() || null,
      sound: document.getElementById('barkSound')?.value.trim() || null
    };
  } else if (channelKey === 'webhook') {
    const whUrl = document.getElementById('webhookUrl')?.value.trim();
    if (!whUrl) {
      showToast('请先填写 Webhook URL 地址！', 'error');
      return;
    }
    let parsedHeaders = null;
    try {
      const hStr = document.getElementById('webhookHeaders')?.value.trim();
      if (hStr) parsedHeaders = JSON.parse(hStr);
    } catch (_) {}
    notifPayload.webhook = {
      enabled: true,
      url: whUrl,
      method: document.getElementById('webhookMethod')?.value || 'POST',
      headers: parsedHeaders,
      body: document.getElementById('webhookBody')?.value.trim() || null
    };
  }

  showToast('正在发送测试通知...', 'info');
  try {
    const res = await apiFetch('/api/v1/test/notify', {
      method: 'POST',
      body: notifPayload
    });
    const json = await res.json();
    if (json.success) {
      showToast('测试消息已发出，请查看目标平台接收情况！', 'success');
    } else {
      showToast('发送失败: ' + json.message, 'error');
    }
  } catch (e) {
    showToast('请求异常: ' + e, 'error');
  }
}

// 发送全部已启用渠道的测试通知 (支持前置 saveConfigFn 执行)
export async function testNotifyAll(saveConfigFn) {
  if (typeof saveConfigFn === 'function') {
    await saveConfigFn();
  }
  const notifPayload = collectNotificationConfig();
  try {
    const res = await apiFetch('/api/v1/test/notify', {
      method: 'POST',
      body: notifPayload
    });
    const json = await res.json();
    if (json.success) {
      showToast('已向全部已启用的通知渠道发送测试消息！', 'success');
    } else {
      showToast('发送失败: ' + json.message, 'error');
    }
  } catch (e) {
    showToast('测试异常: ' + e, 'error');
  }
}
