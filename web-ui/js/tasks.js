// ==========================================
// 多任务状态管理与 Provider 动态表单模块 (Master-Detail)
// ==========================================

import { apiFetch } from './api.js';
import { showToast } from './toast.js';
import { initPasswordToggles } from './auth.js';
import { t, onLocaleChange } from './i18n/index.js';

// 全局任务状态数据
export let globalConfig = null;
export let availableInterfaces = [];
export let savedIpv4NetIf = '';
export let savedIpv6NetIf = '';
export let currentTaskIndex = 0;

export function setGlobalConfig(cfg) {
  globalConfig = cfg;
}

export function setCurrentTaskIndex(idx) {
  currentTaskIndex = idx;
}

// HTML 安全字符转义函数
export function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export const PROVIDER_DISPLAY_NAMES = {
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
  callback: '自定义 Callback'
};

export function getProviderDisplayName(pType) {
  return PROVIDER_DISPLAY_NAMES[pType] || pType || t('task.noProviderConfigured');
}

// 渲染出站物理网卡下拉选项
export function renderHttpInterfaceOptions(selectedVal) {
  const selectEl = document.getElementById('dnsHttpInterface');
  if (!selectEl) return;
  const current = selectedVal !== undefined ? selectedVal : (selectEl.value || '');
  let html = `<option value="">${escapeHtml(t('dns.httpInterfaceDefault'))}</option>`;
  availableInterfaces.forEach(iface => {
    const isSel = (iface.name === current) ? 'selected' : '';
    html += `<option value="${escapeHtml(iface.name)}" ${isSel}>${escapeHtml(iface.display_name || iface.name)}</option>`;
  });
  if (current && !availableInterfaces.some(i => i.name === current)) {
    html += `<option value="${escapeHtml(current)}" selected>${escapeHtml(t('dns.httpInterfaceOffline', { name: current }))}</option>`;
  }
  selectEl.innerHTML = html;
}

// 异步拉取系统物理与虚拟网卡列表
export async function loadNetworkInterfaces() {
  try {
    const res = await apiFetch('/api/v1/network-interfaces');
    const json = await res.json();
    if (json.success && Array.isArray(json.data)) {
      availableInterfaces = json.data;
      renderHttpInterfaceOptions();
      if (document.getElementById('ipv4SourceType')?.value === 'net_interface') {
        renderIpFields('ipv4');
      }
      if (document.getElementById('ipv6SourceType')?.value === 'net_interface') {
        renderIpFields('ipv6');
      }
    }
  } catch (e) {
    console.warn('获取网卡列表失败:', e);
  }
}

// 处理网卡下拉框选择变化
export function handleNetIfSelect(vType) {
  const selVal = document.getElementById(`${vType}NetIfSelect`)?.value;
  const customInput = document.getElementById(`${vType}NetIfCustom`);
  if (selVal === '__custom__') {
    if (customInput) {
      customInput.style.display = 'block';
      customInput.focus();
    }
  } else {
    if (customInput) {
      customInput.style.display = 'none';
      customInput.value = selVal || '';
    }
  }
  if (vType === 'ipv4') {
    savedIpv4NetIf = getNetIfValue('ipv4') || '';
  } else {
    savedIpv6NetIf = getNetIfValue('ipv6') || '';
  }
}

// 获取选定网卡名称值
export function getNetIfValue(vType) {
  const selectEl = document.getElementById(`${vType}NetIfSelect`);
  if (!selectEl) return null;
  if (selectEl.value === '__custom__') {
    return document.getElementById(`${vType}NetIfCustom`)?.value.trim() || null;
  }
  return selectEl.value.trim() || null;
}

// 处理 TTL 下拉框选择变化
export function handleTtlSelect() {
  const selVal = document.getElementById('dnsTtlSelect')?.value;
  const customInput = document.getElementById('dnsTtlCustom');
  if (selVal === '__custom__') {
    if (customInput) {
      customInput.style.display = 'block';
      customInput.focus();
    }
  } else {
    if (customInput) {
      customInput.style.display = 'none';
      customInput.value = '';
    }
  }
}

// 获取选定的 TTL 数值 (秒)
export function getTtlValue() {
  const selectEl = document.getElementById('dnsTtlSelect');
  if (!selectEl) return null;
  if (selectEl.value === '__custom__') {
    const raw = document.getElementById('dnsTtlCustom')?.value.trim();
    const val = parseInt(raw);
    return isNaN(val) ? null : val;
  }
  if (!selectEl.value) return null;
  const val = parseInt(selectEl.value);
  return isNaN(val) ? null : val;
}

// 回显设置 TTL 状态
export function setTtlValue(ttl) {
  const selectEl = document.getElementById('dnsTtlSelect');
  const customInput = document.getElementById('dnsTtlCustom');
  if (!selectEl || !customInput) return;
  if (ttl === undefined || ttl === null || ttl === '' || ttl === 0) {
    selectEl.value = '';
    customInput.style.display = 'none';
    customInput.value = '';
  } else {
    const strTtl = String(ttl);
    const hasOption = Array.from(selectEl.options).some(opt => opt.value === strTtl);
    if (hasOption) {
      selectEl.value = strTtl;
      customInput.style.display = 'none';
      customInput.value = '';
    } else {
      selectEl.value = '__custom__';
      customInput.style.display = 'block';
      customInput.value = strTtl;
    }
  }
}

// 渲染 DNS 服务商动态凭据表单
export function renderProviderFields() {
  const type = document.getElementById('dnsProviderType')?.value || 'cloudflare';
  const container = document.getElementById('providerDynamicFields');
  if (!container) return;
  if (type === 'cloudflare') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>API Token (${t('common.recommended')})</label>
          <input type="password" id="cfApiToken" placeholder="Cloudflare API Token" />
        </div>
        <div class="form-group">
          <label>Global API Key</label>
          <input type="password" id="cfApiKey" placeholder="Global API Key" />
        </div>
      </div>
      <div class="form-group">
        <label>Cloudflare Account Email</label>
        <input type="text" id="cfEmail" placeholder="your_email@example.com" />
      </div>`;
  } else if (type === 'ali_dns') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>AccessKey ID</label>
          <input type="text" id="aliAccessKeyId" placeholder="Aliyun RAM AccessKey ID" />
        </div>
        <div class="form-group">
          <label>AccessKey Secret</label>
          <input type="password" id="aliAccessKeySecret" placeholder="Aliyun RAM AccessKey Secret" />
        </div>
      </div>`;
  } else if (type === 'tencent_cloud') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>SecretId</label>
          <input type="text" id="tcSecretId" placeholder="Tencent Cloud API SecretId" />
        </div>
        <div class="form-group">
          <label>SecretKey</label>
          <input type="password" id="tcSecretKey" placeholder="Tencent Cloud API SecretKey" />
        </div>
      </div>`;
  } else if (type === 'huawei_cloud') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>AccessKey ID (AK)</label>
          <input type="text" id="hwAccessKeyId" placeholder="Huawei Cloud AK" />
        </div>
        <div class="form-group">
          <label>Secret Access Key (SK)</label>
          <input type="password" id="hwSecretAccessKey" placeholder="Huawei Cloud SK" />
        </div>
      </div>
      <div class="form-group">
        <label>Endpoint (${t('common.optional')})</label>
        <input type="text" id="hwEndpoint" placeholder="https://dns.myhuaweicloud.com" />
      </div>`;
  } else if (type === 'porkbun') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>API Key</label>
          <input type="text" id="pbApiKey" placeholder="pk1_..." />
        </div>
        <div class="form-group">
          <label>Secret Key</label>
          <input type="password" id="pbSecretKey" placeholder="sk1_..." />
        </div>
      </div>`;
  } else if (type === 'godaddy') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>API Key</label>
          <input type="text" id="gdApiKey" placeholder="GoDaddy API Key" />
        </div>
        <div class="form-group">
          <label>API Secret</label>
          <input type="password" id="gdApiSecret" placeholder="GoDaddy API Secret" />
        </div>
      </div>`;
  } else if (type === 'dynv6') {
    container.innerHTML = `
      <div class="form-group">
        <label>HTTP Token</label>
        <input type="password" id="dynv6Token" placeholder="Dynv6 API Token" />
      </div>`;
  } else if (type === 'baidu_cloud') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>AccessKey (AK)</label>
          <input type="text" id="bdAccessKeyId" placeholder="Baidu Cloud AK" />
        </div>
        <div class="form-group">
          <label>SecretKey (SK)</label>
          <input type="password" id="bdSecretAccessKey" placeholder="Baidu Cloud SK" />
        </div>
      </div>`;
  } else if (type === 'traffic_route') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>AccessKey ID (AK)</label>
          <input type="text" id="volcAccessKeyId" placeholder="Volcengine AK" />
        </div>
        <div class="form-group">
          <label>Secret Access Key (SK)</label>
          <input type="password" id="volcSecretAccessKey" placeholder="Volcengine SK" />
        </div>
      </div>`;
  } else if (type === 'namecheap') {
    container.innerHTML = `
      <div class="form-group">
        <label>Dynamic DNS Password</label>
        <input type="password" id="ncPassword" placeholder="Namecheap Dynamic DNS Password" />
      </div>`;
  } else if (type === 'namesilo') {
    container.innerHTML = `
      <div class="form-group">
        <label>API Key</label>
        <input type="password" id="nsApiKey" placeholder="NameSilo API Key" />
      </div>`;
  } else if (type === 'spaceship') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>API Key (X-API-Key)</label>
          <input type="text" id="spApiKey" placeholder="Spaceship API Key" />
        </div>
        <div class="form-group">
          <label>API Secret (X-API-Secret)</label>
          <input type="password" id="spApiSecret" placeholder="Spaceship API Secret" />
        </div>
      </div>`;
  } else if (type === 'dynadot') {
    container.innerHTML = `
      <div class="form-group">
        <label>Dynamic DNS Password</label>
        <input type="password" id="ddPassword" placeholder="Dynadot Dynamic DNS Password" />
      </div>`;
  } else if (type === 'vercel') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>Vercel Token</label>
          <input type="password" id="vcToken" placeholder="Vercel Access Token" />
        </div>
        <div class="form-group">
          <label>Team ID (${t('common.optional')})</label>
          <input type="text" id="vcTeamId" placeholder="team_xxxx" />
        </div>
      </div>`;
  } else if (type === 'rainyun') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>API Key (x-api-key)</label>
          <input type="password" id="ryApiKey" placeholder="Rainyun API Key" />
        </div>
        <div class="form-group">
          <label>Domain ID (${t('common.optional')})</label>
          <input type="text" id="ryDomainId" placeholder="Domain ID" />
        </div>
      </div>`;
  } else if (type === 'cloudns') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>Auth ID</label>
          <input type="text" id="cldAuthId" placeholder="ClouDNS Auth ID" />
        </div>
        <div class="form-group">
          <label>Auth Password</label>
          <input type="password" id="cldAuthPassword" placeholder="ClouDNS API Password" />
        </div>
      </div>`;
  } else if (type === 'gcore') {
    container.innerHTML = `
      <div class="form-group">
        <label>Permanent API Key</label>
        <input type="password" id="gcApiKey" placeholder="APIKey xxx" />
      </div>`;
  } else if (type === 'name_com') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>Username</label>
          <input type="text" id="ncUsername" placeholder="Name.com Username" />
        </div>
        <div class="form-group">
          <label>API Token</label>
          <input type="password" id="ncApiToken" placeholder="Name.com API Token" />
        </div>
      </div>`;
  } else if (type === 'dnsla') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>API ID</label>
          <input type="text" id="dnslaApiId" placeholder="DNS.LA API ID" />
        </div>
        <div class="form-group">
          <label>API Secret</label>
          <input type="password" id="dnslaApiSecret" placeholder="DNS.LA API Secret" />
        </div>
      </div>`;
  } else if (type === 'aliesa') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>AccessKey ID</label>
          <input type="text" id="esaAccessKeyId" placeholder="Aliyun AccessKey ID" />
        </div>
        <div class="form-group">
          <label>AccessKey Secret</label>
          <input type="password" id="esaAccessKeySecret" placeholder="Aliyun AccessKey Secret" />
        </div>
      </div>
      <div class="form-group">
        <label>ESA Endpoint (${t('common.optional')})</label>
        <input type="text" id="esaEndpoint" placeholder="https://esa.cn-hangzhou.aliyuncs.com" />
      </div>`;
  } else if (type === 'edgeone') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>SecretId</label>
          <input type="text" id="eoSecretId" placeholder="Tencent Cloud API SecretId" />
        </div>
        <div class="form-group">
          <label>SecretKey</label>
          <input type="password" id="eoSecretKey" placeholder="Tencent Cloud API SecretKey" />
        </div>
      </div>`;
  } else if (type === 'nowcn') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>AccessInstanceID</label>
          <input type="text" id="nowcnId" placeholder="Now.cn AccessInstanceID" />
        </div>
        <div class="form-group">
          <label>SecretKey</label>
          <input type="password" id="nowcnSecret" placeholder="Now.cn SecretKey" />
        </div>
      </div>`;
  } else if (type === 'eranet') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>AccessInstanceID</label>
          <input type="text" id="eranetId" placeholder="Eranet AccessInstanceID" />
        </div>
        <div class="form-group">
          <label>SecretKey</label>
          <input type="password" id="eranetSecret" placeholder="Eranet SecretKey" />
        </div>
      </div>`;
  } else if (type === 'tnethk') {
    container.innerHTML = `
      <div class="grid-2">
        <div class="form-group">
          <label>AccessInstanceID</label>
          <input type="text" id="tnetId" placeholder="TNetHK AccessInstanceID" />
        </div>
        <div class="form-group">
          <label>SecretKey</label>
          <input type="password" id="tnetSecret" placeholder="TNetHK SecretKey" />
        </div>
      </div>`;
  } else if (type === 'nsone') {
    container.innerHTML = `
      <div class="form-group">
        <label>API Key (Secret)</label>
        <input type="password" id="nsoneApiKey" placeholder="IBM NS1 Connect API Key" />
      </div>`;
  } else if (type === 'hipm_dnsmgr') {
    container.innerHTML = `
      <div class="form-group">
        <label>API Token</label>
        <input type="password" id="hipmApiToken" placeholder="HiPM DNSMgr API Token" />
      </div>
      <div class="form-group">
        <label>DNSMgr Endpoint (${t('common.optional')})</label>
        <input type="text" id="hipmEndpoint" placeholder="https://dnsmgr.example.com" />
      </div>`;
  } else if (type === 'callback') {
    container.innerHTML = `
      <div class="form-group">
        <label>Callback URL (Supports #{ip}, #{domain}, #{recordType})</label>
        <input type="text" id="cbUrl" placeholder="https://api.myprovider.com/update?ip=#{ip}&domain=#{domain}" />
      </div>`;
  }
}

// 渲染 IP 获取途径表单
export function renderIpFields(vType) {
  const rawSource = document.getElementById(`${vType}SourceType`)?.value || 'url';
  const sourceType = (rawSource === 'netInterface' || rawSource === 'net_interface') ? 'net_interface' : (rawSource === 'cmd' ? 'command' : rawSource);
  const fieldContainer = document.getElementById(`${vType}DynamicField`);
  if (!fieldContainer) return;

  if (sourceType === 'url') {
    const defaultUrls = vType === 'ipv4'
      ? 'https://api.ipify.org, https://myip.ipip.net/ip, https://ddns.oray.com/checkip'
      : 'https://api64.ipify.org, https://speed.neu6.edu.cn/getIP.php, https://6.ipw.cn';
    fieldContainer.innerHTML = `
      <label>${t('dns.probeUrlLabel')}</label>
      <input type="text" id="${vType}Urls" value="${defaultUrls}" />`;
  } else if (sourceType === 'net_interface') {
    const currentSaved = (vType === 'ipv4' ? savedIpv4NetIf : savedIpv6NetIf) || '';
    let optionsHtml = `<option value="">${t('dns.netIfSelectPlaceholder')}</option>`;
    let matched = false;

    availableInterfaces.forEach(iface => {
      const isSelected = (iface.name === currentSaved);
      if (isSelected) matched = true;
      optionsHtml += `<option value="${escapeHtml(iface.name)}" ${isSelected ? 'selected' : ''}>${escapeHtml(iface.display_name || iface.name)}</option>`;
    });

    const isCustomSelected = (!matched && currentSaved);
    optionsHtml += `<option value="__custom__" ${isCustomSelected ? 'selected' : ''}>${t('dns.netIfCustomOption')}</option>`;

    fieldContainer.innerHTML = `
      <label>${t('dns.netIfSelectLabel')}</label>
      <select id="${vType}NetIfSelect" onchange="handleNetIfSelect('${vType}')">
        ${optionsHtml}
      </select>
      <input type="text" id="${vType}NetIfCustom" placeholder="${t('dns.netIfCustomPlaceholder')}" style="margin-top:8px; display:${isCustomSelected ? 'block' : 'none'};" value="${isCustomSelected ? escapeHtml(currentSaved) : ''}" />`;
  } else if (sourceType === 'command') {
    fieldContainer.innerHTML = `
      <label>${t('dns.cmdLabel')}</label>
      <input type="text" id="${vType}Cmd" placeholder="${t('dns.cmdPlaceholder')}" />`;
  }
}

// 渲染左侧解析任务列表 (Master)
export function renderTaskList() {
  const container = document.getElementById('taskMasterList');
  const badge = document.getElementById('taskCountBadge');
  if (!container || !globalConfig) return;

  const tasks = globalConfig.dns_tasks || [];
  if (badge) badge.innerText = tasks.length.toString();

  if (tasks.length === 0) {
    container.innerHTML = `<div style="text-align:center; padding:20px; color:var(--text-dim); font-size:0.8rem;">${escapeHtml(t('task.emptyList'))}</div>`;
    return;
  }

  if (currentTaskIndex >= tasks.length) {
    currentTaskIndex = tasks.length - 1;
  }

  let html = '';
  tasks.forEach((task, idx) => {
    const isActive = idx === currentTaskIndex;
    const isEnabled = task.enabled !== false;
    const pName = getProviderDisplayName(task.provider?.type);
    
    let domainSummary = t('task.noDomainConfigured');
    if (task.ipv4?.domains && task.ipv4.domains.length > 0) {
      domainSummary = task.ipv4.domains[0] + (task.ipv4.domains.length > 1 ? ` (+${task.ipv4.domains.length - 1})` : '');
    } else if (task.ipv6?.domains && task.ipv6.domains.length > 0) {
      domainSummary = task.ipv6.domains[0] + (task.ipv6.domains.length > 1 ? ` (+${task.ipv6.domains.length - 1})` : '');
    }

    const dotStyle = isEnabled 
      ? 'background:var(--success); box-shadow:0 0 6px var(--success);' 
      : 'background:var(--text-dim); box-shadow:none;';

    html += `
      <div class="task-item-card ${isActive ? 'active' : ''}" onclick="switchTask(${idx})">
        <div class="task-item-head">
          <div class="task-item-name" title="${escapeHtml(task.name || t('task.unnamedTask'))}">
            <span class="dot" style="width:7px; height:7px; border-radius:50%; display:inline-block; ${dotStyle}"></span>
            <span>${escapeHtml(task.name || t('task.unnamedTask'))}</span>
          </div>
          <span class="task-item-provider-tag">${escapeHtml(pName)}</span>
        </div>
        <div class="task-item-domain" title="${escapeHtml(domainSummary)}">${escapeHtml(domainSummary)}</div>
      </div>
    `;
  });

  container.innerHTML = html;
}

// 填充单个任务的配置到右侧表单 (Detail)
export function populateCurrentTaskForm(task) {
  if (!task) return;

  // 1. 任务基础信息
  const nameInput = document.getElementById('currentTaskNameInput');
  if (nameInput) nameInput.value = task.name || '';
  
  const enabledCheck = document.getElementById('currentTaskEnabled');
  if (enabledCheck) enabledCheck.checked = task.enabled !== false;

  // 2. TTL
  setTtlValue(task.ttl);

  // 3. DNS Provider
  if (task.provider && task.provider.type) {
    const pTypeEl = document.getElementById('dnsProviderType');
    if (pTypeEl) pTypeEl.value = task.provider.type;
    renderProviderFields();

    if (task.provider.type === 'cloudflare') {
      if (document.getElementById('cfApiToken')) document.getElementById('cfApiToken').value = task.provider.api_token || '';
      if (document.getElementById('cfApiKey')) document.getElementById('cfApiKey').value = task.provider.api_key || '';
      if (document.getElementById('cfEmail')) document.getElementById('cfEmail').value = task.provider.email || '';
    } else if (task.provider.type === 'ali_dns') {
      if (document.getElementById('aliAccessKeyId')) document.getElementById('aliAccessKeyId').value = task.provider.access_key_id || '';
      if (document.getElementById('aliAccessKeySecret')) document.getElementById('aliAccessKeySecret').value = task.provider.access_key_secret || '';
    } else if (task.provider.type === 'tencent_cloud') {
      if (document.getElementById('tcSecretId')) document.getElementById('tcSecretId').value = task.provider.secret_id || '';
      if (document.getElementById('tcSecretKey')) document.getElementById('tcSecretKey').value = task.provider.secret_key || '';
    } else if (task.provider.type === 'huawei_cloud') {
      if (document.getElementById('hwAccessKeyId')) document.getElementById('hwAccessKeyId').value = task.provider.access_key_id || '';
      if (document.getElementById('hwSecretAccessKey')) document.getElementById('hwSecretAccessKey').value = task.provider.secret_access_key || '';
      if (document.getElementById('hwEndpoint')) document.getElementById('hwEndpoint').value = task.provider.endpoint || '';
    } else if (task.provider.type === 'porkbun') {
      if (document.getElementById('pbApiKey')) document.getElementById('pbApiKey').value = task.provider.api_key || '';
      if (document.getElementById('pbSecretKey')) document.getElementById('pbSecretKey').value = task.provider.secret_key || '';
    } else if (task.provider.type === 'godaddy') {
      if (document.getElementById('gdApiKey')) document.getElementById('gdApiKey').value = task.provider.api_key || '';
      if (document.getElementById('gdApiSecret')) document.getElementById('gdApiSecret').value = task.provider.api_secret || '';
    } else if (task.provider.type === 'dynv6') {
      if (document.getElementById('dynv6Token')) document.getElementById('dynv6Token').value = task.provider.token || '';
    } else if (task.provider.type === 'baidu_cloud') {
      if (document.getElementById('bdAccessKeyId')) document.getElementById('bdAccessKeyId').value = task.provider.access_key_id || '';
      if (document.getElementById('bdSecretAccessKey')) document.getElementById('bdSecretAccessKey').value = task.provider.secret_access_key || '';
    } else if (task.provider.type === 'traffic_route') {
      if (document.getElementById('volcAccessKeyId')) document.getElementById('volcAccessKeyId').value = task.provider.access_key_id || '';
      if (document.getElementById('volcSecretAccessKey')) document.getElementById('volcSecretAccessKey').value = task.provider.secret_access_key || '';
    } else if (task.provider.type === 'namecheap') {
      if (document.getElementById('ncPassword')) document.getElementById('ncPassword').value = task.provider.password || '';
    } else if (task.provider.type === 'namesilo') {
      if (document.getElementById('nsApiKey')) document.getElementById('nsApiKey').value = task.provider.api_key || '';
    } else if (task.provider.type === 'spaceship') {
      if (document.getElementById('spApiKey')) document.getElementById('spApiKey').value = task.provider.api_key || '';
      if (document.getElementById('spApiSecret')) document.getElementById('spApiSecret').value = task.provider.api_secret || '';
    } else if (task.provider.type === 'dynadot') {
      if (document.getElementById('ddPassword')) document.getElementById('ddPassword').value = task.provider.password || '';
    } else if (task.provider.type === 'vercel') {
      if (document.getElementById('vcToken')) document.getElementById('vcToken').value = task.provider.token || '';
      if (document.getElementById('vcTeamId')) document.getElementById('vcTeamId').value = task.provider.team_id || '';
    } else if (task.provider.type === 'rainyun') {
      if (document.getElementById('ryApiKey')) document.getElementById('ryApiKey').value = task.provider.api_key || '';
      if (document.getElementById('ryDomainId')) document.getElementById('ryDomainId').value = task.provider.domain_id || '';
    } else if (task.provider.type === 'cloudns') {
      if (document.getElementById('cldAuthId')) document.getElementById('cldAuthId').value = task.provider.auth_id || '';
      if (document.getElementById('cldAuthPassword')) document.getElementById('cldAuthPassword').value = task.provider.auth_password || '';
    } else if (task.provider.type === 'gcore') {
      if (document.getElementById('gcApiKey')) document.getElementById('gcApiKey').value = task.provider.api_key || '';
    } else if (task.provider.type === 'name_com') {
      if (document.getElementById('ncUsername')) document.getElementById('ncUsername').value = task.provider.username || '';
      if (document.getElementById('ncApiToken')) document.getElementById('ncApiToken').value = task.provider.api_token || '';
    } else if (task.provider.type === 'dnsla') {
      if (document.getElementById('dnslaApiId')) document.getElementById('dnslaApiId').value = task.provider.api_id || '';
      if (document.getElementById('dnslaApiSecret')) document.getElementById('dnslaApiSecret').value = task.provider.api_secret || '';
    } else if (task.provider.type === 'aliesa') {
      if (document.getElementById('esaAccessKeyId')) document.getElementById('esaAccessKeyId').value = task.provider.access_key_id || '';
      if (document.getElementById('esaAccessKeySecret')) document.getElementById('esaAccessKeySecret').value = task.provider.access_key_secret || '';
      if (document.getElementById('esaEndpoint')) document.getElementById('esaEndpoint').value = task.provider.endpoint || '';
    } else if (task.provider.type === 'edgeone') {
      if (document.getElementById('eoSecretId')) document.getElementById('eoSecretId').value = task.provider.secret_id || '';
      if (document.getElementById('eoSecretKey')) document.getElementById('eoSecretKey').value = task.provider.secret_key || '';
    } else if (task.provider.type === 'nowcn') {
      if (document.getElementById('nowcnId')) document.getElementById('nowcnId').value = task.provider.id || '';
      if (document.getElementById('nowcnSecret')) document.getElementById('nowcnSecret').value = task.provider.secret || '';
    } else if (task.provider.type === 'eranet') {
      if (document.getElementById('eranetId')) document.getElementById('eranetId').value = task.provider.id || '';
      if (document.getElementById('eranetSecret')) document.getElementById('eranetSecret').value = task.provider.secret || '';
    } else if (task.provider.type === 'tnethk') {
      if (document.getElementById('tnetId')) document.getElementById('tnetId').value = task.provider.id || '';
      if (document.getElementById('tnetSecret')) document.getElementById('tnetSecret').value = task.provider.secret || '';
    } else if (task.provider.type === 'nsone') {
      if (document.getElementById('nsoneApiKey')) document.getElementById('nsoneApiKey').value = task.provider.api_key || '';
    } else if (task.provider.type === 'hipm_dnsmgr') {
      if (document.getElementById('hipmApiToken')) document.getElementById('hipmApiToken').value = task.provider.api_token || '';
      if (document.getElementById('hipmEndpoint')) document.getElementById('hipmEndpoint').value = task.provider.endpoint || '';
    }
  }

  // 3.5. 出站物理网卡 (HTTP Interface)
  renderHttpInterfaceOptions(task.http_interface || '');

  // 4. IPv4
  if (task.ipv4) {
    const v4EnableEl = document.getElementById('ipv4Enable');
    if (v4EnableEl) v4EnableEl.checked = task.ipv4.enabled !== false;
    const v4Src = (task.ipv4.source_type === 'netInterface' || task.ipv4.source_type === 'net_interface') ? 'net_interface' : (task.ipv4.source_type || 'url');
    const v4SrcEl = document.getElementById('ipv4SourceType');
    if (v4SrcEl) v4SrcEl.value = v4Src;
    savedIpv4NetIf = task.ipv4.net_interface || '';
    renderIpFields('ipv4');
    if (task.ipv4.url_endpoints && document.getElementById('ipv4Urls')) {
      document.getElementById('ipv4Urls').value = task.ipv4.url_endpoints.join(', ');
    }
    if (task.ipv4.cmd && document.getElementById('ipv4Cmd')) {
      document.getElementById('ipv4Cmd').value = task.ipv4.cmd;
    }
    const v4RegexEl = document.getElementById('ipv4Regex');
    if (v4RegexEl) v4RegexEl.value = task.ipv4.regex || '';
    const v4DomainsEl = document.getElementById('ipv4Domains');
    if (v4DomainsEl) v4DomainsEl.value = (task.ipv4.domains || []).join('\n');
  }

  // 5. IPv6
  if (task.ipv6) {
    const v6EnableEl = document.getElementById('ipv6Enable');
    if (v6EnableEl) v6EnableEl.checked = task.ipv6.enabled !== false;
    const v6Src = (task.ipv6.source_type === 'netInterface' || task.ipv6.source_type === 'net_interface') ? 'net_interface' : (task.ipv6.source_type || 'net_interface');
    const v6SrcEl = document.getElementById('ipv6SourceType');
    if (v6SrcEl) v6SrcEl.value = v6Src;
    savedIpv6NetIf = task.ipv6.net_interface || '';
    renderIpFields('ipv6');
    if (task.ipv6.url_endpoints && document.getElementById('ipv6Urls')) {
      document.getElementById('ipv6Urls').value = task.ipv6.url_endpoints.join(', ');
    }
    if (task.ipv6.cmd && document.getElementById('ipv6Cmd')) {
      document.getElementById('ipv6Cmd').value = task.ipv6.cmd;
    }
    const v6RegexEl = document.getElementById('ipv6Regex');
    if (v6RegexEl) v6RegexEl.value = task.ipv6.regex || '';
    const v6DomainsEl = document.getElementById('ipv6Domains');
    if (v6DomainsEl) v6DomainsEl.value = (task.ipv6.domains || []).join('\n');
  }

  initPasswordToggles();
}

// 从右侧表单采集当前任务数据，同步更新回 globalConfig.dns_tasks[index]
export function collectCurrentTaskFromForm(index) {
  if (!globalConfig || !globalConfig.dns_tasks || !globalConfig.dns_tasks[index]) return;

  const pType = document.getElementById('dnsProviderType')?.value || 'cloudflare';
  let providerObj = { type: pType };

  if (pType === 'cloudflare') {
    providerObj.api_token = document.getElementById('cfApiToken')?.value || null;
    providerObj.api_key = document.getElementById('cfApiKey')?.value || null;
    providerObj.email = document.getElementById('cfEmail')?.value || null;
  } else if (pType === 'ali_dns') {
    providerObj.access_key_id = document.getElementById('aliAccessKeyId')?.value || '';
    providerObj.access_key_secret = document.getElementById('aliAccessKeySecret')?.value || '';
  } else if (pType === 'tencent_cloud') {
    providerObj.secret_id = document.getElementById('tcSecretId')?.value || '';
    providerObj.secret_key = document.getElementById('tcSecretKey')?.value || '';
  } else if (pType === 'huawei_cloud') {
    providerObj.access_key_id = document.getElementById('hwAccessKeyId')?.value || '';
    providerObj.secret_access_key = document.getElementById('hwSecretAccessKey')?.value || '';
    const ep = document.getElementById('hwEndpoint')?.value?.trim();
    if (ep) providerObj.endpoint = ep;
  } else if (pType === 'porkbun') {
    providerObj.api_key = document.getElementById('pbApiKey')?.value || '';
    providerObj.secret_key = document.getElementById('pbSecretKey')?.value || '';
  } else if (pType === 'godaddy') {
    providerObj.api_key = document.getElementById('gdApiKey')?.value || '';
    providerObj.api_secret = document.getElementById('gdApiSecret')?.value || '';
  } else if (pType === 'dynv6') {
    providerObj.token = document.getElementById('dynv6Token')?.value || '';
  } else if (pType === 'baidu_cloud') {
    providerObj.access_key_id = document.getElementById('bdAccessKeyId')?.value || '';
    providerObj.secret_access_key = document.getElementById('bdSecretAccessKey')?.value || '';
  } else if (pType === 'traffic_route') {
    providerObj.access_key_id = document.getElementById('volcAccessKeyId')?.value || '';
    providerObj.secret_access_key = document.getElementById('volcSecretAccessKey')?.value || '';
  } else if (pType === 'namecheap') {
    providerObj.password = document.getElementById('ncPassword')?.value || '';
  } else if (pType === 'namesilo') {
    providerObj.api_key = document.getElementById('nsApiKey')?.value || '';
  } else if (pType === 'spaceship') {
    providerObj.api_key = document.getElementById('spApiKey')?.value || '';
    providerObj.api_secret = document.getElementById('spApiSecret')?.value || '';
  } else if (pType === 'dynadot') {
    providerObj.password = document.getElementById('ddPassword')?.value || '';
  } else if (pType === 'vercel') {
    providerObj.token = document.getElementById('vcToken')?.value || '';
    const tid = document.getElementById('vcTeamId')?.value?.trim();
    if (tid) providerObj.team_id = tid;
  } else if (pType === 'rainyun') {
    providerObj.api_key = document.getElementById('ryApiKey')?.value || '';
    const did = document.getElementById('ryDomainId')?.value?.trim();
    if (did) providerObj.domain_id = did;
  } else if (pType === 'cloudns') {
    providerObj.auth_id = document.getElementById('cldAuthId')?.value || '';
    providerObj.auth_password = document.getElementById('cldAuthPassword')?.value || '';
  } else if (pType === 'gcore') {
    providerObj.api_key = document.getElementById('gcApiKey')?.value || '';
  } else if (pType === 'name_com') {
    providerObj.username = document.getElementById('ncUsername')?.value || '';
    providerObj.api_token = document.getElementById('ncApiToken')?.value || '';
  } else if (pType === 'dnsla') {
    providerObj.api_id = document.getElementById('dnslaApiId')?.value || '';
    providerObj.api_secret = document.getElementById('dnslaApiSecret')?.value || '';
  } else if (pType === 'aliesa') {
    providerObj.access_key_id = document.getElementById('esaAccessKeyId')?.value || '';
    providerObj.access_key_secret = document.getElementById('esaAccessKeySecret')?.value || '';
    const ep = document.getElementById('esaEndpoint')?.value?.trim();
    if (ep) providerObj.endpoint = ep;
  } else if (pType === 'edgeone') {
    providerObj.secret_id = document.getElementById('eoSecretId')?.value || '';
    providerObj.secret_key = document.getElementById('eoSecretKey')?.value || '';
  } else if (pType === 'nowcn') {
    providerObj.id = document.getElementById('nowcnId')?.value || '';
    providerObj.secret = document.getElementById('nowcnSecret')?.value || '';
  } else if (pType === 'eranet') {
    providerObj.id = document.getElementById('eranetId')?.value || '';
    providerObj.secret = document.getElementById('eranetSecret')?.value || '';
  } else if (pType === 'tnethk') {
    providerObj.id = document.getElementById('tnetId')?.value || '';
    providerObj.secret = document.getElementById('tnetSecret')?.value || '';
  } else if (pType === 'nsone') {
    providerObj.api_key = document.getElementById('nsoneApiKey')?.value || '';
  } else if (pType === 'hipm_dnsmgr') {
    providerObj.api_token = document.getElementById('hipmApiToken')?.value || '';
    const ep = document.getElementById('hipmEndpoint')?.value?.trim();
    if (ep) providerObj.endpoint = ep;
  }

  const ipv4Urls = (document.getElementById('ipv4Urls')?.value || '').split(',').map(s => s.trim()).filter(Boolean);
  const ipv6Urls = (document.getElementById('ipv6Urls')?.value || '').split(',').map(s => s.trim()).filter(Boolean);

  const taskName = document.getElementById('currentTaskNameInput')?.value.trim() || `${t('task.nameLabel')} ${index + 1}`;
  const taskEnabled = document.getElementById('currentTaskEnabled') ? document.getElementById('currentTaskEnabled').checked : true;

  globalConfig.dns_tasks[index] = {
    name: taskName,
    enabled: taskEnabled,
    provider: providerObj,
    ttl: getTtlValue(),
    http_interface: document.getElementById('dnsHttpInterface')?.value || null,
    ipv4: {
      enabled: document.getElementById('ipv4Enable')?.checked ?? true,
      source_type: document.getElementById('ipv4SourceType')?.value || 'url',
      url_endpoints: ipv4Urls,
      net_interface: getNetIfValue('ipv4'),
      cmd: document.getElementById('ipv4Cmd')?.value || null,
      regex: document.getElementById('ipv4Regex')?.value || null,
      domains: (document.getElementById('ipv4Domains')?.value || '').split('\n').map(s => s.trim()).filter(Boolean)
    },
    ipv6: {
      enabled: document.getElementById('ipv6Enable')?.checked ?? true,
      source_type: document.getElementById('ipv6SourceType')?.value || 'net_interface',
      url_endpoints: ipv6Urls,
      net_interface: getNetIfValue('ipv6'),
      cmd: document.getElementById('ipv6Cmd')?.value || null,
      regex: document.getElementById('ipv6Regex')?.value || null,
      domains: (document.getElementById('ipv6Domains')?.value || '').split('\n').map(s => s.trim()).filter(Boolean)
    }
  };
}

// 切换当前激活的任务
export function switchTask(targetIndex) {
  if (targetIndex === currentTaskIndex) return;
  collectCurrentTaskFromForm(currentTaskIndex);
  currentTaskIndex = targetIndex;
  populateCurrentTaskForm(globalConfig.dns_tasks[currentTaskIndex]);
  renderTaskList();
}

// 新增解析任务
export function addNewTask() {
  collectCurrentTaskFromForm(currentTaskIndex);

  const nextNum = (globalConfig?.dns_tasks ? globalConfig.dns_tasks.length : 0) + 1;
  const defaultTaskName = `${t('task.nameLabel')} ${nextNum}`;
  const newTask = {
    name: defaultTaskName,
    enabled: true,
    provider: { type: 'cloudflare', api_token: '' },
    ttl: null,
    http_interface: null,
    ipv4: {
      enabled: true,
      source_type: 'url',
      url_endpoints: ['https://api.ipify.org', 'https://myip.ipip.net/ip', 'https://ddns.oray.com/checkip'],
      net_interface: null,
      cmd: null,
      regex: null,
      domains: []
    },
    ipv6: {
      enabled: true,
      source_type: 'net_interface',
      url_endpoints: [],
      net_interface: null,
      cmd: null,
      regex: null,
      domains: []
    }
  };

  if (!globalConfig.dns_tasks) globalConfig.dns_tasks = [];
  globalConfig.dns_tasks.push(newTask);
  currentTaskIndex = globalConfig.dns_tasks.length - 1;

  populateCurrentTaskForm(newTask);
  renderTaskList();
  showToast(t('task.newSuccess', { name: newTask.name }), 'success');

  // 聚焦任务名称输入框
  const nameInput = document.getElementById('currentTaskNameInput');
  if (nameInput) {
    nameInput.focus();
    nameInput.select();
  }
}

// 删除当前选中的任务
export function deleteCurrentTask() {
  if (!globalConfig || !globalConfig.dns_tasks || globalConfig.dns_tasks.length <= 1) {
    showToast(t('task.deleteMinWarning'), 'warning');
    return;
  }

  const taskName = globalConfig.dns_tasks[currentTaskIndex]?.name || t('task.unnamedTask');
  if (!confirm(t('task.deleteConfirm', { name: taskName }))) {
    return;
  }

  globalConfig.dns_tasks.splice(currentTaskIndex, 1);
  if (currentTaskIndex >= globalConfig.dns_tasks.length) {
    currentTaskIndex = globalConfig.dns_tasks.length - 1;
  }

  populateCurrentTaskForm(globalConfig.dns_tasks[currentTaskIndex]);
  renderTaskList();
  showToast(t('task.deleteSuccess', { name: taskName }), 'success');
}

// 复制克隆当前任务
export function cloneCurrentTask() {
  if (!globalConfig || !globalConfig.dns_tasks || !globalConfig.dns_tasks[currentTaskIndex]) return;

  collectCurrentTaskFromForm(currentTaskIndex);
  const cloned = JSON.parse(JSON.stringify(globalConfig.dns_tasks[currentTaskIndex]));
  cloned.name = `${cloned.name || t('task.unnamedTask')} - ${t('task.cloneSuffix')}`;

  globalConfig.dns_tasks.push(cloned);
  currentTaskIndex = globalConfig.dns_tasks.length - 1;

  populateCurrentTaskForm(cloned);
  renderTaskList();
  showToast(t('task.cloneSuccess', { name: cloned.name }), 'success');
}

// 实时任务名称输入响应
export function onTaskNameChange(val) {
  if (globalConfig && globalConfig.dns_tasks && globalConfig.dns_tasks[currentTaskIndex]) {
    globalConfig.dns_tasks[currentTaskIndex].name = val.trim() || t('task.unnamedTask');
    renderTaskList();
  }
}

// 实时任务启用状态响应
export function onTaskEnabledChange(checked) {
  if (globalConfig && globalConfig.dns_tasks && globalConfig.dns_tasks[currentTaskIndex]) {
    globalConfig.dns_tasks[currentTaskIndex].enabled = checked;
    renderTaskList();
  }
}

// 测试探测 IP
export async function testIp(type) {
  const isV4 = type === 'ipv4';
  const typeUpper = type.toUpperCase();
  const badgeEl = document.getElementById(`${type}ProbeResult`);
  const btnEl = document.getElementById(`${type}TestBtn`);
  
  const urls = (document.getElementById(`${type}Urls`)?.value || '').split(',').map(s => s.trim()).filter(Boolean);
  const payload = {
    ip_type: type,
    enabled: true,
    source_type: document.getElementById(`${type}SourceType`)?.value || 'url',
    url_endpoints: urls,
    net_interface: getNetIfValue(type),
    cmd: document.getElementById(`${type}Cmd`)?.value || null,
    regex: document.getElementById(`${type}Regex`)?.value || null,
    domains: []
  };

  if (badgeEl) {
    badgeEl.style.display = 'inline-flex';
    badgeEl.className = 'ip-probe-badge loading';
    badgeEl.innerHTML = `<span class="live-dot" style="background:var(--primary); box-shadow:0 0 6px var(--primary);"></span> <span>${escapeHtml(t('dns.probing'))}</span>`;
  }
  if (btnEl) btnEl.disabled = true;

  try {
    const res = await apiFetch('/api/v1/test/ip', {
      method: 'POST',
      body: payload
    });
    const json = await res.json();
    if (json.success) {
      const val = isV4 ? json.data.ipv4 : json.data.ipv6;
      if (val) {
        if (badgeEl) {
          badgeEl.className = 'ip-probe-badge success';
          badgeEl.innerHTML = `<span class="icon" style="color:var(--success);"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg></span> <span>${escapeHtml(t('dns.probeSuccess', { type: typeUpper, ip: '' }))}<span class="ip-text">${escapeHtml(val)}</span></span>`;
        }
        showToast(t('dns.probeToastSuccess', { type: typeUpper, ip: val }), 'success');
      } else {
        if (badgeEl) {
          badgeEl.className = 'ip-probe-badge error';
          badgeEl.innerHTML = `<span class="icon" style="color:var(--danger);"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg></span> <span>${escapeHtml(t('dns.probeNone', { type: typeUpper }))}</span>`;
        }
        showToast(t('dns.probeToastNone', { type: typeUpper }), 'error');
      }
    } else {
      if (badgeEl) {
        badgeEl.className = 'ip-probe-badge error';
        badgeEl.innerHTML = `<span class="icon" style="color:var(--danger);"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg></span> <span>${escapeHtml(t('dns.probeFailed', { message: json.message }))}</span>`;
      }
      showToast(t('dns.probeFailed', { message: json.message }), 'error');
    }
  } catch (e) {
    if (badgeEl) {
      badgeEl.className = 'ip-probe-badge error';
      badgeEl.innerHTML = `<span>${escapeHtml(t('common.requestError', { error: e }))}</span>`;
    }
    showToast(t('common.requestError', { error: e }), 'error');
  } finally {
    if (btnEl) btnEl.disabled = false;
  }
}

// 监听语言切换事件，动态重绘列表与表单选项
onLocaleChange(() => {
  renderTaskList();
  renderHttpInterfaceOptions();
  renderProviderFields();
  renderIpFields('ipv4');
  renderIpFields('ipv6');
});
