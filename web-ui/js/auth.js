// ==========================================
// 认证与会话管理 (登录 / 初始化向导 / 密码显隐)
// ==========================================

import { showToast } from './toast.js';
import { t } from './i18n/index.js';

let onLoginSuccessCallback = null;

export function setOnLoginSuccess(callback) {
  onLoginSuccessCallback = callback;
}

// 初始化所有密码输入框的显隐切换（小眼睛按钮）
export function initPasswordToggles() {
  document.querySelectorAll('input[type="password"], input.password-toggleable').forEach(input => {
    if (input.parentElement && input.parentElement.classList.contains('password-input-wrapper')) return;
    input.classList.add('password-toggleable');
    const wrapper = document.createElement('div');
    wrapper.className = 'password-input-wrapper';
    input.parentNode.insertBefore(wrapper, input);
    wrapper.appendChild(input);

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn-toggle-eye';
    btn.title = t('auth.showPassword');
    btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
    btn.onclick = (e) => {
      e.preventDefault();
      if (input.type === 'password') {
        input.type = 'text';
        btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`;
        btn.title = t('auth.hidePassword');
      } else {
        input.type = 'password';
        btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
        btn.title = t('auth.showPassword');
      }
    };
    wrapper.appendChild(btn);
  });
}

// 视图切换控制 (全屏登录页 / 全屏初始化页 / 主控制台)
export function showLoginPage() {
  const loginPage = document.getElementById('loginPage');
  const initPage = document.getElementById('initPage');
  const mainApp = document.getElementById('mainApp');
  if (loginPage) loginPage.style.display = 'flex';
  if (initPage) initPage.style.display = 'none';
  if (mainApp) mainApp.style.display = 'none';
  initPasswordToggles();
  setTimeout(() => {
    const u = document.getElementById('loginUsername');
    const p = document.getElementById('loginPassword');
    if (u && !u.value) u.focus();
    else if (p) p.focus();
  }, 100);
}

export function showInitPage() {
  const loginPage = document.getElementById('loginPage');
  const initPage = document.getElementById('initPage');
  const mainApp = document.getElementById('mainApp');
  if (initPage) initPage.style.display = 'flex';
  if (loginPage) loginPage.style.display = 'none';
  if (mainApp) mainApp.style.display = 'none';
  initPasswordToggles();
  setTimeout(() => document.getElementById('initPassword')?.focus(), 100);
}

export function showMainApp() {
  const loginPage = document.getElementById('loginPage');
  const initPage = document.getElementById('initPage');
  const mainApp = document.getElementById('mainApp');
  if (loginPage) loginPage.style.display = 'none';
  if (initPage) initPage.style.display = 'none';
  if (mainApp) mainApp.style.display = 'flex';
  initPasswordToggles();
  updateLogoutBtn();
}

export function updateLogoutBtn() {
  const btn = document.getElementById('logoutBtn');
  if (btn) {
    btn.style.display = sessionStorage.getItem('rddns_auth') ? 'inline-flex' : 'none';
  }
}

export function logout() {
  sessionStorage.removeItem('rddns_auth');
  showToast(t('common.logoutSuccess'), 'info');
  showLoginPage();
}

export async function submitInitAuth() {
  const username = document.getElementById('initUsername')?.value.trim();
  const password = document.getElementById('initPassword')?.value;
  const confirm = document.getElementById('initPasswordConfirm')?.value;

  if (!username) {
    showToast(t('auth.usernameEmpty'), 'error');
    return;
  }
  if (!password || password.length < 4) {
    showToast(t('auth.passwordMinLength'), 'error');
    return;
  }
  if (password !== confirm) {
    showToast(t('auth.passwordMismatch'), 'error');
    return;
  }

  const submitBtn = document.getElementById('initSubmitBtn');
  if (submitBtn) submitBtn.disabled = true;

  try {
    const res = await fetch('/api/v1/auth/init', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const json = await res.json();
    if (json.success) {
      const authKey = btoa(username + ':' + password);
      sessionStorage.setItem('rddns_auth', authKey);
      showMainApp();
      showToast(t('auth.initSuccess'), 'success');
      if (onLoginSuccessCallback) {
        onLoginSuccessCallback();
      }
    } else {
      showToast(t('auth.initFailed', { message: json.message }), 'error');
    }
  } catch (e) {
    showToast(t('common.requestError', { error: e }), 'error');
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
}

export async function submitLogin() {
  const username = document.getElementById('loginUsername')?.value.trim();
  const password = document.getElementById('loginPassword')?.value;

  if (!username || !password) {
    showToast(t('auth.inputRequired'), 'error');
    return;
  }

  const submitBtn = document.getElementById('loginSubmitBtn');
  if (submitBtn) submitBtn.disabled = true;

  try {
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });
    const json = await res.json();
    if (json.success) {
      const authKey = btoa(username + ':' + password);
      sessionStorage.setItem('rddns_auth', authKey);
      showMainApp();
      showToast(t('auth.loginSuccess'), 'success');
      if (onLoginSuccessCallback) {
        onLoginSuccessCallback();
      }
    } else {
      showToast(t('auth.loginFailed', { message: json.message }), 'error');
    }
  } catch (e) {
    showToast(t('common.requestError', { error: e }), 'error');
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
}
