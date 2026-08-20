// ==========================================
// 统一 API 请求封装 (支持 Basic Auth 拦截注入与 401 自动跳转)
// ==========================================

import { showLoginPage } from './auth.js';

export async function apiFetch(url, options = {}) {
  options.headers = options.headers || {};
  const auth = sessionStorage.getItem('rddns_auth');
  if (auth) {
    options.headers['Authorization'] = 'Basic ' + auth;
  }
  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData) && typeof options.body !== 'string') {
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }

  try {
    const res = await fetch(url, options);
    if (res.status === 401) {
      showLoginPage();
    }
    return res;
  } catch (err) {
    console.error('API 请求异常:', err);
    throw err;
  }
}
