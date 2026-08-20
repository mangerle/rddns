// ==========================================
// 国际化 (i18n) 核心驱动模块
// ==========================================

import zhCN from './zh-CN.js';
import enUS from './en-US.js';

const locales = {
  'zh-CN': zhCN,
  'en-US': enUS,
};

let currentLocale = 'zh-CN';
const localeChangeListeners = [];

// 注册语言切换事件监听器
export function onLocaleChange(callback) {
  if (typeof callback === 'function') {
    localeChangeListeners.push(callback);
  }
}

// 获取当前语言代码
export function getLocale() {
  return currentLocale;
}

// 翻译取值函数 (支持嵌套路径如 'auth.loginTitle'，以及 {name} 变量插值)
export function t(path, params = {}) {
  if (!path) return '';
  const keys = path.split('.');
  let val = locales[currentLocale];

  for (const k of keys) {
    if (val && typeof val === 'object' && k in val) {
      val = val[k];
    } else {
      // 若当前语言包找不到，回退到简体中文
      let fallbackVal = locales['zh-CN'];
      for (const fk of keys) {
        if (fallbackVal && typeof fallbackVal === 'object' && fk in fallbackVal) {
          fallbackVal = fallbackVal[fk];
        } else {
          fallbackVal = null;
          break;
        }
      }
      val = fallbackVal || path;
      break;
    }
  }

  if (typeof val === 'string') {
    return val.replace(/\{(\w+)\}/g, (_, k) => params[k] !== undefined ? params[k] : `{${k}}`);
  }
  return typeof val === 'string' ? val : path;
}

// 自动扫描并批量更新 DOM 静态文字
export function updateDOM() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (key) {
      const translated = t(key);
      if (translated) el.innerText = translated;
    }
  });

  document.querySelectorAll('[data-i18n-html]').forEach(el => {
    const key = el.getAttribute('data-i18n-html');
    if (key) {
      const translated = t(key);
      if (translated) el.innerHTML = translated;
    }
  });

  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (key) {
      const translated = t(key);
      if (translated) el.placeholder = translated;
    }
  });

  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    const key = el.getAttribute('data-i18n-title');
    if (key) {
      const translated = t(key);
      if (translated) el.title = translated;
    }
  });
}

// 切换当前语言
export function setLocale(lang) {
  if (!locales[lang]) {
    lang = 'zh-CN';
  }
  currentLocale = lang;
  localStorage.setItem('rddns_lang', lang);
  document.documentElement.setAttribute('lang', lang);

  // 1. 刷新 DOM 静态文字
  updateDOM();

  // 2. 触发监听回调（供 tasks / app 等动态重绘模块响应）
  localeChangeListeners.forEach(listener => {
    try {
      listener(currentLocale);
    } catch (e) {
      console.error('语言切换监听回调执行异常:', e);
    }
  });
}

// 初始化语言设置 (支持 LocalStorage 记忆与浏览器语言探测)
export function initI18n() {
  const saved = localStorage.getItem('rddns_lang');
  if (saved && locales[saved]) {
    currentLocale = saved;
  } else if (navigator.language && !navigator.language.toLowerCase().startsWith('zh')) {
    currentLocale = 'en-US';
  } else {
    currentLocale = 'zh-CN';
  }
  setLocale(currentLocale);
}
