// ==========================================
// 主题模式切换管理 (暗色 / 亮色)
// ==========================================

import { showToast } from './toast.js';

// 矢量 Sun / Moon 图标模板
export const SUN_SVG = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"></path></svg>`;
export const MOON_SVG = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z"></path></svg>`;

// 初始化主题模式 (支持 localStorage 记忆与系统色彩偏好)
export function initTheme() {
  const savedTheme = localStorage.getItem('rddns_theme');
  if (savedTheme) {
    document.documentElement.setAttribute('data-theme', savedTheme);
  } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches) {
    document.documentElement.setAttribute('data-theme', 'light');
  } else {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
  updateThemeBtnIcon();
}

export function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  const nextTheme = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', nextTheme);
  localStorage.setItem('rddns_theme', nextTheme);
  updateThemeBtnIcon();
  showToast(`已切换至${nextTheme === 'dark' ? '暗色' : '亮色'}主题`, 'info');
}

export function updateThemeBtnIcon() {
  const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
  const iconSvg = isDark ? SUN_SVG : MOON_SVG;
  ['themeIcon', 'loginThemeIcon', 'initThemeIcon'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = iconSvg;
  });
}
