// This small blocking script restores the preference before the stylesheet paints.
(() => {
  const root = document.documentElement;
  const storageKey = '0xsaleh-theme';
  try {
    const saved = localStorage.getItem(storageKey);
    if (saved === 'light' || saved === 'dark') root.dataset.theme = saved;
  } catch {
    // Storage may be blocked; the default theme and toggle still work.
  }
  document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.querySelector('.theme-toggle');
    const updateLabel = () => {
      const isLight = root.dataset.theme === 'light';
      toggle.setAttribute('aria-label', `Switch to ${isLight ? 'dark' : 'light'} theme`);
      toggle.title = `Switch to ${isLight ? 'dark' : 'light'} theme`;
    };
    updateLabel();
    toggle.hidden = false;
    toggle.addEventListener('click', () => {
      root.dataset.theme = root.dataset.theme === 'light' ? 'dark' : 'light';
      updateLabel();
      try {
        localStorage.setItem(storageKey, root.dataset.theme);
      } catch {
        // Keep the selected theme for this page even when persistence is unavailable.
      }
    });
  });
})();
