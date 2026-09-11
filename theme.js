/**
 * PhishGuard Theme Engine
 * Seamless Dark & Light mode toggle with persistent state in localStorage
 */

// Immediate execution to prevent flash of wrong theme (FOUC)
(function() {
  const savedTheme = localStorage.getItem('phishguard_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
})();

function updateThemeButtonUI(theme) {
  // Sync checkbox switch inputs
  const checkboxes = document.querySelectorAll('.theme-toggle-checkbox');
  checkboxes.forEach(cb => {
    cb.checked = (theme === 'light');
  });

  // Sync tooltips on switch wrappers
  const wrappers = document.querySelectorAll('.theme-switch-wrapper, .checkbox-wrapper-5');
  wrappers.forEach(w => {
    w.setAttribute('title', theme === 'light' ? 'Switch to Dark Mode (Currently Light)' : 'Switch to Light Mode (Currently Dark)');
  });

  // Legacy button UI sync (if present)
  const buttons = document.querySelectorAll('.theme-toggle-btn');
  buttons.forEach(btn => {
    const icon = btn.querySelector('.theme-icon');
    const text = btn.querySelector('.theme-text');
    if (theme === 'light') {
      if (icon) icon.textContent = '☀️';
      if (text) text.textContent = 'Light';
      btn.setAttribute('title', 'Switch to Dark Mode');
    } else {
      if (icon) icon.textContent = '🌙';
      if (text) text.textContent = 'Dark';
      btn.setAttribute('title', 'Switch to Light Mode');
    }
  });
}

function toggleTheme(e) {
  const current = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  let next;
  if (e && e.target && typeof e.target.checked === 'boolean') {
    next = e.target.checked ? 'light' : 'dark';
  } else {
    next = current === 'light' ? 'dark' : 'light';
  }
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('phishguard_theme', next);
  updateThemeButtonUI(next);
}

document.addEventListener('DOMContentLoaded', () => {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  updateThemeButtonUI(current);
});

window.toggleTheme = toggleTheme;
window.updateThemeButtonUI = updateThemeButtonUI;

