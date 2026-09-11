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

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  const next = current === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('phishguard_theme', next);
  updateThemeButtonUI(next);
}

document.addEventListener('DOMContentLoaded', () => {
  const current = document.documentElement.getAttribute('data-theme') || 'dark';
  updateThemeButtonUI(current);
});

window.toggleTheme = toggleTheme;
