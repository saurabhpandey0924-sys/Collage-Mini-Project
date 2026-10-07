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

  // Modern SVG & Legacy button UI sync
  const buttons = document.querySelectorAll('.theme-toggle-btn');
  buttons.forEach(btn => {
    const text = btn.querySelector('.theme-text');
    if (theme === 'light') {
      if (text) text.textContent = 'Light';
      btn.setAttribute('title', 'Switch to Dark Mode');
    } else {
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

  // Inject Glowing Background Orbs for Glassmorphism
  const orbsContainer = document.createElement('div');
  orbsContainer.className = 'orbs-background';
  orbsContainer.innerHTML = `
    <div class="orb orb-1"></div>
    <div class="orb orb-2"></div>
    <div class="orb orb-3"></div>
  `;
  document.body.prepend(orbsContainer);
});

window.toggleTheme = toggleTheme;
window.updateThemeButtonUI = updateThemeButtonUI;


// ============================================================
// UI ANIMATIONS & SCROLL OBSERVERS (Modern Freelance Style)
// ============================================================
document.addEventListener('DOMContentLoaded', () => {
  // 1. Navbar Scroll Effect
  const navbar = document.querySelector('.navbar');
  if (navbar) {
    window.addEventListener('scroll', () => {
      if (window.scrollY > 20) {
        navbar.classList.add('scrolled');
      } else {
        navbar.classList.remove('scrolled');
      }
    });
  }

  // 2. Reveal on Scroll (Intersection Observer)
  const revealElements = document.querySelectorAll('.reveal');
  const revealOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
  };

  const revealOnScroll = new IntersectionObserver(function(entries, observer) {
    entries.forEach(entry => {
      if (!entry.isIntersecting) return;
      entry.target.classList.add('active');
      observer.unobserve(entry.target);
    });
  }, revealOptions);

  revealElements.forEach(el => revealOnScroll.observe(el));
});
