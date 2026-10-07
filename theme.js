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

  // 3. STEP 3: 3D Magnetic Tilt Interactions
  init3DTilt();
});

// ============================================================
// 3D MAGNETIC TILT INTERACTION (Hardware Accelerated 60 FPS)
// ============================================================
function init3DTilt() {
  const cards = document.querySelectorAll('.sample-card, .glass-card[data-tilt]');
  cards.forEach(card => {
    if (card.dataset.tiltBound) return;
    card.dataset.tiltBound = 'true';
    let bounds = null;
    let isHovered = false;

    card.addEventListener('mouseenter', () => {
      bounds = card.getBoundingClientRect();
      isHovered = true;
      card.classList.remove('tilt-reset');
      card.classList.add('is-tilting');
    });

    card.addEventListener('mousemove', (e) => {
      if (!isHovered || !bounds) return;
      const x = e.clientX - bounds.left;
      const y = e.clientY - bounds.top;
      const centerX = bounds.width / 2;
      const centerY = bounds.height / 2;

      // Max 8.5 deg tilt for a classy, premium feel
      const rotateX = -((y - centerY) / centerY) * 8.5;
      const rotateY = ((x - centerX) / centerX) * 8.5;

      card.style.transform = `perspective(1000px) rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) translateY(-6px)`;
      card.style.setProperty('--glare-x', `${(x / bounds.width * 100).toFixed(1)}%`);
      card.style.setProperty('--glare-y', `${(y / bounds.height * 100).toFixed(1)}%`);
    });

    card.addEventListener('mouseleave', () => {
      isHovered = false;
      card.classList.remove('is-tilting');
      card.classList.add('tilt-reset');
      card.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) translateY(0px)';
    });
  });
}

// ============================================================
// STEP 3: MULTI-STAGE HUD SCANNER CONTROLLER
// ============================================================
async function runHudScanSteps(containerId, onFinish) {
  const box = document.getElementById(containerId);
  if (!box) {
    if (onFinish) onFinish();
    return;
  }
  box.style.display = 'block';

  const steps = box.querySelectorAll('.hud-step');
  const step1 = steps[0];
  const step2 = steps[1];
  const step3 = steps[2];
  const bar = box.querySelector('.hud-progress-bar');

  // Stage 1
  if (step1) { step1.className = 'hud-step active'; const s = step1.querySelector('.step-status'); if (s) s.textContent = 'COMPUTING'; }
  if (step2) { step2.className = 'hud-step'; const s = step2.querySelector('.step-status'); if (s) s.textContent = 'PENDING'; }
  if (step3) { step3.className = 'hud-step'; const s = step3.querySelector('.step-status'); if (s) s.textContent = 'PENDING'; }
  if (bar) bar.style.width = '35%';
  await new Promise(r => setTimeout(r, 320));

  // Stage 2
  if (step1) { step1.className = 'hud-step done'; const s = step1.querySelector('.step-status'); if (s) s.textContent = 'DONE'; }
  if (step2) { step2.className = 'hud-step active'; const s = step2.querySelector('.step-status'); if (s) s.textContent = 'INFERENCE'; }
  if (bar) bar.style.width = '70%';
  await new Promise(r => setTimeout(r, 380));

  // Stage 3
  if (step2) { step2.className = 'hud-step done'; const s = step2.querySelector('.step-status'); if (s) s.textContent = 'DONE'; }
  if (step3) { step3.className = 'hud-step active'; const s = step3.querySelector('.step-status'); if (s) s.textContent = 'CORRELATING'; }
  if (bar) bar.style.width = '100%';
  await new Promise(r => setTimeout(r, 320));

  if (step3) { step3.className = 'hud-step done'; const s = step3.querySelector('.step-status'); if (s) s.textContent = 'VERIFIED'; }
  await new Promise(r => setTimeout(r, 180));

  box.style.display = 'none';
  if (onFinish) onFinish();
}

window.init3DTilt = init3DTilt;
window.runHudScanSteps = runHudScanSteps;

