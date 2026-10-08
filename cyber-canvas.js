/**
 * PhishGuard AI — Advanced Interactive Cyber Motion Layer Engine
 * High-Performance 60 FPS Neural Particle Synapse & Cyber Matrix Grid
 * Zero external dependencies • GPU-accelerated • Mobile battery-safe
 */

(function () {
  'use strict';

  // Prevent multiple initializations if script included multiple times
  if (window.__PHISHGUARD_CYBER_CANVAS_ACTIVE__) return;
  window.__PHISHGUARD_CYBER_CANVAS_ACTIVE__ = true;

  // Create & inject background canvas
  let canvas = document.getElementById('cyberCanvas');
  if (!canvas) {
    canvas = document.createElement('canvas');
    canvas.id = 'cyberCanvas';
    canvas.setAttribute('aria-hidden', 'true');
    // Prepend as first child of body so it sits below content
    if (document.body) {
      document.body.prepend(canvas);
    } else {
      document.addEventListener('DOMContentLoaded', () => document.body.prepend(canvas));
    }
  }

  const ctx = canvas.getContext('2d', { alpha: true });
  if (!ctx) return;

  let width = window.innerWidth;
  let height = window.innerHeight;
  let dpr = Math.min(window.devicePixelRatio || 1, 2);

  // Responsive particle density
  function getParticleCount() {
    const w = window.innerWidth;
    if (w < 640) return 32;   // Mobile
    if (w < 1024) return 56;  // Tablet
    return 88;                // Desktop
  }

  let particles = [];
  let dataPackets = [];
  let ripples = [];
  let scanlineY = 0;

  const mouse = {
    x: -9999,
    y: -9999,
    radius: 175,
    active: false
  };

  // Check current theme
  function isDarkTheme() {
    return document.documentElement.getAttribute('data-theme') !== 'light';
  }

  // Color palettes
  function getColors() {
    if (isDarkTheme()) {
      return [
        { r: 56, g: 189, b: 248 },   // Electric Cyan
        { r: 96, g: 165, b: 250 },   // Neon Blue
        { r: 129, g: 140, b: 248 },  // Soft Indigo
        { r: 16, g: 185, b: 129 }    // Security Emerald
      ];
    } else {
      return [
        { r: 2, g: 132, b: 199 },    // Deep Sky
        { r: 14, g: 165, b: 233 },   // Cerulean
        { r: 79, g: 70, b: 229 },    // Modern Indigo
        { r: 16, g: 185, b: 129 }    // Emerald
      ];
    }
  }

  class Particle {
    constructor() {
      this.init();
    }

    init() {
      this.x = Math.random() * width;
      this.y = Math.random() * height;
      this.vx = (Math.random() - 0.5) * 0.7;
      this.vy = (Math.random() - 0.5) * 0.7;
      this.radius = Math.random() * 1.8 + 1.2;
      this.baseAlpha = Math.random() * 0.45 + 0.3;
      this.alpha = this.baseAlpha;
      const palette = getColors();
      this.color = palette[Math.floor(Math.random() * palette.length)];
      this.pulseSpeed = Math.random() * 0.025 + 0.015;
      this.pulseVal = Math.random() * Math.PI * 2;
    }

    update() {
      this.x += this.vx;
      this.y += this.vy;

      // Soft boundary rebound
      if (this.x < 0) { this.x = 0; this.vx *= -1; }
      else if (this.x > width) { this.x = width; this.vx *= -1; }
      if (this.y < 0) { this.y = 0; this.vy *= -1; }
      else if (this.y > height) { this.y = height; this.vy *= -1; }

      // Breathing pulse
      this.pulseVal += this.pulseSpeed;
      this.alpha = this.baseAlpha + Math.sin(this.pulseVal) * 0.18;

      // Mouse inertia / interaction
      if (mouse.active) {
        const dx = mouse.x - this.x;
        const dy = mouse.y - this.y;
        const dist = Math.hypot(dx, dy);

        if (dist < mouse.radius && dist > 1) {
          const force = (1 - dist / mouse.radius) * 0.045;
          this.vx += (dx / dist) * force;
          this.vy += (dy / dist) * force;
        }
      }

      // Physics damping
      this.vx *= 0.985;
      this.vy *= 0.985;

      // Ensure gentle persistent drift
      if (Math.abs(this.vx) < 0.12) this.vx = (Math.random() - 0.5) * 0.45;
      if (Math.abs(this.vy) < 0.12) this.vy = (Math.random() - 0.5) * 0.45;
    }

    draw() {
      const dark = isDarkTheme();
      const a = Math.max(0.08, Math.min(this.alpha * (dark ? 1 : 0.75), 0.9));
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${this.color.r}, ${this.color.g}, ${this.color.b}, ${a})`;
      ctx.fill();

      // Outer glow aura for prominent nodes
      if (this.radius > 2.0 && dark) {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.radius * 2.8, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${this.color.r}, ${this.color.g}, ${this.color.b}, ${a * 0.22})`;
        ctx.fill();
      }
    }
  }

  // Data packet moving along connection lines
  class DataPacket {
    constructor(p1, p2) {
      this.p1 = p1;
      this.p2 = p2;
      this.progress = 0;
      this.speed = Math.random() * 0.012 + 0.008;
      this.alive = true;
    }

    update() {
      this.progress += this.speed;
      if (this.progress >= 1) {
        this.alive = false;
      }
    }

    draw() {
      const x = this.p1.x + (this.p2.x - this.p1.x) * this.progress;
      const y = this.p1.y + (this.p2.y - this.p1.y) * this.progress;
      ctx.beginPath();
      ctx.arc(x, y, 1.8, 0, Math.PI * 2);
      ctx.fillStyle = isDarkTheme() ? 'rgba(56, 189, 248, 0.9)' : 'rgba(2, 132, 199, 0.85)';
      ctx.fill();
    }
  }

  // Ripple effect on click/touch
  class ThreatRipple {
    constructor(x, y) {
      this.x = x;
      this.y = y;
      this.radius = 5;
      this.maxRadius = 130;
      this.alpha = 0.5;
      this.alive = true;
    }

    update() {
      this.radius += 3.5;
      this.alpha = (1 - this.radius / this.maxRadius) * 0.5;
      if (this.radius >= this.maxRadius) {
        this.alive = false;
      }
    }

    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
      ctx.strokeStyle = isDarkTheme() 
        ? `rgba(56, 189, 248, ${Math.max(0, this.alpha)})` 
        : `rgba(2, 132, 199, ${Math.max(0, this.alpha)})`;
      ctx.lineWidth = 1.2;
      ctx.stroke();
    }
  }

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    width = window.innerWidth;
    height = window.innerHeight;

    canvas.width = width * dpr;
    canvas.height = height * dpr;
    canvas.style.width = width + 'px';
    canvas.style.height = height + 'px';

    ctx.scale(dpr, dpr);

    const count = getParticleCount();
    particles = [];
    for (let i = 0; i < count; i++) {
      particles.push(new Particle());
    }
  }

  // Draw subtle ambient cyber grid in background
  function drawCyberGrid() {
    const dark = isDarkTheme();
    const gridSpacing = 70;
    const gridAlpha = dark ? 0.022 : 0.018;

    ctx.strokeStyle = dark ? `rgba(56, 189, 248, ${gridAlpha})` : `rgba(2, 132, 199, ${gridAlpha})`;
    ctx.lineWidth = 0.75;

    // Vertical lines
    for (let x = 0; x <= width; x += gridSpacing) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }

    // Horizontal lines
    for (let y = 0; y <= height; y += gridSpacing) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    // Ambient radar scanline sweep
    scanlineY = (scanlineY + 0.6) % (height + 100);
    const grad = ctx.createLinearGradient(0, scanlineY - 40, 0, scanlineY + 40);
    grad.addColorStop(0, 'rgba(56, 189, 248, 0)');
    grad.addColorStop(0.5, dark ? 'rgba(56, 189, 248, 0.04)' : 'rgba(2, 132, 199, 0.025)');
    grad.addColorStop(1, 'rgba(56, 189, 248, 0)');
    ctx.fillStyle = grad;
    ctx.fillRect(0, scanlineY - 40, width, 80);
  }

  // Laser neural connections
  function drawConnections() {
    const maxDist = 125;
    const len = particles.length;
    const dark = isDarkTheme();

    for (let i = 0; i < len; i++) {
      const p1 = particles[i];

      // Connect to mouse cursor
      if (mouse.active) {
        const dxm = mouse.x - p1.x;
        const dym = mouse.y - p1.y;
        const distM = Math.hypot(dxm, dym);
        if (distM < mouse.radius) {
          const mAlpha = (1 - distM / mouse.radius) * (dark ? 0.42 : 0.3);
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(mouse.x, mouse.y);
          ctx.strokeStyle = dark ? `rgba(56, 189, 248, ${mAlpha})` : `rgba(2, 132, 199, ${mAlpha})`;
          ctx.lineWidth = 1.1;
          ctx.stroke();
        }
      }

      // Connect with nearby peer nodes
      for (let j = i + 1; j < len; j++) {
        const p2 = particles[j];
        const dx = p1.x - p2.x;
        const dy = p1.y - p2.y;
        const dist = Math.hypot(dx, dy);

        if (dist < maxDist) {
          const alpha = (1 - dist / maxDist) * (dark ? 0.22 : 0.14);
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = dark ? `rgba(56, 189, 248, ${alpha})` : `rgba(2, 132, 199, ${alpha})`;
          ctx.lineWidth = 0.75;
          ctx.stroke();

          // Occasionally spawn a moving data packet along this filament
          if (dataPackets.length < 12 && Math.random() < 0.003) {
            dataPackets.push(new DataPacket(p1, p2));
          }
        }
      }
    }
  }

  let animationFrameId = null;

  function render() {
    ctx.clearRect(0, 0, width, height);

    // 1. Draw subtle cyber grid & scanline sweep
    drawCyberGrid();

    // 2. Update and draw nodes
    for (let i = 0; i < particles.length; i++) {
      particles[i].update();
      particles[i].draw();
    }

    // 3. Draw neural filaments
    drawConnections();

    // 4. Update and draw traveling data packets
    for (let i = dataPackets.length - 1; i >= 0; i--) {
      dataPackets[i].update();
      dataPackets[i].draw();
      if (!dataPackets[i].alive) {
        dataPackets.splice(i, 1);
      }
    }

    // 5. Update and draw threat ripples
    for (let i = ripples.length - 1; i >= 0; i--) {
      ripples[i].update();
      ripples[i].draw();
      if (!ripples[i].alive) {
        ripples.splice(i, 1);
      }
    }

    animationFrameId = requestAnimationFrame(render);
  }

  // Pointer tracking
  window.addEventListener('mousemove', (e) => {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
    mouse.active = true;
  }, { passive: true });

  window.addEventListener('mouseleave', () => {
    mouse.active = false;
  }, { passive: true });

  window.addEventListener('touchstart', (e) => {
    if (e.touches && e.touches[0]) {
      mouse.x = e.touches[0].clientX;
      mouse.y = e.touches[0].clientY;
      mouse.active = true;
      if (ripples.length < 5) {
        ripples.push(new ThreatRipple(mouse.x, mouse.y));
      }
    }
  }, { passive: true });

  window.addEventListener('touchmove', (e) => {
    if (e.touches && e.touches[0]) {
      mouse.x = e.touches[0].clientX;
      mouse.y = e.touches[0].clientY;
      mouse.active = true;
    }
  }, { passive: true });

  window.addEventListener('touchend', () => {
    mouse.active = false;
  }, { passive: true });

  // Click creates threat radar ripple
  window.addEventListener('click', (e) => {
    // Avoid interfering with interactive buttons/links
    if (ripples.length < 6) {
      ripples.push(new ThreatRipple(e.clientX, e.clientY));
    }
  }, { passive: true });

  // Tab visibility: 0% CPU consumption in background tabs
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      if (animationFrameId) {
        cancelAnimationFrame(animationFrameId);
        animationFrameId = null;
      }
    } else {
      if (!animationFrameId) {
        animationFrameId = requestAnimationFrame(render);
      }
    }
  });

  // Debounced resize
  let resizeTimeout = null;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(resize, 120);
  });

  // Start on ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      resize();
      render();
    });
  } else {
    resize();
    render();
  }
})();
