/**
 * PhishGuard — High-Performance Neural Synapse & Cyber Canvas
 * Handcrafted 60 FPS Particle Grid with organic physics and mouse-inertia.
 * Lightweight (~5KB), zero external dependencies, battery-safe.
 */

(function () {
  'use strict';

  const canvas = document.createElement('canvas');
  canvas.id = 'cyberCanvas';
  canvas.setAttribute('aria-hidden', 'true');
  document.body.prepend(canvas);

  const ctx = canvas.getContext('2d', { alpha: true });
  if (!ctx) return;

  let width = 0;
  let height = 0;
  let dpr = Math.min(window.devicePixelRatio || 1, 2);

  // Responsive particle counts
  function getParticleCount() {
    const w = window.innerWidth;
    if (w < 640) return 30; // Mobile: battery safe
    if (w < 1024) return 50; // Tablet
    return 75; // Desktop
  }

  let particles = [];
  const mouse = {
    x: -9999,
    y: -9999,
    radius: 170,
    active: false
  };

  // Color palettes tailored for dark / cyber aesthetic
  const colors = [
    { r: 56, g: 189, b: 248 },  // Electric Cyan
    { r: 96, g: 165, b: 250 },  // Sky Blue
    { r: 129, g: 140, b: 248 }, // Indigo accent
    { r: 16, g: 185, b: 129 },  // Security Green (legit nodes)
  ];

  class Particle {
    constructor() {
      this.init();
    }

    init() {
      this.x = Math.random() * width;
      this.y = Math.random() * height;
      this.vx = (Math.random() - 0.5) * 0.65;
      this.vy = (Math.random() - 0.5) * 0.65;
      this.radius = Math.random() * 1.8 + 1.2;
      this.baseAlpha = Math.random() * 0.45 + 0.25;
      this.alpha = this.baseAlpha;
      this.color = colors[Math.floor(Math.random() * colors.length)];
      this.pulseSpeed = Math.random() * 0.02 + 0.01;
      this.pulseVal = Math.random() * Math.PI;
    }

    update() {
      // Natural gentle wandering
      this.x += this.vx;
      this.y += this.vy;

      // Soft bounce on canvas borders
      if (this.x < 0) { this.x = 0; this.vx *= -1; }
      else if (this.x > width) { this.x = width; this.vx *= -1; }
      if (this.y < 0) { this.y = 0; this.vy *= -1; }
      else if (this.y > height) { this.y = height; this.vy *= -1; }

      // Subtle breathing pulse
      this.pulseVal += this.pulseSpeed;
      this.alpha = this.baseAlpha + Math.sin(this.pulseVal) * 0.15;

      // Organic mouse repulsion / attraction
      if (mouse.active) {
        const dx = mouse.x - this.x;
        const dy = mouse.y - this.y;
        const dist = Math.hypot(dx, dy);

        if (dist < mouse.radius && dist > 1) {
          const force = (1 - dist / mouse.radius) * 0.035;
          this.vx += (dx / dist) * force;
          this.vy += (dy / dist) * force;
        }
      }

      // Physics damping (prevents infinite speed buildup)
      this.vx *= 0.985;
      this.vy *= 0.985;

      // Ensure minimum gentle drift
      if (Math.abs(this.vx) < 0.1) this.vx = (Math.random() - 0.5) * 0.4;
      if (Math.abs(this.vy) < 0.1) this.vy = (Math.random() - 0.5) * 0.4;
    }

    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${this.color.r}, ${this.color.g}, ${this.color.b}, ${this.alpha})`;
      ctx.fill();

      // Soft glow aura for larger nodes
      if (this.radius > 2.2) {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.radius * 2.5, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${this.color.r}, ${this.color.g}, ${this.color.b}, ${this.alpha * 0.2})`;
        ctx.fill();
      }
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

    const targetCount = getParticleCount();
    particles = [];
    for (let i = 0; i < targetCount; i++) {
      particles.push(new Particle());
    }
  }

  // Connecting laser lines between nearby nodes
  function drawConnections() {
    const maxDist = 125;
    const len = particles.length;

    for (let i = 0; i < len; i++) {
      const p1 = particles[i];

      // Connect to mouse cursor if within range
      if (mouse.active) {
        const dxm = mouse.x - p1.x;
        const dym = mouse.y - p1.y;
        const distM = Math.hypot(dxm, dym);
        if (distM < mouse.radius) {
          const mAlpha = (1 - distM / mouse.radius) * 0.35;
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(mouse.x, mouse.y);
          ctx.strokeStyle = `rgba(56, 189, 248, ${mAlpha})`;
          ctx.lineWidth = 1.1;
          ctx.stroke();
        }
      }

      // Connect to neighboring nodes
      for (let j = i + 1; j < len; j++) {
        const p2 = particles[j];
        const dx = p1.x - p2.x;
        const dy = p1.y - p2.y;
        const dist = Math.hypot(dx, dy);

        if (dist < maxDist) {
          const alpha = (1 - dist / maxDist) * 0.18;
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = `rgba(56, 189, 248, ${alpha})`;
          ctx.lineWidth = 0.75;
          ctx.stroke();
        }
      }
    }
  }

  let animationFrameId = null;

  function render() {
    ctx.clearRect(0, 0, width, height);

    for (let i = 0; i < particles.length; i++) {
      particles[i].update();
      particles[i].draw();
    }

    drawConnections();

    animationFrameId = requestAnimationFrame(render);
  }

  // Track mouse position smoothly
  window.addEventListener('mousemove', function (e) {
    mouse.x = e.clientX;
    mouse.y = e.clientY;
    mouse.active = true;
  }, { passive: true });

  window.addEventListener('mouseleave', function () {
    mouse.active = false;
  }, { passive: true });

  window.addEventListener('touchstart', function (e) {
    if (e.touches && e.touches[0]) {
      mouse.x = e.touches[0].clientX;
      mouse.y = e.touches[0].clientY;
      mouse.active = true;
    }
  }, { passive: true });

  window.addEventListener('touchend', function () {
    mouse.active = false;
  }, { passive: true });

  // Handle tab visibility (Stop animation when inactive to save 100% CPU/Battery)
  document.addEventListener('visibilitychange', function () {
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
  window.addEventListener('resize', function () {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(resize, 150);
  });

  // Initialize
  window.addEventListener('DOMContentLoaded', function () {
    resize();
    render();
  });

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    resize();
    render();
  }
})();
