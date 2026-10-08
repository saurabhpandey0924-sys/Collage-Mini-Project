/**
 * PhishGuard AI — Advanced Interactive Cyber Motion Layer Engine v4.0
 * High-Performance 60 FPS Neural Particle Synapse, Cyber Matrix Grid & Laser Telemetry
 * Zero external dependencies • Self-contained styling • GPU-accelerated • Mobile battery-safe
 */

(function () {
  'use strict';

  // Prevent multiple initializations if script included multiple times
  if (window.__PHISHGUARD_CYBER_CANVAS_ACTIVE__) return;
  window.__PHISHGUARD_CYBER_CANVAS_ACTIVE__ = true;

  console.log('%c[PhishGuard AI]%c Cyber Motion Layer Active — 60 FPS Matrix Engine v4.0', 'color:#38bdf8;font-weight:bold;', 'color:#10b981;');

  // Create & inject background canvas with guaranteed inline styles (cache-immune)
  let canvas = document.getElementById('cyberCanvas');
  if (!canvas) {
    canvas = document.createElement('canvas');
    canvas.id = 'cyberCanvas';
    canvas.setAttribute('aria-hidden', 'true');
  }

  // Force high-priority inline styling so canvas is guaranteed visible regardless of CSS caching
  canvas.style.cssText = [
    'position: fixed !important',
    'top: 0 !important',
    'left: 0 !important',
    'width: 100vw !important',
    'height: 100vh !important',
    'pointer-events: none !important',
    'z-index: 1 !important',
    'display: block !important',
    'opacity: 1 !important'
  ].join(';');

  function attachCanvas() {
    if (!document.body) return;
    if (canvas.parentNode !== document.body) {
      if (document.body.firstChild) {
        document.body.insertBefore(canvas, document.body.firstChild);
      } else {
        document.body.appendChild(canvas);
      }
    }
  }

  if (document.body) {
    attachCanvas();
  } else {
    document.addEventListener('DOMContentLoaded', attachCanvas);
  }

  const ctx = canvas.getContext('2d', { alpha: true });
  if (!ctx) return;

  let width = window.innerWidth;
  let height = window.innerHeight;
  let dpr = Math.min(window.devicePixelRatio || 1, 2);

  // Responsive particle density (tuned for crisp visibility and high FPS)
  function getParticleCount() {
    const w = window.innerWidth;
    if (w < 640) return 48;   // Mobile
    if (w < 1024) return 80;  // Tablet
    return 115;               // Desktop
  }

  let particles = [];
  let ambientMotes = [];
  let dataPackets = [];
  let ripples = [];
  let scanlineY = 0;

  const mouse = {
    x: -9999,
    y: -9999,
    radius: 190,
    active: false
  };

  // Check current theme
  function isDarkTheme() {
    return document.documentElement.getAttribute('data-theme') !== 'light';
  }

  // High-vibrancy Cyber Palette
  function getColors() {
    if (isDarkTheme()) {
      return [
        { r: 56,  g: 189, b: 248, hex: '#38bdf8' }, // Electric Cyan
        { r: 96,  g: 165, b: 250, hex: '#60a5fa' }, // Neon Azure
        { r: 129, g: 140, b: 248, hex: '#818cf8' }, // Cyber Indigo
        { r: 16,  g: 185, b: 129, hex: '#10b981' }, // Security Emerald
        { r: 244, g: 63,  b: 94,  hex: '#f43f5e' }  // Threat Radar Crimson
      ];
    } else {
      return [
        { r: 2,   g: 132, b: 199, hex: '#0284c7' }, // Deep Cyber Blue
        { r: 14,  g: 165, b: 233, hex: '#0ea5e9' }, // Bright Cerulean
        { r: 79,  g: 70,  b: 229, hex: '#4f46e5' }, // Cobalt Slate
        { r: 16,  g: 185, b: 129, hex: '#10b981' }  // Emerald
      ];
    }
  }

  // Primary Neural Nodes
  class Particle {
    constructor() {
      this.init();
    }

    init() {
      this.x = Math.random() * width;
      this.y = Math.random() * height;
      // Energetic, fluid motion visible immediately
      const speed = Math.random() * 0.9 + 0.6;
      const angle = Math.random() * Math.PI * 2;
      this.vx = Math.cos(angle) * speed;
      this.vy = Math.sin(angle) * speed;
      this.radius = Math.random() * 2.2 + 1.8; // 1.8px - 4.0px
      this.baseAlpha = Math.random() * 0.35 + 0.55; // 0.55 - 0.90
      this.alpha = this.baseAlpha;
      const palette = getColors();
      this.color = palette[Math.floor(Math.random() * palette.length)];
      this.pulseSpeed = Math.random() * 0.04 + 0.02;
      this.pulseVal = Math.random() * Math.PI * 2;
      this.extraGlow = 0;
    }

    update() {
      this.x += this.vx;
      this.y += this.vy;

      // Soft boundary bounce
      if (this.x < 0) { this.x = 0; this.vx *= -1; }
      else if (this.x > width) { this.x = width; this.vx *= -1; }
      if (this.y < 0) { this.y = 0; this.vy *= -1; }
      else if (this.y > height) { this.y = height; this.vy *= -1; }

      // Breathing pulse
      this.pulseVal += this.pulseSpeed;
      this.alpha = this.baseAlpha + Math.sin(this.pulseVal) * 0.18;

      // Scanline excitation: brighten when radar beam passes over node
      const distFromScan = Math.abs(this.y - scanlineY);
      if (distFromScan < 50) {
        this.extraGlow = (1 - distFromScan / 50) * 0.45;
      } else {
        this.extraGlow *= 0.92;
      }

      // Mouse interactive physics (repel + magnetic warp)
      if (mouse.active) {
        const dx = mouse.x - this.x;
        const dy = mouse.y - this.y;
        const dist = Math.hypot(dx, dy);

        if (dist < mouse.radius && dist > 1) {
          const force = (1 - dist / mouse.radius) * 0.08;
          this.vx += (dx / dist) * force;
          this.vy += (dy / dist) * force;
        }
      }

      // Physics damping & minimum drift
      this.vx *= 0.988;
      this.vy *= 0.988;

      // Guarantee continuous fluid drift
      const currentSpeed = Math.hypot(this.vx, this.vy);
      if (currentSpeed < 0.4) {
        this.vx += (Math.random() - 0.5) * 0.3;
        this.vy += (Math.random() - 0.5) * 0.3;
      } else if (currentSpeed > 3.2) {
        this.vx *= 0.95;
        this.vy *= 0.95;
      }
    }

    draw() {
      const dark = isDarkTheme();
      const a = Math.max(0.2, Math.min(this.alpha + this.extraGlow, 1.0));

      // 1. Outer Neon Aura
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius * (dark ? 3.2 : 2.5), 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${this.color.r}, ${this.color.g}, ${this.color.b}, ${a * (dark ? 0.28 : 0.18)})`;
      ctx.fill();

      // 2. High-intensity Core
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(${this.color.r}, ${this.color.g}, ${this.color.b}, ${a})`;
      ctx.fill();

      // 3. Central white photon point for high-energy nodes
      if (this.radius > 2.6 && dark) {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.radius * 0.45, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255, 255, 255, ${a * 0.9})`;
        ctx.fill();
      }
    }
  }

  // Floating Cyber Motes (Digital Dust rising upward in background)
  class CyberMote {
    constructor() {
      this.init();
    }

    init() {
      this.x = Math.random() * width;
      this.y = Math.random() * height;
      this.vy = -(Math.random() * 0.7 + 0.3); // Rise upward
      this.vx = (Math.random() - 0.5) * 0.4;
      this.radius = Math.random() * 1.4 + 0.8;
      this.alpha = Math.random() * 0.4 + 0.2;
    }

    update() {
      this.y += this.vy;
      this.x += this.vx;
      if (this.y < -10) {
        this.y = height + 10;
        this.x = Math.random() * width;
      }
      if (this.x < 0) this.x = width;
      else if (this.x > width) this.x = 0;
    }

    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
      ctx.fillStyle = isDarkTheme() 
        ? `rgba(56, 189, 248, ${this.alpha * 0.4})` 
        : `rgba(2, 132, 199, ${this.alpha * 0.3})`;
      ctx.fill();
    }
  }

  // Traveling Telemetry Data Packet
  class DataPacket {
    constructor(p1, p2) {
      this.p1 = p1;
      this.p2 = p2;
      this.progress = 0;
      this.speed = Math.random() * 0.025 + 0.015;
      this.alive = true;
      this.color = Math.random() > 0.2 ? 'rgba(56, 189, 248, 1)' : 'rgba(16, 185, 129, 1)';
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

      // Glow halo
      ctx.beginPath();
      ctx.arc(x, y, 4.5, 0, Math.PI * 2);
      ctx.fillStyle = this.color.replace('1)', '0.3)');
      ctx.fill();

      // Sharp white/cyan spark
      ctx.beginPath();
      ctx.arc(x, y, 2.2, 0, Math.PI * 2);
      ctx.fillStyle = '#ffffff';
      ctx.fill();
    }
  }

  // Interactive Sonar / Radar Shockwave on click or touch
  class RadarRipple {
    constructor(x, y) {
      this.x = x;
      this.y = y;
      this.radius = 8;
      this.maxRadius = Math.min(width, height) * 0.38;
      this.alpha = 0.85;
      this.alive = true;
    }

    update() {
      this.radius += 5.5;
      this.alpha = (1 - this.radius / this.maxRadius) * 0.85;
      if (this.radius >= this.maxRadius) {
        this.alive = false;
      }

      // Gently push nearby particles as the ripple propagates
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        const dist = Math.hypot(p.x - this.x, p.y - this.y);
        if (Math.abs(dist - this.radius) < 22) {
          const angle = Math.atan2(p.y - this.y, p.x - this.x);
          p.vx += Math.cos(angle) * 0.9;
          p.vy += Math.sin(angle) * 0.9;
          p.extraGlow = 0.6;
        }
      }
    }

    draw() {
      if (this.alpha <= 0) return;
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
      ctx.strokeStyle = isDarkTheme() 
        ? `rgba(56, 189, 248, ${Math.max(0, this.alpha)})` 
        : `rgba(2, 132, 199, ${Math.max(0, this.alpha)})`;
      ctx.lineWidth = 2.0;
      ctx.stroke();

      // Inner faint secondary ring
      if (this.radius > 25) {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.radius * 0.65, 0, Math.PI * 2);
        ctx.strokeStyle = isDarkTheme() 
          ? `rgba(96, 165, 250, ${Math.max(0, this.alpha * 0.5)})` 
          : `rgba(14, 165, 233, ${Math.max(0, this.alpha * 0.4)})`;
        ctx.lineWidth = 1.0;
        ctx.stroke();
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

    const count = getParticleCount();
    particles = [];
    for (let i = 0; i < count; i++) {
      particles.push(new Particle());
    }

    ambientMotes = [];
    const moteCount = Math.floor(count * 0.4);
    for (let i = 0; i < moteCount; i++) {
      ambientMotes.push(new CyberMote());
    }
  }

  // Cyber Grid with Holographic Laser Sweep
  function drawCyberGrid() {
    const dark = isDarkTheme();
    const gridSpacing = width < 640 ? 55 : 75;
    const gridAlpha = dark ? 0.045 : 0.035;

    ctx.strokeStyle = dark ? `rgba(56, 189, 248, ${gridAlpha})` : `rgba(2, 132, 199, ${gridAlpha})`;
    ctx.lineWidth = 0.8;

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

    // Dynamic radar scanning laser sweep (travels from top to bottom continuously)
    scanlineY = (scanlineY + 1.6) % (height + 140);
    const beamY = scanlineY - 70;
    const grad = ctx.createLinearGradient(0, beamY - 45, 0, beamY + 45);
    grad.addColorStop(0, 'rgba(56, 189, 248, 0)');
    grad.addColorStop(0.5, dark ? 'rgba(56, 189, 248, 0.12)' : 'rgba(2, 132, 199, 0.08)');
    grad.addColorStop(1, 'rgba(56, 189, 248, 0)');
    ctx.fillStyle = grad;
    ctx.fillRect(0, beamY - 45, width, 90);

    // Glowing laser beam edge line
    ctx.beginPath();
    ctx.moveTo(0, beamY);
    ctx.lineTo(width, beamY);
    ctx.strokeStyle = dark ? 'rgba(56, 189, 248, 0.28)' : 'rgba(2, 132, 199, 0.18)';
    ctx.lineWidth = 1.2;
    ctx.stroke();
  }

  // Neural Synapse Laser Filaments
  function drawConnections() {
    const maxDist = width < 640 ? 110 : 145;
    const len = particles.length;
    const dark = isDarkTheme();

    for (let i = 0; i < len; i++) {
      const p1 = particles[i];

      // Connect to mouse cursor with bright energy tether
      if (mouse.active) {
        const dxm = mouse.x - p1.x;
        const dym = mouse.y - p1.y;
        const distM = Math.hypot(dxm, dym);
        if (distM < mouse.radius) {
          const mAlpha = (1 - distM / mouse.radius) * (dark ? 0.65 : 0.45);
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(mouse.x, mouse.y);
          ctx.strokeStyle = dark ? `rgba(56, 189, 248, ${mAlpha})` : `rgba(2, 132, 199, ${mAlpha})`;
          ctx.lineWidth = 1.5;
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
          const proximity = 1 - dist / maxDist;
          const alpha = proximity * (dark ? 0.38 : 0.24);
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(p2.x, p2.y);
          ctx.strokeStyle = dark ? `rgba(56, 189, 248, ${alpha})` : `rgba(2, 132, 199, ${alpha})`;
          ctx.lineWidth = proximity > 0.6 ? 1.2 : 0.8;
          ctx.stroke();

          // Spawn high-energy data packet across this synapse
          if (dataPackets.length < 18 && Math.random() < 0.007) {
            dataPackets.push(new DataPacket(p1, p2));
          }
        }
      }
    }
  }

  let animationFrameId = null;

  function render() {
    ctx.clearRect(0, 0, width, height);

    // 1. Cyber Matrix Grid & Laser Scanline Sweep
    drawCyberGrid();

    // 2. Rising background Cyber Motes
    for (let i = 0; i < ambientMotes.length; i++) {
      ambientMotes[i].update();
      ambientMotes[i].draw();
    }

    // 3. Update & Draw Neural Particles
    for (let i = 0; i < particles.length; i++) {
      particles[i].update();
      particles[i].draw();
    }

    // 4. Neural Synapses
    drawConnections();

    // 5. High-speed Telemetry Data Packets
    for (let i = dataPackets.length - 1; i >= 0; i--) {
      dataPackets[i].update();
      dataPackets[i].draw();
      if (!dataPackets[i].alive) {
        dataPackets.splice(i, 1);
      }
    }

    // 6. Interactive Sonar Waves
    for (let i = ripples.length - 1; i >= 0; i--) {
      ripples[i].update();
      ripples[i].draw();
      if (!ripples[i].alive) {
        ripples.splice(i, 1);
      }
    }

    animationFrameId = requestAnimationFrame(render);
  }

  // Pointer Interaction Events
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
        ripples.push(new RadarRipple(mouse.x, mouse.y));
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

  // Interactive Click / Tap triggers tactical sonar ripple
  window.addEventListener('click', (e) => {
    if (ripples.length < 6) {
      ripples.push(new RadarRipple(e.clientX, e.clientY));
    }
  }, { passive: true });

  // Tab Visibility optimization: 0% GPU load when tab hidden
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

  // Debounced Window Resize
  let resizeTimer = null;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      attachCanvas();
      resize();
    }, 100);
  });

  // Initialization trigger
  function boot() {
    attachCanvas();
    resize();
    if (!animationFrameId) {
      animationFrameId = requestAnimationFrame(render);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }

  // Backup trigger on window.onload
  window.addEventListener('load', () => {
    attachCanvas();
    if (particles.length === 0) {
      resize();
    }
  });

})();
