/**
 * ECDAT Framer Motion & Circular Micro-Animation Engine
 * Air-gapped, zero-remote-dependency motion physics system.
 * Implements Framer Motion spring physics, precision number rollups,
 * circular radar/orbital telemetry animations, morphing layout transitions,
 * and tactile micro-interactions conforming to UI/UX Pro Max guidelines.
 */

(function (global) {
  'use strict';

  // Check user motion preferences
  function prefersReducedMotion() {
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  // ---------------------------------------------------------------------------
  // 1. Analytical Spring Physics Engine (Damped harmonic oscillator)
  // ---------------------------------------------------------------------------
  class Spring {
    constructor(config = {}) {
      this.stiffness = config.stiffness ?? 220; // k: spring stiffness
      this.damping = config.damping ?? 24;      // c: damping coefficient
      this.mass = config.mass ?? 1;             // m: mass
      this.velocity = config.velocity ?? 0;     // initial velocity
      this.precision = config.precision ?? 0.001;
    }

    solve(x0, v0, t) {
      const k = this.stiffness;
      const c = this.damping;
      const m = this.mass;

      const omega0 = Math.sqrt(k / m);
      const zeta = c / (2 * Math.sqrt(m * k));

      if (zeta < 1) {
        const omegaD = omega0 * Math.sqrt(1 - zeta * zeta);
        const decay = Math.exp(-zeta * omega0 * t);
        const cos = Math.cos(omegaD * t);
        const sin = Math.sin(omegaD * t);

        const A = x0;
        const B = (v0 + zeta * omega0 * x0) / omegaD;

        const x = decay * (A * cos + B * sin);
        const v = -zeta * omega0 * x + decay * (-A * omegaD * sin + B * omegaD * cos);
        return { x, v };
      } else if (zeta === 1) {
        const decay = Math.exp(-omega0 * t);
        const A = x0;
        const B = v0 + omega0 * x0;
        const x = (A + B * t) * decay;
        const v = (B - omega0 * (A + B * t)) * decay;
        return { x, v };
      } else {
        const r1 = -omega0 * (zeta - Math.sqrt(zeta * zeta - 1));
        const r2 = -omega0 * (zeta + Math.sqrt(zeta * zeta - 1));
        const A = (v0 - r2 * x0) / (r1 - r2);
        const B = x0 - A;
        const x = A * Math.exp(r1 * t) + B * Math.exp(r2 * t);
        const v = A * r1 * Math.exp(r1 * t) + B * r2 * Math.exp(r2 * t);
        return { x, v };
      }
    }

    animate({ from, to, onUpdate, onComplete }) {
      if (prefersReducedMotion() || Math.abs(from - to) < this.precision) {
        onUpdate?.(to);
        onComplete?.();
        return { stop: () => {} };
      }

      const delta = from - to;
      let v0 = this.velocity;
      const startTime = performance.now();
      let animId = null;

      const tick = (now) => {
        const t = (now - startTime) / 1000;
        const { x, v } = this.solve(delta, v0, t);
        const currentVal = to + x;

        onUpdate?.(currentVal);

        if (Math.abs(x) < this.precision && Math.abs(v) < this.precision * 4) {
          onUpdate?.(to);
          onComplete?.();
          return;
        }

        animId = requestAnimationFrame(tick);
      };

      animId = requestAnimationFrame(tick);
      return {
        stop: () => {
          if (animId) cancelAnimationFrame(animId);
        }
      };
    }
  }

  // ---------------------------------------------------------------------------
  // 2. Framer Motion Helper API
  // ---------------------------------------------------------------------------
  const Motion = {
    Spring,

    /**
     * Visible, high-fluidity number counting animation (0 -> N roll-up)
     * High frame-rate interpolation using tuned easeOutQuart curve.
     */
    countTo(targetEl, targetValue, options = {}) {
      const element = typeof targetEl === 'string' ? document.getElementById(targetEl) : targetEl;
      if (!element) return;

      const {
        duration = 1050,
        prefix = '',
        suffix = '',
        from = null,
        delay = 0,
        decimals = null,
        forceRoll = false
      } = options;

      const targetNum = parseFloat(targetValue) || 0;
      let startNum = 0;

      if (from !== null && from !== undefined) {
        startNum = parseFloat(from) || 0;
      } else if (element.dataset.animatedVal !== undefined) {
        startNum = parseFloat(element.dataset.animatedVal) || 0;
      } else {
        const existing = element.textContent.replace(/[^0-9.-]/g, '');
        startNum = existing ? (parseFloat(existing) || 0) : 0;
      }

      const formatVal = (num) => {
        if (decimals !== null) return num.toFixed(decimals);
        if (Number.isInteger(targetNum)) return Math.round(num).toString();
        if (Math.abs(targetNum) >= 100) return Math.round(num).toString();
        return (Math.round(num * 10) / 10).toFixed(1);
      };

      if (prefersReducedMotion()) {
        element.textContent = `${prefix}${formatVal(targetNum)}${suffix}`;
        element.dataset.animatedVal = String(targetNum);
        return;
      }

      // If already at target value and not forced to roll, return
      if (!forceRoll && Math.abs(startNum - targetNum) < 0.0001 && element.dataset.animatedVal !== undefined) {
        element.textContent = `${prefix}${formatVal(targetNum)}${suffix}`;
        return;
      }

      // Display start value immediately during delay so there is no flash of target value
      element.textContent = `${prefix}${formatVal(startNum)}${suffix}`;

      // Clean up previous animations on this element
      if (element._motionAnimId) {
        cancelAnimationFrame(element._motionAnimId);
        element._motionAnimId = null;
      }
      if (element._motionTimeoutId) {
        clearTimeout(element._motionTimeoutId);
        element._motionTimeoutId = null;
      }

      const startAnimation = () => {
        let startTime = null;

        // Visual rolling class for tactile glow
        element.classList.add('num-rolling');
        element.classList.remove('num-settled');

        // EaseOutQuart: fast dynamic takeoff, silky smooth deceleration into rest
        const easeOutQuart = (t) => 1 - Math.pow(1 - t, 4);

        const step = (timestamp) => {
          if (!startTime) startTime = timestamp;
          const elapsed = timestamp - startTime;
          const progress = Math.min(elapsed / duration, 1);
          const eased = easeOutQuart(progress);
          const current = startNum + (targetNum - startNum) * eased;

          element.textContent = `${prefix}${formatVal(current)}${suffix}`;
          element.dataset.animatedVal = String(current);

          if (progress < 1) {
            element._motionAnimId = requestAnimationFrame(step);
          } else {
            element.textContent = `${prefix}${formatVal(targetNum)}${suffix}`;
            element.dataset.animatedVal = String(targetNum);
            element._motionAnimId = null;
            element.classList.remove('num-rolling');
            element.classList.add('num-settled');
            setTimeout(() => element.classList.remove('num-settled'), 500);
          }
        };

        element._motionAnimId = requestAnimationFrame(step);
      };

      if (delay > 0) {
        element._motionTimeoutId = setTimeout(startAnimation, delay);
      } else {
        startAnimation();
      }
    },

    // Morphing Tab Slider (Framer Motion layoutId="activeTab" pattern)
    setupMorphingTabs(tabNavSelector, activeIndicatorSelector) {
      const nav = document.querySelector(tabNavSelector);
      const indicator = document.querySelector(activeIndicatorSelector);
      if (!nav || !indicator) return;

      let currentX = 0;
      let currentW = 0;
      let springX = new Spring({ stiffness: 320, damping: 28 });
      let springW = new Spring({ stiffness: 320, damping: 28 });
      let stopX = null;
      let stopW = null;

      function updateIndicatorToTab(tabBtn, immediate = false) {
        if (!tabBtn) return;
        const navRect = nav.getBoundingClientRect();
        const tabRect = tabBtn.getBoundingClientRect();

        const targetX = tabRect.left - navRect.left + nav.scrollLeft;
        const targetW = tabRect.width;

        if (immediate || prefersReducedMotion()) {
          indicator.style.transform = `translateX(${targetX}px)`;
          indicator.style.width = `${targetW}px`;
          indicator.style.opacity = '1';
          currentX = targetX;
          currentW = targetW;
          return;
        }

        indicator.style.opacity = '1';
        if (stopX) stopX.stop();
        if (stopW) stopW.stop();

        stopX = springX.animate({
          from: currentX,
          to: targetX,
          onUpdate: (x) => {
            currentX = x;
            indicator.style.transform = `translateX(${x}px)`;
          }
        });

        stopW = springW.animate({
          from: currentW,
          to: targetW,
          onUpdate: (w) => {
            currentW = w;
            indicator.style.width = `${w}px`;
          }
        });
      }

      // Initialize to current active tab
      const activeTab = nav.querySelector('.tab-btn.active') || nav.querySelector('.tab-btn');
      if (activeTab) {
        updateIndicatorToTab(activeTab, true);
      }

      // Hook tab click events
      nav.addEventListener('click', (e) => {
        const btn = e.target.closest('.tab-btn');
        if (btn) {
          updateIndicatorToTab(btn, false);
        }
      });

      // Recalculate on window resize
      window.addEventListener('resize', () => {
        const currentActive = nav.querySelector('.tab-btn.active');
        if (currentActive) updateIndicatorToTab(currentActive, true);
      });
    },

    // Tactile Circular Ripple Wave Effect on click
    setupCircularRipples(selector) {
      document.addEventListener('pointerdown', (e) => {
        if (prefersReducedMotion()) return;
        const target = e.target.closest(selector);
        if (!target) return;

        const rect = target.getBoundingClientRect();
        const ripple = document.createElement('span');
        ripple.className = 'circular-ripple';
        const diameter = Math.max(rect.width, rect.height) * 2;
        const radius = diameter / 2;

        ripple.style.width = ripple.style.height = `${diameter}px`;
        ripple.style.left = `${e.clientX - rect.left - radius}px`;
        ripple.style.top = `${e.clientY - rect.top - radius}px`;

        target.appendChild(ripple);
        setTimeout(() => ripple.remove(), 700);
      });
    },

    // Interactive Card Spotlight Glint (tracking mouse coordinates)
    setupCardSpotlight(cardSelector) {
      const cards = document.querySelectorAll(cardSelector);
      cards.forEach(card => {
        card.addEventListener('pointermove', (e) => {
          if (prefersReducedMotion()) return;
          const rect = card.getBoundingClientRect();
          const x = e.clientX - rect.left;
          const y = e.clientY - rect.top;
          card.style.setProperty('--mouse-x', `${x}px`);
          card.style.setProperty('--mouse-y', `${y}px`);
        });
      });
    },

    // Magnetic Button Micro-Interaction
    setupMagneticButtons(buttonSelector) {
      if (prefersReducedMotion()) return;
      const btns = document.querySelectorAll(buttonSelector);
      btns.forEach(btn => {
        btn.addEventListener('mousemove', (e) => {
          const rect = btn.getBoundingClientRect();
          const x = e.clientX - rect.left - rect.width / 2;
          const y = e.clientY - rect.top - rect.height / 2;
          btn.style.transform = `translate(${x * 0.15}px, ${y * 0.15}px)`;
        });
        btn.addEventListener('mouseleave', () => {
          btn.style.transform = 'translate(0px, 0px)';
        });
      });
    }
  };

  // ---------------------------------------------------------------------------
  // 3. Fluid Circular Radar & Quantum Reticle Animation Component
  // ---------------------------------------------------------------------------
  class CircularRadarReticle {
    constructor(svgElementId, options = {}) {
      this.svg = document.getElementById(svgElementId);
      this.options = Object.assign({
        cx: 210,
        cy: 210,
        r0: 85,
        r1: 195,
        radarSpeed: 0.024, // rad per frame base surveillance
        reticleSpeed: 0.006,
      }, options);

      this.angle = 0;
      this.reticleAngle = 0;
      this.compassAngle = 0;
      this.pulsePhase1 = 0;
      this.pulsePhase2 = 0.5; // Staggered dual pulse waves
      this.satellitesAngle = [0, (2 * Math.PI) / 3, (4 * Math.PI) / 3];
      this.targets = [];
      this.isRunning = false;
      this.isScanMode = false;
      this.speedMultiplier = 1.0;
      this.targetMultiplier = 1.0;
      this.animId = null;

      this.initSvgLayers();
    }

    initSvgLayers() {
      if (!this.svg) return;

      // Group for static reticle & degree marks
      let bgGroup = this.svg.querySelector('#radar-bg-group');
      if (!bgGroup) {
        bgGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        bgGroup.setAttribute('id', 'radar-bg-group');
        this.svg.insertBefore(bgGroup, this.svg.firstChild);
      }
      this.bgGroup = bgGroup;

      // Build concentric circular rings & crosshairs
      this.renderConcentricRings();

      // Sweeping radar beam element
      let sweepEl = this.svg.querySelector('#radar-sweep-beam');
      if (!sweepEl) {
        sweepEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        sweepEl.setAttribute('id', 'radar-sweep-beam');
        sweepEl.setAttribute('fill', 'url(#radar-sweep-gradient)');
        sweepEl.setAttribute('opacity', '0.42');
        sweepEl.setAttribute('pointer-events', 'none');
        this.svg.appendChild(sweepEl);
      }
      this.sweepEl = sweepEl;

      // Leading edge glow beam line
      let leadLine = this.svg.querySelector('#radar-lead-line');
      if (!leadLine) {
        leadLine = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        leadLine.setAttribute('id', 'radar-lead-line');
        leadLine.setAttribute('stroke', '#34D399');
        leadLine.setAttribute('stroke-width', '1.6');
        leadLine.setAttribute('stroke-linecap', 'round');
        leadLine.setAttribute('opacity', '0.8');
        leadLine.setAttribute('pointer-events', 'none');
        this.svg.appendChild(leadLine);
      }
      this.leadLine = leadLine;

      // Leading edge tip particle dot
      let leadTip = this.svg.querySelector('#radar-lead-tip');
      if (!leadTip) {
        leadTip = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        leadTip.setAttribute('id', 'radar-lead-tip');
        leadTip.setAttribute('r', '2.5');
        leadTip.setAttribute('fill', '#6EE7B7');
        leadTip.setAttribute('opacity', '0.9');
        leadTip.setAttribute('pointer-events', 'none');
        this.svg.appendChild(leadTip);
      }
      this.leadTip = leadTip;

      // Group for dynamic radar target ping ripples
      let pingsGroup = this.svg.querySelector('#radar-pings-group');
      if (!pingsGroup) {
        pingsGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        pingsGroup.setAttribute('id', 'radar-pings-group');
        pingsGroup.setAttribute('pointer-events', 'none');
        this.svg.appendChild(pingsGroup);
      }
      this.pingsGroup = pingsGroup;

      // Concentric rotating reticle ring with tick marks
      let reticleEl = this.svg.querySelector('#radar-rotating-reticle');
      if (!reticleEl) {
        reticleEl = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        reticleEl.setAttribute('id', 'radar-rotating-reticle');
        this.svg.appendChild(reticleEl);
        this.renderReticleTicks(reticleEl);
      }
      this.reticleEl = reticleEl;

      // Inner counter-rotating calibration ring
      let innerRingEl = this.svg.querySelector('#radar-inner-counter');
      if (!innerRingEl) {
        innerRingEl = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        innerRingEl.setAttribute('id', 'radar-inner-counter');
        innerRingEl.setAttribute('cx', this.options.cx);
        innerRingEl.setAttribute('cy', this.options.cy);
        innerRingEl.setAttribute('r', (this.options.r0 + this.options.r1) / 2);
        innerRingEl.setAttribute('fill', 'none');
        innerRingEl.setAttribute('stroke', 'rgba(99, 102, 241, 0.22)');
        innerRingEl.setAttribute('stroke-width', '1');
        innerRingEl.setAttribute('stroke-dasharray', '5 12');
        this.svg.appendChild(innerRingEl);
      }
      this.innerRingEl = innerRingEl;

      // Dual dynamic Sonar Pulse Waves (expanding circles)
      let pulseRing1 = this.svg.querySelector('#radar-pulse-ring-1');
      if (!pulseRing1) {
        pulseRing1 = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        pulseRing1.setAttribute('id', 'radar-pulse-ring-1');
        pulseRing1.setAttribute('cx', this.options.cx);
        pulseRing1.setAttribute('cy', this.options.cy);
        pulseRing1.setAttribute('r', this.options.r0);
        pulseRing1.setAttribute('fill', 'none');
        pulseRing1.setAttribute('stroke', '#10B981');
        pulseRing1.setAttribute('stroke-width', '1.2');
        pulseRing1.setAttribute('opacity', '0.45');
        this.svg.appendChild(pulseRing1);
      }
      this.pulseRing1 = pulseRing1;

      let pulseRing2 = this.svg.querySelector('#radar-pulse-ring-2');
      if (!pulseRing2) {
        pulseRing2 = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        pulseRing2.setAttribute('id', 'radar-pulse-ring-2');
        pulseRing2.setAttribute('cx', this.options.cx);
        pulseRing2.setAttribute('cy', this.options.cy);
        pulseRing2.setAttribute('r', this.options.r0);
        pulseRing2.setAttribute('fill', 'none');
        pulseRing2.setAttribute('stroke', '#38BDF8');
        pulseRing2.setAttribute('stroke-width', '1.0');
        pulseRing2.setAttribute('opacity', '0.35');
        this.svg.appendChild(pulseRing2);
      }
      this.pulseRing2 = pulseRing2;

      // Orbiting Satellite Sensor Nodes
      let satGroup = this.svg.querySelector('#radar-satellites-group');
      if (!satGroup) {
        satGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        satGroup.setAttribute('id', 'radar-satellites-group');
        this.svg.appendChild(satGroup);
        this.renderSatellites(satGroup);
      }
      this.satGroup = satGroup;
    }

    renderConcentricRings() {
      const { cx, cy, r0, r1 } = this.options;
      this.bgGroup.innerHTML = '';

      // Radial defs for sweep gradient - fixed with userSpaceOnUse to eliminate jumping distortion
      let defs = this.svg.querySelector('defs');
      if (!defs) {
        defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
        this.svg.prepend(defs);
      }

      defs.innerHTML = `
        <radialGradient id="radar-sweep-gradient" gradientUnits="userSpaceOnUse" cx="${cx}" cy="${cy}" r="${r1}" fx="${cx}" fy="${cy}">
          <stop offset="0%" stop-color="#10B981" stop-opacity="0.35" />
          <stop offset="50%" stop-color="#059669" stop-opacity="0.14" />
          <stop offset="90%" stop-color="#047857" stop-opacity="0.02" />
          <stop offset="100%" stop-color="#047857" stop-opacity="0" />
        </radialGradient>
      `;

      // 4 concentric range circles with subtle precision dashes
      const rings = [0.25, 0.5, 0.75, 1.0];
      rings.forEach(fraction => {
        const r = r0 + (r1 - r0) * fraction;
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', cx);
        circle.setAttribute('cy', cy);
        circle.setAttribute('r', r);
        circle.setAttribute('fill', 'none');
        circle.setAttribute('stroke', fraction === 1.0 ? 'rgba(16, 185, 129, 0.32)' : 'rgba(255, 255, 255, 0.08)');
        circle.setAttribute('stroke-width', fraction === 1.0 ? '1.4' : '0.8');
        circle.setAttribute('stroke-dasharray', fraction === 1.0 ? '4 8' : '2 6');
        this.bgGroup.appendChild(circle);
      });

      // 4 quadrant crosshairs with cardinal telemetry marks
      const cardinals = [
        { ang: -Math.PI / 2, label: '000° N' },
        { ang: 0, label: '090° E' },
        { ang: Math.PI / 2, label: '180° S' },
        { ang: Math.PI, label: '270° W' }
      ];

      cardinals.forEach(({ ang, label }) => {
        const x1 = cx + (r0 - 6) * Math.cos(ang);
        const y1 = cy + (r0 - 6) * Math.sin(ang);
        const x2 = cx + (r1 + 10) * Math.cos(ang);
        const y2 = cy + (r1 + 10) * Math.sin(ang);

        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', x1);
        line.setAttribute('y1', y1);
        line.setAttribute('x2', x2);
        line.setAttribute('y2', y2);
        line.setAttribute('stroke', 'rgba(16, 185, 129, 0.22)');
        line.setAttribute('stroke-width', '1');
        line.setAttribute('stroke-dasharray', '3 4');
        this.bgGroup.appendChild(line);

        const tx = cx + (r1 + 22) * Math.cos(ang);
        const ty = cy + (r1 + 22) * Math.sin(ang) + 3;
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', tx);
        text.setAttribute('y', ty);
        text.setAttribute('text-anchor', 'middle');
        text.setAttribute('fill', 'rgba(148, 163, 184, 0.7)');
        text.setAttribute('font-size', '7.5');
        text.setAttribute('font-family', 'var(--font-mono)');
        text.setAttribute('letter-spacing', '0.05em');
        text.textContent = label;
        this.bgGroup.appendChild(text);
      });
    }

    renderReticleTicks(reticleGroup) {
      const { cx, cy, r1 } = this.options;
      const tickRadius = r1 + 8;
      const numTicks = 48;

      for (let i = 0; i < numTicks; i++) {
        const rad = (i * 2 * Math.PI) / numTicks;
        const isMajor = i % 12 === 0;
        const isSemi = i % 4 === 0;
        const len = isMajor ? 7 : (isSemi ? 4.5 : 2.5);

        const x1 = cx + tickRadius * Math.cos(rad);
        const y1 = cy + tickRadius * Math.sin(rad);
        const x2 = cx + (tickRadius + len) * Math.cos(rad);
        const y2 = cy + (tickRadius + len) * Math.sin(rad);

        const tick = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        tick.setAttribute('x1', x1);
        tick.setAttribute('y1', y1);
        tick.setAttribute('x2', x2);
        tick.setAttribute('y2', y2);
        tick.setAttribute('stroke', isMajor ? '#10B981' : (isSemi ? 'rgba(16, 185, 129, 0.55)' : 'rgba(148, 163, 184, 0.28)'));
        tick.setAttribute('stroke-width', isMajor ? '1.5' : '0.9');
        reticleGroup.appendChild(tick);
      }
    }

    renderSatellites(satGroup) {
      satGroup.innerHTML = '';
      const colors = ['#10B981', '#38BDF8', '#818CF8'];
      for (let i = 0; i < 3; i++) {
        const node = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        node.setAttribute('class', `orbit-satellite-node node-${i}`);
        node.setAttribute('r', '2.8');
        node.setAttribute('fill', colors[i]);
        node.setAttribute('opacity', '0.9');
        satGroup.appendChild(node);
      }
    }

    updateTargets(records = []) {
      const { r0, r1 } = this.options;
      const items = [...records].sort((a, b) => ((b.risk?.score || 0) - (a.risk?.score || 0)));
      const N = items.length;
      if (!N) {
        this.targets = [];
        return;
      }
      const sweep = 2 * Math.PI * 0.86;
      const start = Math.PI / 2 + (2 * Math.PI - sweep) / 2;
      const step = sweep / Math.max(1, N);
      const tierColors = {
        CRITICAL: '#F43F5E',
        HIGH: '#F97316',
        MEDIUM: '#F59E0B',
        LOW: '#10B981',
      };
      this.targets = items.map((r, i) => {
        const a = (start + step * (i + 0.5)) % (2 * Math.PI);
        const scoreVal = r.risk?.score !== undefined ? r.risk.score : (r.tier === 'CRITICAL' ? 85 : (r.tier === 'HIGH' ? 65 : (r.tier === 'MEDIUM' ? 45 : 20)));
        const scoreFrac = Math.max(0.12, Math.min(1.0, scoreVal / 100));
        const dist = r0 + (r1 - r0) * scoreFrac;
        return {
          angle: a,
          radius: dist,
          color: tierColors[r.tier] || '#10B981',
          lastPing: 0
        };
      });
    }

    triggerTargetPing(tgt) {
      if (!this.pingsGroup || prefersReducedMotion()) return;
      const { cx, cy } = this.options;
      const px = cx + tgt.radius * Math.cos(tgt.angle);
      const py = cy + tgt.radius * Math.sin(tgt.angle);

      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('cx', px.toFixed(1));
      circle.setAttribute('cy', py.toFixed(1));
      circle.setAttribute('r', '3');
      circle.setAttribute('fill', 'none');
      circle.setAttribute('stroke', tgt.color);
      circle.setAttribute('stroke-width', '1.6');
      circle.setAttribute('opacity', '0.9');
      this.pingsGroup.appendChild(circle);

      const startTime = performance.now();
      const duration = 700;

      const pingStep = (t) => {
        const elapsed = t - startTime;
        const p = Math.min(elapsed / duration, 1);
        const r = 3 + 15 * p;
        const op = 0.9 * (1 - p);
        circle.setAttribute('r', r.toFixed(1));
        circle.setAttribute('opacity', op.toFixed(2));
        if (p < 1) {
          requestAnimationFrame(pingStep);
        } else {
          circle.remove();
        }
      };
      requestAnimationFrame(pingStep);
    }

    setScanMode(on) {
      this.isScanMode = !!on;
      this.targetMultiplier = on ? 3.0 : 1.0;
    }

    start() {
      if (this.isRunning || prefersReducedMotion()) return;
      this.isRunning = true;

      const { cx, cy, r0, r1 } = this.options;
      const sweepAngleSpan = Math.PI / 3.4;
      const satRadius = r1 + 10;

      const animateFrame = () => {
        if (!this.isRunning) return;

        // Smooth speed easing when switching between surveillance and active scanning
        this.speedMultiplier += (this.targetMultiplier - this.speedMultiplier) * 0.08;

        const effectiveRadarSpeed = this.options.radarSpeed * this.speedMultiplier;
        const effectiveReticleSpeed = this.options.reticleSpeed * this.speedMultiplier;

        this.angle = (this.angle + effectiveRadarSpeed) % (2 * Math.PI);
        this.reticleAngle = (this.reticleAngle - effectiveReticleSpeed) % (2 * Math.PI);
        this.compassAngle = (this.compassAngle + effectiveReticleSpeed * 1.5) % (2 * Math.PI);

        const pulseSpeed = 0.016 * this.speedMultiplier;
        this.pulsePhase1 = (this.pulsePhase1 + pulseSpeed) % 1.0;
        this.pulsePhase2 = (this.pulsePhase2 + pulseSpeed) % 1.0;

        // 1. Rotating outer reticle tick ring
        if (this.reticleEl) {
          const deg = (this.reticleAngle * 180) / Math.PI;
          this.reticleEl.setAttribute('transform', `rotate(${deg} ${cx} ${cy})`);
        }

        // 2. Counter-rotating inner dashed circle
        if (this.innerRingEl) {
          const degInner = (this.compassAngle * 180) / Math.PI;
          this.innerRingEl.setAttribute('transform', `rotate(${degInner} ${cx} ${cy})`);
        }

        // 3. Sweeping radar beam pie slice
        if (this.sweepEl) {
          const a1 = this.angle - sweepAngleSpan;
          const a2 = this.angle;

          const x0 = cx, y0 = cy;
          const x1 = cx + r1 * Math.cos(a1);
          const y1 = cy + r1 * Math.sin(a1);
          const x2 = cx + r1 * Math.cos(a2);
          const y2 = cy + r1 * Math.sin(a2);

          const largeArc = sweepAngleSpan > Math.PI ? 1 : 0;
          const d = `M ${x0} ${y0} L ${x1} ${y1} A ${r1} ${r1} 0 ${largeArc} 1 ${x2} ${y2} Z`;
          this.sweepEl.setAttribute('d', d);
        }

        // 4. Leading sweep beam line & luminous particle tip
        if (this.leadLine) {
          const lx1 = cx + r0 * Math.cos(this.angle);
          const ly1 = cy + r0 * Math.sin(this.angle);
          const lx2 = cx + r1 * Math.cos(this.angle);
          const ly2 = cy + r1 * Math.sin(this.angle);
          this.leadLine.setAttribute('x1', lx1);
          this.leadLine.setAttribute('y1', ly1);
          this.leadLine.setAttribute('x2', lx2);
          this.leadLine.setAttribute('y2', ly2);

          if (this.leadTip) {
            this.leadTip.setAttribute('cx', lx2);
            this.leadTip.setAttribute('cy', ly2);
          }
        }

        // 5. Dynamic target radar pings
        if (this.targets && this.targets.length) {
          const now = performance.now();
          const currentAng = (this.angle) % (2 * Math.PI);
          this.targets.forEach((tgt) => {
            let diff = (currentAng - tgt.angle + 2 * Math.PI) % (2 * Math.PI);
            if (diff < 0.12 && (now - tgt.lastPing) > 900) {
              tgt.lastPing = now;
              this.triggerTargetPing(tgt);
            }
          });
        }

        // 6. Dual staggered expanding sonar pulse waves
        if (this.pulseRing1) {
          const pr1 = r0 + (r1 - r0) * this.pulsePhase1;
          const pOp1 = Math.max(0, 0.5 * (1 - this.pulsePhase1));
          this.pulseRing1.setAttribute('r', pr1.toFixed(1));
          this.pulseRing1.setAttribute('opacity', pOp1.toFixed(2));
        }

        if (this.pulseRing2) {
          const pr2 = r0 + (r1 - r0) * this.pulsePhase2;
          const pOp2 = Math.max(0, 0.4 * (1 - this.pulsePhase2));
          this.pulseRing2.setAttribute('r', pr2.toFixed(1));
          this.pulseRing2.setAttribute('opacity', pOp2.toFixed(2));
        }

        // 7. Orbiting satellite sensor nodes
        if (this.satGroup) {
          const nodes = this.satGroup.querySelectorAll('.orbit-satellite-node');
          const speeds = [0.009 * this.speedMultiplier, -0.013 * this.speedMultiplier, 0.016 * this.speedMultiplier];
          nodes.forEach((node, idx) => {
            this.satellitesAngle[idx] = (this.satellitesAngle[idx] + speeds[idx]) % (2 * Math.PI);
            const a = this.satellitesAngle[idx];
            const sx = cx + satRadius * Math.cos(a);
            const sy = cy + satRadius * Math.sin(a);
            node.setAttribute('cx', sx.toFixed(1));
            node.setAttribute('cy', sy.toFixed(1));
          });
        }

        this.animId = requestAnimationFrame(animateFrame);
      };

      this.animId = requestAnimationFrame(animateFrame);
    }

    stop() {
      this.isRunning = false;
      if (this.animId) cancelAnimationFrame(this.animId);
    }
  }

  // Export to global scope
  global.Motion = Motion;
  global.CircularRadarReticle = CircularRadarReticle;

})(typeof window !== 'undefined' ? window : this);
