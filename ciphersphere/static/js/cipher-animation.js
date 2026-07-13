(() => {
  "use strict";

  const canvas = document.querySelector("[data-cipher-animation]");
  if (!(canvas instanceof HTMLCanvasElement)) return;

  const context = canvas.getContext("2d", { alpha: true });
  if (!context) return;

  const root = document.documentElement;
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
  const compactViewport = window.matchMedia("(max-width: 700px)");
  const particles = [];
  let width = 1;
  let height = 1;
  let scale = 1;
  let frame = 0;
  let lastFrame = 0;
  let shape = 0;
  let shapeChangedAt = 0;
  let needsStaticFrame = true;

  const isTokenTheme = () => root.dataset.appearance === "cipher-noir";
  const effectsPaused = () => root.classList.contains("effects-paused");
  const mayAnimate = () => isTokenTheme() && !effectsPaused() && !reducedMotion.matches && !document.hidden;

  const particleCount = () => compactViewport.matches ? 150 : 280;

  const resetParticles = () => {
    const count = particleCount();
    particles.length = 0;
    for (let index = 0; index < count; index += 1) {
      particles.push({
        x: width * (0.35 + Math.random() * 0.3),
        y: height * (0.35 + Math.random() * 0.3),
        alpha: 0.2 + Math.random() * 0.8,
        size: 0.55 + Math.random() * 1.25,
        seed: Math.random() * Math.PI * 2,
      });
    }
    needsStaticFrame = true;
  };

  const resize = () => {
    const bounds = canvas.getBoundingClientRect();
    scale = Math.min(window.devicePixelRatio || 1, 1.6);
    width = Math.max(1, Math.round(bounds.width));
    height = Math.max(1, Math.round(bounds.height));
    canvas.width = Math.round(width * scale);
    canvas.height = Math.round(height * scale);
    context.setTransform(scale, 0, 0, scale, 0, 0);
    resetParticles();
    draw(performance.now(), true);
  };

  const sphereTarget = (index, time) => {
    const count = particles.length;
    const golden = Math.PI * (3 - Math.sqrt(5));
    const y3 = 1 - ((index + 0.5) / count) * 2;
    const ring = Math.sqrt(Math.max(0, 1 - y3 * y3));
    const theta = index * golden + time * 0.00016;
    const x3 = Math.cos(theta) * ring;
    const z3 = Math.sin(theta) * ring;
    const radius = Math.min(width, height) * 0.32;
    const perspective = 0.78 + (z3 + 1) * 0.12;
    return {
      x: width * 0.5 + x3 * radius * perspective,
      y: height * 0.5 + y3 * radius,
      depth: (z3 + 1) * 0.5,
    };
  };

  const circuitTarget = (index, time) => {
    const branches = compactViewport.matches ? 18 : 26;
    const branch = index % branches;
    const step = Math.floor(index / branches);
    const steps = Math.ceil(particles.length / branches);
    const progress = (step + 1) / (steps + 1);
    const baseAngle = (branch / branches) * Math.PI * 2;
    const elbow = ((step % 3) - 1) * 0.055;
    const pulse = Math.sin(time * 0.0008 + branch * 0.7) * 3;
    const radius = Math.min(width, height) * (0.08 + progress * 0.37) + pulse;
    return {
      x: width * 0.5 + Math.cos(baseAngle + elbow) * radius,
      y: height * 0.5 + Math.sin(baseAngle + elbow) * radius,
      depth: 0.35 + progress * 0.65,
    };
  };

  const latticeTarget = (index, time) => {
    const bands = 7;
    const band = index % bands;
    const position = Math.floor(index / bands) / Math.ceil(particles.length / bands);
    const angle = position * Math.PI * 2 + time * (0.00008 + band * 0.000009);
    const radius = Math.min(width, height) * (0.1 + band * 0.038);
    const wave = Math.sin(angle * 3 + band) * 10;
    return {
      x: width * 0.5 + Math.cos(angle) * (radius + wave),
      y: height * 0.5 + Math.sin(angle) * radius * 0.72,
      depth: 0.38 + band / bands * 0.62,
    };
  };

  const targetFor = (index, time) => {
    if (shape === 1) return circuitTarget(index, time);
    if (shape === 2) return latticeTarget(index, time);
    return sphereTarget(index, time);
  };

  const drawConnections = (color) => {
    context.strokeStyle = color;
    context.lineWidth = 0.55;
    for (let index = 0; index < particles.length; index += 4) {
      const particle = particles[index];
      for (let offset = 1; offset <= 4; offset += 1) {
        const other = particles[(index + offset) % particles.length];
        const distance = Math.hypot(particle.x - other.x, particle.y - other.y);
        if (distance > 38) continue;
        context.globalAlpha = Math.max(0, 0.11 - distance / 420);
        context.beginPath();
        context.moveTo(particle.x, particle.y);
        context.lineTo(other.x, other.y);
        context.stroke();
      }
    }
  };

  const draw = (time, staticOnly = false) => {
    context.clearRect(0, 0, width, height);
    const styles = getComputedStyle(root);
    const particleColor = styles.getPropertyValue("--particle-color").trim() || "rgb(225 228 226)";
    const signalColor = styles.getPropertyValue("--signal-color").trim() || "rgb(246 202 47)";
    const easing = staticOnly ? 1 : 0.055;

    particles.forEach((particle, index) => {
      const target = targetFor(index, time);
      particle.x += (target.x - particle.x) * easing;
      particle.y += (target.y - particle.y) * easing;
      const signal = index % 31 === 0;
      context.fillStyle = signal ? signalColor : particleColor;
      context.globalAlpha = Math.min(1, particle.alpha * (0.38 + target.depth * 0.72));
      context.beginPath();
      context.arc(particle.x, particle.y, particle.size * (0.65 + target.depth * 0.55), 0, Math.PI * 2);
      context.fill();
    });

    drawConnections(particleColor);
    context.globalAlpha = 1;
    needsStaticFrame = false;
  };

  const stop = () => {
    if (frame) window.cancelAnimationFrame(frame);
    frame = 0;
  };

  const tick = (time) => {
    if (!mayAnimate()) {
      stop();
      if (needsStaticFrame && isTokenTheme()) draw(time, true);
      return;
    }
    if (!shapeChangedAt) shapeChangedAt = time;
    if (time - shapeChangedAt > 6000) {
      shape = (shape + 1) % 3;
      shapeChangedAt = time;
    }
    if (time - lastFrame >= 32) {
      draw(time);
      lastFrame = time;
    }
    frame = window.requestAnimationFrame(tick);
  };

  const sync = () => {
    stop();
    needsStaticFrame = true;
    if (isTokenTheme()) {
      draw(performance.now(), !mayAnimate());
      if (mayAnimate()) frame = window.requestAnimationFrame(tick);
    } else {
      context.clearRect(0, 0, width, height);
    }
  };

  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(canvas);
  compactViewport.addEventListener?.("change", resize);
  reducedMotion.addEventListener?.("change", sync);
  document.addEventListener("visibilitychange", sync);
  window.addEventListener("ciphersphere:effects", sync);
  new MutationObserver(sync).observe(root, { attributes: true, attributeFilter: ["data-appearance", "class"] });
  resize();
  sync();
})();
