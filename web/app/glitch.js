// CipherChat by DarkCipher Systems: the "connect glitch". When a call's video starts, the picture tears in (RGB channel
// split, displaced bands, scanlines and noise) and settles, then the encryption line types in under it.
//
// It draws on a canvas laid over the <video> for under a second and then removes itself, so the live picture is never
// touched or delayed. Only frames already on this device are drawn; nothing leaves it. People whose system asks for
// reduced motion get a short fade instead. No inline styles or scripts (the portal's CSP), no libraries.

const DURATION = 900;            // ms of glitch before the picture settles
const SUFFIX = " · encrypted";

function reduced() {
  return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

// Deterministic jitter per frame, so the effect looks chaotic without Math.random's cost in a hot loop
function rng(seed) {
  let s = seed >>> 0 || 1;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 4294967296);
}

function typeIn(el, text) {
  let i = 0;
  const glyphs = "▓▒░<>/\\_-=+*#";
  const tick = () => {
    i += 1;
    const tail = i < text.length ? glyphs[i % glyphs.length] : "";
    el.textContent = text.slice(0, i) + tail;
    if (i < text.length) setTimeout(tick, 28);
  };
  tick();
}

/** The off-screen canvases paint() works in (made once per glitch, reused every frame). */
export function makeLayers() {
  const layer = () => { const c = document.createElement("canvas"); return { c, x: c.getContext("2d") }; };
  return { frame: layer(), red: layer(), cyan: layer() };
}

/**
 * One moment of the effect on ctx (w × h): t runs 0 → 1, `now` seeds the jitter. `source` is the video (or any image
 * source), cropped like object-fit: cover so the hand-over to the live picture doesn't jump; null = still waiting.
 */
export function paint(ctx, layers, source, w, h, t, now) {
  for (const l of Object.values(layers)) if (l.c.width !== w || l.c.height !== h) { l.c.width = w; l.c.height = h; }
  const power = (1 - t) * (1 - t);                 // strong at first, easing out
  const r = rng((now | 0) ^ 0x9e3779b9);
  ctx.clearRect(0, 0, w, h);
  if (source) {
    const sw = source.videoWidth || source.width, sh = source.videoHeight || source.height;
    const scale = Math.max(w / sw, h / sh), cw = w / scale, ch = h / scale;
    layers.frame.x.drawImage(source, (sw - cw) / 2, (sh - ch) / 2, cw, ch, 0, 0, w, h);
    for (const [l, colour] of [[layers.red, "#ff0000"], [layers.cyan, "#00ffff"]]) {
      l.x.globalCompositeOperation = "source-over";
      l.x.drawImage(layers.frame.c, 0, 0);
      l.x.globalCompositeOperation = "multiply";
      l.x.fillStyle = colour;
      l.x.fillRect(0, 0, w, h);
    }
    // red and cyan (green + blue) pulled apart; added back together they are exactly the picture
    const split = Math.round(14 * power) + 1;
    ctx.drawImage(layers.cyan.c, -split, 0);
    ctx.globalCompositeOperation = "lighter";
    ctx.drawImage(layers.red.c, split, 0);
    ctx.globalCompositeOperation = "source-over";
    // horizontal bands torn sideways
    const bands = Math.round(10 * power) + 1;
    for (let i = 0; i < bands; i++) {
      const y = r() * h, bh = 4 + r() * 38 * power, dx = (r() - 0.5) * 120 * power;
      ctx.drawImage(layers.frame.c, 0, y, w, bh, dx, y, w, bh);
    }
  } else {
    ctx.fillStyle = "#050909";
    ctx.fillRect(0, 0, w, h);
  }
  // teal scanlines and a little noise on top
  ctx.fillStyle = "rgba(54, 210, 203, " + (0.10 + 0.25 * power) + ")";
  for (let y = (now / 12) % 4; y < h; y += 4) ctx.fillRect(0, y, w, 1);
  ctx.fillStyle = "rgba(255, 255, 255, " + 0.35 * power + ")";
  for (let i = 0; i < 160 * power; i++) ctx.fillRect(r() * w, r() * h, 2, 1);
}

/**
 * Plays the connect glitch over `video` (which must sit in a positioned container, e.g. .call-tile).
 * `label` is the line typed in afterwards, e.g. "ML-KEM-1024". Resolves when it's finished.
 */
export function glitchIn(video, label = "ML-KEM-1024") {
  const tile = video.parentElement;
  const caption = document.createElement("div");
  caption.className = "glitch-caption";
  tile.append(caption);

  if (reduced()) {
    tile.classList.add("glitch-fade");
    typeIn(caption, label + SUFFIX);
    return new Promise((done) => setTimeout(() => { tile.classList.remove("glitch-fade"); done(); }, 400));
  }

  const canvas = document.createElement("canvas");
  canvas.className = "glitch-canvas";
  tile.append(canvas);
  tile.classList.add("glitching");
  const ctx = canvas.getContext("2d", { alpha: true });
  const layers = makeLayers();
  const start = performance.now();

  return new Promise((done) => {
    const frame = (now) => {
      const t = Math.min(1, (now - start) / DURATION);
      const w = tile.clientWidth, h = tile.clientHeight;
      if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; }
      paint(ctx, layers, video.readyState >= 2 ? video : null, w, h, t, now);
      canvas.style.opacity = String(t < 0.85 ? 1 : (1 - t) / 0.15);

      if (t < 1) return requestAnimationFrame(frame);
      canvas.remove();
      tile.classList.remove("glitching");
      typeIn(caption, label + SUFFIX);
      done();
    };
    requestAnimationFrame(frame);
  });
}
