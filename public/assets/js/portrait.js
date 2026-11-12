/* Particle portrait — image-driven halftone (Arthsome)
   Source-independent: sample the source image on an offscreen canvas and
   place one particle per sampled cell. Replacing the source file (crystal
   today, real portrait later) requires no logic change.
   Uses Pointer Events, ResizeObserver, IntersectionObserver lifecycle,
   and prefers-reduced-motion. Falls back to a static <img> on any failure.
*/
(function(){
  "use strict";
  var frame = document.getElementById("portraitFrame");
  var canvas = document.getElementById("portraitCanvas");
  if (!frame || !canvas) return;
  var ctx = canvas.getContext("2d", { alpha: false });

  var CONFIG = {
    portraitSource: frame.getAttribute("data-portrait") || "assets/img/portrait/crystal.png",
    density: 3,          // sample grid step in source pixels (lower = denser)
    contrastThreshold: 0.52,
    focalX: 0.5, focalY: 0.42,
    minSize: 0.7, maxSize: 2.6,
    radius: 90,          // pointer influence radius (CSS px)
    scatter: 26,         // max displacement (px) at high velocity
    recovery: 0.08,      // spring back per frame
    ambientDrift: 0.25
  };

  var img = new Image();
  img.crossOrigin = "anonymous";
  var particles = [], W = 0, H = 0, dpr = 1;
  var pointer = { x: -9999, y: -9999, vx: 0, vy: 0, active: false, lastT: 0 };
  var raf = 0, visible = true, running = false, reduce = false;

  function staticFallback(){
    canvas.style.display = "none";
    var f = frame.querySelector(".portrait-fallback");
    if (f) f.style.display = "block";
    else { var i = document.createElement("img"); i.src = CONFIG.portraitSource; i.className = "portrait-fallback"; i.alt = "Arthsome crystal — static fallback"; frame.appendChild(i); }
  }
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) { staticFallback(); return; }

  function sample(){
    // draw source scaled to sample grid (contain, focal preserved)
    var sw = Math.ceil(W / 3), sh = Math.ceil(H / 3);
    var off = document.createElement("canvas"); off.width = sw; off.height = sh;
    var octx = off.getContext("2d", { willReadFrequently: true });
    // contain-fit source into sw x sh around focal point
    var s = Math.min(sw / img.width, sh / img.height);
    var dw = img.width * s, dh = img.height * s;
    var dx = (sw - dw) * CONFIG.focalX, dy = (sh - dh) * CONFIG.focalY;
    octx.drawImage(img, dx, dy, dw, dh);
    var data;
    try { data = octx.getImageData(0, 0, sw, sh).data; } catch(e){ staticFallback(); return; }
    particles = [];
    var step = Math.max(1, Math.round(CONFIG.density * (Math.min(W, H) / 420)));
    for (var sy = 0; sy < sh; sy += step) {
      for (var sx = 0; sx < sw; sx += step) {
        var i = (sy * sw + sx) * 4;
        var r = data[i], g = data[i+1], b = data[i+2], a = data[i+3];
        if (a < 40) continue;
        var lum = (0.299*r + 0.587*g + 0.114*b) / 255;
        // halftone: darkness -> particle alpha/size (dark areas dense)
        var dark = 1 - lum;
        var strength = Math.max(dark, 0.12);
        if (lum > 0.92 && dark < 0.06) continue; // paper stays empty
        var x = sx / sw * W, y = sy / sh * H;
        var size = CONFIG.minSize + strength * (CONFIG.maxSize - CONFIG.minSize);
        particles.push({ hx: x, hy: y, x: x, y: y, vx: 0, vy: 0, s: size, a: Math.min(1, 0.25 + strength), seed: Math.random() * 6.28 });
      }
    }
    if (!particles.length) staticFallback();
  }

  function resize(){
    var rect = frame.getBoundingClientRect();
    W = Math.max(160, rect.width); H = Math.max(200, rect.height);
    dpr = Math.min(window.devicePixelRatio || 1, 1.75);
    canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
    canvas.style.width = W + "px"; canvas.style.height = H + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, W, H);
    if (img.complete && img.naturalWidth) sample();
  }

  function setPointer(cx, cy){
    var rect = canvas.getBoundingClientRect();
    var x = cx - rect.left, y = cy - rect.top;
    var now = performance.now();
    var dt = Math.max(8, now - (pointer.lastT || now));
    pointer.vx = (x - pointer.x) / dt; pointer.vy = (y - pointer.y) / dt;
    pointer.x = x; pointer.y = y; pointer.active = true; pointer.lastT = now;
  }

  function tick(t){
    raf = requestAnimationFrame(tick);
    if (!visible || document.hidden) return;
    ctx.fillStyle = "#ffffff"; ctx.fillRect(0, 0, W, H);
    var speed = Math.min(2.4, Math.hypot(pointer.vx, pointer.vy) * 1.6);
    pointer.vx *= 0.88; pointer.vy *= 0.88;
    if (!pointer.active && speed < 0.02) pointer.x = -9999;
    for (var k = 0; k < particles.length; k++) {
      var p = particles[k];
      var dx = p.x - pointer.x, dy = p.y - pointer.y;
      var dist = Math.hypot(dx, dy);
      if (dist < CONFIG.radius && dist > 0.01) {
        var fall = 1 - dist / CONFIG.radius;
        var fx = (dx / dist) * fall * (2 + speed * CONFIG.scatter * fall * 0.4);
        var fy = (dy / dist) * fall * (2 + speed * CONFIG.scatter * fall * 0.4);
        p.vx += fx * 0.35; p.vy += fy * 0.35;
      }
      // spring home + ambient drift
      p.vx += (p.hx - p.x) * CONFIG.recovery;
      p.vy += (p.hy - p.y) * CONFIG.recovery;
      p.vx += Math.sin(t / 1600 + p.seed) * CONFIG.ambientDrift * 0.08;
      p.vy += Math.cos(t / 1800 + p.seed) * CONFIG.ambientDrift * 0.08;
      p.vx *= 0.86; p.vy *= 0.86;
      p.x += p.vx; p.y += p.vy;
      var off = Math.hypot(p.vx, p.vy);
      ctx.fillStyle = off > 0.6 ? "#2f4d0c" : "#141714";
      ctx.globalAlpha = p.a;
      ctx.beginPath(); ctx.arc(p.x, p.y, p.s + Math.min(0.6, off * 0.12), 0, 6.29); ctx.fill();
    }
    ctx.globalAlpha = 1;
  }

  // Pointer Events: buttons=0 drag/tap only, vertical scroll preserved
  frame.addEventListener("pointermove", function(e){
    if (e.pointerType === "touch" && Math.abs(e.movementY||0) > Math.abs(e.movementX||0)) return;
    setPointer(e.clientX, e.clientY);
  }, { passive: true });
  frame.addEventListener("pointerdown", function(e){ setPointer(e.clientX, e.clientY); });
  frame.addEventListener("pointerleave", function(){ pointer.active = false; });
  frame.setAttribute("touch-action", "pan-y");

  // Lifecycle: only render when on screen; resize via observer
  if ("IntersectionObserver" in window) {
    var io = new IntersectionObserver(function(es){ es.forEach(function(e){
      visible = e.isIntersecting;
      if (visible && !running) { running = true; raf = requestAnimationFrame(tick); }
      if (!visible && running) { running = false; cancelAnimationFrame(raf); }
    }); }, { threshold: 0.05 });
    io.observe(frame);
  } else { running = true; raf = requestAnimationFrame(tick); }
  if (window.ResizeObserver) new ResizeObserver(resize).observe(frame);
  window.addEventListener("resize", resize);

  img.onload = function(){ resize(); if (!running) { running = true; raf = requestAnimationFrame(tick); } };
  img.onerror = staticFallback;
  img.src = CONFIG.portraitSource;
  resize();
})();
