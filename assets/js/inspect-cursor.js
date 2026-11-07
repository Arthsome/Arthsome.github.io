/* P3 — Custom INSPECT cursor for research preview surfaces (pointer:fine only).
   Shows dot + trailing ring + contextual INSPECT label over .featured,
   .post-card and .dock-item; native cursor hidden only while hovering. */
(function () {
  "use strict";
  var fine = window.matchMedia("(pointer: fine)").matches;
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (!fine || reduce) return;

  var body = document.body;
  body.classList.add("inspector");

  var dot = document.createElement("div");
  dot.className = "inspector-dot";
  var ring = document.createElement("div");
  ring.className = "inspector-ring";
  var label = document.createElement("div");
  label.className = "inspector-label";
  label.textContent = "Inspect";
  body.appendChild(dot);
  document.body.appendChild(ring);
  document.body.appendChild(label);

  var pos = { x: -100, y: -100 };
  var ringPos = { x: -100, y: -100 };
  var hovering = false;
  var raf = null;

  function loop() {
    ringPos.x += (pos.x - ringPos.x) * 0.16;
    ringPos.y += (pos.y - ringPos.y) * 0.16;
    dot.style.transform = "translate3d(" + (pos.x - 3) + "px," + (pos.y - 3) + "px,0) translate(-50%,-50%)";
    ring.style.transform = "translate3d(" + (ringPos.x - 11) + "px," + (ringPos.y - 11) + "px,0) translate(-50%,-50%)";
    label.style.transform = "translate3d(" + pos.x + "px," + (pos.y - 18) + "px,0) translate(-50%, -50%)";
    raf = requestAnimationFrame(loop);
  }
  loop();

  function show(txt) {
    if (label.textContent !== txt) label.textContent = txt;
    label.classList.add("on");
    dot.classList.add("on");
    ring.classList.add("on");
  }
  function hide() {
    label.classList.remove("on");
    dot.classList.remove("on");
    ring.classList.remove("on");
  }

  function labelFor(hit) {
    if (hit.classList && hit.classList.contains("dock-item")) {
      var nm = hit.getAttribute("data-name");
      return nm ? String(nm).toUpperCase() : "Inspect";
    }
    if (hit.classList && hit.classList.contains("featured")) return "Featured";
    var idx = hit.querySelector(".post-card-idx");
    if (idx) { var t = String(idx.textContent || "").trim(); if (t) return t; }
    return "Inspect";
  }

  function resolve(e) {
    var t = e.target;
    while (t) {
      if (t.closest) {
        var hit = t.closest(".post-card, .featured, .dock-item");
        if (hit) return hit;
      }
      t = t.parentNode;
    }
    return null;
  }

  document.addEventListener("mousemove", function (e) { pos = { x: e.clientX, y: e.clientY }; }, { passive: true });
  document.addEventListener("mouseover", function (e) {
    var hit = resolve(e);
    if (hit) {
      hovering = true;
      body.classList.add("inspector-hover");
      show(labelFor(hit));
    } else {
      hovering = false;
      body.classList.remove("inspector-hover");
      hide();
    }
  }, { passive: true });
  document.addEventListener("mouseout", function (e) {
    if (!hovering) return;
    var rt = e.relatedTarget;
    var still = false;
    var t = rt;
    while (t) {
      if (t.closest) { if (t.closest(".post-card, .featured, .dock-item")) { still = true; break; } }
      t = t.parentNode;
    }
    if (!still) {
      hovering = false;
      body.classList.remove("inspector-hover");
      hide();
    }
  }, { passive: true });
  document.addEventListener("mouseleave", function () { hovering = false; body.classList.remove("inspector-hover"); hide(); }, { passive: true });
  window.addEventListener("blur", hide);

  window.addEventListener("pagehide", function () {
    hovering = false;
    body.classList.remove("inspector-hover");
    hide();
  });
})();
