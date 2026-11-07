/* Interactive liquid-glass folder dock — Arthsome
   Pointer-proximity magnification (transform only, stable hit areas),
   shared glass bubble, touch/tap navigation. No layout measurement loops.
*/
(function(){
  "use strict";
  var dock = document.querySelector(".dock");
  if (!dock) return;
  var items = Array.prototype.slice.call(dock.querySelectorAll(".dock-item"));
  if (!items.length) return;
  var bubble = document.getElementById("dockBubble");
  var fine = window.matchMedia("(pointer: fine)").matches;
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function setMag(activeEl, pointerX){
    if (!fine || reduce) return;
    var rects = items.map(function(el){ return el.getBoundingClientRect(); });
    items.forEach(function(el, i){
      var r = rects[i];
      var cx = r.left + r.width / 2, cy = r.top + r.height / 2;
      var dist = Math.hypot(cx - pointerX.x, cy - pointerX.y);
      var fall = Math.exp(-(dist * dist) / (2 * 120 * 120));
      var s = 0.94 + fall * 0.28; // 0.94 rest → ~1.22 peak
      if (el === activeEl) s = Math.max(s, 1.18);
      el.style.setProperty("--s", s.toFixed(3));
    });
  }
  function resetMag(){ items.forEach(function(el){ el.style.setProperty("--s", "1"); }); }
  function syncBubble(el){
    if (!bubble) return;
    var name = el.getAttribute("data-name"), desc = el.getAttribute("data-desc"), idx = el.getAttribute("data-idx");
    bubble.querySelector(".db-idx").textContent = idx;
    bubble.querySelector(".db-name").textContent = name;
    bubble.querySelector(".db-desc").textContent = desc;
    bubble.classList.add("show"); bubble.hidden = false;
  }

  items.forEach(function(el){
    el.addEventListener("pointermove", function(e){
      if (e.pointerType === "touch" || e.pointerType === "pen") return;
      setMag(el, {x: e.clientX, y: e.clientY});
      syncBubble(el);
      items.forEach(function(x){ x.classList.toggle("active", x === el); });
    }, { passive: true });
    el.addEventListener("pointerleave", function(){
      el.classList.remove("active"); resetMag();
      if (bubble){ bubble.classList.remove("show"); bubble.hidden = true; }
    });
    el.addEventListener("focus", function(){ resetMag(); el.classList.add("active"); syncBubble(el); el.style.setProperty("--s", "1.18"); });
    el.addEventListener("blur", function(){ el.classList.remove("active"); resetMag(); if (bubble){ bubble.classList.remove("show"); bubble.hidden = true; } });
    el.addEventListener("touchstart", function(){
      el.classList.add("active"); el.style.setProperty("--s", "1.16");
      syncBubble(el);
    }, { passive: true });
  });

  // View Transition handoff (same-origin; skip modified clicks)
  document.addEventListener("click", function(e){
    var a = e.target.closest && e.target.closest(".dock-item");
    if (!a) return;
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button === 1) return;
    if (reduce || !document.startViewTransition) return;
    var href = a.getAttribute("href"); if (!href || href[0] === "#") return;
    e.preventDefault(); a.classList.add("active"); syncBubble(a);
    setTimeout(function(){
      try { document.startViewTransition(function(){ window.location.href = href; }); }
      catch(err){ window.location.href = href; }
    }, 140);
  }, { capture: true });
})();
