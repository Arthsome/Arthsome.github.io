/* Folder dock — centralized pointer tracking + anchored bubble + tap states */
(function(){
  "use strict";
  var rail = document.querySelector(".dock-rail");
  var bubble = document.getElementById("dockBubble");
  if (!rail) return;
  var items = Array.prototype.slice.call(rail.querySelectorAll(".dock-item"));
  var fine = window.matchMedia("(pointer: fine)").matches;
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var active = null, navigating = false;

  function magAt(x, y){
    if (!fine || reduce) return;
    var rects = items.map(function(el){ return el.getBoundingClientRect(); });
    items.forEach(function(el, i){
      var r = rects[i];
      var cx = r.left + r.width/2, cy = r.top + r.height/2;
      var d = Math.hypot(cx - x, cy - y);
      var fall = Math.exp(-(d*d)/(2*110*110));
      var s = 0.90 + fall * 0.34;
      if (el === active) s = Math.max(s, 1.22);
      el.style.setProperty("--s", s.toFixed(3));
    });
  }
  function resetMag(){ items.forEach(function(el){ el.style.setProperty("--s","1"); }); }
  function anchorBubble(el){
    if (!bubble) return;
    var name = el.getAttribute("data-name"), desc = el.getAttribute("data-desc"), idx = el.getAttribute("data-idx");
    bubble.querySelector(".db-idx").textContent = idx;
    bubble.querySelector(".db-name").textContent = name;
    bubble.querySelector(".db-desc").textContent = desc;
    bubble.hidden = false;
    var dockEl = dockElOf();
    var ir = el.getBoundingClientRect(), dr = dockEl.getBoundingClientRect();
    var left = ir.left - dr.left + ir.width/2 - bubble.offsetWidth/2;
    left = Math.max(0, Math.min(left, dr.width - bubble.offsetWidth));
    bubble.style.left = left + "px";
    bubble.style.bottom = "calc(100% + 10px)";
    bubble.classList.add("show");
  }
  function dockElOf(){ return rail.closest(".dock") || rail; }
  function hideBubble(){ if (bubble){ bubble.classList.remove("show"); bubble.hidden = true; } }
  function setActive(el){
    active = el;
    items.forEach(function(x){ x.classList.toggle("active", x === el); });
    anchorBubble(el);
  }
  function clearAll(){ active = null; items.forEach(function(x){ x.classList.remove("active"); }); resetMag(); hideBubble(); }

  // Centralized tracking on the rail: no per-item leave flicker
  rail.addEventListener("pointermove", function(e){
    if (e.pointerType === "touch" || e.pointerType === "pen") return;
    var t = e.target.closest ? e.target.closest(".dock-item") : null;
    if (t && items.indexOf(t) !== -1) { setActive(t); }
    magAt(e.clientX, e.clientY);
  }, { passive: true });
  rail.addEventListener("pointerleave", clearAll);
  items.forEach(function(el){
    el.addEventListener("focus", function(){ resetMag(); el.classList.add("active"); setActive(el); el.style.setProperty("--s","1.22"); });
    el.addEventListener("blur", function(){ el.classList.remove("active"); resetMag(); if (active === el){ active = null; hideBubble(); } });
  });

  // Mobile tap choreography: pressed → opening → navigating (single tap, no second tap)
  if (!fine) {
    items.forEach(function(el){
      el.addEventListener("touchstart", function(){ el.dataset.state = "pressed"; if (reduce) return; el.style.setProperty("--s","1.16"); setActive(el); }, { passive: true });
    });
  }

  document.addEventListener("click", function(e){
    var a = e.target.closest ? e.target.closest(".dock-item") : null;
    if (!a || navigating) return;
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button === 1) return;
    var href = a.getAttribute("href"); if (!href || href[0] === "#") return;
    a.dataset.state = "opening";
    setActive(a);
    if (reduce || !document.startViewTransition) return; // let anchor work directly
    e.preventDefault(); navigating = true; a.dataset.state = "navigating";
    setTimeout(function(){
      try { document.startViewTransition(function(){ window.location.href = href; }); }
      catch(err){ window.location.href = href; }
    }, 150);
  }, { capture: true });
})();
