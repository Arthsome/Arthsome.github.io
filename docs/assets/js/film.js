/* film.js — pause offscreen footage; never hijack playback state otherwise. */
(function () {
  "use strict";
  var videos = document.querySelectorAll("[data-film]");
  if (!videos.length) return;
  if (!("IntersectionObserver" in window)) {
    videos.forEach(function (v) { v.play().catch(function () {}); });
    return;
  }
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (en) {
      var v = en.target;
      if (en.isIntersecting) { v.play().catch(function () {}); }
      else { v.pause(); }
    });
  }, { threshold: 0.08 });
  videos.forEach(function (v) { io.observe(v); });
})();
