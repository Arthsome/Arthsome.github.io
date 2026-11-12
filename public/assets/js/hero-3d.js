/* hero-3d.js — LIVING FORENSIC EXHIBITION · signature 3D object.
   Real GLB (Grab3D CC0 motherboard, ~39k verts, single mesh) rendered with
   Three.js (GLTFLoader). Studio lighting, soft contact shadow, drag-to-rotate
   with inertia, pointer parallax, and scroll-linked camera approach over a
   210vh sticky hero. Lazy: initializes only when the hero nears viewport.
   Falls back to the poster image (circuit macro frame) if WebGL/GLB/CDN fail.
   Reduced motion / touch: static-ish framing, drag still works, no autoplay. */
(function () {
  "use strict";
  var host = document.querySelector("[data-hero3d]");
  if (!host) return;
  var canvas = host.querySelector("canvas");
  var poster = host.querySelector(".hero3d-poster");
  if (!canvas) return;

  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var fine = window.matchMedia("(pointer: fine)").matches;
  var coarse = !fine;
  var heroEl = host.closest(".hero3d") || host;
  var started = false;

  function start() {
    if (started) return;
    started = true;
    boot().catch(function () { /* poster remains */ });
  }

  if (window.IntersectionObserver) {
    var io = new IntersectionObserver(function (entries) {
      if (entries[0].isIntersecting) { start(); io.disconnect(); }
    }, { rootMargin: "60% 0px" });
    io.observe(host);
  } else { start(); }

  async function boot() {
    var THREE, GLTFLoader;
    try {
      THREE = await import("three");
      var mod = await import("three/addons/loaders/GLTFLoader.js");
      GLTFLoader = mod.GLTFLoader;
    } catch (e) { return; }

    var glTest = document.createElement("canvas").getContext("webgl2") ||
                 document.createElement("canvas").getContext("webgl");
    if (!glTest) return;

    var renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, coarse ? 1.5 : 2));
    renderer.shadowMap.enabled = true;
    renderer.shadowMap.type = THREE.PCFSoftShadowMap;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.outputColorSpace = THREE.SRGBColorSpace;

    var scene = new THREE.Scene();
    var camera = new THREE.PerspectiveCamera(38, 1, 0.1, 100);
    camera.position.set(0, 1.4, 10);

    // Studio lighting — warm key + cool fill + acid rim (no neon)
    scene.add(new THREE.HemisphereLight(0xffffff, 0xdfe4cd, 0.9));
    var key = new THREE.DirectionalLight(0xffffff, 2.4);
    key.position.set(4, 7, 5);
    key.castShadow = true;
    key.shadow.mapSize.set(1024, 1024);
    key.shadow.camera.left = -6; key.shadow.camera.right = 6;
    key.shadow.camera.top = 6; key.shadow.camera.bottom = -6;
    key.shadow.radius = 6;
    scene.add(key);
    var fill = new THREE.DirectionalLight(0xeef2e2, 0.6);
    fill.position.set(-5, 2, -3);
    scene.add(fill);
    var rim = new THREE.DirectionalLight(0xc4f544, 0.5);
    rim.position.set(0, 3, -6);
    scene.add(rim);

    // Soft contact shadow
    var ground = new THREE.Mesh(
      new THREE.PlaneGeometry(30, 30),
      new THREE.ShadowMaterial({ opacity: 0.2 })
    );
    ground.rotation.x = -Math.PI / 2;
    ground.position.y = -1.55;
    ground.receiveShadow = true;
    scene.add(ground);

    var loader = new GLTFLoader();
    var gltf;
    try {
      gltf = await loader.loadAsync("assets/models/motherboard.glb");
    } catch (e) { return; }
    var model = gltf.scene;

    // Center + scale from bounding box (node structure: single mesh)
    var bbox = new THREE.Box3().setFromObject(model);
    var size = bbox.getSize(new THREE.Vector3());
    var center = bbox.getCenter(new THREE.Vector3());
    model.position.sub(center);
    var fit = 5.4 / Math.max(size.x, size.y, size.z);
    model.scale.setScalar(fit);
    var group = new THREE.Group();
    model.traverse(function (o) { if (o.isMesh) { o.castShadow = true; o.receiveShadow = true; } });
    group.add(model);
    scene.add(group);
    group.rotation.x = -0.18;

    canvas.style.opacity = "1";
    if (poster) poster.style.opacity = "0";

    var dragging = false, vel = { y: 0, x: 0 };
    var rot = { y: -0.5, x: -0.18 };
    var target = { y: -0.5, x: -0.18 };
    var px = { x: 0, y: 0 }, pxt = { x: 0, y: 0 };
    var last = { x: 0, y: 0 };
    var visible = true;

    function onDown(e) {
      dragging = true;
      last.x = e.clientX; last.y = e.clientY;
      vel.y = 0; vel.x = 0;
      canvas.setPointerCapture && canvas.setPointerCapture(e.pointerId);
    }
    function onMove(e) {
      if (dragging) {
        var dx = e.clientX - last.x, dy = e.clientY - last.y;
        last.x = e.clientX; last.y = e.clientY;
        vel.y = dx * 0.008; vel.x = dy * 0.006;
        target.y += vel.y;
        target.x = Math.max(-0.9, Math.min(0.7, target.x + vel.x));
      } else if (fine) {
        pxt.x = (e.clientX / (window.innerWidth || 1) - 0.5);
        pxt.y = (e.clientY / (window.innerHeight || 1) - 0.5);
      }
    }
    function onUp() { dragging = false; }
    canvas.addEventListener("pointerdown", onDown);
    window.addEventListener("pointermove", onMove, { passive: true });
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", onUp);

    // frame the object right-of-center on wide screens, centered on portrait
    function frameOffset() {
      var aspect = host.clientWidth / Math.max(host.clientHeight, 1);
      group.position.x = aspect > 1.15 ? 1.9 : 0;
    }
    frameOffset();
    function resize() {
      var w = host.clientWidth, h = host.clientHeight;
      if (!w || !h) return;
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
    }
    if (window.ResizeObserver) new ResizeObserver(function () { resize(); frameOffset(); }).observe(host);
    resize();

    if (window.IntersectionObserver) {
      new IntersectionObserver(function (entries) { visible = entries[0].isIntersecting; }, { threshold: 0.02 }).observe(heroEl);
    }

    var t0 = performance.now();
    function frame(now) {
      requestAnimationFrame(frame);
      if (!visible) return;
      var t = (now - t0) / 1000;
      if (!dragging) {
        target.y += vel.y * 0.94; vel.y *= 0.94;
        target.x = Math.max(-0.9, Math.min(0.7, target.x + vel.x * 0.94)); vel.x *= 0.94;
      }
      // scroll progress through sticky hero
      var vh = window.innerHeight || 1;
      var total = heroEl.offsetHeight - vh;
      var p = reduce ? 0 : Math.max(0, Math.min(1, (window.pageYOffset - heroEl.offsetTop) / Math.max(total, 1)));
      var idleRot = reduce ? 0 : t * 0.12;
      group.rotation.y = target.y + idleRot + p * 1.1;
      group.rotation.x = target.x - p * 0.12;
      group.position.y = reduce ? 0 : Math.sin(t * 0.8) * 0.12 + (1 - p) * 0;
      px.x += (pxt.x - px.x) * 0.05;
      px.y += (pxt.y - px.y) * 0.05;
      camera.position.z = 10 - p * 3.4;
      camera.position.x = px.x * 1.6;
      camera.position.y = 1.4 - px.y * 0.9 + p * 0.6;
      camera.lookAt(0, -0.2 + p * 0.2, 0);
      // annotations yield as the camera approaches
      host.classList.toggle("approached", p > 0.55);
      renderer.render(scene, camera);
    }
    requestAnimationFrame(frame);
  }
})();
