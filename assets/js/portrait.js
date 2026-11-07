/* Particle portrait distortion — Arthsome (Three.js, local canvas, capped DPR) */
(function(){
  "use strict";
  var canvas = document.getElementById("portraitCanvas");
  var frame = document.getElementById("portraitFrame");
  if (!canvas || !frame) return;
  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var imgSrc = frame.getAttribute("data-portrait") || "assets/img/portrait/portrait.svg";

  function staticFallback(){
    canvas.style.display = "none";
    var img = document.createElement("img");
    img.src = imgSrc; img.alt = "Arthsome — monochrome halftone portrait";
    img.className = "portrait-fallback";
    frame.appendChild(img);
  }
  if (reduce) { staticFallback(); return; }

  var THREE_URL = "https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.min.js";
  function loadThree(cb){
    if (window.THREE) return cb();
    var s = document.createElement("script"); s.src = THREE_URL; s.onload = cb; s.onerror = function(){ staticFallback(); };
    document.head.appendChild(s);
  }
  loadThree(function(){
    var THREE = window.THREE;
    var renderer;
    try { renderer = new THREE.WebGLRenderer({canvas:canvas, alpha:true, antialias:false}); }
    catch(e){ staticFallback(); return; }
    renderer.setClearColor(0xffffff, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.75));
    var scene = new THREE.Scene();
    var camera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0.01, 10);
    camera.position.z = 1;

    var uniforms = {
      tMap: { value: null },
      uPointer: { value: new THREE.Vector2(-10, -10) },
      uVel: { value: 0 },
      uTime: { value: 0 },
      uScroll: { value: 0 },
      uRes: { value: new THREE.Vector2(4, 5) }
    };
    var mat = new THREE.ShaderMaterial({
      uniforms: uniforms,
      vertexShader: 'varying vec2 vUv; void main(){ vUv = uv; gl_Position = vec4(position.xy, 0.0, 1.0); }',
      fragmentShader: [
        'precision highp float;',
        'varying vec2 vUv;',
        'uniform sampler2D tMap;',
        'uniform vec2 uPointer;',
        'uniform float uVel;',
        'uniform float uTime;',
        'uniform float uScroll;',
        'float hash(vec2 p){ return fract(sin(dot(p, vec2(127.1,311.7))) * 43758.5453123); }',
        'void main(){',
        '  vec2 uv = vUv; uv.y = 1.0 - uv.y;',
        '  vec3 imgRes = vec3(800.0, 1000.0, 1.0);',
        '  float imgAsp = imgRes.x / imgRes.y;',
        '  float scrAsp = uRes.x / uRes.y;',
        '  if (scrAsp > imgAsp) { uv.x = (uv.x - 0.5) * (imgAsp / scrAsp) + 0.5; } else { uv.y = (uv.y - 0.5) * (scrAsp / imgAsp) + 0.5; }',
        '  float dist = distance(vUv, uPointer);',
        '  float fall = smoothstep(0.55, 0.0, dist);',
        '  float v = clamp(uVel, 0.0, 3.0);',
        '  float n = hash(floor(vUv * 220.0) + vec2(floor(uTime * 18.0), 0.0));',
        '  vec2 disp = vec2(n - 0.5, hash(floor(vUv * 180.0)) - 0.5) * fall * (0.010 + 0.028 * v);',
        '  if (uv.x < 0.0 || uv.x > 1.0 || uv.y < 0.0 || uv.y > 1.0) { gl_FragColor = vec4(1.0); return; }',
        '  vec2 duv = uv + disp;',
        '  float split = fall * (0.004 + 0.010 * v);',
        '  vec4 c;',
        '  c.r = texture2D(tMap, duv + vec2(split, 0.0)).r;',
        '  c.g = texture2D(tMap, duv).g;',
        '  c.b = texture2D(tMap, duv - vec2(split, 0.0)).b;',
        '  c.a = 1.0;',
        // halftone quantize toward monochrome + acid ticks
        '  float lum = dot(c.rgb, vec3(0.299, 0.587, 0.114));',
        '  float q = floor(lum * 5.0) / 5.0;',
        '  vec3 mono = vec3(q);',
        '  float scan = step(0.985, fract(vUv.y * 160.0 + uTime * 0.35)) * fall;',
        '  mono = mix(mono, vec3(0.77, 0.96, 0.27), scan * 0.9);',
        '  float grain = hash(vUv * (480.0 + uVel * 40.0));',
        '  mono += (grain - 0.5) * 0.05;',
        '  gl_FragColor = vec4(mono, 1.0);',
        '}'
      ].join('\n')
    });
    var mesh = new THREE.Mesh(new THREE.PlaneGeometry(2, 2), mat);
    scene.add(mesh);

    canvas.style.opacity = '0';
    new THREE.TextureLoader().load(imgSrc, function(tex){ canvas.style.opacity = '1';
      uniforms.tMap.value = tex;
      resize();
      animate();
    }, undefined, function(){ staticFallback(); });

    function resize(){
      var rect = frame.getBoundingClientRect();
      renderer.setSize(Math.max(1, rect.width), Math.max(1, rect.height), true);
      uniforms.uRes.value.set(rect.width, rect.height);
      camera.left = -1; camera.right = 1; camera.top = 1; camera.bottom = -1;
      camera.updateProjectionMatrix();
    }
    if (window.ResizeObserver) new ResizeObserver(resize).observe(frame);
    window.addEventListener("resize", resize);

    var target = new THREE.Vector2(-10, -10), cur = new THREE.Vector2(-10, -10);
    var last = null, lastT = 0, vel = 0;
    function setPointer(cx, cy){
      var r = canvas.getBoundingClientRect();
      var x = (cx - r.left) / (r.width || 1), y = (cy - r.top) / (r.height || 1);
      target.set(x, 1 - y);
      var now = performance.now();
      if (last) {
        var dx = x - last.x, dy = (1 - y) - last.y, dt = Math.max(1, now - lastT);
        vel = Math.min(3, vel * 0.6 + (Math.hypot(dx, dy) / dt) * 120);
      }
      last = {x:x, y:1-y}; lastT = now;
    }
    frame.addEventListener("pointermove", function(e){ setPointer(e.clientX, e.clientY); });
    frame.addEventListener("pointerdown", function(e){ setPointer(e.clientX, e.clientY); });
    frame.addEventListener("pointerleave", function(){ target.set(-10, -10); });
    frame.addEventListener("touchmove", function(e){ if(e.touches[0]) setPointer(e.touches[0].clientX, e.touches[0].clientY); }, {passive:true});
    frame.addEventListener("touchend", function(){ target.set(-10, -10); });

    var t0 = performance.now();
    function animate(){
      requestAnimationFrame(animate);
      if (!document.hidden) {
        uniforms.uTime.value = (performance.now() - t0) / 1000;
        uniforms.uScroll.value = window.scrollY || 0;
        vel *= 0.92; uniforms.uVel.value = vel;
        cur.lerp(target, 0.14);
        uniforms.uPointer.value.copy(cur);
        renderer.render(scene, camera);
      }
    }
  });
})();
