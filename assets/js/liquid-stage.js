/* liquid-stage.js — signature scroll-linked liquid distortion (WebGL1/GLSL ES 1.0).
   Inspired by Codrops' Liquid Distortion (Yannis Yannakopoulos) but
   dependency-free: no PixiJS/GSAP. Three research photos crossfade by scroll
   progress; displacement intensity ramps with scroll velocity and decays.
   Fails silent (fallback <img> stays) when WebGL is unavailable.
   Reduced motion / touch / non-fine pointers still get the photo, just no or
   gentler distortion — the canvas is never blank. */
(function () {
  "use strict";

  var host = document.querySelector("[data-liquid]");
  if (!host) return;
  var canvas = host.querySelector("canvas");
  if (!canvas) return;

  var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var fine = window.matchMedia("(pointer: fine)").matches;
  var gl = canvas.getContext("webgl", { antialias: false, alpha: false }) ||
           canvas.getContext("experimental-webgl", { antialias: false, alpha: false });
  if (!gl) return; // fallback <img> remains visible

  var label = host.querySelector(".liquid-label");
  var chapters = ["hex dump comparison", "obfuscation pipeline", "key sensitivity"];

  var VERT = "attribute vec2 p;varying vec2 vUv;void main(){vUv=p*0.5+0.5;gl_Position=vec4(p,0.0,1.0);}";
  var FRAG =
    "precision mediump float;\n" +
    "varying vec2 vUv;\n" +
    "uniform sampler2D u_a;\n" +
    "uniform sampler2D u_b;\n" +
    "uniform sampler2D u_c;\n" +
    "uniform sampler2D u_dmap;\n" +
    "uniform float u_mix;\n" +
    "uniform float u_intensity;\n" +
    "uniform vec2 u_res;\n" +
    "uniform vec2 u_texRes;\n" +
    "float cover(vec2 uv){float ca=u_res.x/u_res.y;float cb=u_texRes.x/u_texRes.y;return 0.0;}\n" +
    "vec2 fit(vec2 uv){\n" +
    "  float ca = u_res.x / u_res.y;\n" +
    "  float cb = u_texRes.x / u_texRes.y;\n" +
    "  vec2 s = vec2(1.0);\n" +
    "  if (cb > ca) { s.x = ca / cb; } else { s.y = cb / ca; }\n" +
    "  return (uv - 0.5) * s + 0.5;\n" +
    "}\n" +
    "void main(){\n" +
    "  vec2 uv = fit(vUv);\n" +
    "  vec2 duv = fit(vUv * 1.6);\n" +
    "  vec4 dd = texture2D(u_dmap, duv);\n" +
    "  vec2 off = (dd.rg - 0.5) * u_intensity;\n" +
    "  uv += off;\n" +
    "  vec4 ca = texture2D(u_a, uv);\n" +
    "  vec4 cb = texture2D(u_b, uv);\n" +
    "  vec4 cc = texture2D(u_c, uv);\n" +
    "  vec4 col = (u_mix < 0.5) ? mix(ca, cb, smoothstep(0.15, 0.5, u_mix))\n" +
    "                            : mix(cb, cc, smoothstep(0.5, 0.85, u_mix));\n" +
    "  float gray = dot(col.rgb, vec3(0.299, 0.587, 0.114));\n" +
    "  vec3 treated = mix(vec3(gray), col.rgb, 0.55);\n" +
    "  vec3 lime = vec3(0.769, 0.961, 0.267);\n" +
    "  treated = mix(treated, treated * lime * 1.35, 0.10);\n" +
    "  float vig = smoothstep(0.95, 0.35, distance(vUv, vec2(0.5)));\n" +
    "  col.rgb = treated * (0.72 + 0.38 * vig);\n" +
    "  gl_FragColor = vec4(col.rgb, 1.0);\n" +
    "}";

  function sh(type, src) {
    var s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) return null;
    return s;
  }
  var vs = sh(gl.VERTEX_SHADER, VERT);
  var fs = sh(gl.FRAGMENT_SHADER, FRAG);
  if (!vs || !fs) return;
  var prog = gl.createProgram();
  gl.attachShader(prog, vs);
  gl.attachShader(prog, fs);
  gl.linkProgram(prog);
  if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return;
  gl.useProgram(prog);

  var buf = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
  var loc = gl.getAttribLocation(prog, "p");
  gl.enableVertexAttribArray(loc);
  gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

  var U = {
    a: gl.getUniformLocation(prog, "u_a"),
    b: gl.getUniformLocation(prog, "u_b"),
    c: gl.getUniformLocation(prog, "u_c"),
    dmap: gl.getUniformLocation(prog, "u_dmap"),
    mix: gl.getUniformLocation(prog, "u_mix"),
    intensity: gl.getUniformLocation(prog, "u_intensity"),
    res: gl.getUniformLocation(prog, "u_res"),
    texRes: gl.getUniformLocation(prog, "u_texRes"),
  };

  function loadTex(src, unit) {
    return new Promise(function (resolve) {
      var img = new Image();
      img.onload = function () {
        var tex = gl.createTexture();
        gl.activeTexture(gl.TEXTURE0 + unit);
        gl.bindTexture(gl.TEXTURE_2D, tex);
        gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, true);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, img);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
        resolve({ w: img.naturalWidth, h: img.naturalHeight });
      };
      img.onerror = function () { resolve(null); };
      img.src = src;
    });
  }

  var texA = "assets/img/wht-shellcode/01-hexdump-comparison.png";
  var texB = "assets/img/wht-shellcode/02-pipeline-flow.png";
  var texC = "assets/img/wht-shellcode/05-key-sensitivity.png";
  var texD = "assets/img/textures/fractal-noise-large.webp";

  var ready = false;
  var texRes = { w: 1600, h: 1066 };
  var idle = reduce ? 0 : (fine ? 0.018 : 0.008);
  var intensity = idle;
  var lastY = window.pageYOffset || 0;
  var running = true;

  Promise.all([loadTex(texA, 0), loadTex(texB, 1), loadTex(texC, 2), loadTex(texD, 3)]).then(function (sizes) {
    gl.uniform1i(U.a, 0);
    gl.uniform1i(U.b, 1);
    gl.uniform1i(U.c, 2);
    gl.uniform1i(U.dmap, 3);
    if (sizes[0]) texRes = sizes[0];
    ready = true;
  });

  function resize() {
    var dpr = Math.min(window.devicePixelRatio || 1, fine ? 1.5 : 1.2);
    var w = Math.round(canvas.clientWidth * dpr);
    var h = Math.round(canvas.clientHeight * dpr);
    if (w > 0 && h > 0) {
      if (canvas.width !== w || canvas.height !== h) {
        canvas.width = w;
        canvas.height = h;
      }
      gl.viewport(0, 0, w, h);
    }
  }
  if (window.ResizeObserver) new ResizeObserver(resize).observe(canvas);
  window.addEventListener("resize", resize, { passive: true });
  resize();

  if (window.IntersectionObserver) {
    new IntersectionObserver(function (entries) {
      running = entries[0].isIntersecting;
    }, { threshold: 0.02 }).observe(host);
  }

  var curMix = 0;
  var raf = 0;
  function frame() {
    raf = requestAnimationFrame(frame);
    if (!running || !ready || canvas.width === 0) return;
    var y = window.pageYOffset || 0;
    var vel = Math.min(Math.abs(y - lastY) / 900, 0.12);
    lastY = y;
    if (reduce) {
      intensity = 0;
    } else {
      var target = idle + vel;
      intensity += (target - intensity) * 0.08;
      intensity *= 0.985;
      if (intensity < idle) intensity = idle;
    }
    var rect = host.getBoundingClientRect();
    var vh = window.innerHeight || 1;
    var p = (vh - rect.top) / (vh + rect.height);
    p = Math.max(0, Math.min(1, p));
    curMix += (p - curMix) * 0.06;
    if (label) {
      var idx = curMix < 0.34 ? 0 : curMix < 0.67 ? 1 : 2;
      var txt = "chapter 0" + (idx + 1) + " — " + chapters[idx];
      if (label.textContent !== txt) label.textContent = txt;
    }
    gl.uniform1f(U.mix, curMix);
    gl.uniform1f(U.intensity, intensity);
    gl.uniform2f(U.res, canvas.width, canvas.height);
    gl.uniform2f(U.texRes, texRes.w, texRes.h);
    gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
  }
  frame();

  document.addEventListener("visibilitychange", function () {
    if (document.hidden) { cancelAnimationFrame(raf); raf = 0; }
    else if (!raf) frame();
  });
})();
