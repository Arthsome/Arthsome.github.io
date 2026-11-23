// Raw WebGL2 domain-warped FBM, tuned for a warm paper ground with an acid whisper.
(function initShaderBackground(){
  const canvas=document.getElementById('webgl-bg');
  if(!canvas)return;
  const prefersReduced=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const gl=canvas.getContext('webgl2',{alpha:false,antialias:false,powerPreference:'high-performance'});
  if(!gl)return; // CSS --paper fallback already in place

  const vsSource=`#version 300 es
    in vec2 a_pos;
    void main(){ gl_Position=vec4(a_pos,0.0,1.0); }`;

  const fsSource=`#version 300 es
    precision highp float;
    uniform vec2 u_resolution; uniform float u_time; uniform vec2 u_mouse; uniform float u_scroll;
    out vec4 outColor;

    float hash(vec2 p){ p=fract(p*vec2(123.34,456.21)); p+=dot(p,p+45.32); return fract(p.x*p.y); }
    float noise(vec2 p){
      vec2 i=floor(p), f=fract(p); vec2 u=f*f*(3.0-2.0*f);
      return mix(mix(hash(i),hash(i+vec2(1.0,0.0)),u.x),
                 mix(hash(i+vec2(0.0,1.0)),hash(i+vec2(1.0,1.0)),u.x),u.y);
    }
    float fbm(vec2 p){
      float v=0.0,a=0.5; mat2 rot=mat2(0.8,0.6,-0.6,0.8);
      for(int i=0;i<4;i++){ v+=a*noise(p); p=rot*p*2.02; a*=0.5; }
      return v;
    }
    float dither(vec2 c){ vec3 m=vec3(0.06711056,0.00583715,52.9829189); return fract(m.z*fract(dot(c,m.xy))); }

    void main(){
      vec2 uv=(gl_FragCoord.xy-0.5*u_resolution.xy)/min(u_resolution.x,u_resolution.y);
      vec2 mouse=(u_mouse-0.5)*0.65;
      float t=u_time*0.1+u_scroll*0.35;
      vec2 q=vec2(fbm(uv+vec2(0.0,t*0.3)),fbm(uv+vec2(5.2,1.3)));
      vec2 r=vec2(fbm(uv+2.0*q+vec2(1.7,9.2)+mouse*0.7+t*0.15),
                  fbm(uv+2.0*q+vec2(8.3,2.8)-mouse*0.5-t*0.12));
      float f=fbm(uv*1.1+r*1.35);

      vec3 paper=vec3(0.957,0.961,0.933);
      vec3 hi=vec3(0.980,0.980,0.965);
      vec3 acid=vec3(0.714,0.945,0.231);
      vec3 col=mix(paper,hi,smoothstep(0.16,0.76,f));
      float rim=smoothstep(0.6,0.98,dot(r,q));
      col=mix(col,acid,rim*0.10);
      float glow=exp(-length(uv-mouse*0.75)*3.2);
      col+=vec3(0.05,0.09,0.01)*glow*0.22;
      float vig=1.0-dot(uv,uv)*0.18;
      col*=clamp(vig,0.82,1.0);
      col+=(dither(gl_FragCoord.xy)-0.5)/255.0;
      outColor=vec4(col,1.0);
    }`;

  function compile(type,source){
    const sh=gl.createShader(type); gl.shaderSource(sh,source); gl.compileShader(sh);
    if(!gl.getShaderParameter(sh,gl.COMPILE_STATUS)){gl.deleteShader(sh);return null;}
    return sh;
  }
  const vs=compile(gl.VERTEX_SHADER,vsSource), fs=compile(gl.FRAGMENT_SHADER,fsSource);
  if(!vs||!fs)return;
  const program=gl.createProgram(); gl.attachShader(program,vs); gl.attachShader(program,fs); gl.linkProgram(program);
  if(!gl.getProgramParameter(program,gl.LINK_STATUS))return;
  const buffer=gl.createBuffer(); gl.bindBuffer(gl.ARRAY_BUFFER,buffer);
  gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([-1,-1,1,-1,-1,1,1,1]),gl.STATIC_DRAW);
  const posLoc=gl.getAttribLocation(program,'a_pos');
  const uRes=gl.getUniformLocation(program,'u_resolution');
  const uTime=gl.getUniformLocation(program,'u_time');
  const uMouse=gl.getUniformLocation(program,'u_mouse');
  const uScroll=gl.getUniformLocation(program,'u_scroll');

  let width=0,height=0;
  const mouse={x:.5,y:.5,tx:.5,ty:.5};
  let scrollProgress=0;
  function resize(){
    const dpr=Math.min(window.devicePixelRatio||1,2);
    width=Math.floor(window.innerWidth*dpr); height=Math.floor(window.innerHeight*dpr);
    canvas.width=width; canvas.height=height; gl.viewport(0,0,width,height);
  }
  window.addEventListener('resize',resize,{passive:true});
  window.addEventListener('pointermove',e=>{mouse.tx=e.clientX/window.innerWidth;mouse.ty=1-e.clientY/window.innerHeight;},{passive:true});
  window.addEventListener('scroll',()=>{
    const max=Math.max(1,document.documentElement.scrollHeight-window.innerHeight);
    scrollProgress=window.scrollY/max;
  },{passive:true});
  resize();
  const start=performance.now();
  function render(now){
    mouse.x+=(mouse.tx-mouse.x)*0.05; mouse.y+=(mouse.ty-mouse.y)*0.05;
    gl.useProgram(program); gl.bindBuffer(gl.ARRAY_BUFFER,buffer);
    gl.enableVertexAttribArray(posLoc); gl.vertexAttribPointer(posLoc,2,gl.FLOAT,false,0,0);
    gl.uniform2f(uRes,width,height);
    gl.uniform1f(uTime,prefersReduced?0:(now-start)*0.001);
    gl.uniform2f(uMouse,mouse.x,mouse.y);
    gl.uniform1f(uScroll,scrollProgress);
    gl.drawArrays(gl.TRIANGLE_STRIP,0,4);
    if(!prefersReduced)requestAnimationFrame(render);
  }
  requestAnimationFrame(render);
})();
