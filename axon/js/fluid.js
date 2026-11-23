/* GPU fluid — classic stable fluids on half-float ping-pong targets.
   curl → vorticity → divergence → pressure(5) → gradient subtract → advect. */
import T from './three.js';

const VERT = `
varying vec2 vUv; varying vec2 vL; varying vec2 vR; varying vec2 vT; varying vec2 vB;
uniform vec2 texelSize;
void main(){
  vUv = uv;
  vL = vUv - vec2(texelSize.x, 0.0);
  vR = vUv + vec2(texelSize.x, 0.0);
  vT = vUv + vec2(0.0, texelSize.y);
  vB = vUv - vec2(0.0, texelSize.y);
  gl_Position = vec4(position.xy, 0.0, 1.0);
}`;

const SPLAT = `
varying vec2 vUv; uniform sampler2D uTarget; uniform float aspectRatio;
uniform vec2 point; uniform vec3 color; uniform float radius;
void main(){
  vec2 p = vUv - point; p.x *= aspectRatio;
  vec3 splat = exp(-dot(p, p) / radius) * color;
  vec3 base = texture2D(uTarget, vUv).xyz;
  gl_FragColor = vec4(base + splat, 1.0);
}`;

const CURL = `
varying vec2 vUv; varying vec2 vL; varying vec2 vR; varying vec2 vT; varying vec2 vB;
uniform sampler2D uVelocity;
void main(){
  float L = texture2D(uVelocity, vL).y;
  float R = texture2D(uVelocity, vR).y;
  float T = texture2D(uVelocity, vT).x;
  float B = texture2D(uVelocity, vB).x;
  gl_FragColor = vec4(0.5 * (R - L - T + B), 0.0, 0.0, 1.0);
}`;

const VORTICITY = `
varying vec2 vUv; varying vec2 vL; varying vec2 vR; varying vec2 vT; varying vec2 vB;
uniform sampler2D uVelocity; uniform sampler2D uCurl; uniform float curl; uniform float dt;
void main(){
  float L = texture2D(uCurl, vL).x; float R = texture2D(uCurl, vR).x;
  float T = texture2D(uCurl, vT).x; float B = texture2D(uCurl, vB).x;
  float C = texture2D(uCurl, vUv).x;
  vec2 force = 0.5 * vec2(abs(T) - abs(B), abs(R) - abs(L));
  force /= length(force) + 0.0001; force *= curl * C; force.y *= -1.0;
  vec2 vel = texture2D(uVelocity, vUv).xy + force * dt;
  gl_FragColor = vec4(clamp(vel, -1000.0, 1000.0), 0.0, 1.0);
}`;

const DIVERGENCE = `
varying vec2 vUv; varying vec2 vL; varying vec2 vR; varying vec2 vT; varying vec2 vB;
uniform sampler2D uVelocity;
void main(){
  float L = texture2D(uVelocity, vL).x; float R = texture2D(uVelocity, vR).x;
  float T = texture2D(uVelocity, vT).y; float B = texture2D(uVelocity, vB).y;
  vec2 C = texture2D(uVelocity, vUv).xy;
  if (vL.x < 0.0) L = -C.x; if (vR.x > 1.0) R = -C.x;
  if (vT.y > 1.0) T = -C.y; if (vB.y < 0.0) B = -C.y;
  gl_FragColor = vec4(0.5 * (R - L + T - B), 0.0, 0.0, 1.0);
}`;

const CLEAR = `
varying vec2 vUv; uniform sampler2D uTexture; uniform float value;
void main(){ gl_FragColor = value * texture2D(uTexture, vUv); }`;

const PRESSURE = `
varying vec2 vUv; varying vec2 vL; varying vec2 vR; varying vec2 vT; varying vec2 vB;
uniform sampler2D uPressure; uniform sampler2D uDivergence;
void main(){
  float L = texture2D(uPressure, vL).x; float R = texture2D(uPressure, vR).x;
  float T = texture2D(uPressure, vT).x; float B = texture2D(uPressure, vB).x;
  float div = texture2D(uDivergence, vUv).x;
  gl_FragColor = vec4((L + R + B + T - div) * 0.25, 0.0, 0.0, 1.0);
}`;

const GRADIENT = `
varying vec2 vUv; varying vec2 vL; varying vec2 vR; varying vec2 vT; varying vec2 vB;
uniform sampler2D uPressure; uniform sampler2D uVelocity;
void main(){
  float L = texture2D(uPressure, vL).x; float R = texture2D(uPressure, vR).x;
  float T = texture2D(uPressure, vT).x; float B = texture2D(uPressure, vB).x;
  vec2 vel = texture2D(uVelocity, vUv).xy - vec2(R - L, T - B);
  gl_FragColor = vec4(vel, 0.0, 1.0);
}`;

const ADVECT = `
varying vec2 vUv; uniform sampler2D uVelocity; uniform sampler2D uSource;
uniform vec2 texelSize; uniform vec2 dyeTexelSize; uniform float dt; uniform float dissipation;
void main(){
  vec2 coord = vUv - dt * texture2D(uVelocity, vUv).xy * texelSize;
  vec4 result = texture2D(uSource, coord);
  gl_FragColor = dissipation * result;
}`;

const DISPLAY = `
varying vec2 vUv; uniform sampler2D uTexture;
void main(){
  vec3 c = texture2D(uTexture, vUv).rgb;
  gl_FragColor = vec4(c, max(max(c.r, c.g), c.b));
}`;

function material(fragment, uniforms){
  return new T.ShaderMaterial({
    vertexShader: VERT, fragmentShader: fragment, uniforms,
    depthTest: false, depthWrite: false
  });
}

function makeRT(size, type){
  return new T.WebGLRenderTarget(size, size, {
    type, format: T.RGBAFormat,
    minFilter: T.LinearFilter, magFilter: T.LinearFilter,
    wrapS: T.ClampToEdgeWrapping, wrapT: T.ClampToEdgeWrapping,
    depthBuffer: false, stencilBuffer: false
  });
}

class DoubleRT {
  constructor(size, type){ this.a=makeRT(size,type); this.b=makeRT(size,type); }
  get read(){ return this.a.texture; }
  get write(){ return this.b.texture; }
  swap(){ const t=this.a; this.a=this.b; this.b=t; }
  dispose(){ this.a.dispose(); this.b.dispose(); }
}

export class GPUFluid {
  constructor(renderer){
    this.renderer=renderer;
    this.simRes=256; this.dyeRes=512;
    this.velocityDissipation=0.98;
    this.densityDissipation=0.97;
    this.pressureDissipation=0.95;
    this.pressureIterations=5;
    this.curlStrength=30;
    this.dt=1/60;
    const gl=renderer.getContext();
    const isWebGL2=renderer.capabilities.isWebGL2;
    const canFloat=isWebGL2 ? !!gl.getExtension('EXT_color_buffer_float') : !!gl.getExtension('OES_texture_float');
    this.type = canFloat ? T.HalfFloatType : T.UnsignedByteType;

    this.velocity=new DoubleRT(this.simRes,this.type);
    this.density=new DoubleRT(this.dyeRes,this.type);
    this.pressure=new DoubleRT(this.simRes,this.type);
    this.divergence=makeRT(this.simRes,this.type);
    this.curlRT=makeRT(this.simRes,this.type);

    this.quad=new T.BufferGeometry();
    this.quad.setAttribute('position',new T.Float32BufferAttribute([-1,-1,0, 1,-1,0, -1,1,0, 1,1,0],3));
    this.quad.setAttribute('uv',new T.Float32BufferAttribute([0,0, 1,0, 0,1, 1,1],2));
    this.quad.setIndex([0,1,2, 2,1,3]);
    this.camera=new T.OrthographicCamera(-1,1,1,-1,0,1);
    this.scene=new T.Scene();
    this.mesh=new T.Mesh(this.quad,null);
    this.mesh.frustumCulled=false;
    this.scene.add(this.mesh);

    const simT=new T.Vector2(1/this.simRes,1/this.simRes);
    const dyeT=new T.Vector2(1/this.dyeRes,1/this.dyeRes);
    this.m={
      splat:material(SPLAT,{uTarget:{value:null},aspectRatio:{value:1},point:{value:new T.Vector2()},color:{value:new T.Vector3()},radius:{value:0.01}}),
      curl:material(CURL,{uVelocity:{value:null},texelSize:{value:simT}}),
      vorticity:material(VORTICITY,{uVelocity:{value:null},uCurl:{value:null},curl:{value:this.curlStrength},dt:{value:this.dt}}),
      divergence:material(DIVERGENCE,{uVelocity:{value:null},texelSize:{value:simT}}),
      clear:material(CLEAR,{uTexture:{value:null},value:{value:this.pressureDissipation}}),
      pressure:material(PRESSURE,{uPressure:{value:null},uDivergence:{value:null},texelSize:{value:simT}}),
      gradient:material(GRADIENT,{uPressure:{value:null},uVelocity:{value:null},texelSize:{value:simT}}),
      advect:material(ADVECT,{uVelocity:{value:null},uSource:{value:null},texelSize:{value:simT},dyeTexelSize:{value:dyeT},dt:{value:this.dt},dissipation:{value:this.velocityDissipation}}),
      display:material(DISPLAY,{uTexture:{value:null},texelSize:{value:dyeT}})
    };
    this.mask=null;
    this.resize(window.innerWidth,window.innerHeight);
  }

  resize(w,h){
    if(this.mask)this.mask.dispose();
    this.mask=new T.WebGLRenderTarget(Math.max(2,Math.floor(w)),Math.max(2,Math.floor(h)),{
      type:T.UnsignedByteType,format:T.RGBAFormat,
      minFilter:T.LinearFilter,magFilter:T.LinearFilter,depthBuffer:false,stencilBuffer:false
    });
    this.m.splat.uniforms.aspectRatio.value=w/h;
  }

  blit(mat,target){
    this.mesh.material=mat;
    const prev=this.renderer.getRenderTarget();
    this.renderer.setRenderTarget(target||null);
    this.renderer.render(this.scene,this.camera);
    this.renderer.setRenderTarget(prev);
  }

  splat(x,y,dx,dy,radius,mobile){
    const aspect=this.m.splat.uniforms.aspectRatio.value;
    const r=radius/200*0.1;
    const s=this.m.splat;
    // velocity: force colour, additive
    s.uniforms.uTarget.value=this.velocity.read;
    s.uniforms.point.value.set(x,y);
    s.uniforms.color.value.set(dx,dy,1);
    s.uniforms.radius.value=r;
    this.blit(s,this.velocity.write); this.velocity.swap();
    // density: white
    s.uniforms.uTarget.value=this.density.read;
    s.uniforms.color.value.set(1,1,1);
    s.uniforms.radius.value=r*(mobile?0.8:1);
    this.blit(s,this.density.write); this.density.swap();
  }

  step(){
    // curl
    this.m.curl.uniforms.uVelocity.value=this.velocity.read;
    this.blit(this.m.curl,this.curlRT);
    // vorticity
    this.m.vorticity.uniforms.uVelocity.value=this.velocity.read;
    this.m.vorticity.uniforms.uCurl.value=this.curlRT.texture;
    this.blit(this.m.vorticity,this.velocity.write); this.velocity.swap();
    // divergence
    this.m.divergence.uniforms.uVelocity.value=this.velocity.read;
    this.blit(this.m.divergence,this.divergence);
    // clear pressure
    this.m.clear.uniforms.uTexture.value=this.pressure.read;
    this.m.clear.uniforms.value.value=this.pressureDissipation;
    this.blit(this.m.clear,this.pressure.write); this.pressure.swap();
    // pressure jacobi
    this.m.pressure.uniforms.uDivergence.value=this.divergence.texture;
    for(let i=0;i<this.pressureIterations;i++){
      this.m.pressure.uniforms.uPressure.value=this.pressure.read;
      this.blit(this.m.pressure,this.pressure.write); this.pressure.swap();
    }
    // gradient subtract
    this.m.gradient.uniforms.uPressure.value=this.pressure.read;
    this.m.gradient.uniforms.uVelocity.value=this.velocity.read;
    this.blit(this.m.gradient,this.velocity.write); this.velocity.swap();
    // advect velocity
    this.m.advect.uniforms.uVelocity.value=this.velocity.read;
    this.m.advect.uniforms.uSource.value=this.velocity.read;
    this.m.advect.uniforms.dissipation.value=this.velocityDissipation;
    this.m.advect.uniforms.texelSize.value=new T.Vector2(1/this.simRes,1/this.simRes);
    this.blit(this.m.advect,this.velocity.write); this.velocity.swap();
    // advect density
    this.m.advect.uniforms.uVelocity.value=this.velocity.read;
    this.m.advect.uniforms.uSource.value=this.density.read;
    this.m.advect.uniforms.dissipation.value=this.densityDissipation;
    this.m.advect.uniforms.texelSize.value=new T.Vector2(1/this.dyeRes,1/this.dyeRes);
    this.blit(this.m.advect,this.density.write); this.density.swap();
    // mask to viewport target
    this.m.display.uniforms.uTexture.value=this.density.read;
    this.blit(this.m.display,this.mask);
  }

  get velocityTexture(){ return this.velocity.read; }
  get densityTexture(){ return this.mask.texture; }
}
