/* 262,144 GPU particles bound to a twisted hollow SDF ring, stirred by fluid. */
import T from './three.js';

const SIM_VERT = `
varying vec2 vUv;
void main(){ vUv = uv; gl_Position = vec4(position.xy, 0.0, 1.0); }`;

const SIM_FRAG = `
precision highp float;
varying vec2 vUv;
uniform sampler2D uPosition;
uniform sampler2D uOrigin;
uniform sampler2D uRandom;
uniform sampler2D uFluidVelocity;
uniform sampler2D uFluidDensity;
uniform float uTime;
uniform float uHZ;
uniform float uMouseStrength;
uniform mat4 uProjection;
uniform mat4 uModel;
uniform mat4 uCameraWorld;

/* analytic-ish curl of three sine-sum potentials */
vec3 potential(vec3 p){
  return vec3(
    sin(p.y * 1.7 + p.z * 1.3) + sin(p.x * 2.1 - p.z * 0.9),
    sin(p.z * 1.9 + p.x * 1.1) + sin(p.y * 2.3 - p.x * 0.7),
    sin(p.x * 1.5 + p.y * 1.7) + sin(p.z * 2.0 - p.y * 0.8)
  );
}
vec3 curlNoise(vec3 p){
  float e = 0.01;
  vec3 dx = vec3(e,0.0,0.0), dy = vec3(0.0,e,0.0), dz = vec3(0.0,0.0,e);
  vec3 px0 = potential(p-dx), px1 = potential(p+dx);
  vec3 py0 = potential(p-dy), py1 = potential(p+dy);
  vec3 pz0 = potential(p-dz), pz1 = potential(p+dz);
  float x = (py1.z - py0.z) - (pz1.y - pz0.y);
  float y = (pz1.x - pz0.x) - (px1.z - px0.z);
  float z = (px1.y - px0.y) - (py1.x - py0.x);
  return normalize(vec3(x,y,z) / (2.0 * e) + 0.00001);
}

vec3 qrot(vec3 p, vec4 q){
  return p + 2.0 * cross(q.xyz, cross(q.xyz, p) + q.w * p);
}

float sdfShape(vec3 p){
  if (length(p) > 0.8) return length(p) - 0.7;
  p.z = sqrt(p.z * p.z + 0.0215) - sqrt(0.012);
  p = qrot(p, normalize(vec4(0.5, 0.5, 0.5, 0.5)));
  float a = atan(p.y, p.x);
  float tw = p.z * 3.0 + 0.3 * sin(a * 3.0);
  float c = cos(tw), s = sin(tw);
  vec3 q = vec3(c * p.x - s * p.y, s * p.x + c * p.y, p.z);
  float R = 0.34;
  float r = 0.13 + 0.035 * sin(a * 5.0) + 0.02 * sin(q.z * 12.0);
  vec2 t = vec2(length(q.xy) - R, q.z);
  return length(t) - r;
}
vec3 sdfNormal(vec3 p){
  float e = 0.001;
  return normalize(vec3(
    sdfShape(p + vec3(e,0,0)) - sdfShape(p - vec3(e,0,0)),
    sdfShape(p + vec3(0,e,0)) - sdfShape(p - vec3(0,e,0)),
    sdfShape(p + vec3(0,0,e)) - sdfShape(p - vec3(0,0,e))
  ) + 0.00001);
}

void main(){
  vec3 pos = texture2D(uPosition, vUv).xyz;
  vec3 origin = texture2D(uOrigin, vUv).xyz;

  if (length(pos) > 0.7) pos /= 2.0;

  pos += curlNoise(pos * 0.1 + uTime * 0.05) * 0.0002 * uHZ;
  vec3 gradient = sdfNormal(pos);
  float sdf = sdfShape(pos);
  pos += cross(normalize(pos + 0.00001), normalize(gradient)) * 0.0005;
  pos += -gradient * sdf * 0.5;
  pos += (origin - pos) * 0.0002 * uHZ;

  vec4 clip = uProjection * uModel * vec4(pos, 1.0);
  vec2 screenUV = clip.xy / clip.w * 0.5 + 0.5;
  if (screenUV.x > 0.0 && screenUV.x < 1.0 && screenUV.y > 0.0 && screenUV.y < 1.0){
    vec3 flow = vec3(texture2D(uFluidVelocity, screenUV).xy, 0.0);
    flow = (uCameraWorld * vec4(flow, 0.0)).xyz;
    float density = texture2D(uFluidDensity, screenUV).r;
    pos += flow * 0.0001 * uHZ * uMouseStrength * density;
  }
  gl_FragColor = vec4(pos, 1.0);
}`;

const POINT_VERT = `
precision highp float;
uniform sampler2D uPosition;
uniform float uTime;
uniform float uDpr;
attribute vec4 random;
varying float vR; varying float vY; varying float vZ; varying float vScale;
void main(){
  vec3 pos = texture2D(uPosition, position.xy).xyz;
  pos *= mix(1.0, 1.5, pow(random.y, 150.0));
  vec4 mv = modelViewMatrix * vec4(pos, 1.0);
  float dist = max(0.001, -mv.z);
  vScale = smoothstep(3.0, 15.0, dist) * mix(0.5, 1.0, random.z);
  gl_PointSize = 0.04 * uDpr * 2.0 * vScale * (1000.0 / dist);
  vR = random.x; vY = random.y; vZ = random.z;
  gl_Position = projectionMatrix * mv;
}`;

const POINT_FRAG = `
precision highp float;
uniform sampler2D uMatcap;
uniform float uTime;
varying float vR; varying float vY; varying float vZ; varying float vScale;
vec3 softLight(vec3 b, vec3 s){
  return mix(2.0*b*s + b*b*(1.0-2.0*s), sqrt(b)*(2.0*s-1.0)+2.0*b*(1.0-s), step(vec3(0.5), s));
}
vec3 overlay(vec3 b, vec3 s){
  return mix(2.0*b*s, 1.0-2.0*(1.0-b)*(1.0-s), step(vec3(0.5), b));
}
void main(){
  vec2 uv = gl_PointCoord;
  if (length(uv - 0.5) > 0.5) discard;
  if (vScale < 0.1) discard;
  float ang = sin(uTime + vY * 20.0) * 0.5 + 1.0;
  float c = cos(ang), s = sin(ang);
  vec2 muv = mat2(c,-s,s,c) * (uv - 0.5) + 0.5;
  vec3 mat = texture2D(uMatcap, clamp(muv, 0.0, 1.0)).rgb;
  vec3 base = mix(vec3(0.0), vec3(0.2), vR);
  base = mix(base, vec3(0.6, 0.45, 1.0), pow(vZ, 100.0));
  float sparkle = 0.5 + (0.4 + sin(uTime * 4.0 + vY * 20.0)) * pow(vZ, 10.0) * 2.5;
  vec3 col = base * sparkle;
  col = mix(col, softLight(col, mat), 0.8);
  col = mix(col, overlay(col, mat), 0.2);
  gl_FragColor = vec4(col, 1.0);
}`;

function makeRT(size, type){
  return new T.WebGLRenderTarget(size,size,{
    type, format:T.RGBAFormat,
    minFilter:T.NearestFilter, magFilter:T.NearestFilter,
    wrapS:T.ClampToEdgeWrapping, wrapT:T.ClampToEdgeWrapping,
    depthBuffer:false, stencilBuffer:false
  });
}

export class Particles {
  constructor(renderer, mobile){
    this.renderer=renderer;
    this.size = mobile ? 128 : 512;
    const N = this.size * this.size;
    this.count=N;
    const gl=renderer.getContext();
    const canFloat=renderer.capabilities.isWebGL2 ? !!gl.getExtension('EXT_color_buffer_float') : !!gl.getExtension('OES_texture_float');
    const type=canFloat ? T.FloatType : T.HalfFloatType;

    // origin texture: random uniform in [-1,1]^3
    const originData=new Float32Array(N*4);
    const randomData=new Float32Array(N*4);
    for(let i=0;i<N;i++){
      originData[i*4+0]=Math.random()*2-1;
      originData[i*4+1]=Math.random()*2-1;
      originData[i*4+2]=Math.random()*2-1;
      originData[i*4+3]=1;
      randomData[i*4+0]=Math.random();
      randomData[i*4+1]=Math.random();
      randomData[i*4+2]=Math.random();
      randomData[i*4+3]=Math.random();
    }
    this.origin=new T.DataTexture(originData,this.size,this.size,T.RGBAFormat,T.FloatType);
    this.origin.needsUpdate=true;
    this.randomTex=new T.DataTexture(randomData,this.size,this.size,T.RGBAFormat,T.FloatType);
    this.randomTex.needsUpdate=true;

    this.rtA=makeRT(this.size,type);
    this.rtB=makeRT(this.size,type);
    // seed current positions from origin
    const seed=new T.ShaderMaterial({
      vertexShader:SIM_VERT,
      fragmentShader:`varying vec2 vUv; uniform sampler2D uTex; void main(){ gl_FragColor = texture2D(uTex, vUv); }`,
      uniforms:{uTex:{value:this.origin}}, depthTest:false, depthWrite:false
    });
    this.quadScene=new T.Scene();
    this.quadCam=new T.OrthographicCamera(-1,1,1,-1,0,1);
    this.quadGeo=new T.BufferGeometry();
    this.quadGeo.setAttribute('position',new T.Float32BufferAttribute([-1,-1,0, 1,-1,0, -1,1,0, 1,1,0],3));
    this.quadGeo.setAttribute('uv',new T.Float32BufferAttribute([0,0, 1,0, 0,1, 1,1],2));
    this.quadGeo.setIndex([0,1,2, 2,1,3]);
    this.quadMesh=new T.Mesh(this.quadGeo,seed);
    this.quadMesh.frustumCulled=false;
    this.quadScene.add(this.quadMesh);
    const prev=renderer.getRenderTarget();
    renderer.setRenderTarget(this.rtA); renderer.render(this.quadScene,this.quadCam);
    renderer.setRenderTarget(this.rtB); renderer.render(this.quadScene,this.quadCam);
    renderer.setRenderTarget(prev);

    this.simMat=new T.ShaderMaterial({
      vertexShader:SIM_VERT, fragmentShader:SIM_FRAG,
      uniforms:{
        uPosition:{value:this.rtA.texture}, uOrigin:{value:this.origin}, uRandom:{value:this.randomTex},
        uFluidVelocity:{value:null}, uFluidDensity:{value:null},
        uTime:{value:0}, uHZ:{value:1}, uMouseStrength:{value:0.4},
        uProjection:{value:new T.Matrix4()}, uModel:{value:new T.Matrix4()}, uCameraWorld:{value:new T.Matrix4()}
      }, depthTest:false, depthWrite:false
    });

    // point geometry: position.xy used as UV, random vec4 attribute
    const posArr=new Float32Array(N*3);
    for(let i=0;i<N;i++){
      posArr[i*3+0]=(i%this.size)/this.size + 0.5/this.size;
      posArr[i*3+1]=Math.floor(i/this.size)/this.size + 0.5/this.size;
      posArr[i*3+2]=0;
    }
    this.geometry=new T.BufferGeometry();
    this.geometry.setAttribute('position',new T.BufferAttribute(posArr,3));
    this.geometry.setAttribute('random',new T.BufferAttribute(randomData,4));

    this.pointMat=new T.ShaderMaterial({
      vertexShader:POINT_VERT, fragmentShader:POINT_FRAG,
      uniforms:{
        uPosition:{value:this.rtA.texture}, uTime:{value:0},
        uDpr:{value:Math.min(window.devicePixelRatio||1,2)},
        uMatcap:{value:null}
      },
      transparent:true, blending:T.AdditiveBlending,
      depthTest:true, depthWrite:false
    });
    this.points=new T.Points(this.geometry,this.pointMat);
    this.points.frustumCulled=false;
  }

  setMatcap(texture){ this.pointMat.uniforms.uMatcap.value=texture; }

  update(dt,time,camera,group,fluidVelocity,fluidDensity){
    const u=this.simMat.uniforms;
    u.uPosition.value=this.rtA.texture;
    u.uFluidVelocity.value=fluidVelocity;
    u.uFluidDensity.value=fluidDensity;
    u.uTime.value=time;
    u.uHZ.value=Math.min(3,dt*60);
    u.uProjection.value.multiplyMatrices(camera.projectionMatrix,camera.matrixWorldInverse);
    group.updateMatrixWorld();
    u.uModel.value.copy(group.matrixWorld);
    u.uCameraWorld.value.copy(camera.matrixWorld);
    this.quadMesh.material=this.simMat;
    const prev=this.renderer.getRenderTarget();
    this.renderer.setRenderTarget(this.rtB);
    this.renderer.render(this.quadScene,this.quadCam);
    this.renderer.setRenderTarget(prev);
    const t=this.rtA; this.rtA=this.rtB; this.rtB=t;
    this.pointMat.uniforms.uPosition.value=this.rtA.texture;
    this.pointMat.uniforms.uTime.value=time;
  }
}
