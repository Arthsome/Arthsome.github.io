import T from './three.js';
import { GPUFluid } from './fluid.js';
import { Particles } from './particles.js';
import { MATCAP_URI } from './matcap.js';

const mobile = window.innerWidth <= 760 || matchMedia('(pointer:coarse)').matches;
const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ---------- UI ---------- */
const CHIPS=['All','Light','Physics','Fluids','Grid','Audio','Volumes','Particles','Capture','Render'];
document.getElementById('tags').innerHTML=CHIPS.map((c,i)=>`<span class="chip${i===0?' active':''}">${c}</span>`).join('');

const CARDS=[
  {v:'https://pub-86dc5b5484314368ac5436a674b0d919.r2.dev/aaaf/oraciteslArea.mp4',l:'Lattices / zone',r:'Ambient light\nstudy'},
  {v:'https://pub-86dc5b5484314368ac5436a674b0d919.r2.dev/aaaf/facet-glass-hero.mp4',l:'Prism / shell',r:'Dispersion hero\nrender'},
  {v:'https://pub-86dc5b5484314368ac5436a674b0d919.r2.dev/aaaf/stellarmind-hero.mp4',l:'Nebular / loop',r:'Procedural hero\nsequence'},
  {v:'https://pub-86dc5b5484314368ac5436a674b0d919.r2.dev/aaaf/thedropthroughArea.mp4',l:'Fall / forward',r:'Dolly track\nstudy'}
];
document.getElementById('list').innerHTML=CARDS.map(c=>`
  <div class="card">
    <div class="thumb"><video src="${c.v}" autoplay muted loop playsinline preload="metadata"></video></div>
    <div class="meta"><span class="l">${c.l}</span><span class="r">${c.r}</span></div>
  </div>`).join('');
document.querySelectorAll('.chip').forEach(chip=>chip.addEventListener('click',()=>{
  document.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));
  chip.classList.add('active');
}));

/* ---------- three.js ---------- */
const canvas=document.getElementById('bg');
const renderer=new T.WebGLRenderer({canvas,antialias:false,alpha:false,powerPreference:'high-performance'});
renderer.setPixelRatio(Math.min(window.devicePixelRatio||1,2));
renderer.setSize(window.innerWidth,window.innerHeight,false);
renderer.setClearColor(0x000000,1);

const scene=new T.Scene();
const camera=new T.PerspectiveCamera(30,window.innerWidth/window.innerHeight,0.1,1000);
const BASE=new T.Vector3(-1.17,0,6);
camera.position.copy(BASE);
camera.lookAt(0,0,0);

const group=new T.Group();
group.position.set(0.343,0.16,-1);
group.rotation.set(-28.4*Math.PI/180, 390*Math.PI/180, 4.92*Math.PI/180);
group.scale.set(5,5,6);
scene.add(group);

const fluid=new GPUFluid(renderer);
const particles=new Particles(renderer,mobile);
const loader=new T.TextureLoader();
loader.load(MATCAP_URI,t=>{
  t.minFilter=T.LinearFilter; t.magFilter=T.LinearFilter;
  particles.setMatcap(t);
});
group.add(particles.points);

/* ---------- mouse / fluid ---------- */
const mouse={x:window.innerWidth/2,y:window.innerHeight/2,px:window.innerWidth/2,py:window.innerHeight/2,last:performance.now()};
function setPointer(x,y){ mouse.x=x; mouse.y=y; }
window.addEventListener('pointermove',e=>setPointer(e.clientX,e.clientY),{passive:true});
window.addEventListener('touchstart',e=>{if(e.touches[0])setPointer(e.touches[0].clientX,e.touches[0].clientY);},{passive:true});
window.addEventListener('touchmove',e=>{if(e.touches[0])setPointer(e.touches[0].clientX,e.touches[0].clientY);},{passive:true});

function clampMap(v,a,b,c,d){ return c+(d-c)*Math.max(0,Math.min(1,(v-a)/(b-a))); }

function fluidInput(now){
  const dx=mouse.x-mouse.px, dy=mouse.y-mouse.py;
  const len=Math.hypot(dx,dy);
  if(len>0.01){
    const radius=clampMap(len,0,5,0,60)*(mobile?0.8:1)*0.6;
    const mult=clampMap(len,0,15,0,10);
    const aspect=window.innerWidth/window.innerHeight;
    const x=mouse.x/window.innerWidth, y=1-mouse.y/window.innerHeight;
    let sx=mouse.px/window.innerWidth, sy=1-mouse.py/window.innerHeight;
    if(now-mouse.last>50){ sx=x; sy=y; }
    const steps=Math.max(1,Math.min(12,Math.ceil(len/8)));
    for(let i=1;i<=steps;i++){
      const t=i/steps;
      const ix=sx+(x-sx)*t, iy=sy+(y-sy)*t;
      fluid.splat(ix,iy,(dx/window.innerWidth)*mult*aspect*40,-(dy/window.innerHeight)*mult*40,radius,mobile);
    }
    mouse.last=now;
  }
  mouse.px=mouse.x; mouse.py=mouse.y;
}

/* ---------- loop ---------- */
let last=performance.now();
function tick(now){
  requestAnimationFrame(tick);
  const dt=Math.min(0.05,(now-last)/1000); last=now;

  fluidInput(now);
  fluid.step();

  // gaze camera
  const nx=(mouse.x/window.innerWidth)*2-1;
  const ny=(mouse.y/window.innerHeight)*2-1;
  const target=BASE.clone();
  target.x+=nx*(-1);
  target.y+=ny*2;
  camera.position.lerp(target,0.05);
  camera.lookAt(0,0,0);
  camera.updateMatrixWorld();

  particles.update(dt,reduce?0:now*0.001,camera,group,fluid.velocityTexture,fluid.densityTexture);
  renderer.render(scene,camera);
}
requestAnimationFrame(tick);

/* ---------- resize ---------- */
window.addEventListener('resize',()=>{
  const w=window.innerWidth,h=window.innerHeight;
  renderer.setSize(w,h,false);
  camera.aspect=w/h; camera.updateProjectionMatrix();
  fluid.resize(w,h);
});
