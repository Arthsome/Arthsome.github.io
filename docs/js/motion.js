import { PORTFOLIO_DATA as D } from './data.js';

/* ---------- content hydration ---------- */
function hydrate(){
  const {identity,projects,capabilities,ledger,disciplines,socials}=D;
  const setHTML=(id,v)=>{const e=document.getElementById(id);if(e)e.innerHTML=v;};
  const setText=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v;};
  setText('hero-availability',identity.availability);
  setText('hero-role',identity.role);
  setHTML('hero-headline',identity.headlineHTML);
  setText('hero-bio',identity.bio);
  setHTML('hero-stats',identity.stats.map(([v,u,l])=>`<div class="stat-item"><span class="stat-val">${v}</span><span class="stat-unit">${u}</span><span class="mono-tag">${l}</span></div>`).join(''));

  const marquee=disciplines.map(d=>`<span>${d}</span><span class="accent-glyph">✦</span>`).join('');
  setHTML('marquee-a',marquee); setHTML('marquee-b',marquee);

  setHTML('work-list',projects.map(p=>`
    <article class="work-row" tabindex="0" role="button" data-project-id="${p.id}" data-cursor="OPEN">
      <span class="work-idx">${p.index}</span>
      <h3 class="work-name">${p.title}</h3>
      <span class="work-scope">${p.scope}</span>
      <span class="work-year">${p.year}</span>
      <span class="work-arrow" aria-hidden="true">↗</span>
    </article>`).join(''));

  setHTML('capabilities-list',capabilities.map(c=>`
    <article class="cap-card">
      <div class="cap-head"><span class="mono-tag">${c.index} // ${c.tag}</span></div>
      <h3 class="cap-title">${c.title}</h3><p class="cap-body">${c.body}</p>
      <div class="cap-tags">${c.tags.map(t=>`<span class="cap-tag">${t}</span>`).join('')}</div>
    </article>`).join(''));

  setHTML('ledger-grid',ledger.map(col=>`
    <div class="ledger-cell"><span class="mono-tag">${col.code}</span><h3>${col.title}</h3>
      <ul class="ledger-items">${col.items.map(([k,v])=>`<li><span>${k}</span><span>${v}</span></li>`).join('')}</ul>
    </div>`).join(''));

  setHTML('social-links',socials.map(s=>`<a href="${s.url}" target="_blank" rel="noopener noreferrer">${s.label}</a>`).join(''));
}

/* ---------- accessible line split ---------- */
function splitLines(){
  document.querySelectorAll('[data-split="lines"]').forEach(el=>{
    if(el.dataset.splitDone)return;
    const raw=el.innerHTML.split(/<br\s*\/?>/i);
    el.setAttribute('aria-label',el.textContent.replace(/\s+/g,' ').trim());
    el.innerHTML=raw.map(line=>`<span class="line-mask" aria-hidden="true"><span class="line-inner">${line.trim()}</span></span>`).join('');
    el.dataset.splitDone='1';
  });
}

/* ---------- per-character split for text-reaction (Hermeus-style) ---------- */
function splitChars(){
  document.querySelectorAll('.hero-title .line-inner').forEach(line=>{
    if(line.dataset.charSplit)return;
    // split text nodes only — nested <em> keeps its own styling
    const walker=document.createTreeWalker(line,NodeFilter.SHOW_TEXT);
    const nodes=[]; let n;
    while((n=walker.nextNode()))nodes.push(n);
    nodes.forEach(node=>{
      const frag=document.createDocumentFragment();
      for(const ch of node.textContent){
        const span=document.createElement('span');
        span.className='tr-char';
        span.textContent=ch===' '?'\u00a0':ch;
        frag.appendChild(span);
      }
      node.parentNode.replaceChild(frag,node);
    });
    line.dataset.charSplit='1';
  });
}

/* ---------- sliding nav pill (Graphical-style) ---------- */
function initNavPill(){
  const nav=document.querySelector('.nav-links'), pill=document.querySelector('.nav-pill');
  if(!nav||!pill)return;
  const move=el=>{
    if(!el)return;
    const a=el.getBoundingClientRect(), b=nav.getBoundingClientRect();
    pill.style.transform=`translateY(-50%) translateX(${a.left-b.left}px)`;
    pill.style.width=a.width+'px';
    pill.style.opacity='1';
  };
  document.querySelectorAll('.nav-link').forEach(a=>{
    a.addEventListener('pointerenter',()=>move(a));
    a.addEventListener('focus',()=>move(a));
    a.addEventListener('pointerdown',()=>a.classList.add('is-pressed'));
    a.addEventListener('pointerup',()=>a.classList.remove('is-pressed'));
  });
  nav.addEventListener('pointerleave',()=>pill.style.opacity='0');
}

/* ---------- Jakarta clock ---------- */
function initClock(){
  const clocks=document.querySelectorAll('.live-clock');
  const update=()=>{
    const t=new Date().toLocaleTimeString('en-GB',{timeZone:'Asia/Jakarta',hour12:false});
    clocks.forEach(c=>c.textContent=t);
  };
  update(); setInterval(update,1000);
}

/* ---------- motion choreography ---------- */
function initChoreography(){
  const reduced=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if(typeof gsap==='undefined'||typeof ScrollTrigger==='undefined'){
    document.querySelector('.preloader')?.remove(); return null;
  }
  gsap.registerPlugin(ScrollTrigger);
  if(reduced){document.querySelector('.preloader')?.remove();return null;}

  let lenis=null;
  if(typeof Lenis!=='undefined'){
    lenis=new Lenis({duration:1.15,easing:t=>Math.min(1,1.001-Math.pow(2,-10*t)),smoothWheel:true});
    lenis.on('scroll',ScrollTrigger.update);
    gsap.ticker.add(t=>lenis.raf(t*1000));
    gsap.ticker.lagSmoothing(0);
  }

  const heroLines=document.querySelectorAll('.hero-title .line-inner');
  gsap.set(heroLines,{yPercent:115,rotateZ:1.2});
  gsap.set(['.hero-top-meta','.hero-eyebrow','.hero-bottom'],{opacity:0,y:20});
  gsap.set('[data-reveal="line"]',{scaleX:0});

  const counter={val:0}, countEl=document.querySelector('.preloader-count'),
        barEl=document.querySelector('.preloader-bar-fill'), preloader=document.querySelector('.preloader');
  const master=gsap.timeline();
  master.to(counter,{val:100,duration:1.1,ease:'power3.inOut',onUpdate:()=>{
      const v=Math.round(counter.val);
      if(countEl)countEl.textContent=String(v).padStart(3,'0');
      if(barEl)barEl.style.transform=`scaleX(${v/100})`;
    }})
    .to(preloader,{clipPath:'inset(0% 0% 100% 0%)',duration:.9,ease:'expo.inOut',onComplete:()=>preloader?.remove()})
    .to(['.hero-top-meta','.hero-eyebrow'],{opacity:1,y:0,duration:.65,stagger:.08,ease:'power3.out'},'-=0.45')
    .to(heroLines,{yPercent:0,rotateZ:0,duration:.95,stagger:.09,ease:'expo.out'},'-=0.5')
    .to('.hero-bottom',{opacity:1,y:0,duration:.75,ease:'power3.out'},'-=0.6')
    .to('.hero-divider',{scaleX:1,duration:.85,ease:'expo.out'},'-=0.6');

  gsap.to('.scroll-progress-bar',{scaleX:1,ease:'none',scrollTrigger:{trigger:document.body,start:'top top',end:'bottom bottom',scrub:true}});

  /* scroll-linked hero zoom-out: the masthead recedes as the index arrives */
  gsap.to('.hero-headline-wrap',{
    scale:.94,y:-40,opacity:.25,ease:'none',
    scrollTrigger:{trigger:'.hero',start:'top top',end:'bottom top',scrub:1}
  });

  /* velocity marquee + pause control */
  const track=document.querySelector('.marquee-track'), toggle=document.querySelector('.marquee-toggle');
  if(track){
    let x=0,boost=0,paused=false,half=track.scrollWidth/2;
    addEventListener('resize',()=>{half=track.scrollWidth/2;},{passive:true});
    lenis?.on('scroll',({velocity})=>{if(!paused)boost=Math.min(8,Math.abs(velocity)*.12);});
    gsap.ticker.add(()=>{
      if(paused)return;
      if(half<=0)return;
      x-=0.55+boost; boost*=0.92;
      if(Math.abs(x)>=half)x=0;
      track.style.transform=`translate3d(${x}px,0,0)`;
    });
    if(toggle)toggle.addEventListener('click',()=>{
      paused=!paused;
      toggle.setAttribute('aria-pressed',String(paused));
      toggle.querySelector('.mt-label').textContent=paused?'Play':'Pause';
      toggle.setAttribute('aria-label',paused?'Play the discipline ticker':'Pause the discipline ticker');
    });
  }

  document.querySelectorAll('.section-header .line-inner, .pin-left .line-inner').forEach((line,i)=>{
    gsap.from(line,{yPercent:115,duration:.85,ease:'expo.out',delay:(i%3)*.06,
      scrollTrigger:{trigger:line.closest('section, footer'),start:'top 80%',once:true}});
  });
  document.querySelectorAll('[data-reveal="line"]:not(.hero-divider)').forEach(hr=>{
    gsap.to(hr,{scaleX:1,duration:.9,ease:'expo.out',scrollTrigger:{trigger:hr,start:'top 88%',once:true}});
  });
  gsap.from('.work-row',{opacity:0,y:26,duration:.7,stagger:.08,ease:'power3.out',scrollTrigger:{trigger:'.work-list',start:'top 82%',once:true}});
  gsap.from('.cap-card',{opacity:0,y:32,duration:.75,stagger:.12,ease:'power3.out',scrollTrigger:{trigger:'.pin-right',start:'top 82%',once:true}});
  return lenis;
}

/* ---------- interactions ---------- */
function initInteractions(lenis){
  const fine=window.matchMedia('(hover:hover) and (pointer:fine)').matches;
  const reduced=window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const toggleBtn=document.querySelector('.nav-toggle'), drawer=document.querySelector('.mobile-drawer');
  if(toggleBtn&&drawer){
    const close=()=>{toggleBtn.classList.remove('is-open');drawer.classList.remove('is-open');toggleBtn.setAttribute('aria-expanded','false');drawer.setAttribute('aria-hidden','true');lenis?.start();};
    toggleBtn.addEventListener('click',()=>{
      const opening=!drawer.classList.contains('is-open');
      toggleBtn.classList.toggle('is-open',opening); drawer.classList.toggle('is-open',opening);
      toggleBtn.setAttribute('aria-expanded',String(opening));
      drawer.setAttribute('aria-hidden',String(!opening));
      opening?lenis?.stop():lenis?.start();
    });
    drawer.querySelectorAll('a').forEach(a=>a.addEventListener('click',close));
  }
  document.querySelectorAll('a[href^="#"]').forEach(a=>a.addEventListener('click',e=>{
    const target=document.querySelector(a.getAttribute('href'));
    if(target&&lenis){e.preventDefault();lenis.scrollTo(target,{offset:-40});}
  }));
  window.__scrollToTop=()=>lenis?lenis.scrollTo(0):window.scrollTo({top:0,behavior:'smooth'});

  /* case drawer */
  const modal=document.querySelector('.project-modal');
  function open(id){
    const p=D.projects.find(x=>x.id===id); if(!p||!modal)return;
    document.getElementById('modal-index').textContent=`CASE // ${p.index}`;
    document.getElementById('modal-no').textContent=p.index;
    document.getElementById('modal-role').textContent=p.role;
    document.getElementById('modal-year').textContent=p.year;
    document.getElementById('modal-stack').textContent=p.stack;
    document.getElementById('modal-title').textContent=p.title;
    document.getElementById('modal-summary').textContent=p.summary;
    document.getElementById('modal-link').href=p.link;
    document.getElementById('modal-highlights').innerHTML=p.highlights.map((h,i)=>`<div class="highlight-box"><span class="mono-tag">0${i+1}</span><p style="margin-top:.35rem">${h}</p></div>`).join('');
    modal.classList.add('is-open'); modal.setAttribute('aria-hidden','false'); lenis?.stop();
  }
  function close(){if(!modal)return;modal.classList.remove('is-open');modal.setAttribute('aria-hidden','true');lenis?.start();}
  document.querySelectorAll('.work-row').forEach(row=>{
    row.addEventListener('click',()=>open(row.dataset.projectId));
    row.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();open(row.dataset.projectId);}});
  });
  document.querySelector('.modal-backdrop')?.addEventListener('click',close);
  document.querySelector('.modal-close')?.addEventListener('click',close);
  window.addEventListener('keydown',e=>{if(e.key==='Escape'&&modal?.classList.contains('is-open'))close();});

  if(!fine||reduced)return;

  const dot=document.querySelector('.cursor-dot'), ring=document.querySelector('.cursor-ring'),
        label=document.querySelector('.cursor-label'), preview=document.querySelector('.work-preview'),
        pvVisual=document.getElementById('preview-visual'), pvNo=document.getElementById('preview-no'),
        pvTag=document.getElementById('preview-tag'), pvYear=document.getElementById('preview-year');
  let mx=innerWidth/2,my=innerHeight/2,rx=mx,ry=my,px=mx,py=my,vx=0;
  addEventListener('pointermove',e=>{
    mx=e.clientX;my=e.clientY;
    if(dot&&dot.style.opacity!=='1'){dot.style.opacity='1';ring.style.opacity='1';}
  },{passive:true});
  document.querySelectorAll('[data-cursor]').forEach(el=>{
    el.addEventListener('mouseenter',()=>{label.textContent=el.dataset.cursor;ring.classList.add('is-active');});
    el.addEventListener('mouseleave',()=>ring.classList.remove('is-active'));
  });
  document.querySelectorAll('.work-row').forEach(row=>{
    row.addEventListener('mouseenter',()=>{
      const p=D.projects.find(x=>x.id===row.dataset.projectId); if(!p||!preview)return;
      pvNo.textContent=p.index; pvTag.textContent=p.scope.toUpperCase(); pvYear.textContent=p.year;
      preview.classList.add('is-visible');
    });
    row.addEventListener('mouseleave',()=>preview?.classList.remove('is-visible'));
  });
  document.querySelectorAll('.magnetic').forEach(el=>{
    const s=parseFloat(el.dataset.magnetic||'0.25'); let rect=null;
    el.addEventListener('mouseenter',()=>{rect=el.getBoundingClientRect();});
    el.addEventListener('mousemove',e=>{
      if(!rect)return;
      const dx=(e.clientX-(rect.left+rect.width/2))*s, dy=(e.clientY-(rect.top+rect.height/2))*s;
      el.style.transform=`translate3d(${dx}px,${dy}px,0)`;
    });
    el.addEventListener('mouseleave',()=>{
      rect=null; el.style.transition='transform .55s cubic-bezier(.22,1,.36,1)';
      el.style.transform='translate3d(0,0,0)';
      setTimeout(()=>{el.style.transition='';},550);
    });
  });
  function raf(){
    rx+=(mx-rx)*0.16; ry+=(my-ry)*0.16;
    vx=(mx-px)*0.25; px+=(mx-px)*0.12; py+=(my-py)*0.12;
    if(dot)dot.style.transform=`translate3d(${mx}px,${my}px,0)`;
    if(ring)ring.style.transform=`translate3d(${rx}px,${ry}px,0)`;
    if(preview){
      const tilt=Math.max(-8,Math.min(8,vx*.35));
      const scale=preview.classList.contains('is-visible')?1:.86;
      preview.style.transform=`translate3d(${px+28}px,${py-120}px,0) rotate(${tilt}deg) scale(${scale})`;
    }
    requestAnimationFrame(raf);
  }
  requestAnimationFrame(raf);
}

/* ---------- glass email: copy + event-driven light ---------- */
function initGlassEmail(){
  const box=document.querySelector('.email-glass');
  if(!box)return;
  const btn=box.querySelector('.eg-address'), hint=box.querySelector('#eg-hint');
  btn?.addEventListener('click',async()=>{
    const email=btn.dataset.copy;
    try{await navigator.clipboard.writeText(email);}catch(_){
      const t=document.createElement('textarea');t.value=email;document.body.append(t);t.select();document.execCommand('copy');t.remove();
    }
    if(hint)hint.textContent='COPIED ✓';
    box.classList.add('is-copied');
    setTimeout(()=>{if(hint)hint.textContent='COPY ↗';box.classList.remove('is-copied');},1600);
  });
  if(matchMedia('(pointer:coarse)').matches)return;
  box.addEventListener('pointermove',e=>{
    const r=box.getBoundingClientRect();
    box.style.setProperty('--mx',((e.clientX-r.left)/r.width*100)+'%');
    box.style.setProperty('--my',((e.clientY-r.top)/r.height*100)+'%');
  },{passive:true});
}

/* ---------- text reaction: event-driven, no per-frame layout reads ---------- */
function initTextReaction(){
  if(matchMedia('(pointer:coarse)').matches||matchMedia('(prefers-reduced-motion: reduce)').matches)return;
  const title=document.querySelector('.hero-title');
  const chars=[...document.querySelectorAll('.hero-title .tr-char')];
  if(!title||!chars.length)return;
  const ring=document.querySelector('.cursor-ring');
  let centers=[];
  const measure=()=>{ centers=chars.map(c=>{const r=c.getBoundingClientRect();return [r.left+r.width/2,r.top+r.height/2];}); };
  const reset=()=>{ chars.forEach(c=>{c.style.transform='';c.style.opacity='';}); if(ring)ring.classList.remove('is-text'); };
  // measure once after fonts settle, then on resize — never inside rAF
  (document.fonts?.ready||Promise.resolve()).then(()=>requestAnimationFrame(measure));
  addEventListener('resize',()=>{reset();requestAnimationFrame(measure);},{passive:true});
  let queued=false,mx=0,my=0;
  const apply=()=>{
    queued=false;
    let touched=false;
    for(let i=0;i<chars.length;i++){
      const [cx,cy]=centers[i];
      const dx=mx-cx, dy=my-cy;
      const dist=Math.hypot(dx,dy);
      if(dist<140&&dist>0.001){
        const f=1-dist/140;
        chars[i].style.transform=`translate3d(${-dx*0.18*f}px,${-dy*0.18*f}px,0)`;
        chars[i].style.opacity=String(1-f*0.45);
        touched=true;
      }else if(chars[i].style.transform){
        chars[i].style.transform='';chars[i].style.opacity='';
      }
    }
    if(ring)ring.classList.toggle('is-text',touched);
  };
  addEventListener('pointermove',e=>{mx=e.clientX;my=e.clientY;if(!queued){queued=true;requestAnimationFrame(apply);}},{passive:true});
  addEventListener('pointerleave',reset);
}

window.addEventListener('DOMContentLoaded',()=>{
  hydrate(); splitLines(); splitChars(); initClock();
  const lenis=initChoreography();
  initNavPill();
  initInteractions(lenis);
  initTextReaction();
  initGlassEmail();
});
