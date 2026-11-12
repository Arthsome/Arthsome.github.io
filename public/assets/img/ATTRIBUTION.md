# Asset Attribution

All assets in `assets/img/` are self-hosted (no hotlinks). Sources below.

## Textures & icons — MOTION/LAB (CC0 1.0 Universal)

Retained after the forensic-editorial redesign (decorative layers removed):

- **Fractal noise displacement map** — `assets/img/textures/fractal-noise-large.webp`
  (evaluated during the liquid stage; removed when the stage was superseded
  by real 3D + footage). Pack: https://motionlab.one/assets/packs/grain-noise-textures-12/ — CC0 1.0.
- **Line icon sprite** — `assets/img/ui/sprite.svg` (48 icons, 24px grid,
  1.5px stroke, currentColor). Individual files removed; sprite only.
  Pack: https://motionlab.one/assets/packs/line-icons-48/ — License: CC0 1.0.

## Photography (removed)

Pexels stock photos (circuit board / mesh / server) were downloaded and
tested, then removed — the homepage now uses the site's own WHT article
figures (`assets/img/wht-shellcode/`, MIT-licensed research artefacts from
posts/wht-shellcode-obfuscation) as the primary visual material. Stock
originals: Pexels (Jakub Pabis, Jonathan Borba, Panumas Nikhomkhai).

## Liquid distortion effect

Signature scroll-linked liquid stage is a hand-rolled WebGL fragment shader
(`assets/js/liquid-stage.js`, GLSL ES 1.0, no external dependencies).
Inspired by **"Liquid Distortion Slideshow" by Yannis Yannakopoulos for
Codrops** (https://tympanus.net/Development/LiquidDistortion/); PixiJS/GSAP
are NOT vendored — the displacement math is re-implemented to keep the page
dependency-free. Codrops license: usable in personal/commercial integrated
projects; not redistributable as-is — this repo does not include their code.

## Placeholder portrait

`assets/img/portrait/crystal.png` — placeholder crystal. The real portrait
will be shot separately and processed into the existing particle halftone
pipeline (`assets/js/portrait.js`).

## 3D model — Grab3D (CC0)

- `assets/models/motherboard.glb` — motherboard, GLB, ~3.2 MB, ~39k verts,
  single mesh / single material (no separable components; no exploded view).
  Source: https://grab3d.com/models/electronics/motherboard/
  Direct: https://grab3d.com/dl/motherboard/motherboard.glb
  License: CC0. Rendered with Three.js in `assets/js/hero-3d.js` (inspired by
  the object-led direction of studio-merlin.com and ciechanow.ski).

## Footage — Pexels (Free Video License)

- `assets/video/circuit-a.mp4` (1920×1080, 19s) + poster — macro printed
  circuit board. https://videos.pexels.com/video-files/6754824/
- `assets/video/circuit-b.mp4` (1280×720, 13s) + poster — circuit close-up.
  https://videos.pexels.com/video-files/6754820/

Pexels License: free to use; no attribution required — recorded here for
provenance. Footage is never color-graded into neon/cyberpunk.
