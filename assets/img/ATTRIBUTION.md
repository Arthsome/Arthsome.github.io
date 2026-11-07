# Asset Attribution

All assets in `assets/img/` are self-hosted (no hotlinks). Sources below.

## Textures & icons — MOTION/LAB (CC0 1.0 Universal)

- **Grain-noise texture pack** — `assets/img/textures/`
  Film grain, halftone dots, fractal noise, scanlines, dust/speckle,
  brushed metal, paper fibre. Procedurally generated, seamless 1024×1024 WebP.
  Source: https://motionlab.one/assets/packs/grain-noise-textures-12/
  License: CC0 1.0 — no attribution required; included here for provenance.
- **Line icon set (48 SVG, 24px grid, 1.5px stroke, currentColor)** —
  `assets/img/ui/` (sprite.svg + individual files).
  Source: https://motionlab.one/assets/packs/line-icons-48/
  License: CC0 1.0.

## Photography — Pexels License

Optimized to WebP (max-width 1600px) for web delivery; originals unchanged in source.

- `assets/img/research/pcb-circuit.webp` — dusty circuit board macro.
  Jakub Pabis. https://www.pexels.com/photo/close-up-of-a-dusty-computer-circuit-board-36169778/
- `assets/img/research/mesh-industrial.webp` — industrial metal mesh.
  Jonathan Borba. https://www.pexels.com/photo/close-up-of-industrial-metal-mesh-pattern-36346048/
- `assets/img/research/server-rack.webp` — server infrastructure.
  Panumas Nikhomkhai. https://www.pexels.com/photo/server-rack-in-modern-data-center-37605910/

Pexels License: free to use for personal/commercial projects; no attribution
required, provided here for provenance.

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
