# Vance — design system notes

The site is branded **Vance**. The system is called **Instrument & Archive**:
a precision-editorial light-mode layout in acid lime with one premium material
(Liquid Glass). No aurora orbs, no conic-gradient spheres, no decorative
dataviz, no three-column feature grid, no gradient text.

## System

| Axis | Decision |
|---|---|
| Canvas | `#F4F5EE` warm paper, 0.6px dot grain + SVG turbulence noise, `#FAFAF6` elevated |
| Ink | `#121712` / `#464D43` / `#798174` (hierarchy by role, not invented greys) |
| Signal | `#B6F13B` acid lime — highlighter swipe, index numbers, status, button flow |
| Display | **Gloock** — high-contrast editorial serif, 400 only, `-.022em` tracking |
| Text | Onest, 17px / 1.62 |
| Micro | IBM Plex Mono, uppercase, `.1em` tracking — indices and labels |
| Quote | Instrument Serif — used exactly once, for the position statement |
| Rhythm | 8px base, 1320px max, hairline rules, numbered sections |
| Motion | one easing `cubic-bezier(.22,1,.36,1)`, GSAP + Lenis, reduced-motion fallback |

## Logo — the Vance mark

A monogram/lettermark: one ribbon folded into a faceted **V**, with a cut notch
at the base and a single signal dot. Rationale from the 2026 logo research:

- *Simple, memorable, legible at favicon size* — the silhouette is two strokes;
  no text baked into the icon.
- *Works in black and white* — the shape carries the identity, the lime→mint→sea
  gradient is a secondary layer only. A mono version ships at
  `public/assets/img/vance-mark-mono.svg`.
- *Kinetic with one anchor* — the V is the constant; on the site it reveals
  left-to-right on load, the dot pops after it, the nav mark reacts on hover,
  and a large watermark of it floats behind the hero.
- *Tactile digitalism* — variable optical weight between the two arms instead
  of a uniform geometric stroke.

Files: `vance-mark.svg` (full colour), `vance-mark-mono.svg` (mono).

## Buttons — a shaped family, not rounded boxes

Every button uses the same **chamfered rectangle**: two opposed corners cut by
`--cut`, a 1px inset hairline frame, and a `drop-shadow` that follows the
silhouette. No `border-radius`, no pill. The cut is the semantic shape — it
reads as an instrument panel / file tab, consistent with a security researcher.

| Role | Shape | Fill |
|---|---|---|
| Primary | chamfer `12px` → `18px` on hover | flowing lime→mint→sea gradient, dark ink |
| Secondary | same silhouette, smaller chamfer `10px` | hollow frosted paper + lime hairline |
| Utility (nav) | chamfer `9px` | instrument black, lime signal text |
| Icon-only (copy) | circle | the one place a circle is semantically right |

The arrow travels on hover; press feedback starts on pointer-down via a ripple.

## Material recipe (`.glass`)

Four stacked optics, not a single blur:

1. translucent white tint gradient
2. `backdrop-filter: blur(26px) saturate(190%) brightness(1.02)`
3. specular inset top highlight + faint inner glow + a slowly rotating conic
   sheen (`@property --sheen-angle`) in lime/sea-glass
4. hairline outer rim + soft two-layer drop shadow

Used only on the nav, hero plate, contact dock, work case files and contact
panel. One hero plate adds an SVG displacement filter (`#liquid-refract`, scale
12) as a Chromium progressive enhancement. Glass **breathes with scroll**:
`--glass-blur` and `scale` are scrubbed on the plate, work cards and contact
panel; the nav condenses to `blur(34px) / scale(.97)` once scrolled.

Fallbacks: no `backdrop-filter`, `prefers-reduced-transparency`,
`prefers-contrast`, `prefers-reduced-motion`.

## References read

- [`bowen31337/apple-design`](https://github.com/bowen31337/apple-design) —
  liquid-glass layers, refraction recipe, token system; `motion-physics.md`
  (springs from live values, press feedback, velocity handoff) and `gsap.md`
  (CustomEase, quickTo, ScrollTrigger choreography).
- [`JUNGHERZ/GlassKit`](https://github.com/JUNGHERZ/GlassKit) — iOS 26 material
  vocabulary, fluid droplet timing, accessibility tokens.
- [`7uanf/glass-refraction`](https://github.com/7uanf/glass-refraction) —
  shimmer sweep, specular breathing, chromatic dispersion; restrained refraction.
- [`nextlevelbuilder/ui-ux-pro-max-skill`](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) —
  curated typography/style datasets. Gloock-type high-contrast serif and the
  glass/iridescent style entries informed the display and material choices.
- [`Ga14ctic/awwwards-skill`](https://github.com/Ga14ctic/awwwards-skill) —
  commission-one-unforgettable-element discipline and motion-lens consistency.
- [Adobe — Logo design tips and trends for 2026](https://www.adobe.com/express/learn/blog/logo-design-tips-trends) —
  survey of 285 designers: memorability, legibility, kinetic logos with one
  anchor, tactile digitalism, thumbnail testing.
- [Graphic Design Junction — How to Design a Logo, 2026](https://graphicdesignjunction.com/2026/08/how-to-design-a-logo/) —
  research → concept → monogram → vector → black-and-white and favicon testing.

Implementation is original and dependency-free beyond Astro/GSAP/Lenis. No code
was copied; the references informed decisions only.
