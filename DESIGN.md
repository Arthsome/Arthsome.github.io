# Arthsome — design system notes

Landing page redesign, November 2026. The system is called **Instrument & Archive**:
a precision-editorial layout in acid-lime light mode with one premium material
(Liquid Glass). No aurora orbs, no conic-gradient spheres, no decorative
dataviz, no three-column feature grid, no gradient text.

## System

| Axis | Decision |
|---|---|
| Canvas | `#F4F5EE` warm paper, 0.6px dot grain at 5px pitch, `#FAFAF6` elevated |
| Ink | `#121712` / `#464D43` / `#798174` (hierarchy by role, not invented greys) |
| Signal | `#B6F13B` acid lime — highlighter swipe, index numbers, status, primary fills |
| Display | Bricolage Grotesque (variable wdth/opsz), tight `-.04em` tracking |
| Text | Onest, 17px / 1.62 |
| Micro | IBM Plex Mono, uppercase, `.1em` tracking — indices and labels |
| Quote | Instrument Serif — used exactly once, for the position statement |
| Rhythm | 8px base, 1320px max, hairline `#0000001f` rules, numbered sections |
| Motion | one easing `cubic-bezier(.22,1,.36,1)`, 0.4–1.2s, GSAP + Lenis |

## Material recipe (`.glass`)

Four stacked optics, not a single blur:

1. translucent white tint gradient
2. `backdrop-filter: blur(22px) saturate(180%)` — saturation is what makes glass read as lit
3. specular inset top highlight + faint inner glow
4. hairline outer rim + soft two-layer drop shadow

Used only on the nav, hero plate, contact dock, work case files and contact panel.
One hero plate adds an SVG displacement filter (`#liquid-refract`, scale 12) as a
Chromium progressive enhancement behind `@supports`. Fallbacks included for no
`backdrop-filter`, `prefers-reduced-transparency` and `prefers-contrast`.

Layout specifics: top nav is a floating glass bar on desktop; it becomes a
bottom floating glass tab bar on mobile with iOS safe-area insets and
IntersectionObserver-driven active state. All content, links, copy affordances,
GSAP reveals and counters from the original homepage are preserved.

## Open-source references read before building

- [`bowen31337/apple-design`](https://github.com/bowen31337/apple-design) — skill;
  `references/liquid-glass.md` (four-layer material model, specular highlight,
  `feTurbulence` + `feDisplacementMap` refraction, thickness→numbers table,
  accessibility fallbacks) and `references/tokens.md` (role-based semantic tokens,
  two-layer shadows, opacity-encoded labels).
- [`JUNGHERZ/GlassKit`](https://github.com/JUNGHERZ/GlassKit) — MIT, CSS-only;
  iOS 26 material vocabulary, fluid selection/droplet timing tokens, design
  tokens, light/dark theming, reduced-transparency handling.
- [`7uanf/glass-refraction`](https://github.com/7uanf/glass-refraction) — MIT;
  tiered glass surfaces, restrained refraction scale (8–16), specular breathing
  and chromatic dispersion as a progressive layer.
- [`nextlevelbuilder/ui-ux-pro-max-skill`](https://github.com/nextlevelbuilder/ui-ux-pro-max-skill) —
  design-intelligence skill; style/palette/type selection discipline.

Implementation is original and dependency-free beyond the existing Astro/GSAP/Lenis
stack. No code was copied from the referenced projects; their techniques informed
the material and token decisions above.
