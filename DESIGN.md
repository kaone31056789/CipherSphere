# CipherSphere two-system interface

## Design direction

CipherSphere has exactly two complete visual systems. They share the same accessible information architecture and security workflows, but their composition, material language, shape grammar, typography, density, and motion are intentionally different. The switcher is available from **Appearance** in the top-right navigation and from **Profile → Interface theme**. The choice persists locally.

### Cipher Noir

Cipher Noir is the default dark security console. It uses a near-black editorial canvas, strict one-pixel grid lines, square modules, sparse white typography, and a warm yellow signal color. Generative particle organisms visualize encrypted systems without conveying essential status. Content is arranged as an asymmetric technical publication rather than a collection of generic rounded cards.

- Flat black and charcoal planes
- Tight 1–2px corners and ruled dividers
- Warm yellow for primary actions and active state
- White particle spheres, radial circuits, and orbit lattices
- Direct, restrained control motion and scanning traces

### Signal Atelier

Signal Atelier is a warm material workshop. It uses an off-white paper chassis, large sculpted black islands, acid-yellow reveal surfaces, rounded cutouts, and an original layered sheet-and-lens object. Layouts feel like art-directed industrial product boards instead of a light recolor of Cipher Noir.

- Warm paper canvas with subtle grain
- Large black islands and 24–32px sculpted radii
- Acid yellow for selected and revealed surfaces
- Layered material sheets, optical cores, and dimensional object motion
- Oversized editorial type and playful-but-controlled spatial transitions

## Shared identity

The original CipherSphere mark combines an angular protected core with crossing orbital paths. The mark is SVG, remains recognizable in either system, and is always paired with the written product name where identity matters.

## Motion system

Theme changes use the browser View Transitions API when available, with a short opacity/scale fallback. Cipher Noir’s signature animation is a morphing particle system. Signal Atelier uses layered material and optical motion. Reveal, hover, and navigation feedback use transforms and opacity so layout does not jump.

Every persistent effect can be paused from the top-right **Pause effects** control or Profile settings. `prefers-reduced-motion: reduce` disables non-essential movement, smooth scrolling, and transition choreography. Animation never carries essential information.

## Accessibility behavior

- The document declares English, has a skip link, one `main`, and logical headings.
- Decorative art, particle canvases, and logo flourishes are hidden from assistive technology.
- Both systems maintain WCAG 2.2 AA text and control contrast.
- Focus uses a two-layer ring designed for both dark and light surfaces.
- Controls preserve readable labels, visible selected state, and practical 44px targets.
- Forms keep labels above controls and associate hints and errors through `aria-describedby`.
- Error messages announce assertively; success and preference changes announce politely.
- Tables retain semantic headers and scroll horizontally at narrow widths.
- At 980px navigation becomes a labeled disclosure; multi-column composition collapses without losing content or control order.

## Content rules

Labels use direct verbs: Encrypt, Decrypt, Download, Share, Delete. Security status is stated in text and never inferred from color or animation. Encryption keys remain visually distinct, selectable, and paired with explicit copy controls. Shared-file views never display or retrieve an encryption key from the server.
