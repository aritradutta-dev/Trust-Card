---
name: Trust Card
colors:
  surface: '#faf8ff'
  surface-dim: '#d2d9f4'
  surface-bright: '#faf8ff'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f2f3ff'
  surface-container: '#eaedff'
  surface-container-high: '#e2e7ff'
  surface-container-highest: '#dae2fd'
  on-surface: '#131b2e'
  on-surface-variant: '#434655'
  inverse-surface: '#283044'
  inverse-on-surface: '#eef0ff'
  outline: '#737686'
  outline-variant: '#c3c6d7'
  surface-tint: '#0053db'
  primary: '#004ac6'
  on-primary: '#ffffff'
  primary-container: '#2563eb'
  on-primary-container: '#eeefff'
  inverse-primary: '#b4c5ff'
  secondary: '#515f74'
  on-secondary: '#ffffff'
  secondary-container: '#d5e3fc'
  on-secondary-container: '#57657a'
  tertiary: '#006058'
  on-tertiary: '#ffffff'
  tertiary-container: '#007b71'
  on-tertiary-container: '#b3fff3'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#dbe1ff'
  primary-fixed-dim: '#b4c5ff'
  on-primary-fixed: '#00174b'
  on-primary-fixed-variant: '#003ea8'
  secondary-fixed: '#d5e3fc'
  secondary-fixed-dim: '#b9c7df'
  on-secondary-fixed: '#0d1c2e'
  on-secondary-fixed-variant: '#3a485b'
  tertiary-fixed: '#89f5e7'
  tertiary-fixed-dim: '#6bd8cb'
  on-tertiary-fixed: '#00201d'
  on-tertiary-fixed-variant: '#005049'
  background: '#faf8ff'
  on-background: '#131b2e'
  surface-variant: '#dae2fd'
typography:
  headline-xl:
    fontFamily: Inter
    fontSize: 36px
    fontWeight: '600'
    lineHeight: 44px
    letterSpacing: -0.02em
  headline-xl-mobile:
    fontFamily: Inter
    fontSize: 28px
    fontWeight: '600'
    lineHeight: 36px
    letterSpacing: -0.015em
  headline-lg:
    fontFamily: Inter
    fontSize: 28px
    fontWeight: '600'
    lineHeight: 36px
    letterSpacing: -0.015em
  headline-lg-mobile:
    fontFamily: Inter
    fontSize: 22px
    fontWeight: '600'
    lineHeight: 30px
    letterSpacing: -0.01em
  headline-md:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '600'
    lineHeight: 24px
    letterSpacing: -0.005em
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 26px
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 22px
  body-sm:
    fontFamily: Inter
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 20px
  label-badge:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '600'
    lineHeight: 16px
    letterSpacing: 0.02em
  mono-inspection:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '500'
    lineHeight: 20px
    letterSpacing: -0.01em
  mono-inspection-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '500'
    lineHeight: 16px
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-desktop: 1.5rem
  margin: 1rem
  margin-tablet: 2rem
  margin-desktop: 2.5rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 1rem
  space-lg: 1.5rem
  space-xl: 2rem
---

## Brand & Style

This design system establishes an environment of quiet vigilance, clinical clarity, and responsible reassurance. Designed for users evaluating suspicious links, SMS phishing hooks, and deceptive communication context cues, the interface avoids alarmist theatrics, sensory overload, and false absolutes. 

The aesthetic marries high-integrity editorial minimalism with precision diagnostics. The UI acts as a calm investigative lens:
- **Atmospheric Calm:** Warm, non-sterile off-white canvases ground the experience, eliminating glare and anxiety.
- **Epistemic Humility:** The interface never stamps an absolute "Safe" badge on unknown entities. It reports factual observations with structured clarity (e.g., "No strong warning markers detected" rather than "Guaranteed safe").
- **Inspectable Anatomy:** Technical details (URLs, registrar dates, redirect chains) are rendered with uncompromising legibility using dedicated monospaced tokens, distinct from conversational guidance.
- **Evidence-Driven Hierarchy:** Information unfolds progressively—from high-level assessment to scannable evidence cards, down to raw forensic context.

## Colors

The palette balances soft organic neutrals with surgical indicator accents. Every tint and shade satisfies WCAG AAA legibility standards against light surfaces.

### Surfaces & Neutral Architecture
- **Base Canvas (`#FBFBFA` / `#F7F6F2`):** A soft, parchment-tinged canvas that prevents screen fatigue and differentiates floating cards naturally.
- **Card Surface (`#FFFFFF`):** High-clarity white for modular cards, input areas, and inspection panels.
- **Surface Border (`#E2E8F0` / `#E5E7EB`):** Subtle, grounding lines providing structural containment without visual noise.
- **Primary Ink (`#0F172A`):** Deep slate-navy for headline hierarchy, body copy, and structural anchors.
- **Secondary Slate (`#475569`):** Subdued slate for supporting text, inspectable metadata keys, and secondary descriptors.
- **Muted Caption (`#64748B`):** Tertiary slate for timestamps, footnote disclaimers, and inactive cues.

### Functional & Threat Status Tokens
- **Primary Action (`#2563EB` / Active `#1D4ED8`):** Reserved exclusively for intentional, deliberate user actions (e.g., "Inspect Link", "View Deep Scan"). Never used decoratively.
- **Caution / Suspicious Flag:**
  - Ink: `#B45309` (Amber dark)
  - Accent / Icon: `#D97706`
  - Background Container: `#FEF3C7`
  - Border Container: `#FDE68A`
- **Critical / Threat Marker:**
  - Ink: `#B91C1C` (Red deep)
  - Accent / Icon: `#DC2626`
  - Background Container: `#FEE2E2`
  - Border Container: `#FECACA`
- **Low-Risk / Neutral Baseline ("No strong warning markers found"):**
  - Ink: `#0F766E` (Slate-teal deep)
  - Accent / Icon: `#0D9488`
  - Background Container: `#CCFBF1`
  - Border Container: `#99F6E4`
  - *Rule:* Always accompanied by explanatory language. Never use neon greens or declarative "Safe" assertions.

## Typography

The typographic engine uses **Inter** for conversational prose and systemic hierarchy, paired with **JetBrains Mono** for forensic URL dissections, domain breakdowns, and security certificates.

### Typographic Principles
- **URL & Hostname Treatment:** URLs are never presented as unbroken plain body text. Hostnames, top-level domains, and path parameters use `mono-inspection` to expose homoglyphs, zero-width characters, and subdomain spoofing.
- **Rhythmic Vertical Proportion:** Body text maintains a generous line-height (`1.6x` to `1.62x`) to preserve effortless scanning when reviewing dense risk summaries.
- **Semantic Weight Distribution:** Semibold (`600`) is used deliberately for card titles, risk scores, and badges. Regular (`400`) handles narrative deductions. Bold (`700`) is avoided to keep the interface balanced and composed.

## Layout & Spacing

A mobile-first, single-column reading column drives the architectural layout. On larger screens, the interface expands into an inspected dual-column workbench without stretching primary readable surfaces.

### Column Systems & Breakpoints
- **Mobile (<640px):** Single-column layout. Margin is `1rem` (`16px`), gutter is `1rem`. The maximum inspection container width is `100%`, anchored by ergonomic top and bottom taskbars.
- **Tablet (640px–1023px):** Centered layout column with a max width of `640px`. Margin expands to `2rem`.
- **Desktop (≥1024px):** Fixed-center container maxing at `840px` for standard inspection, or an optional asymmetric `1040px` split (65% Primary Evidence Column / 35% Technical Metadata Inspector). Canvas margins expand to `2.5rem`.

### Spacing Cadence
- **`space-xs` (4px):** Micro gaps between badge text and status icons.
- **`space-sm` (8px):** Tight stack between related inspection labels and value pairs.
- **`space-md` (16px):** Standard internal padding for cards, inputs, and button insets.
- **`space-lg` (24px):** Distance separating independent evidence cards and alert tiers.
- **`space-xl` (32px):** Section breaks between verdict panels and historical inputs.

## Elevation & Depth

Visual hierarchy uses **tonal layer separation combined with soft-diffusion ambient shadows** and **crisp, low-contrast structural outlines**. Heavy dropshadows and glossy skeuomorphism are absent; depth signals tactile interaction and hierarchical focus.

### Surface Tiers
- **Tier 0 (Background):** Neutral canvas (`#FBFBFA`). Receives no elevation.
- **Tier 1 (Resting Cards & Inspection Blocks):** Pure white (`#FFFFFF`) surface framed by a 1px border (`#E2E8F0`) and an ambient, low-opacity shadow:
  - `box-shadow: 0 1px 3px 0 rgba(15, 23, 42, 0.04), 0 1px 2px -1px rgba(15, 23, 42, 0.03)`
- **Tier 2 (Elevated Focus / Interactive Hover):** Elevated search inputs during focus, active modals, and pulled-out detail panels:
  - `box-shadow: 0 8px 16px -4px rgba(15, 23, 42, 0.05), 0 4px 6px -2px rgba(15, 23, 42, 0.02)`
  - Border tint softens slightly to `#CBD5E1`.
- **Tier 3 (Floating Action Bars / Critical Sheets):** Docked bottom cards on mobile:
  - `box-shadow: 0 -4px 12px 0 rgba(15, 23, 42, 0.04), 0 20px 24px -4px rgba(15, 23, 42, 0.06)`

## Shapes

The design system incorporates a **Rounded (Level 2)** shape vocabulary, using calibrated corners to convey approachability while maintaining technical precision.

- **Base Radius (`0.5rem` / `8px`):** Default for input fields, action buttons, alert boxes, and secondary chips.
- **Container Radius (`rounded-lg` / `1rem` / `16px`):** Used on primary assessment cards, evidence cards, and analysis modules.
- **Modal & Sheet Radius (`rounded-xl` / `1.5rem` / `24px`):** Applied to mobile bottom drawer handles, deep-dive forensic modals, and search panels.
- **Pill Geometry:** Reserved strictly for high-contrast context badges (e.g., `TLD: .xyz`, `Redirect Detected`) to visually separate metadata tokens from rectangular interactive targets.

## Components

### 1. Primary Verdict Card
- **Structure:** Anchored at the top of an analysis view. Features a crisp white background with a 1px border colored according to risk context (`#FECACA`, `#FDE68A`, or `#99F6E4`).
- **Header:** Features an integrated badge (e.g., "Caution Warranted", "No Strong Warnings Detected") accompanied by a plain-language summary in `headline-md`.
- **Verdict Disclaimer:** Accompanied by a standardized, unclickable caption: *"Based on real-time domain age, DNS configurations, and threat database matching. New attacks emerge continuously."*

### 2. Evidence Items & Lists
- **Structure:** Modular, stacked horizontal cards containing scannable findings (e.g., Domain Age, SSL Issuer, Urgency Language Analysis).
- **Layout:** Icon container (left, 36x36px with 8px radius) tinted to match finding severity, title in `headline-sm`, rationale in `body-md`, and technical forensic data presented in a secondary block with `mono-inspection`.
- **Dividers:** Cards remain visually isolated with `space-sm` gaps rather than hairline separators, maintaining readability on mobile.

### 3. High-Contrast Accessible Badges
- **Shape & Spec:** Full pill shape (`border-radius: 9999px`), vertical padding `4px`, horizontal padding `10px`.
- **Typographic Scale:** `label-badge` (`12px`, weight `600`).
- **States:**
  - *Threat:* Background `#FEE2E2`, border `#FECACA`, text `#B91C1C`.
  - *Caution:* Background `#FEF3C7`, border `#FDE68A`, text `#B45309`.
  - *Neutral Observation:* Background `#CCFBF1`, border `#99F6E4`, text `#0F766E`.
  - *Informational Meta:* Background `#F1F5F9`, border `#E2E8F0`, text `#475569`.

### 4. Interactive Input Fields
- **Container:** Pure white, minimum touch target height `48px` (mobile optimized), `0.5rem` border-radius.
- **Default State:** Border `#E2E8F0`, placeholder text `#94A3B8`, text `#0F172A`.
- **Focus State:** Border `#2563EB`, outer ring glow `0 0 0 3px rgba(37, 99, 235, 0.12)`.
- **Mono Mode:** For raw URL pastes, typography dynamically shifts to `mono-inspection` with automatic protocol and host parsing.

### 5. Buttons
- **Primary:** Background `#2563EB`, text `#FFFFFF`, hover `#1D4ED8`, height `48px`, semibold `14px`. Soft diffused drop-shadow `rgba(37, 99, 235, 0.15)`.
- **Secondary / Tertiary:** Background `#FFFFFF`, border `1px solid #E2E8F0`, text `#0F172A`, hover `#F8FAFC`.
- **Destructive Action (e.g., "Block & Report Domain"):** Background `#FEE2E2`, border `1px solid #FECACA`, text `#B91C1C`, hover `#FCDADA`.

### 6. Interactive Inspection Accordions
- **Design:** Nested inside evidence cards to conceal heavy technical data (DNS TXT records, WHOIS registrant JSON, SSL SHA fingerprints).
- **Toggle Mechanism:** Clear chevron indicator paired with descriptive count label (e.g., "View 3 Redirect Hops"). Monospaced readouts inside are rendered inside a recessed container with background `#F8FAFC` and border `#E2E8F0`.