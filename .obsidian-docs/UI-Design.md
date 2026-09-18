# UI Design Direction

Related: [[roadmap]] · [[Architecture]]

**Dark mode is the default and primary theme** (not a toggle added later). Overall feel: clean, smooth, futuristic — a control-deck for infrastructure, not a form-heavy admin panel.

## Visual Language
- **Base palette:** near-black / deep charcoal or deep navy background (avoid pure `#000` — flat black reads cheap; something like `#0a0e14`–`#12161f` range feels richer), with layered surface tones (2–3 shades lighter) to separate cards/panels/nav without hard borders.
- **Accent color:** one or two saturated accents against the dark base — electric cyan, violet, or a cyan→violet gradient reads "futuristic" without tipping into neon-cyberpunk cliché. Use the accent sparingly: primary actions, active states, run-status glow — not everywhere.
- **Status color coding should echo Ansible's own CLI conventions** so it feels familiar to anyone who's run playbooks before: green = ok/success, yellow = changed, red = failed/unreachable, cyan/blue = skipped. Keep this consistent across run history, live log view, and host status indicators.
- **Depth via glow/blur, not heavy borders/shadows** — subtle box-shadow glow on active/focused elements, soft backdrop-blur on modals/overlays (glassmorphism-lite) reads modern and futuristic without being gimmicky.
- **Motion:** smooth, short transitions (150–250ms ease-out) on state changes, hover, panel open/close. Live log output should stream in smoothly (auto-scroll, subtle fade-in per line) rather than jump-scrolling.

## Typography
- **UI font:** a clean modern sans — Inter, Geist, or similar variable font. Avoid anything default-system-feeling (no plain Arial/system-ui only).
- **Monospace for anything Ansible-related:** playbook YAML, live run output, inventory files — JetBrains Mono, Fira Code, or Geist Mono. This is a big part of the "futuristic ops tool" feel since the log viewer is the app's centerpiece.

## Suggested Implementation Path (fits the React/Vue + TS stack from [[Architecture]])
- **Tailwind CSS** for styling — fast to build a consistent dark theme with design tokens (CSS variables for the palette, so light mode later is a token swap, not a rewrite).
- **shadcn/ui + Radix primitives** (if going React) — unstyled, accessible components you skin yourself, which suits a custom dark/futuristic look far better than a pre-themed component library (e.g. Material UI fights you on this). If Vue is chosen instead, Radix Vue + the same Tailwind-token approach applies.
- A **terminal-style component** for the live log viewer specifically — monospace, dark background even relative to the rest of the UI, ANSI color pass-through (Ansible output already carries color codes worth preserving rather than stripping).

## Accessibility Guardrail
Dark + glow aesthetics can easily fail contrast requirements. Keep body text at minimum WCAG AA contrast against its background even where accents are more playful — this matters more here than on a typical marketing site since users will be reading run logs to debug real failures.

## Reference Points (mood, not literal copy)
Tools with a similar "dark, technical, clean" feel worth glancing at for inspiration: Vercel's dashboard, Linear, Raycast, GitHub's dark theme, Grafana's dark mode. Not to imitate wholesale, but they land the "professional futuristic ops tool" tone this roadmap is going for.
