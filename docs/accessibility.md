# Accessibility

AnsiDeck aims to meet the [Web Content Accessibility Guidelines (WCAG) 2.1](https://www.w3.org/TR/WCAG21/)
at level AA, so that people who use a keyboard, a screen reader or other assistive technology can run
playbooks too. This page says what is checked, how, and what is known not to be covered yet. Problems are
bugs: please report them in [GitHub Issues](https://github.com/HoneyBearTech/AnsiDeck/issues).

## What is checked

- **Every pull request** runs [axe-core](https://github.com/dequelabs/axe-core) against every page and the
  sign-in screen in the frontend test suite (`frontend/src/test/a11y.test.tsx`), with the WCAG 2.0 and
  2.1 A and AA rules and axe's best practices. A violation fails CI. The tests also find controls the way
  assistive technology does, by their accessible names and roles, so an unlabelled control usually
  breaks a test too.
- **Colour contrast** can't be measured without a real browser, so it is checked with axe in headless
  Chrome against the built app (every page and the main dialogs), together with the rules above, when the
  UI changes. The last run (October 2026, before v0.1.0) found no violations.
- **Keyboard use** was checked in the same browser: everything can be reached with Tab in a sensible order
  and shows a visible focus ring; dialogs take focus, keep it inside while open, close with Escape and
  return focus to the control that opened them; selects open and choose with the keyboard. The
  focus-return behaviour has a regression test.

## How the UI is built for it

- Components are built on [Radix UI](https://www.radix-ui.com/) primitives, which implement the WAI-ARIA
  patterns (dialog, select, checkbox, switch) including focus management and keyboard support.
- Every form control has a visible label tied to it (or an `aria-label` where the visible text is
  elsewhere, such as a row's role selector), every page has one `<h1>` with section headings below it,
  and the app has header, navigation and main landmarks.
- Run output keeps its colours (ANSI) but never relies on colour alone: statuses are written out
  ("failed", "changed", "unreachable") next to their colour.
- Lint rules (`jsx-a11y` in oxlint) catch common mistakes such as missing labels or misused roles.

## Known gaps

- **Dark theme only.** The palette is designed and checked for the dark theme; there is no light or
  high-contrast theme yet.
- **English only.** The UI isn't translated, and its text isn't yet extracted for translation.
- **No screen-reader walk-through yet.** The checks above are automated plus a keyboard pass; nobody has
  yet tested complete tasks with a screen reader such as NVDA, JAWS or VoiceOver. Reports from people who
  do are very welcome.
- **Small screens.** The layout isn't designed for phones yet (planned, see the [roadmap](roadmap.md)).
