# Accessibility foundation

Accessibility is a system contract spanning input, display, text, sound,
applications, and services. Keyboard navigation, focus visibility, scalable
text, high contrast, reduced motion, screen reading, and alternative input must
not be retrofitted solely at the application layer.

## Implemented in Seed

The framebuffer terminal uses high-contrast theme roles, a visible cursor,
distinct glyphs, Unicode cells, and resolution-aware scaling. Serial output
provides a non-framebuffer diagnostic path.

## Scaffolded

Per-monitor scale, semantic input events, render surfaces, theme roles, and
future GUI IPC create extension points.

## Future

Accessibility trees, screen reader protocol, spoken output, keyboard-only GUI
operation, high-contrast themes, magnification, reduced motion, captioning,
switch input, focus policy, and accessibility testing are unimplemented.
