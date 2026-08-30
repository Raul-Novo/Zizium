# Graphical user interface

The future graphical stack consists of the Aura compositor, ZiUI toolkit, Home
desktop shell, Settings, Files, and the Luma terminal. It is light by default,
calm, keyboard navigable, accessibility-aware, and independently scaled per
monitor. Dark mode is an option, not the sole identity.

## Implemented in Seed

Only the shared colour palette, framebuffer abstraction, bitmap terminal, and
per-output scale heuristic are implemented. There is no window system.

## Scaffolded

Display adapters, outputs, monitors, modes, framebuffers, and render surfaces
provide names for later composition. IPC ports/channels are reserved for
display and input routing. Theme and accessibility requirements are documented.

## Future

Aura, ZiUI, Home, windows, surfaces, input focus, damage tracking, GPU
acceleration, accessibility tree, clipboard, drag-and-drop, notifications,
screen capture permissions, and all graphical applications remain absent.
