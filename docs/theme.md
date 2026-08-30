# Visual theme

Zizium's default identity is calm, modern, light, precise, friendly, and
developer-oriented. It is not terminal-only as a long-term design.

The frozen Seed palette is:

| Name | Value |
| --- | --- |
| `ZI_COLOUR_PRIMARY` | `#6496e6` |
| `ZI_COLOUR_SOFT_ACCENT` | `#d1ecfc` |
| `ZI_COLOUR_BACKGROUND` | `#f7fbff` |
| `ZI_COLOUR_TEXT` | `#172033` |
| `ZI_COLOUR_MUTED_TEXT` | `#5f6f8a` |
| `ZI_COLOUR_PANEL_BORDER` | `#d7e7f8` |
| `ZI_COLOUR_SUCCESS` | `#63c785` |
| `ZI_COLOUR_WARNING` | `#e6b864` |
| `ZI_COLOUR_ERROR` | `#e66f6f` |

## Implemented in Seed

Public `ZiColour` values and British-spelled constants are defined. The early
framebuffer terminal uses the background, text, primary, muted, warning, and
error roles with serial fallback.

## Scaffolded

Theme roles, per-monitor scaling, font fallback, dark mode, and accessibility
requirements are documented but have no theme service or resource loader.

## Future

Aura and ZiUI theme resources, iconography, dark and high-contrast variants,
user customisation, animation policy, colour management, and theme packages are
unimplemented.

Optional Easter eggs may use `System21`, `BlueCore`, or `FirstLight` only in
hidden, harmless metadata. They must not affect boot, security, ABI, ZiFS, or
normal user behaviour and must never imply endorsement.
