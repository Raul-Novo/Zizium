# Fonts

The early boot font must visibly distinguish uppercase `I`, lowercase `l`,
digit `1`, uppercase `O`, and digit `0`. Missing glyphs render a replacement
symbol rather than silently becoming another character.

## Implemented in Seed

The build generates an embedded 8×16 bitmap table from Spleen 2.2.0 under its
BSD-2-Clause licence. The terminal renders scaled bitmap pixels, uses a
replacement glyph, and tests the five easily confused glyphs for distinct
bitmaps.

## Scaffolded

Terminal cells can retain Unicode scalars and combining marks. Display scale is
per output. The renderer currently has one bitmap face and no fallback chain.

## Future

Multiple faces and sizes, TrueType/OpenType parsing, shaping, hinting, font
fallback, emoji and symbols, variable fonts, subpixel policy, caching,
per-monitor metrics, and FontHost are unimplemented. The 8×16 font is suitable
for early diagnostics, not a complete daily-use text system.
