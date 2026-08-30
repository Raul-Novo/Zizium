# Localisation

Project-owned source and the default English interface use British English.
Localisation data is separate from internal identifiers and must support
language packs, timezone data, locale date/time and number formatting, keyboard
layouts, decimal separators, calendars, and later right-to-left text and IMEs.

## Implemented in Seed

UTF-8 validation, scalar conversion, Unicode terminal storage, and a generated
Unicode 17.0.0 property foundation exist. The source spelling check enforces a
focused set of mandated British forms.

## Scaffolded

Keyboard layouts and composition state have versioned structures. Spanish is
the first required non-English keyboard/locale target, but no layout table or
translated string catalogue exists.

## Future

Timezone database, locale negotiation, resource bundles, plural rules,
date/time/numeric formatting, Spanish keyboard tables, language packs, RTL,
shaping, IME, fallback, and translation tooling are unimplemented.
