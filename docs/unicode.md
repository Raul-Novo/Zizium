# Unicode and text model

UTF-8 is the native byte representation for names and ordinary `char` strings.
A Unicode scalar is a 32-bit value excluding surrogates and values above
U+10FFFF. Invalid input is never silently treated as a filename.

Filesystem component comparison validates both operands and compares their
exact UTF-8 sequences. Seed performs no normalisation or case folding;
canonically equivalent sequences therefore remain different names.

## Implemented in Seed

- Strict UTF-8 validation and iteration.
- Rejection of overlong encodings, surrogates, truncation, illegal continuation
  bytes, and out-of-range scalars.
- Scalar-to-UTF-8 encoding and UTF-8-to-UTF-16 conversion primitives with
  explicit buffer sizing.
- U+FFFD replacement handling for display paths which choose recovery.
- Generated width/property ranges from pinned Unicode 17.0.0 data for terminal
  cell decisions, plus combining and wide-cell representations.

Host tests exercise boundaries, malformed sequences, replacement behaviour,
UTF-16 surrogate pairs, and canonically distinct paths.

## Scaffolded

Terminal cells hold a base scalar, two combining marks, width, and continuation
state. Input events carry scalars independently of key events. The public
design leaves room for grapheme segmentation, fallback fonts, and composition.

## Future

Complete grapheme-cluster rules, line breaking, bidirectional text, shaping,
full East Asian width policy, emoji sequences, collation, filesystem
normalisation migration, locale data, and IMEs require generated tables and
versioned policy. A later normalisation policy must never be enabled silently
on an existing ZiFS volume.
