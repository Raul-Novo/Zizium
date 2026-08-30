# Input architecture

Input separates physical scancodes, logical keycodes, modifier state, and
Unicode text events. Key events are not assumed to be ASCII text.

The model reserves input, keyboard, and mouse devices; Shift, Control, Alt,
AltGr, Caps Lock, and Num Lock; keyboard layouts; dead-key/composition state;
and timestamped text input.

## Implemented in Seed

Versioned structures and a strict translation boundary exist. The translation
routine validates devices and events, but returns
`ZI_STATUS_NOT_IMPLEMENTED` because no layout table is active. Early Luma input
comes from polled UTF-8 serial bytes, not a keyboard driver.

## Scaffolded

PS/2 and USB HID keyboard/mouse categories, layout-table pointers, composition
buffers, special keys, repeat state, and Spanish locale identifiers are
reserved. The keyboard `.sys` artefact is a non-runnable placeholder.

## Future

Interrupt input, PS/2, USB, mouse acceleration, Spanish and other layouts,
AltGr, dead keys, composition, IME, secure attention, input routing, and unusual
shortcut policy remain unimplemented.

Some laptop Fn combinations are consumed by keyboard firmware and never
reported as distinct scancodes. Zizium can only expose events the hardware or
firmware makes observable; it will not fabricate an Fn event.
