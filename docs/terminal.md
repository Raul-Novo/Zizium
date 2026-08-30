# Terminal and Luma

The terminal stores Unicode cells independently from framebuffer pixels. Its
visible viewport is a window over a larger scrollback ring; scrolling does not
mutate the underlying logical lines.

## Implemented in Seed

The caller supplies bounded cell and line-use storage. Cells hold a scalar, two
combining scalars, foreground/background colours, display width, and
continuation flags. The ring supports wrapping, new lines, scrollback eviction,
viewport Page Up/Page Down movement, clearing, and UTF-8 writes. A separate
bounded command-history ring supports previous/next navigation.

The framebuffer console validates a 32-bit XRGB surface, selects a rational
per-output scale, renders generated Spleen 8×16 glyphs, provides U+FFFD fallback,
draws a cursor, wraps, and mirrors diagnostics to COM1. Unsupported surfaces
fall back to serial.

Early Luma polls COM1 and provides bounded UTF-8 line editing, history,
whitespace and quoted-argument parsing, and the commands `Help`, `Version`,
`Get-Memory`, `Get-Volume`, `Get-File`, `Show-Log`, `History`, and
`Clear-Screen`. `Get-File` uses exact ZiFS lookup.

Normal boot now launches `C:\Zizium\Shell\luma.exe` as a real Ring-3 PE from
ZiFS. SessionHost sends it a versioned channel handshake and the bounded command
`Start-Process "C:\Program Files\Zizium\Hello Seed.exe"`. Luma uses the shared
UTF-8 quote parser, first proves that a wrong-case image path fails, then calls
the public create/wait/close path for the exact file. It polls the still-
initialised child, runs and waits with an infinite timeout, requires exit code
21, and rejects the stale closed handle. This is a genuine process-launch
vertical slice, not yet an interactive user console.

The kernel-integrated serial command loop is no longer the normal interface.
It runs only for `zi.shell=recovery`, `zi.storage=module`, or the injected
storage-recovery gates and emits the legacy `LUMA_READY` marker there.

Tests cover wrapping, eviction, viewport movement, history, quoting, spaces,
incomplete quotes, argument limits, Unicode input, and distinct `I`, `l`, `1`,
`O`, and `0` glyphs.

## Scaffolded

Interactive console IPC, keyboard-driven user-mode Luma, object-valued pipeline
output, redirection, richer line editing, asynchronous output, and true
framebuffer scrollback navigation are interfaces or design only. The current
user-mode Luma consumes one bootstrap command and exits cleanly.

## Future

Persistent user-mode command reading, scripting, completion, permissions,
command discovery, terminal escape policy, grapheme-aware editing, selection,
clipboard, IME/dead-key composition, font fallback, accessibility hooks, and
multiple terminal windows remain unimplemented.
