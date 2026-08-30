# Audio

The future `ZiAudio` stack consists of AudioHost, device endpoints, an audio
session per application, mixing, per-application volume, routing, capture
permissions, and a later low-latency path.

## Implemented in Seed

No audio data path or hardware driver is implemented.

## Scaffolded

`AudioHost.zsvc`, driver/device stacks, IPC, security identities, and power
states reserve integration points for output, input, audio jacks, SPDIF, and an
Intel HDA-style controller architecture without making a vendor endorsement.

## Future

PCM formats, clocks, resampling, mixing, sessions, exclusive and low-latency
modes, endpoint discovery, microphone consent, jack sensing, SPDIF, Bluetooth
audio, and hardware drivers remain unimplemented.
