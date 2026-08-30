# Display and per-monitor scaling

Display state is modelled as adapters, outputs, monitors, modes, framebuffers,
scale factors, and render surfaces. Scale belongs to each output/monitor pair;
there is no global zoom assumption.

## Implemented in Seed

The integer-only heuristic returns a reduced rational factor:

| Pixel height | Scale |
| ---: | ---: |
| up to 1080 | 1/1 |
| 1081–1440 | 5/4 |
| 1441–2160 | 2/1 |
| above 2160 | 5/2 |

Threshold tests cover every boundary. The Limine framebuffer is represented as
one output but is consumed through the general display structures. The early
terminal applies the factor to glyph pixels without floating point.

## Scaffolded

`ZiDisplayAdapter`, `ZiDisplayOutput`, `ZiMonitor`, `ZiDisplayMode`,
`ZiFramebuffer`, `ZiScaleFactor`, and `ZiRenderSurface` reserve multi-output
identity, geometry, pixel format, physical dimensions, and scale.

## Future

EDID, mode setting, hotplug, independent output transforms, fractional-quality
text rendering, user overrides, compositor surfaces, colour management, HDR,
and accessibility magnification are not implemented.
