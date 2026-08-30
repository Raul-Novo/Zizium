# Power management

Power policy belongs to PowerHost while the kernel coordinates system and
device transitions. Planned operations include shutdown, restart, sleep,
hibernate, battery state, lid actions, display sleep, CPU states, device states,
and thermal policy.

## Implemented in Seed

Only device power-state values and a versioned power-manager structure exist.
QEMU termination is controlled by the host; the kernel has no shutdown path.

## Scaffolded

`PowerHost.zsvc`, driver power IRPs, device state, ACPI boot information, and
service dependencies reserve the architecture.

## Future

ACPI table parsing, SCI/GPE handling, power buttons, orderly shutdown, reboot,
sleep, hibernation images, battery and lid devices, CPU idle/performance states,
thermal zones, wake policy, and device transition ordering are unimplemented.
