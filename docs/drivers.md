# Driver architecture

Zizium drivers are PE `.sys` images managed through driver objects, device
objects, typed dispatch tables, IRP-like requests, and layered device stacks.
Bus, function, and filter roles are explicit.

The planned hardware families include PCI/PCIe, ACPI, USB and HID, PS/2,
keyboard and mouse, display and monitor, HDMI and DisplayPort, SATA/PATA/IDE,
AHCI, NVMe, block storage, audio and SPDIF, printers, network, timers, RTC,
serial, memory information, battery, power, and thermal control.

## Implemented in Seed

Versioned `ZiDriverObject`, `ZiDeviceObject`, `ZiDriverContext`,
`ZiPlugAndPlayManager`, and `ZiPowerManager` structures exist. A validated
device-attachment helper links an upper and lower device. Checksummed ACPI
MCFG discovery drives bounded PCIe ECAM enumeration, BAR decoding/probing, and
exact-match function-driver selection. Discovered PCI functions are published
under exact-case `\System\Devices\PCI\...` names through real device objects.

The statically linked NVMe function driver attaches to the selected PCI device
stack, enables memory decoding and bus mastering, maps BAR0 uncached, creates
owned DMA-backed admin and I/O queues, identifies one namespace, publishes
`\System\Devices\Storage\NVMe0`, and services block read, write, and flush
requests through the I/O manager. Transfers are chunked through the existing
owned DMA buffer, checked for exact byte completion, and serialised by the
controller lock. It uses bounded polling and fails closed on controller fatal
state or timeout. QEMU now proves durable ZiFS commit, reboot, rollback, and
replay through this path. Representative keyboard and framebuffer `.sys`
files still link only as import-free PE placeholders.

## Scaffolded

Driver load and unload interfaces return `ZI_STATUS_NOT_IMPLEMENTED`. The
placeholder entry points report not implemented and cannot be loaded. Driver
kind, device power state, dispatch arrays, extension pointers, stack links, and
service-manifest input reserve the intended dynamic-driver contract. The NVMe
driver is built into the kernel; no `.sys` loader, general PnP state machine,
resource arbiter, or hot-unplug path exists.

## Future

PE driver mapping, signatures, driver identities, general PnP, controller
interrupts, MSI/MSI-X, IOMMU isolation, resource arbitration, unload safety,
power transitions, verifier checks, crash containment, scatter/gather and
per-request DMA mapping, AHCI, physical-hardware validation, and the remaining
hardware families stay unimplemented. The polling NVMe write path has only
been validated against QEMU 11; no physical-hardware support claim follows
from it or from a placeholder `.sys` artefact.
