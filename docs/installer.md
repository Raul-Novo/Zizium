# Zizium Setup

Zizium Setup will select disks, create GPT partitions, preserve or create the
EFI System Partition, format ZiFS, install boot files, create recovery storage,
detect hardware, choose initial packages, and create the first account.

## Implemented in Seed

The host image builder deterministically creates a development GPT image with a
FAT32 EFI System Partition and ZiFS partition. `mkzifs` formats the system
hierarchy. This is a build artefact generator, not an installer.

## Scaffolded

The partition GUID, boot layout, filesystem formatter, recovery directories,
service/package concepts, and future account model define inputs to Setup.

## Future

Interactive UI, destructive-action confirmation, disk enumeration,
partition resizing, EFI boot-variable installation, real-device ZiFS format,
hardware assessment, package selection, account creation, recovery partition,
repair mode, upgrades, rollback, and installation logs are unimplemented.
