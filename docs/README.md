# Zizium documentation index

This index describes the current Zizium 0.3 documentation set. Each subsystem
document separates implemented behaviour from scaffolded interfaces and future
work. The verified storage implementation includes bounded durable mutation,
journalling, recovery, lifecycle handling, read-only inspection, and a separate
fail-closed offline repair tool. Durable identity and logon are the current
engineering focus; their status is not a production security claim.

The launch boundary enforces restricted service policy and token-bound
EXE/DLL/traversal access checks. See [services](services.md),
[security](security.md) and [PE/COFF](pe_coff.md); this is not secure logon.
Native-ID primitives and SYSTEM-only initial security-directory provisioning
are also implemented prerequisites; no production account has been provisioned.

Disabled-record persistence, private-policy validation and crash recovery are
host-tested. Six dedicated NVMe boots additionally verify durable issuance,
tombstones, non-reuse and access denials. Normal boot and logon do not use a
database yet; see the database contract and verification report.

## Foundations

- [Architecture](architecture.md)
- [Boot](boot.md)
- [Build and dependencies](build.md)
- [Microsoft x64 ABI](abi.md)
- [x64 exceptions and interrupts](interrupts.md)
- [PE/COFF](pe_coff.md)
- [Native syscalls](syscalls.md)
- [ZIA public API](api.md)
- [Versioning](versioning.md)
- [Continuation guide](continuation.md)

## Kernel and storage

- [Physical and virtual memory](memory.md)
- [Processes and Ring 3](processes.md)
- [Object manager](object_manager.md)
- [Scheduler](scheduler.md)
- [Security](security.md)
- [Native identity encoding and reservation](identity.md)
- [Bound identity database and storage](identity_database.md)
- [Identity and credential threat model](identity_security.md)
- [IPC](ipc.md)
- [I/O manager](io_manager.md)
- [Drivers](drivers.md)
- [ZiFS](zifs.md)
- [ZiFS offline repair](zifs_repair.md)
- [Debugging](debugging.md)
- [Logging](logging.md)

## Text, interaction, and display

- [Unicode](unicode.md)
- [Terminal](terminal.md)
- [Input](input.md)
- [Display scaling](display_scaling.md)
- [Theme](theme.md)
- [Fonts](fonts.md)
- [Accessibility](accessibility.md)
- [Language policy](language_policy.md)
- [Localisation](localisation.md)

## User mode and development

- [ZiCRT](zcrt.md)
- [ZCC](compiler.md)
- [SDK](sdk.md)
- [Runtime](runtime.md)
- [Services](services.md)
- [Accounts](accounts.md)
- [Application sandboxing](app_sandboxing.md)

## Long-term platform architecture

- [GUI](gui.md)
- [Networking](networking.md)
- [Audio](audio.md)
- [Power](power.md)
- [Packages](packages.md)
- [Updates and recovery](update_recovery.md)
- [Installer](installer.md)

The authoritative verification and implementation ledger is
[ZIZIUM_PROGRESS.md](../ZIZIUM_PROGRESS.md).
