# Zizium documentation index

This index describes the current Zizium 0.2 "Luma" documentation set. Each subsystem
document separates implemented behaviour from scaffolded interfaces and future
work. Phases 0–6 are complete; Phase 7's bounded writable ZiFS slice includes
file growth and multi-block directories but remains active pending clean
unmount and repair policy/tooling.

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
- [IPC](ipc.md)
- [I/O manager](io_manager.md)
- [Drivers](drivers.md)
- [ZiFS](zifs.md)
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
