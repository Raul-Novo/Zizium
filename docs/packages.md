# zpkg and `.zipkg` packages

The native package manager is `zpkg`. A `.zipkg` package will describe name,
semantic version, architecture, required Zizium version, files, services,
dependencies, permissions/capabilities, hooks, digital signature, and rollback
information.

Planned commands include `zpkg install`, `update`, `remove`, and `search`.

## Implemented in Seed

The ZiFS hierarchy reserves package, manifest, cache, and rollback directories.
No package parser, command, or installation transaction exists.

## Scaffolded

PackageHost and UpdateHost manifests reserve security and service ownership.
The service and capability documents define future integration constraints.

## Future

The archive format, canonical metadata encoding, repository protocol,
dependency solver, signature and trust policy, transactional installation,
hook sandbox, file ownership database, delta updates, rollback, removal, and
search are wholly unimplemented. Hooks must never run with ambient SYSTEM
authority.
