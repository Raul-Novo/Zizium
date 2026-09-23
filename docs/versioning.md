# Versioning and release channels

Components use semantic versioning once their public contracts are stable.
Before 1.0, incompatible experimental format or ABI changes require an explicit
major/minor gate and migration notes; silent reinterpretation is forbidden.

The current implementation version is Zizium 0.3. Zizium 1.0 denotes the
daily-use acceptance boundary defined in the engineering roadmap, not a claim
about the current repository. Reference documentation uses version numbers and
subsystem names without release codenames.

Reserved release channels are Stable, Preview, and Nightly. These names do not
imply that a distribution or support programme currently exists.

## Implemented

The kernel, tools, PE placeholders, ZiFS header, structures, service manifests,
and dependency manifest carry explicit version values where needed. The target
name is `x86_64-pc-zizium-pe`. Zizium 0.3 includes verified bounded ZiFS durability;
identity and access management remain under development. This is an experimental
implementation, not a signed or publicly supported release.

## Scaffolded

Release-channel names and milestone ordering are documented. There is no
release metadata service or compatibility database.

## Future

ABI baselines, symbol versioning, component manifests, upgrade compatibility,
channel signing, support windows, deprecation, and release engineering remain
to be defined before public binary compatibility is promised.
