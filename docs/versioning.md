# Versioning and release channels

Components use semantic versioning once their public contracts are stable.
Before 1.0, incompatible experimental format or ABI changes require an explicit
major/minor gate and migration notes; silent reinterpretation is forbidden.

Planned milestones are:

- Zizium 0.1 “Seed”;
- Zizium 0.2 “Luma”;
- Zizium 0.3 “ZiFS”;
- Zizium 0.4 “ZIA”;
- Zizium 1.0 “Calm”.

Release channels are Stable, Preview, and Nightly.

## Implemented in Seed

The kernel, tools, PE placeholders, ZiFS header, structures, service manifests,
and dependency manifest carry explicit version values where needed. The target
name is `x86_64-pc-zizium-pe`.

## Scaffolded

Release-channel names and milestone ordering are documented. There is no
release metadata service or compatibility database.

## Future

ABI baselines, symbol versioning, component manifests, upgrade compatibility,
channel signing, support windows, deprecation, and release engineering remain
to be defined before public binary compatibility is promised.
