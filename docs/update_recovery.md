# Updates and recovery

The target update system uses signed, atomic system changes with rollback. ZiFS
snapshots may later provide a storage primitive, but recovery cannot depend on
an unimplemented feature.

Reserved locations include `C:\Recovery`, `C:\Recovery\Rollback`, and
`C:\System Volume\Snapshots`.

## Implemented in Seed

ZiFS has transaction rollback/replay, redundant-superblock selection and
repair, explicit flush and clean-unmount state, and automatic recovery of a
valid transaction-free interrupted mount. A separate offline host utility can
repair only uniquely provable superblock redundancy, journal-header
redundancy, and transaction-free interrupted-mount states through a reviewed
plan/apply boundary. These are filesystem durability primitives, not a system
update, data-salvage, or general reconstruction facility. The directory
hierarchy and service-manifest boundaries also exist.

## Scaffolded

UpdateHost, PackageHost, CrashHost, recovery directories, journal space, and
package rollback metadata establish intended ownership. No native recovery UI
or user-mode repair service exists.

## Future

Signed manifests, update staging, atomic activation, boot-success recording,
rollback selection, recovery boot, system repair, driver rollback, package
rollback, snapshot integration, and interrupted-update recovery are
unimplemented. Recovery must remain usable when the main ZiFS volume is damaged.
