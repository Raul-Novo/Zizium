# Updates and recovery

The target update system uses signed, atomic system changes with rollback. ZiFS
snapshots may later provide a storage primitive, but recovery cannot depend on
an unimplemented feature.

Reserved locations include `C:\Recovery`, `C:\Recovery\Rollback`, and
`C:\System Volume\Snapshots`.

## Implemented in Seed

Only the directory hierarchy and service-manifest boundaries exist.

## Scaffolded

UpdateHost, PackageHost, CrashHost, recovery directories, journal space, and
package rollback metadata establish intended ownership.

## Future

Signed manifests, update staging, atomic activation, boot-success recording,
rollback selection, recovery boot, system repair, driver rollback, package
rollback, snapshot integration, and interrupted-update recovery are
unimplemented. Recovery must remain usable when the main ZiFS volume is damaged.
