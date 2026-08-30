# Zizium service manifests

These version-one `.zsvc` files define stable service identity, executable,
dependency, start-order, restart, permission, logging, token-policy, and
implementation-status fields. The strict parser validates all manifests and
the Phase 6 bootstrap supervises ServiceHost, SecurityHost, LogHost, MountHost,
and SessionHost. The remaining manifests reserve future services.

Paths are case-sensitive. `Status=Scaffolded` must remain on each future service
until its named PE programme has a real implementation and a verified launch
path. `Status=Implemented` means only the documented Phase 6 bootstrap contract;
it does not claim a persistent production service manager.
