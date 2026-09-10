# Zizium service manifests

These version-one `.zsvc` files define stable service identity, executable,
dependency, start-order, restart, permission, logging, token-policy, and
implementation-status fields. The strict parser validates all manifests and
the Phase 6 bootstrap supervises ServiceHost, SecurityHost, LogHost, MountHost,
and SessionHost. The remaining manifests reserve future services.

Passing parser validation does not authorise a launch. The kernel separately
matches the exact name, executable, declared identity and token policy against
its approved bootstrap table; `Permissions` cannot mint privileges.
SessionHost now declares `NID:SERVICE:SessionHost`, retains `SessionBootstrap`,
and runs as reserved SERVICE:3 with Users membership only. LogHost/MountHost
reserve SERVICE:1/2; only ServiceHost and SecurityHost use SYSTEM:1, without
group memberships. Luma likewise has Users, not Administrators membership.
Old SessionBootstrap manifests declaring NID:SYSTEM are rejected. Rebuild the
image after updating these files. These reserved pairs are not durable account
issuance; see [the service contract](../../../docs/services.md).

Paths are case-sensitive. `Status=Scaffolded` must remain on each future service
until its named PE programme has a real implementation and a verified launch
path. `Status=Implemented` means only the documented Phase 6 bootstrap contract;
it does not claim a persistent production service manager.
