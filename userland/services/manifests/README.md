# Zizium service manifests

These version-one `.zsvc` files define stable service identity, executable,
dependency, start-order, restart, permission, logging, token-policy, and
implementation-status fields. The strict parser validates all manifests and
the service and session bootstrap supervises ServiceHost, SecurityHost, LogHost, MountHost,
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

The new issuer-bound identity codec reserves dynamic values from 256 upwards,
but these bootstrap manifests are not enrolled database records. Do not convert
their declared strings into issued identities or migrate the reserved pairs
implicitly; see [the identity contract](../../../docs/identity.md).
New ZiFS images reserve `C:\Zizium\Security` for SYSTEM:1 only. The current
ServiceHost and SecurityHost bootstrap tokens share that access; no isolated
resident credential broker or authenticated account is implied.

The identity store validates the actual private descriptor and commits disabled
records through ZiFS, with host crash tests and six native persistence boots.
It has no service IPC or token-issuance
entry point yet; these manifests do not enrol accounts. See
[the database contract](../../../docs/identity_database.md).

Paths are case-sensitive. `Status=Scaffolded` must remain on each future service
until its named PE programme has a real implementation and a verified launch
path. `Status=Implemented` means only the documented service and session bootstrap contract;
it does not claim a persistent production service manager.
