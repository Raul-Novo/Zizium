# Security model

Zizium security is based on identities, access tokens, privileges, security
descriptors, ordered ACLs, and per-handle access masks. The design does not use
POSIX owner/group/mode bits as its primary policy.

Identities are represented conceptually as `NID:SYSTEM`,
`NID:ADMINISTRATORS`, `NID:USERS`, `NID:GUESTS`, `NID:SERVICE:<name>`, and
`NID:USER:<id>`. Seed uses authority/value pairs internally; durable NID
encoding is not yet frozen.

Access bits are Read, Write, Execute, Delete, List, Create, ModifyAcl,
TakeOwnership, and their FullControl union.

## Implemented in Seed

The host-tested token validator requires a versioned token, a recognised user
authority, a bounded group array, and recognised group identities. The access
check validates versioned inputs, matches the token user and groups, processes
ordered deny and allow ACEs, accumulates partial grants, and succeeds only when
every requested bit is granted. A matching deny ACE rejects its intersecting
request. Missing or empty discretionary ACLs deny access. There is no implicit
administrator or SYSTEM bypass.

Every Seed user process is created with a validated token before its address
space is entered. The process owns a copy of the group array, preventing the
launch caller from changing group membership after creation. Teardown clears
that token storage together with the process slot. Host tests cover malformed
tokens and lifecycle binding in addition to ACL decisions.

Tests cover deny precedence, group grants, partial access, empty ACLs, invalid
inputs, and default denial.

ZiFS now stores versioned, checksummed security descriptors in its `ZISD`
region. Each `ZISE` record contains a nonzero security ID, owner, primary
group, descriptor control flags, DACL-presence flag, and up to 12 ordered ACEs.
The complete 1–16-block region has a CRC32C and every record has an independent
CRC32C. Mount rejects malformed identities, access masks, flags, ordering,
reserved bytes, checksums, duplicate IDs, and any live file record whose
security ID is absent.

`mkzifs.exe` assigns descriptor ID 1 to the initial hierarchy. The default
ordered DACL denies Guests mutation rights, grants SYSTEM and Administrators
FullControl, and grants Users Read, Execute, and List. A normal QEMU boot loads
that root descriptor and proves SYSTEM allow, Users read allow, Guests write
deny, and default deny for an unlisted identity. A separate corrupted-table
boot must reject direct mounting before policy use and may continue only via
the explicitly requested clean recovery module.

Every process now owns a generation-safe handle table. Handle creation checks
the object's security descriptor against that process token and records only
the granted mask. Every lookup checks the requested operation against the
stored mask and may require an exact object type. Duplication cannot request
rights absent from the source handle and repeats ACL evaluation with the
target process token; there is no trusted-process or administrator shortcut.

IPC handle transfer uses that same duplication boundary. Shared sections add
an immutable maximum-access mask, so an ACL grant cannot turn a read-only
section into a writable one. Malformed transfer masks and unknown access bits
are rejected before any target handle is created, and queue rollback closes a
handle created during a losing close/full race.

Every user process is also an ACL-secured process object. Public child creation
inherits an owned copy of the parent's token; the parent can receive only a
Read/Execute process handle. Core service launches derive explicit narrow
SYSTEM, service, or session-bootstrap tokens from validated manifest policy.
SessionHost and Luma use distinct identities, while their channel descriptor
contains ordered allow ACEs for only those two token users. No administrator or
SYSTEM bypass is introduced.

## Scaffolded

Object headers and ZiFS records carry security-descriptor references. Driver
loading and manifest `Permissions` remain policy reservations. Privilege bits
exist in access tokens but no privilege semantics are active. Bootstrap tokens
are supplied by trusted kernel launch policy rather than a logon or token-
creation service. File ACL loading, token-creation calls, IPC port creation,
and capability enforcement are not exposed, so the working boundary must not
be mistaken for complete authorisation.

ZiFS create, rename, move, truncate, and delete preserve or remove file-record
security references consistently. Creation rejects an unknown security ID.
Descriptor creation/update, deduplication, journalled ACL changes, inheritance
application, and owner changes are not yet exposed.

## Future

Durable identity storage, password hashing, logon, token creation, ACL
inheritance, owner changes, auditing, elevation, service isolation, app
capabilities, revocation, impersonation, and security-descriptor caching need
implementation and adversarial review. Privilege separation alone is not an
authorisation model; no protected service or user session should rely on the
Seed token contract yet.
