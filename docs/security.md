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

The Phase 8 prerequisite correction caps tokens at 16 group entries before any
group is read. SYSTEM, USER, and SERVICE may be token principals; GROUP may
only appear as a membership. Duplicate and invalid memberships are rejected.
The process-owned array uses the same capacity constant. An inheritance-only
ACE is still structurally validated but never grants or denies access to the
current object. This does not implement propagation or ACL inheritance.

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

The offline ZiFS repair boundary treats security metadata as evidence, never
as reconstructible data. A plan is refused when any security-table checksum,
descriptor, identity, ACE, or live security reference is invalid. The tool
cannot regenerate, discard, or weaken an ACL to make a volume mountable.

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
Read/Execute process handle. Core service launches derive explicit bootstrap
SYSTEM, service, or session-bootstrap tokens from validated manifest policy.
SessionHost and Luma use distinct identities, while their channel descriptor
contains ordered allow ACEs for only those two token users. No administrator or
SYSTEM bypass is introduced.

## Active Phase 8 work

Read [identity_security.md](identity_security.md) for the threat model and
credential dependency evaluation. The bootstrap now resolves only five approved
name/path/declared-identity/token-policy combinations. No manifest string alone
mints SYSTEM rights. Non-SYSTEM services, SessionHost, Luma and the ordinary-C
acceptance processes have Users membership, not Administrators. The two approved
SYSTEM hand-off programmes have no group memberships. All privileges remain zero.
Reserved service values are explicit and distinct, never hashes; see
[services.md](services.md) for their temporary scope and migration restrictions.

Every filesystem-backed executable and DLL source now requires Execute on each
traversed directory and Read plus Execute on the final file under its launch
token. No missing-token or SYSTEM bypass exists. Checks precede payload allocation
and reading; a failed later DLL check releases earlier source allocations.
Each acceptance process checks its own DLL sources, rather than reusing one
authorised source set across distinct tokens. Child launches use the parent's
owned token. The volume and token must remain stable through lookup/read: this
is enforced operationally by the synchronous single-writer bootstrap, not by a
new concurrent file-object or security-revocation lock.

Host tests include an actual old-hash collision, policy/path substitution,
restricted group rights, directory versus image access, absent tokens, missing
Read/Execute bits, DLL rollback, and corrupt policy. QEMU requires denial of an
unprovisioned SYSTEM service and of an image launch under an unlisted identity,
with no process publication or kernel-pool allocation leak.

The next security boundary is a durable, versioned NID and identity database,
credential-verified logon, database-derived token construction, persistent
ownership/default ACL inheritance, restricted service tokens, checked
privileges, explicit elevation, and structured audit evidence. Its initial
acceptance must isolate two local profiles and prove that neither malformed
database state nor a non-elevated token can acquire administrative rights.

## Scaffolded

Object headers and ZiFS records carry security-descriptor references. Driver
loading and manifest `Permissions` remain policy reservations. Privilege bits
exist in access tokens but no privilege semantics are active. Bootstrap tokens
are supplied by trusted kernel launch policy rather than a logon or token-
creation service. Public file ACL queries, token-creation calls, IPC port creation,
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
