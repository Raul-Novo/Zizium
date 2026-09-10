# Identity and credential security boundary

Review date: 2026-09-05. This document defines the Phase 8 threat model and a
dependency evaluation, not an authentication implementation. Read it with
[security.md](security.md), [accounts.md](accounts.md),
[services.md](services.md), and [zifs.md](zifs.md). The byte-level NID and
database specifications must refine these requirements without weakening them.

## Implemented

The existing executive validates Seed authority/value identifiers and owned
process tokens, evaluates ordered ACLs, and enforces granted handle rights.
ZiFS persists checksummed security descriptors and validates live references.
Its journal provides bounded old-or-new recovery for supported mutations.
The service/session path still uses trusted bootstrap tokens. No password is
accepted, no persistent account authenticates a session, and no elevation
service is operational.

The 2026-09-08 prerequisite implementation replaces hash-based service principals
with explicit reserved launch policy, removes bootstrap Administrators grants,
and checks directory and EXE/DLL ACLs under the launch token. These corrections
close those initial shortcuts but do not implement the database/issuer/logon
boundaries below. No candidate credential dependency has been adopted.

This review establishes design requirements only. A wire codec or a passing
format test does not establish identity issuance, database trust, credential
verification, or two-user isolation.

## Scaffolded

SecurityHost is the intended account/credential broker; SessionHost owns
interactive sessions; ServiceHost requests restricted service launches. Their
current hand-off programmes are not resident security services. Privilege and
inheritance fields reserve future semantics. Public token creation, protected
credential input, secret-memory services, database updates, and authentication
IPC remain unimplemented.

## Assets, adversaries, and trust boundaries

Protected assets include password inputs and verifiers, account state, group
membership, identity allocation history, profile ownership, ACLs, tokens,
privileges, session state, audit evidence, and the code/configuration that
interprets them. Confidentiality of verifiers matters even though they cannot
be used directly as passwords: copying them enables offline guesses.

In scope are an unprivileged process sending forged requests, an authenticated
user attacking another profile, malformed or substituted database bytes,
resource-exhaustion requests, service crashes, interrupted transactions, stale
tokens, and accidental or deliberate rollback. The eventual threat model must
also cover compromised services and hostile removable volumes.

| Boundary | Required decision |
| --- | --- |
| Untrusted process to SecurityHost | Authenticate the IPC peer using kernel-owned handles/tokens, bound all messages, and authorise each operation. Caller-supplied identity or role fields are never proof. |
| SecurityHost to executive | A narrowly granted token-issuance operation accepts only a broker-bound result for the current account generation and session request. It is not a general caller-supplied token constructor. |
| Credential input to verifier | Use a protected, session-bound path with explicit buffer ownership. Luma history, serial logs, environment, command arguments, clipboard, and ordinary terminal scrollback must not carry secrets. |
| ZiFS bytes to identity state | Validate structure, limits, authority binding, references, generations, and supported policy before publishing any account. A checksum alone confers no authority. |
| Account state to file/object access | Translate only identities from the active bound authority; construct immutable owned tokens and enforce ACLs at kernel boundaries. |
| Service manifest to launch token | Resolve a provisioned service identity and administratively approved policy. A manifest name or `Permissions` text cannot mint rights. |
| Security operation to audit storage | Publish bounded outcome records without secrets; protect the sink and make loss or inability to record visible. |

The current development boot, host image files, and debugger are trusted
operational inputs, not protected against a hostile host or firmware. Kernel
compromise, malicious DMA, modified boot media, and offline disk replacement
cannot be prevented by this initial account design. Secure Boot, authenticated
storage and trusted monotonic state require later implementation. Development
serial input must never be advertised as a secure password-entry channel.

## Durable identity and authority binding

Use a durable NID consisting conceptually of a local-authority UUID plus the
existing numeric authority and value. The UUID names the installation's
identity issuer, not a drive letter, display name, disk position, or host
machine name. Equality must include every component. Textual account names
are exact validated UTF-8 lookup attributes, not access-control identifiers;
renaming an account must not change its NID or its ACL ownership.

Keep the current two-field `ZiSecurityId` internal ABI unchanged until an
explicit migration is implemented. Do not silently append a UUID to existing
tokens or reinterpret the eight-byte identities already stored in `ZISE`.
The temporary bridge may admit only the one active, explicitly bound local
authority. A foreign authority with the same numeric pair must fail closed,
not lose its UUID during translation. Cross-authority ACLs need a versioned
descriptor/token representation or an explicit bijective mapping later.

The future database header must bind its local authority and database identity
to the configured system-volume identity and protected database object. A
volume UUID by itself is not trusted proof: both UUIDs and files can be copied.
Opening a path named `C:\Zizium\Security\...` is insufficient unless its
volume, object, policy, and active authority have been resolved through the
trusted boot/provisioning contract. Foreign or ambiguous database state must
disable authentication; it must not silently enrol itself.

Issuance rules:

- Reserve well-known/bootstrap pairs explicitly. Do not reinterpret a service
  ordinal or a test identifier as an authenticated local user.
- Allocate nonzero values monotonically within each authority class, persist
  the high-water mark with issuance, reject exhaustion, and never wrap.
- Deletion leaves a durable non-reuse rule or tombstone. A newly created
  account with the same name receives a new identity and cannot inherit stale
  ACL grants. Renaming and disabling preserve identity.
- Group membership must reference live records of the required type. Reject
  duplicates, self-membership, unsupported nesting, and foreign references.
- Restoring a snapshot must not permit reuse of identifiers issued after that
  snapshot. When a trusted high-water mark cannot be established, do not resume
  issuance under the old authority; recovery needs an explicit migration or a
  newly provisioned authority.
- Cloned installation images must enrol a new authority before accepting
  credentials. A deterministic development fixture UUID is test-only and must
  never become the identity of multiple installed systems.

## Database transactions, recovery, and rollback

The identity database belongs on ZiFS, with access restricted to the broker
and explicitly authorised administration/recovery operations. Ordinary users,
including unelevated administrator accounts, must not obtain raw read/write
handles to verifier records. Backup and repair tools are security principals
with explicit policy, not an exception to it.

Freeze maximum records, names, memberships, verifier bytes, and transaction
workspace before persistence is enabled. Use explicit byte encoding, supported
versions, lengths, reserved-zero fields, checksums, duplicate detection,
reference/type checks, and generation consistency. Never validate directly
over a caller-writable buffer and subsequently use its changed contents.

Account creation must not publish an enabled identity before its profile,
owner, ACL, credential state, and membership are durable. Existing ZiFS
transactions cannot yet perform all those changes as one general operation.
Either extend and test the transaction boundary or specify a resumable,
persisted disabled/provisioning state; every intermediate state denies logon.
Apply the same rule to password change, group modification, deletion,
ownership transfer, and audit obligations. Never claim multi-object atomicity
merely because each individual file write is journalled.

CRC32C detects accidental corruption and some torn writes. Anyone able to
replace a database can recompute it. ZiFS generations order recovery candidates
but are not authenticated monotonic counters. Even a valid MAC or signature
does not reject replay of an older authentic database unless its freshness is
bound to trusted state outside the replayed storage. Password hashing provides
neither database authenticity nor anti-rollback.

Within one running instance, reject older generations than the already accepted
state and invalidate in-flight verification results when the relevant account
or policy generation changes. Across reboot, the current platform cannot
reliably detect wholesale rollback. Record that limitation; do not claim that
a local generation field solves it. A future trusted-counter/key design must
define failure, backup, reset, migration, and recovery behaviour before use.

Corrupt, truncated, conflicting, unsupported, or unbound databases fail closed.
Do not fall back automatically to old verifiers or a permissive bootstrap
account. Recovery is a distinct, explicitly selected mode with a separate
authorisation policy and visible evidence. The existing offline ZiFS repair
tool must continue refusing security damage rather than reconstructing policy.

## Credential dependency evaluation

The algorithm candidate is Argon2id version 1.3. RFC 9106 gives two reference
profiles: 2 GiB with one pass, or 64 MiB with three passes for less memory;
both use four lanes, a 16-byte salt, and a 32-byte result. These are evaluation
inputs, not Zizium's approved operational parameters. The RFC also supplies
test vectors. [RFC 9106, sections 4 and 5](https://www.rfc-editor.org/rfc/rfc9106.html#section-4)

| Candidate | Evidence and integration assessment |
| --- | --- |
| libsodium | Upstream lists 1.0.22 in April 2026, signed release material and current MSVC work. Its high-level password API provides encoded parameters, verification, and rehash checks. Preferred maintained user-mode candidate; its larger platform surface needs a reviewed native port. [Releases](https://github.com/jedisct1/libsodium/releases/tag/1.0.22-RELEASE), [password API](https://raw.githubusercontent.com/jedisct1/libsodium-doc/master/password_hashing/default_phf.md) |
| Argon2 reference implementation | Upstream's latest listed release is 20190702. It exposes Argon2id, allocator callbacks, separate lane/thread counts, and memory-clearing controls. A narrower port/test-oracle candidate, but old release cadence warrants a current commit/security-maintenance audit; it does not prove abandonment or safety. [Releases](https://github.com/P-H-C/phc-winner-argon2/releases), [public interface](https://raw.githubusercontent.com/P-H-C/phc-winner-argon2/master/include/argon2.h) |

libsodium's top-level licence is ISC. The Argon2 reference package offers
CC0-1.0 or Apache-2.0; Apache-2.0 is the proposed choice if that package is
adopted, with notices retained. Neither is automatically relicensed as
Zizium-owned work. Inspect the exact selected source and its bundled notices
before distribution; these observations are not a completed licence audit.
[libsodium licence](https://raw.githubusercontent.com/jedisct1/libsodium/master/LICENSE),
[Argon2 reference licence](https://raw.githubusercontent.com/P-H-C/phc-winner-argon2/master/LICENSE)

Recommendation: evaluate libsodium first in a host-only interoperability and
resource-bound test harness; retain the reference implementation as a possible
narrower native adapter and independent vector oracle. Do not select a
dependency solely because it builds on Windows: a Windows library imports
host services and is not a Zizium PE library. The native target requires
reviewed allocation, entropy, memory protection, clearing, initialisation,
threading, CPU-dispatch, and failure adapters. Password work must run outside
interrupt handlers and dispatcher locks, preferably in isolated user-mode
SecurityHost after its execution and resource-limiting prerequisites exist.

No dependency was downloaded, added to the manifest, built, or approved by
this document. Before adoption, record an immutable revision, archive hash,
verified provenance, licence inventory, upstream security/update owner, native
patch list, reproducible build, scalar/SIMD tests, and all enabled algorithms.
Normal builds must remain offline. Fetch only through the explicit dependency
workflow under `external/deps`.

## Verifier policy and denial-of-service limits

The future credential record must store an explicit algorithm/version and the
exact cost parameters, salt, and result needed for verification. Do not let a
library's changeable default silently reinterpret an old verifier. libsodium
documents both encoded verifier storage and default-algorithm changes; its
verification API reads the encoded parameters.
[Password API contract](https://raw.githubusercontent.com/jedisct1/libsodium-doc/master/password_hashing/default_phf.md)

Before calling any password library, parse into owned bounded storage and
enforce Zizium's supported algorithms and minimum/maximum memory, passes,
lanes, salt/result lengths, and total record length. Reject excessive decimal
fields and arithmetic overflow before allocation. Never feed arbitrary encoded
parameters straight into a costly verifier. Parameters below the accepted
legacy policy require explicit migration or reset, not silent acceptance.

The initial live verifier should admit at most one expensive request at once,
with a bounded queue, per-origin/session and global rate limits, and reserved
memory so requests cannot exhaust kernel or session resources. Freeze concrete
queue, password-byte, cost, and time bounds only after measuring the native
guest and supported machines. Allocation failure, exhaustion, cancellation,
or verifier failure never produces a token. A timeout cannot safely interrupt
a library by freeing memory while it still uses it; stop the isolated worker
only through tested process cleanup or wait for bounded work to complete.

Unknown-user and wrong-password replies should avoid account enumeration and
use a bounded equivalent-cost path where appropriate. This must share the
same global admission limit; otherwise dummy verification becomes a denial-
of-service primitive. Backoff must not allow one attacker to permanently lock
out another user without a documented recovery policy. Do not promise perfect
timing indistinguishability without measurement and review.

Credential input is length-delimited; never silently truncate, trim, fold
case, or apply a filesystem transformation. Freeze and version a password
Unicode policy separately before accepting credentials. A byte-exact UTF-8
initial policy is possible, but later changes require migration and test
vectors rather than changing the meaning of existing secrets on upgrade.

Successful verification may request a cost upgrade, but persistence must be
transactional and recheck the credential generation before publication. Do not
overwrite a concurrently changed password. A verifier is not an encryption
key; do not invent a derivation or pepper scheme without an independently
reviewed key-storage and recovery design.

## Secret memory and entropy prerequisites

Provide a secret-buffer lifecycle with owned storage, minimum necessary
copies, compiler-resistant clearing, guarded access, and explicit cleanup on
success, failure, timeout, service crash, and session termination. Wipe password
input and temporary derived material as soon as no longer needed; ensure
compiler optimisation does not remove clearing. Mark relevant memory as
non-pageable and excluded from dumps before claiming those properties. The
current absence of paging is not a permanent secret-memory contract.

The Argon2 reference interface distinguishes optional password clearing from
internal-workspace clearing. A wrapper must own and clear its input regardless
of the library option; library defaults do not erase copies elsewhere.
[Argon2 memory controls](https://raw.githubusercontent.com/P-H-C/phc-winner-argon2/master/include/argon2.h)

A native entropy service must define its trusted sources, startup readiness,
reseed policy, failure reporting, and approved generator. Salt and installation
authority generation must fail if secure randomness is unavailable. Do not
substitute timestamps, CPU identifiers, unconditioned hardware instructions,
deterministic fixture seeds, or the ordinary build reproducibility seed.
Successful random output and unique fixture values alone do not validate an
entropy source. The library must consume a tested native provider rather than
silently attempting POSIX or Windows host APIs inside Zizium.

Do not log passwords, verifier payloads, salts paired with verifiers, raw token
bytes, secret buffers, or arbitrary credential request bodies. Crash capture,
IPC tracing, debugger access, and backup policy must honour this boundary.

## Tokens, ownership, elevation, and audit

The trusted broker must derive the user, effective groups, restrictions,
privileges, credential generation, account-policy generation, and session
binding from one validated account snapshot. Recheck account enabled/deleted
state and relevant generations after verification, before token issuance.
Use kernel-owned immutable copies; a caller cannot edit token membership.

Disabling an account, deleting it, changing group membership, or changing its
password needs an explicit token/session revocation rule. At minimum, block
new tokens immediately and define which existing sessions/handles survive.
Password change must not accidentally revive stale session identifiers.
Do not imply that closing one token revokes all previously granted handles.

Ownership is not an implicit FullControl grant. ACL inheritance must define
file/directory, inherit-only, inherited, and explicit ACE order, preserve deny
semantics, respect the on-disk ACE bound, and fail rather than truncate policy.
Creating a private profile under the current Users-readable default descriptor
is insufficient: install its private descriptor before exposing the profile
or enabling the account. Move semantics must state whether inherited entries
are retained or recalculated and preserve journalled old-or-new policy.

Unelevated administrator membership must not automatically become effective
administrative grants. Model disabled/deny-only groups or construct a genuinely
restricted token; require a versioned contract before adding those semantics
to the current token ABI. Elevation must bind explicit consent/credentials to
the exact request, target image, requested rights, and originating session.
The consent channel must resist spoofing and request replay. Service manifests
and parent processes cannot manufacture elevation. SYSTEM remains subject to
explicit policy; there is no implicit SYSTEM or administrator bypass.

Audit records should identify the event schema, boot/session/request IDs,
actor and target NIDs, policy/account generation, operation, requested rights,
decision, and `ZiStatus`. Record logon outcomes, account and group changes,
token issuance/revocation, denied protected operations, ownership/ACL changes,
privilege use, elevation, recovery, and audit loss. Bound and escape text.
Wall-clock time is descriptive until trustworthy time is available; retain a
monotonic event sequence and explicit boot identity as well.

Security-changing operations must reserve audit capacity or return a clear
failure before mutation when recording is mandatory. Persistence failures and
crashes need correlated intent/outcome or recovery records; a pre-commit
"success" log is not proof of a committed operation. A log on the same
unauthenticated disk is not tamper-proof evidence or an anti-rollback anchor.

## Future implementation and acceptance

Phase 8 remains incomplete until the real credential, persistence, token,
ownership, elevation, and audit boundaries work. Required adversarial evidence
includes:

1. Two provisioned local users log on independently after reboot. Each creates
   and reads private data; the other cannot read, write, delete, list protected
   contents, change ownership/ACLs, or duplicate a more powerful handle.
2. Inherited owner/group/ACL state survives reboot and crash injection. Exact-
   case names, spaces, non-ASCII names, and canonically distinct names retain
   their documented meaning without becoming alternative authentication paths.
3. Delete/recreate and name reuse cannot recover old ACL grants. Foreign
   authorities with identical numeric values never alias local users.
4. Malformed lengths, versions, checksums, duplicate NIDs/names, wrong record
   types, missing groups, generation conflicts, UUID substitution, and unknown
   verifier algorithms fail without publishing state or issuing a token.
5. Password-library vectors and cross-implementation checks pass. Boundary
   parameters, allocation failure, queue exhaustion, cancellation, invalid
   UTF-8, credential changes during verification, and worker crash are tested.
6. A user process cannot submit its own group/privilege list, impersonate a
   service, reuse another session's result, or silently elevate. Explicit
   elevation produces bounded audit evidence; denied requests do not grant
   temporary access.
7. Every supported account mutation and migration has exhaustive relevant
   write/flush crash tests showing old or new policy. Incomplete provisioning
   stays disabled. Recovery never converts corruption into a permissive login.
8. Secret cleanup, log/dump redaction, event loss, revocation semantics, and
   cloned/rolled-back authority behaviour are tested at their real boundaries.

Compatibility is deliberate: preserve current Seed descriptors and bootstrap
tests until a separately versioned migration exists. Migration must bind old
numeric pairs to the chosen authority, preserve explicit ACL order, reserve
non-reusable IDs, and reject ambiguous mappings. Upgrade must not silently
enable old test accounts or default passwords. Unknown future records are
rejected, not downgraded to a weaker policy. Keep a reviewed recovery path and
test interruption before, during, and after migration; never interpret a new
format using the old structure layout.

TODO(identity-security): complete native secret-memory and entropy contracts,
dependency pin/audit, resource measurements, protected broker IPC, journalled
account/profile/ACL updates, explicit migration, revocation and elevation,
and all acceptance evidence before enabling password logon.
