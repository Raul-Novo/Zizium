# Native identity format and reservation boundary

## Implemented prerequisite

`zi/identity.h` defines a native identity as a 16-byte issuer identifier plus
the existing authority/value pair. Validation, equality, explicit byte
encoding/decoding, an explicit one-issuer local-resolution helper and bounded
candidate reservation are implemented. These primitives are host-tested; they
are used by the disabled-record store, not by a production account or logon service.

The issuer is an opaque nonzero UUID in canonical octet order. It identifies
the installation's identity authority, not its drive letter or a display name.
It is never overlaid with the mixed-field Windows GUID representation. The
validator rejects the nil issuer but does not establish entropy, provenance or
uniqueness. Production provisioning must obtain an issuer from the future
approved entropy service. Fixed issuer bytes in tests are fixtures only.

## Version-one wire record

Exactly 32 bytes are accepted on decode. Integer fields are little-endian;
issuer bytes preserve their canonical order. No C structure is serialised.

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 4 | ASCII magic `ZNID` |
| 4 | 2 | format version, 1 |
| 6 | 2 | record size, 32 |
| 8 | 16 | nonzero issuer UUID octets |
| 24 | 4 | existing numeric authority |
| 28 | 4 | nonzero authority-local value |

Unknown versions, sizes, magic, authorities, zero values and nil issuers fail.
Encoding requires capacity of at least 32 bytes and writes exactly 32; decoding
requires exactly 32, so callers must frame records explicitly. Outputs remain
unchanged on failure. The record is an identifier, not a credential, signature,
checksum or certificate. Database integrity and issuer trust belong to the
separate persistence/provisioning contract.

Equality validates both identities and compares every issuer octet, authority
and value. Equal numeric pairs from different issuers are distinct. Invalid
identities are never equal, including two nil identities.

## Reserved and dynamic values

Values 1–255 in every authority are reserved for well-known/bootstrap policy.
Zero is invalid. The dynamic GROUP, USER and SERVICE ranges start at 256.
SYSTEM identities cannot be allocated by the dynamic reservation helper.
Existing SYSTEM:1, GROUP:1/2/3, SERVICE:1/2/3 and demonstration USER:21 keep
their current meanings; none becomes an authenticated account automatically.

`ZiIdentityIssuerState` carries a separate high-water value for GROUP, USER
and SERVICE, initially at least 255. A reservation validates the state and
requested authority, increments only that authority's counter, and returns an
unpublished identity and candidate state. UINT32_MAX exhaustion fails without
wrapping or changing either output. Names do not participate in allocation.

This operation deliberately does not publish, persist or authenticate anything.
The caller must serialise reservations and atomically commit the new high-water
state with the disabled account record before exposing an issued identity.
Repeated calls against the same old state intentionally produce the same
candidate: using this primitive without the database transaction would reuse
IDs and is forbidden. Deletion must not lower a committed high-water value.
Snapshot recovery requires the threat model's explicit non-reuse/issuer policy;
an in-memory counter does not solve rollback across reboot.

## Explicit legacy bridge

Existing `ZiSecurityId`, tokens and the eight-byte IDs in ZiFS `ZISE` records
are unchanged. `zi_identity_resolve_local` permits only a dynamic GROUP, USER
or SERVICE value belonging to the separately supplied active issuer. Foreign
issuers and reserved/SYSTEM identities fail with AccessDenied. The output is
unchanged on failure. The helper never guesses an issuer from a record or path.

The caller must already hold an authorised database record and a trusted active
issuer binding. Matching bytes are necessary but not proof of issuance,
authentication or a safe migration. Do not use this helper as token creation,
accept a caller-selected active issuer, or silently attach an issuer to legacy
ACL entries. Existing dynamic-looking legacy values also require explicit
migration; a value of at least 256 is not sufficient evidence of database origin.

## Persistence integration

The database and storage wrapper bind issuer, volume, database
identity and file object to caller-supplied trusted provisioning state. Bounded
records validate exact UTF-8 names, high-water values, tombstones, disabled
states, group references and an in-session generation floor. Issuance commits
the candidate and high-water value together before publishing an ID. See
[identity_database.md](identity_database.md) for the wire and ownership contract.
Host crash tests and six native NVMe boots verify disabled issuance, deletion,
non-reuse and binding/access denials. Production provisioning is not implemented;
database users/services remain disabled and cannot authenticate.

The current ZiFS write path can replace up to 24 data blocks within a bounded
transaction, but this alone does not authorise database access. The initial
formatter now provisions SYSTEM:1-only descriptor ID 2 on the exact
`C:\Zizium\Security` subtree and imported child files. The broadly readable
descriptor ID 1 elsewhere remains inappropriate for credentials. This is only
an initial storage prerequisite: the storage wrapper validates its actual
file descriptor and trusted binding, not privacy inferred from a path or ID.
Runtime creation must explicitly install the private policy until real
inheritance exists. No database file, password verifier, new token or default
password is created by the native-identity codec or formatter policy.

## Future and acceptance

Implement production trusted provisioning and
journalled private-policy updates for existing volumes. The host-tested codec,
transaction-backed issuance and tombstones do not solve offline rollback or
interrupted multi-object profile provisioning. Then integrate reviewed credential handling,
two-user isolation, inheritance, revocation, audit and elevation as described in
[identity_security.md](identity_security.md). A passing identifier round-trip or
reservation test is not completion of identity and access management.
