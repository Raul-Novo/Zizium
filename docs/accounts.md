# Accounts and sessions

The account model will provide local users, groups, guests, service identities,
profile creation, logon sessions, lock state, and explicit administrative
elevation. ACL templates define access to each profile and shared directory.

## Implemented in Seed

Security IDs, token user/group membership, ordered ACL checks, and service
identity strings are implemented. SessionHost and Luma form a real but trusted
bootstrap user-mode session with distinct tokens and a secured channel. No
credential is accepted, no durable local account is loaded, and the session is
not the result of authentication.

The bootstrap now uses a reserved SERVICE:3 SessionHost principal and USER:21
demonstration Luma principal, both with Users membership only. Their executable
and DLL loads require directory traversal and Read/Execute ACL grants. These
are restricted boot fixtures, not issued durable accounts or secure logon.

## Scaffolded

The default ZiFS hierarchy contains `C:\Users\Default`, `C:\Users\Public`, and
the standard profile subdirectories. Identity names reserve SYSTEM,
ADMINISTRATORS, USERS, GUESTS, SERVICE, and USER forms. SessionHost and
SecurityHost manifests define ownership boundaries.

## Active Phase 8 work

Phase 8 begins with a threat model and a bounded, versioned, checksummed,
transactional identity database on ZiFS. It must freeze durable NIDs, construct
tokens only after credential verification, create two isolated local profiles,
and apply persistent ownership and default ACL inheritance. A maintained,
reviewed memory-hard password hash must be selected at the proper execution
boundary; Zizium will not invent password cryptography.

## Future

Identity database, password hashing and policy, PIN support, logon UI, secure
credential input, token creation, profile copying, lock/unlock, guest policy,
service logon, account recovery, auditing, and a consent-based elevation flow
are unimplemented.
