# Accounts and sessions

The account model will provide local users, groups, guests, service identities,
profile creation, logon sessions, lock state, and explicit administrative
elevation. ACL templates define access to each profile and shared directory.

## Implemented in Seed

Security IDs, token user/group membership, ordered ACL checks, and service
identity strings are implemented or represented. No credential is accepted and
no user session exists.

## Scaffolded

The default ZiFS hierarchy contains `C:\Users\Default`, `C:\Users\Public`, and
the standard profile subdirectories. Identity names reserve SYSTEM,
ADMINISTRATORS, USERS, GUESTS, SERVICE, and USER forms. SessionHost and
SecurityHost manifests define ownership boundaries.

## Future

Identity database, password hashing and policy, PIN support, logon UI, secure
credential input, token creation, profile copying, lock/unlock, guest policy,
service logon, account recovery, auditing, and a consent-based elevation flow
are unimplemented.
