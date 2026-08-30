# Application sandboxing

Traditional ACLs remain mandatory. Modern applications will additionally use
tokens, privileges, and declarative capabilities so installation does not
imply unrestricted access.

Candidate capabilities include files, network, camera, microphone,
notifications, background execution, start-up tasks, display capture, and
input monitoring.

## Implemented in Seed

ACL access checks and token group matching provide only the base mechanism.
There is no application sandbox boundary.

## Scaffolded

Service manifest permission fields, access-mask propagation, security
descriptor links, and future package metadata reserve places for capabilities.

## Future

Capability identities, consent UI, resource brokers, private storage, network
isolation, revocation, background quotas, policy updates, package-signature
binding, and auditing require a complete user/process security boundary.
