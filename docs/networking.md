# Networking

`ZiNet` will be the native networking API. The intended stack includes
Ethernet, Wi-Fi, IPv4, IPv6, TCP, UDP, DNS, DHCP, TLS, firewall policy, and
network profiles. A BSD sockets compatibility layer may be added later but is
not the native design.

## Implemented in Seed

No networking protocol or network driver is implemented. The service and
driver architectures merely reserve appropriate integration points.

## Scaffolded

`NetworkHost.zsvc`, device/driver objects, asynchronous I/O, IPC concepts, and
the future names `ZiNetCreateSocket`, `ZiNetConnect`, `ZiNetSend`, and
`ZiNetReceive` establish ownership boundaries.

## Future

Link drivers, packet buffers, routing, neighbour discovery, addressing, socket
objects, DNS/DHCP clients, TLS, certificate trust, firewalling, Wi-Fi security,
and network isolation are wholly unimplemented and require security review.
