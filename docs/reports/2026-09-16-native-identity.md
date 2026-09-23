# Historical checkpoint — superseded by the root progress report

# Zizium verified progress report

Phases 0–7 remain complete for their recorded milestones. Phase 8 remains ACTIVE.
This checkpoint validates the native-identity format/reservation prerequisite.
It does not implement durable accounts, transactional issuance or secure logon.
The preceding launch-authorisation checkpoint is preserved in
[the historical report](docs/reports/2026-09-08-launch-authorisation.md).

## 1. Date and time

Work began before the pause on 2026-09-08 and resumed on 2026-09-16.
Final evidence: 2026-09-16 approximately 15:44 Europe/Madrid (UTC+02:00).
Repository state and live processes were rechecked after the pause.
The preceding goal continuation produced real source changes; this continuation
completed their tests, analysis, documentation and build validation.

## 2. Summary

Added an explicit 32-byte issuer-bound native identity codec, all-component
equality, a checked single-issuer local-resolution helper and bounded dynamic
reservation candidates. GROUP/USER/SERVICE dynamic values begin at 256;
SYSTEM and values 1–255 cannot pass the dynamic bridge. Counters fail on
exhaustion rather than wrapping. Outputs remain unchanged on failure.

The eight-byte ZiSecurityId, existing process tokens and ZiFS ACL records are
unchanged. No database, credential, issued account or logon token is created.
The reservation helper returns unpublished state which must later be committed
with a disabled account record through the database transaction.

The current Clang-Tidy file lacked required public-name exceptions. Two narrow
entries were restored to preserve the mandated ABI names while keeping all
private naming and compiler safety checks.

## 3. Exact files created

- kernel/include/zi/identity.h
- kernel/executive/security/identity.c
- tests/host/phase8_identity_test.c
- docs/identity.md
- docs/reports/2026-09-08-launch-authorisation.md

## 4. Exact files modified

- .clang-tidy
- scripts/build_driver.py
- tests/host/phase8_tests.h
- tests/host/test_main.c
- README.md
- docs/README.md
- docs/security.md
- docs/accounts.md
- docs/identity_security.md
- docs/build.md
- docs/architecture.md
- docs/continuation.md
- userland/services/manifests/README.md
- ZIZIUM_PLAN.md
- ZIZIUM_PROGRESS.md

This is the known edit inventory, not a Git diff; the workspace has no Git
metadata. Generated artefacts/logs remain under build/. The prior report is
archived without changing its historical body. Unrelated files were preserved.

## 5. Exact files deleted

None. Normal builds regenerated only their scoped build artefacts.

## 6. Build commands run

All commands used the existing build graph from C:\dev\osdev\Zizium.
Clang/LLVM 22.1.8 and Python 3.14.5 were confirmed locally. The PowerShell
wrappers load the installed x64 Visual Studio environment.

| Command | Log beneath build/ | Result |
| --- | --- | --- |
| make image | phase8-identity-image.log | pass |
| make release | phase8-identity-release.log | pass |
| make intel | phase8-identity-intel.log | pass; 39 groups/3,465 assertions |
| make image | phase8-identity-normal-image.log | pass; normal debug image restored |
| make release | phase8-identity-release-repeat.log | pass; repeat comparison matches all 21 selected artefacts |
| make deps | phase8-identity-deps.log | pass; existing pins verified, no download |

Intel was selected only for the optional validation command by prepending
C:\Program Files (x86)\Intel\oneAPI\compiler\2026.0\bin to that shell's PATH.

Release comparison used PowerShell ErrorActionPreference=Stop and
Get-FileHash -Algorithm SHA256. It required exactly 21 files:
release/kernel/zizium.efi, release/images/zizium-root.zifs,
release/images/zizium.img and all 18 .exe/.dll/.lib/.sys files directly in
release/native. Hashes from the first release build matched the repeated build.
PDBs and host tools are not included in that 21-file reproducibility claim.

## 7. Test and analysis commands run

| Command | Log beneath build/ | Result |
| --- | --- | --- |
| make test | phase8-identity-baseline.log | pre-edit baseline: 38 groups/3,285 assertions |
| make test | phase8-identity-test1.log | pass: 39 groups/3,461 assertions |
| make analyse | phase8-identity-analyse1.log | failed on existing mandated public function names |
| make analyse | phase8-identity-analyse2.log | failed on existing assembly-linked public constant name |
| make analyse | phase8-identity-analyse3.log | failed on new test-function cognitive complexity |
| make analyse | phase8-identity-analyse4.log | failed on one remaining test-function complexity threshold |
| make test | phase8-identity-test-final.log | pass: 39 groups/3,461 assertions |
| make analyse | phase8-identity-analyse-final.log | pass |
| make sanitise | phase8-identity-sanitise.log | pass: 39 groups/3,461 assertions |
| make boot-test | phase8-identity-boot.log | pass, all current serial markers |
| make test | phase8-identity-test-complete.log | pass: final 39 groups/3,465 assertions |
| make analyse | phase8-identity-analyse-complete.log | pass for final source |
| make sanitise | phase8-identity-sanitise-complete.log | pass: final 39 groups/3,465 assertions |
| python scripts/check_spelling.py | tool output | pass before report; repeated after report |

clang-format -i was applied to the new/changed C sources and headers.
make analyse includes formatting verification and Clang-Tidy; make test also
runs strict host compilation, self-contained headers, inspector/repair fixtures
and all fifteen service-manifest checks. Sanitisation here is AddressSanitizer,
not a claim of UBSan or TSan coverage.

The final four extra assertions extend exhaustion coverage from USER to all
three dynamic authority classes. The production implementation did not change
after the successful boot gate.

## 8. Results and evidence

Final host suite and optional Intel suite: 39/39 groups, 3,465 assertions.
The new group adds 180 assertions over the 3,285-assertion baseline.
Final analysis, AddressSanitizer, normal boot and 21-file release comparison pass.

Tests cover a literal golden wire record, exact output length and trailing
sentinel, every truncated input size, oversized sizes, bad header bytes,
invalid authorities/values/issuers, unchanged failure outputs, every foreign
issuer byte position, reserved/SYSTEM bridge denial, independent counters,
in-place candidate chaining, invalid state and exhaustion of all dynamic roles.

The new module is compiled into the shared graph, but no live account issuer
or token-creation path calls it yet. Host proof of the primitives must not be
described as a booted account database.

Debug artefact SHA-256 after normal image restoration:

- kernel/zizium.efi:
  15538cf8b71f450310f32a0093b70b017b3bed39e67cb5833ba69448cfec2cc4
- images/zizium-root.zifs:
  6161ea0c8eb478e01f341076af46c8a8ff3ff7609aa4ea2c4dd88556bf26fc17
- images/zizium.img:
  6f251048cbf0879e5a8d75a8e1f680bbb5f7788d848bcde92fa23fbb897fdbf0

Release artefact SHA-256:

- kernel/zizium.efi:
  873bafae78dc9af7f601d893c25a855dfb9662e4a76037b7b9532625986b1223
- images/zizium-root.zifs:
  7a8ea978ca7876525cccb9087b9ddef30fb2b8fd604094d82e9a40a5c0c25ddf
- images/zizium.img:
  29329f1a0adbf4b551bc8cdf297d55777a5415ea8447098b0db69a60b3eeea4c

The separate fault/storage/32-boot durability suites passed at the preceding
launch checkpoint, not in this identifier-only step. No ZiFS mutation, mount,
driver, scheduler or syscall implementation changed here. Rerun those broader
gates when integrating persistent identity/ACL storage; do not claim current
crash-tested identity issuance.

## 9. Errors encountered

Analysis initially rejected existing ZiSucceeded, ZiFailed, ZkKernelMain and
ZkX64InterruptStubTable because the current root configuration did not contain
their mandated public-family exceptions. The observed file state differed from
the preceding checkpoint; no assumption was made about who changed it.

After resolving that ABI/style conflict, the new assertion-heavy test functions
exceeded cognitive-complexity thresholds. Tests were split into codec, invalid
identity, truncated/header/buffer, issuer/reserved binding, reservation and
invalid/exhausted state cases. No assertion was removed to pass analysis and
no new warning suppression was added.

All final commands reached terminal success. No unresolved build/test failure
remains for this prerequisite.

## 10. Warnings and style conflicts

The only root style changes are FunctionIgnoredRegexp and
GlobalConstantIgnoredRegexp for the mandated Zi/Zx/Zk/ZiFs public families.
The first protects native API/entry names; the second protects the assembly ABI
constant. The remaining naming configuration is unchanged. Global-variable
exceptions were not added because the gate did not require them.

This resolves a documented conflict between generic snake_case rules and frozen
public ABI naming. No public symbol was renamed. No bounds, lifetime, conversion,
alignment, analyser or compiler safety warning was disabled.

The central -Weverything -Werror policy and its pre-existing individually
documented exceptions remain unchanged. Final analysis has no unsuppressed
project warning. Third-party/system-header suppression counts are not project
diagnostics.

## 11. Missing dependencies

None for the verified build/test paths. Native secure entropy, protected secret
input, secret-memory lifecycle, an approved password-library adapter and a
trusted persistent identity database remain engineering prerequisites.

## 12. Dependencies downloaded

None. Existing external/deps pins were verified:

- Limine 12.5.2:
  a4b4539e4229c25f5ceba93ada8a71b8a2c57d7b7900ea5f86c588e1b7afe621
- Limine protocol 630686a3dd3ce40f9e510a7dd9fea6b4c60d952e:
  4de542d1c232b230ca4af04c5b89a78f51c9bdacb928a94ac44fc88377208a63
- Spleen 2.2.0:
  ec42925c6b56d2138c862b2f97147c872e472f674bf03423417d827a08d69a89
- Unicode UCD 17.0.0:
  2066d1909b2ea93916ce092da1c0ee4808ea3ef8407c94b4f14f5b7eb263d28e

## 13. Downloads not completed

None attempted unsuccessfully. No cryptographic library was fetched or adopted.

## 14. Implemented

Native identity validation/equality/byte codec, explicit foreign/reserved
identity rejection at the local bridge, versioned issuer candidate validation,
per-authority high-water candidate reservation and exhaustion handling.
These are tested reusable prerequisites, not durable issuance.

## 15. Scaffolded, not implemented

Identity database persistence, issuer/volume/database-object trust binding,
record issuance and tombstones, account provisioning, credential verification,
logon-derived tokens, persistent ACL inheritance, revocation, privilege checks,
elevation and audit persistence remain incomplete.

## 16. Intentionally absent

No credential, account file, default password, authentication fallback,
implicit legacy identity migration or custom cryptography was introduced.
The native identity record itself is not a signature or certificate.
A matching issuer UUID alone cannot authorise issuance or authentication.

## 17. Remaining implementation sequence

1. Implement bounded identity-database records and trusted issuer/volume/file
   binding using the explicit native identity codec.
2. Provision genuinely private database metadata before accepting secrets:
   the formatter's broad default descriptor is not a credential-storage policy.
3. Commit new high-water state and disabled account record in one ZiFS
   transaction; retain non-reuse on deletion and reject ambiguous rollback.
4. Test interrupted provisioning, malformed records, collisions/references,
   transaction failure and old-or-new recovery before publishing issued IDs.
5. Add native entropy/secret-memory/broker prerequisites and a reviewed
   credential adapter, then two isolated users, inheritance, audit and elevation.

## 18. Boot status

The native AMD64 PE kernel continues to boot through UEFI/Limine in QEMU/EDK2.
All normal acceptance markers, including SERVICE_POLICY_DENIED and
IMAGE_ACCESS_DENIED, pass. Normal debug images were restored. No new identity
database is mounted or issuer activated during boot.

## 19. ZiFS status

Existing direct NVMe ZiFS root, bounded writable transactions, journal/recovery,
durable security descriptors, inspection and narrow offline repair remain.
The root volume bytes are unchanged by the identifier prerequisite.
ZiFS still stores its existing eight-byte ACL IDs; no on-disk migration occurred.

The database will need an explicit protected-object and transactional issuance
contract. Existing file writes alone are not account provisioning or durable
non-reuse. Never store irreplaceable data on development volumes.

## 20. Scheduler status

32 priority levels and live single-CPU kernel-thread pre-emption remain.
No scheduler change was made. SMP and concurrent scheduled user execution
remain future work.

## 21. ACL/security status

Existing default-deny ACLs, owned tokens/handles, restricted approved bootstrap
service policy and token-bound image traversal checks remain.
The new bridge checks all issuer bytes and rejects dynamic mapping of SYSTEM
or reserved values. It requires an already authorised record and independently
trusted active issuer; it is not a public token-minting API.

Repeated reservation against the same old in-memory state yields the same
candidate. Only the future serialised durable transaction can prevent reuse.
CRCs/UUIDs/generations do not provide authentication or anti-rollback by themselves.

## 22. Terminal/Luma status

The bounded filesystem-backed Luma session and child-launch demonstration remain
boot-verified. USER:21 is still a trusted bootstrap fixture with Users membership,
not a durable account or secure logon. Full interactive user console/GUI remain
future work.

## 23. Unicode status

Existing UTF-8/UTF-16, exact-case paths and terminal foundations remain.
The identity codec uses binary issuer/value fields, not name hashes or case
folding. Account-name Unicode policy still belongs to the future database.
No filename normalisation was introduced.

## 24. Driver status

Existing ACPI/PCIe, DMA/MMIO, IRP, GPT and polling QEMU NVMe remain.
No driver code or support claim changed. Dynamic .sys loading, broad PnP/USB
and physical-hardware qualification remain incomplete.

## 25. PE/COFF status

Native PE kernel, programmes, DLLs, loader and image ACL boundaries remain.
The new core module compiles in the normal PE kernel build.
No executable format, entry ABI, relocation/import policy or syscall ABI changed.

## 26. ZCC/ZiCRT status

Ordinary C main and the minimal runtime still boot and execute. ZCC remains a
host Clang-driver scaffold; ZiCRT is not a complete C library. No runtime or
compiler implementation changed in this prerequisite.

## 27. ZIA/Zx status

Existing bounded process/debug/channel/wait/close calls remain.
No new public identity issuance, account, credential or elevation syscall exists.
The native identity helpers are kernel-internal/shared testable components,
not a stable exported user DLL API.

## 28. Documentation status

All three project READMEs and relevant architecture, accounts, security,
identity threat-boundary, build, roadmap and continuation docs were updated.
docs/identity.md defines the actual wire/ownership/reservation contract and
explicitly separates implementation from persistence/authentication.
The previous report is archived; this report was written last.

## 29. Known limitations

Phase 8 and the full OS goal remain incomplete. The identifier codec neither
generates secure UUIDs nor verifies their provenance. The local bridge must
never receive an active issuer copied from an untrusted imported record.
No protection against whole-volume rollback or hostile boot media is claimed.
Zizium is not yet a secure multi-user or daily-use OS.

## 30. Technical debt

- Trusted identity database/volume/file binding and protected storage policy.
- Durable issuance, non-reuse, provisioning and migration from legacy IDs.
- Credential/entropy/secret-memory and protected broker/input prerequisites.
- Concurrent file/security locking and revocation.
- Persistent ACL update/inheritance, audited elevation and two-user isolation.
- Hermetic tooling and broader hardware validation.
- No VCS metadata: continue preserving unrelated edits with explicit inventories.

## 31. Suggested next prompt

Continue Phase 8 from the 39-group/3,465-assertion identifier checkpoint.
Read AGENTS, roadmap, this report, continuation, identity.md, identity_security,
accounts, security and ZiFS transaction contracts. Implement protected
identity-database storage and trusted binding, then atomically commit disabled
records and high-water state with adversarial/crash tests. Do not publish IDs
from zi_identity_reserve alone or interpret a byte-codec test as authentication.
Preserve all launch denial, storage and durability gates. Update documentation
and this report last; keep the full daily-use OS objective active.

## 32. Continuation instructions

All reported command handles reached terminal success; no validation process
needs resuming from this checkpoint. Recheck actual processes before restarting
later work. The previous goal's partial identity sources were completed here.

Use explicit little-endian byte encoding and canonical issuer octets. Dynamic
IDs start at 256; well-known/bootstrap IDs are not enrolled accounts. SYSTEM is
not dynamically reservable. The old ZiSecurityId/token/ZISE layouts remain
unchanged. Any migration or credential storage requires a new explicit contract
and tests. The current public-name Clang-Tidy exceptions are necessary ABI
exceptions, not permission to relax private naming or safety diagnostics.

## 33. Frozen decisions

Preserve product names, GPL-3.0-or-later work and third-party licences; x64 first,
UEFI/Limine through ZiBootContext; native PE/COFF; Microsoft x64 C ABI and
RAX/R10/RDX/R8/R9 syscall convention; C17 with minimal assembly; ZiFS-only root
with type GUID 9ef9e22a-3719-44d4-89af-de9cc7b6b255, FAT32 ESP only; exact UTF-8
paths and spaces; ordinary main and optional ZIA; default-deny ACL/token policy;
32 scheduler priorities; rational per-output scaling; British English and the
calm blue palette; journal/checkpoint recovery and fail-closed offline repair.
Keep explicit identity versioning/migration, the reserved/bootstrap separation,
strict warnings, all denial gates and truthful milestone evidence.
