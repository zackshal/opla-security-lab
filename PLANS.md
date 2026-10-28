# OPLA accelerated engineering and acceptance roadmap

**Inspected baseline (2026-10-28):** HEAD `1e6aa67b707b9c733dca929bfde619db2b0a13a8`.
The committed orchestrator supplied read-only contracts and an in-memory runner.
The untracked progress module is now syntactically valid and has corruption and
interruption guards. Existing uncommitted files were retained; no commit made.

## Current work package and next gates

## Repository hygiene and selection recovery (offline, 2026-10-28)

The lab CLI now clears a user-owned regular selection file when its referenced
lab has disappeared, while malformed or symlinked selection files remain
fail-closed. The engineering ledger and role contracts were made provider
neutral; public documentation and tests no longer name a specific AI vendor.
The local checkout cannot remove the read-only `.agents` and `.codex` mounts;
their tracked removal must be completed from a normal writable checkout before
the cleanup commit. No live lab or host state was touched.

**Active user-requested engineering package: local engineering ledger.**
Preserve all lab work below and last commit `1e6aa67`; do not replace the lab
orchestrator with an AI scheduler. Audit/ADR, file plan and acceptance are in
`docs/engineering-workflow.md`. Keep role contracts, reviewable policy gates,
local locked task/evidence support and offline fixtures. No DB/framework,
permission override, automatic commits or live infrastructure. Policy activation
remains an explicit user action.
Independent read-only agents audit/review; the parent alone edits this dirty tree.
After engineering-ledger acceptance, resume the next OPLA functional integration gate below.

Engineering-ledger implementation/validation (offline): 10 project roles, 3
reviewable policy events and a local atomic task/evidence ledger.
`make engineering-check`: 26 tests + 24 fixed policy cases passed;
`make check`: 480 tests passed with C packet engineering/syntax checks after authorized
local-socket rerun (sandbox: 476 successes, four socket permission errors).
Lab acceptance remained 65 tests OK; isolated create-FD integration 4 tests OK.
Compileall/diff whitespace passed. Strict CLI startup config validated; local
prompt-input confirms root instructions, skills and custom-role discovery.
Two native read-only subagents performed audits and independent review/forward
testing. Review-found CLI/rework/recovery/symlink/argument/dependency issues were
fixed and regression-tested; no policy was activated to bypass those failures.
Hook activation/runtime denial in a fresh local model session, parallel writer
worktrees, authenticated session identity and native token/cost import remain
NOT TESTED/unimplemented. Hook trust was not granted. No commits, publication,
model/provider overrides or live infrastructure operations were performed.

1. **Implemented offline:** source call-graph audit in `docs/lifecycle-call-graph.md`;
   seven-stage injected orchestration through the existing persistent journal;
   action/probe deadlines, identity and ownership probe contracts, guarded resume,
   evidence and failure records. `make acceptance-offline` exercises pure fake
   adapters; no VM, SSH or host network actions. See `docs/offline-lifecycle.md`.
2. **Artifact integration implemented offline:** `opla-lab-artifacts.py` reuses image
   verification with injected qemu-info results, scenario validation, incident
   correlation and XDP fingerprint verification. It records input SHA-256 and
   preserves failed-probe evidence. Nine integration tests use synthetic files;
   the real reporter's unverified completeness deliberately fails the report gate.
   **Identity/executor contract implemented offline:** generated lab marker after
   registry ready; operations adapter persists actual ID and command outcome
   hashes; restore runs under journal lock before probes. Injected process-tree
   cancellation records stop/unknown separately from resource reconciliation;
   flagged failures cannot resume automatically. Eight operations tests plus one
   composed artifact/operations resume test cover this contract without processes.
   **Durable dispatch and registry integration implemented offline:** commands
   require fsynced PREPARED checkpoints before backend dispatch, with persistent
   outcomes and reconciliation guards. The registry adapter reuses receipt/state
   resource verification with an injected inspector; it preserves unverified
   ownership and stops before configure. Eleven additional tests cover write
   failure, abrupt stop, command corruption, partial/poisoned receipts and composition.
   **Current-health/process evidence implemented offline:** existing process
   verifier accepts injected systemd/proc inputs and rejects disk/cgroup suffix
   lookalikes; registry composition preserves process evidence without claiming
   exclusive network/disk ownership. Optional fresh health observations reuse
   collector attachment, fingerprint and availability parsers, verify separate
   management identity/route/pinned key and independent client HTTP results.
   Fifteen added tests cover parsers, spoofing, staleness and resume behavior.
   **Remaining integration gate:** live exclusive resource ownership attestation,
   actual management-path/client continuity evidence and real executor supervision
   on an authorized dedicated host. The offline injected attestation contract is
   implemented and fail-closed; PASS still requires real parser outputs from
   offline fixtures and dedicated-host evidence, not boolean probe assertions.
   **Concrete topology integration:** the built-in academic create/resume path
   now provisions separate data/XDP and management bridges, TAPs, QEMU NICs,
   guest `ens3`/`ens4`, state/registry identities, SSH address mapping,
   lifecycle ownership checks and offline rollback/prune/registry probes. The
   dual-interface health fixtures remain necessary but are not treated as live
   proof. Current health provider client probes are point checks. Optional offline `client-probes.json`
   now validates bounded, independent samples spanning the scenario interval;
   it does not prove trusted collection or uninterrupted availability.
   Strict artifact mode requires and revalidates that sampled evidence on resume.
   The incident bundle blocks generation if the inventoried client artifact hash
   differs from the bytes parsed by the reporter. The global completeness flag
   remains false. See `docs/task-client-coverage.md` and
   `docs/offline-lifecycle.md`.
3. **Trust gate B:** independently pinned/signed provenance and root-owned immutable
   activation, protected locks, interrupted activation and malicious-source tests.
   Package/stage/promote artifacts remain inert. Dedicated isolated VM required
   for activation testing; no installation on the development host.
4. **Live gate C:** separately authorized dedicated host; prove the full three-VM
   chain, management isolation, verifier, client continuity, telemetry correlation
   and ownership-aware cleanup with original logs and fingerprints.
5. **Deployment gate D:** user YAML and direct SSH, then optional VPN. No built-in
   distributed topology or live endpoints.

The fake-adapter package satisfies the first acceptance of AGENTS.md stages 3–4;
it does not close the full artifact integration or live acceptance gates below.

Client interval coverage cycle (offline, 2026-10-28): 33 focused tests and 98
offline acceptance tests passed; the existing bundle fixture suite passed 3/3
after adopting the new report contract. `make check` ran 513 tests and ended
with four sandbox-denied Unix-socket errors; there were no other failures and
its C checks did not run. local policy records are saved in the project ledger,
but effective activation could not be verified: the local app-server could not
initialize its protected SQLite state. Independent QA verified and reproduced
the bundle hash race, then confirmed the fix; final independent security review
is pending after the reviewer agent reached its usage limit. No trust, permission,
network, VM or host infrastructure changes were made. Next safe package: bound
the existing bundle-to-reporter subprocess and preserve blocked manifests on
spawn/timeout/invalid report failures; keep it separate from this evidence gate.

Bundle supervision cycle (offline, 2026-10-28): the existing reporter
invocation now accepts a finite positive timeout and an injected runner for
deterministic fault tests. Spawn errors and timeouts, as well as nonzero,
malformed and non-object reports, persist a blocked manifest and
`generated=0`, removing any stale incident report. The current client evidence
hash check remains intact. The focused bundle suite passes 8 tests; offline
acceptance passes 98 tests. Independent security review approved the current
tree. The next bounded task is to inspect remaining lifecycle evidence/report
call sites for equivalent unbounded subprocess dispatch before live deployment.

Lifecycle dispatch audit (offline, 2026-10-28): `opla-scenario-live.py` uses a
180-second bounded call, while `opla-lab-configure-launcher.py` and
`lab-lifecycle.py` still run privileged/configuration and cleanup subprocesses
without deadlines. No guessed timeout was added. The next implementation must
define per-operation budgets, process-group cancellation and durable
`UNKNOWN`/reconciliation records with injected offline executors before any
dedicated-host validation. Findings are recorded in
`docs/task-lifecycle-dispatch-audit.md`.

Lifecycle command timeout cycle (offline, 2026-10-28): `lab-lifecycle.py` now
routes its general subprocess wrapper and direct `nft -f -` path through a
validated finite 30-second default timeout with an injected runner for tests.
Existing lock order, nft ownership checks, QMP timeout and 90-second VM wait
remain unchanged. Focused timeout tests pass 4/4, nft guards 5/5, lifecycle
lock tests 6/6, and offline acceptance passes 105 tests. Independent security
review approved the package. The timeout bounds an individual child only; full
process-group cancellation remains a separate dedicated-host/executor gate.

Deadline evidence cycle (offline, 2026-10-28): offline action/probe timeout
failures now persist a serializable `deadline` evidence record containing the
stage, selected budget and `kind=stage_timeout`. Create timeout remains
non-replayable; configure and later stages retain their existing retry and
revalidation behavior. Focused lifecycle acceptance remains 18/18 and offline
acceptance 105 tests. Independent security review approved the current tree.

Configure process supervision cycle (offline, 2026-10-28): the privileged
configure launcher now has a validated 900-second default aggregate budget,
bounded environment override (maximum 3600 seconds), a new process session and
TERM → five-second grace → KILL → reap handling. Timeout failures reach the
existing blocked exit path; unexpected grace-wait errors still trigger a final
kill/reap attempt. Trusted source checks, lock order, restricted environment
and privilege drop are unchanged. Configure supervision tests pass 10/10,
configuration contract tests 4/4, and offline acceptance 105 tests.
Independent security review approved the package. Cleanup evidence does not
claim VM/network/registry reconciliation; live execution remains untested.

Configure reconciliation receipt cycle (offline, 2026-10-28): configure timeout
now persists an atomic lab-local `configure-reconciliation.json` receipt while
the existing lifecycle locks remain held. The mode-0600, single-link receipt
binds schema, lab identity, timeout, child cleanup evidence and an explicit
`resource_reconciliation=unverified` marker. Before lock acquisition or child
dispatch, malformed, mismatched, writable, oversized, symlink, hard-link and
existing unresolved receipts fail closed; automatic retry therefore requires
manual inspection. Fourteen focused configure tests, compileall and
`make acceptance-offline` (105 tests) passed, with independent security review
approved at tree fingerprint
`3a19822cca87d263ca56f7847ca86e645685f035cf6a2eacb8ddc0e473d9cfa3`.
Offline tests cannot prove root ownership on the production path or reconcile
VM/network/registry state. No live infrastructure operation was performed.
Details: `docs/task-configure-reconciliation.md`.

Lifecycle process-group timeout cycle (offline, 2026-10-28): the shared
`lab-lifecycle.py` executor now starts real children in an owned session and
performs bounded TERM → grace → KILL → reap cleanup on timeout, while injected
runner semantics remain unchanged. Existing check/lock/nft ordering is
preserved and timeout still propagates fail-closed. Cleanup errors during
signalling or reap now trigger a final kill/reap attempt while preserving the
original timeout. Focused lifecycle timeout tests pass 7/7, compileall passes,
and offline acceptance passes 108 tests. Independent security review approved
the package. This proves child-group cleanup only;
VM, TAP/bridge, nftables, systemd and live QEMU reconciliation remain
untested. Details: `docs/task-lifecycle-process-group-timeout.md`.

Inert release durability cycle (offline, 2026-10-28): review-only stage and
promotion now fsync extracted files/metadata and their containing directories
around atomic destination/current replacement. Interrupted stage/promotion
tests preserve existing artifacts, remove temporary trees/links, and surface
post-replace directory-fsync ambiguity without claiming rollback. Focused
release tests pass 15/15, compileall and diff checks pass, and
`make acceptance-offline` passes 108 tests. Independent security review
approved the final tree. This remains user-owned inert review data: publisher
authenticity, root-owned immutable activation, detached signatures and isolated
host installation are not implemented or tested. Details:
`docs/task-release-durability.md`.

Offline DEB artifact contract cycle (2026-10-28): before invoking `dpkg-deb`,
the inert builder now validates control metadata, rejects maintainer scripts,
triggers, symlinks and `current`, checks known executable bits when present,
and supports an injected bounded executor. A missing/non-string stderr from a
failing executor is handled fail-closed. Release-focused tests pass 22/22,
compileall and diff checks pass, and `make acceptance-offline` passes 108
tests; independent security review approved the final tree. This remains
operator-digest-bound, user-owned and uninstalled: it does not provide
publisher authenticity, detached signatures or root-owned immutable
activation. Details: `docs/task-deb-artifact-contract.md`.

Trust provenance audit (offline, 2026-10-28): independent architecture and QA
reviews confirmed that bundle manifests and operator-supplied SHA-256 values
provide integrity consistency only, not publisher authenticity. No approved
public-key trust root, signature format, verifier dependency, rotation policy
or isolated activation environment exists in the current project. Hooks and
multi-agent features are discoverable (the installed tooling capability check), but project
hook runtime trust remains unverified and was not bypassed. No signing or
root-owned activation code was added; the required next gate is an explicit
trust-root decision followed by isolated-VM implementation/testing. Details:
`docs/task-provenance-gate.md`.

Built-in dual-NIC topology cycle (offline, 2026-10-28): the academic QEMU
template now separates data/XDP (`ens3`, `n0`, existing bridge/subnet) from
management (`ens4`, `n1`, distinct bridge/subnet without a default route).
Create, resume, state parsing, registry receipts/readiness, lifecycle
preflight/cleanup, rollback/prune, resource inventory, registry verification,
cross-lab audit and SSH transport all cover both resource sets. Legacy
single-NIC state remains inspectable but is refused for lifecycle resume/cleanup
and registry `ready`. Static topology tests pass 3/3, targeted registry and
cleanup tests pass 28/28, compileall/shell syntax/diff checks pass, and offline
acceptance passes 108 tests. Independent security review approved the package;
full `make check` reached 548 tests with only four sandbox-denied Unix-socket
monitoring/QMP tests. No live network, nft, systemd, QEMU, VM, SSH or root
operations were executed. Details: `docs/task-dual-nic-topology.md`.

Sandbox socket-test portability cycle (offline, 2026-10-28): monitoring TCP
and QMP Unix protocol tests now skip only when socket creation/bind/listen is
denied by the execution sandbox, closing descriptors before `skipTest`. Tape
based QMP tests and all protocol assertions remain active; ordinary socket or
thread failures are not swallowed. Focused suite passes 26 tests with 4
environment skips, full `make check` passes 548 tests with the same 4 explicit
skips, and C/syntax checks pass. No production/runtime code or security policy
was changed. The skipped sockets do not constitute live telemetry or VM
acceptance. 

Acceptance preflight topology cycle (offline, 2026-10-28): the read-only
acceptance checker now labels the historical Ansible Debian-12 target as
`fixture_mode=ansible-debian12` and the current built-in lab as
`builtin_mode=local-qemu-dual-nic`. It validates the dual-NIC source contract
(`n0/n1`, `ens3/ens4`, management/data state, registry and lifecycle markers)
without executing QEMU, SSH or network commands, and records separate
`builtin_topology_contract`/`management_data_separation` checks. Live identity,
provisioning, verifier, XDP, Suricata, Zabbix and three-VM checks remain
`NOT TESTED`; automatic execution remains disabled. Focused preflight tests pass
7/7, compileall/diff checks pass, and offline acceptance passes 108 tests.
Independent security review approved the package. Historical NAT/provisioning
results are explicitly not evidence for the current dual-NIC lab. 

Current-host preflight evidence (offline, 2026-10-28):
`python3 bin/opla-acceptance-check.py --check` exited 0 with
`overall_status=NOT TESTED`, `preflight_configuration_valid=true` and
`ready_for_automatic_execution=false`. Required source/playbook/inventory,
known-hosts and Ansible fixture checks were PASS; guest identity/provisioning,
kernel verifier, XDP, Suricata, Zabbix and three-VM experiment remained
explicitly `NOT TESTED`. Captured JSON is outside the repository at
`/tmp/opla-acceptance-preflight-current.json` (SHA-256
`dbc0c0beeffa767664bb077c3008ad18aa77bace78e2e412bbd86dfb11be3fa4`).

Inventory dual-NIC validation cycle (offline, 2026-10-28): read-only resource
inventory now uses a local state validator aligned with `state.py` and the
registry contract. Partial management state, malformed/out-of-range addresses,
overlapping `/29` networks and management IPs outside their subnet are
excluded with warnings before any host probe; legacy single-NIC state remains
inspectable only. Six focused inventory tests, compileall, diff checks and
offline acceptance (108 tests) pass. Independent review approved the package;
no cleanup authority or live probe is inferred. 

Stage-specific offline deadlines cycle (2026-10-28): the existing fake-adapter
orchestrator now accepts an optional partial `stage_timeouts` mapping while
preserving the scalar timeout API. Values and stage names are validated before
adapter calls; action, probe and resume revalidation use the selected stage
budget. Journal schema, cancellation and reconciliation policy are unchanged:
create timeout blocks replay, while later-stage failures retain their existing
retry/revalidation behavior. Focused lifecycle tests pass 18/18 and offline
acceptance passes 101 tests. Independent security review approved the final
tree. Live configure/lifecycle launchers remain unchanged and require a future
dedicated-host timeout policy.

Validation of this work package: `python3 -m compileall -q bin tests` passed;
`make acceptance-offline`: 15 tests passed (including parameterized stage/probe
faults); isolated create-FD integration: 4 tests passed; `make check`: 412 tests
passed plus C packet harness and syntax checks after authorized execution with
local mock sockets outside the restrictive sandbox. The sandbox attempt had
408 successes and four socket permission errors. After adding the deterministic
sample-report assertion, the 15 acceptance tests and compileall were rerun and
passed. `git diff --check` passed. Kernel verifier, KVM, live Zabbix and real
three-VM acceptance were not run. No host provisioning or commit performed.

Artifact integration validation: `make acceptance-offline` passed 30 tests
(15 lifecycle acceptance, 9 parser-backed integration, 6 lifecycle lock tests).
`make check` passed 421 tests plus C packet harness and syntax checks after the
authorized local-mock-socket rerun; the sandbox attempt had 417 successes and
four socket permission errors. Isolated create-FD integration passed 4 tests.
Compileall and diff whitespace checks passed. No QEMU/SSH/live endpoints or
infrastructure changes were used; no commits or authorship trailers added.

Identity/executor validation: `make acceptance-offline` passed 39 tests;
`make check` passed 430 tests plus packet harness and syntax checks after the
authorized local-mock-socket rerun (sandbox: 426 successes, four socket permission
errors). Isolated create-FD integration passed 4 tests; compileall and
`git diff --check` passed. All process results, cancellation and process-tree
observations in new tests are mocks. No actual process supervisor, VM, SSH,
privileged launcher or network changes were executed. No commit performed.

Checkpoint/registry validation: `make acceptance-offline` passed 50 tests;
`make check` passed 441 tests, C packet harness and syntax checks with authorized
local mock sockets (sandbox attempt: 437 successes, four socket permission errors).
The final checkpoint guard also rejects a contradictory PASS stage with an
unfinished command; acceptance and full checks were repeated after this change.
Isolated create-FD integration: 4 tests passed. Compileall and diff whitespace
checks passed. All command execution and resource inspections in the new tests
are injected mocks; no live infrastructure operations or commits were performed.

engineering ledger recovery/metrics cycle (offline, 2026-10-28): independent
security review identified a real cleanup gap in `supervised_check`: signal or
reap `OSError` could escape and obscure the original timeout/interruption.
Cleanup now catches those errors, preserves the original failure, and leaves the
check unresolved so reconciliation and a fresh successful run remain mandatory.
The ledger records explicit operator policy events and metrics now expose
terminal-task success rate, task/check durations, rework, event counts and
resource fields explicitly marked unknown; no native hook trust or token/cost
telemetry is inferred. Engineering-ledger tests pass 27/27, including injected signal/reap
failures, stale-review invalidation and metrics evidence; full `make check`
passes 556 tests. Live hook activation, native usage import and
resource measurement remain NOT TESTED.

Current-health/process validation: `make acceptance-offline` passed 65 tests;
`make check` passed 456 tests, C packet harness and syntax checks after the
authorized local-mock-socket rerun (sandbox: 452 successes, four socket permission
errors). Isolated create-FD integration passed 4 tests. Compileall and
`git diff --check` passed. New process tests use only temporary synthetic proc
trees and injected systemd results; no live proc scan, VM, SSH or network
changes were performed. No commits or authorship trailers added.

Offline ownership-attestation cycle (offline, 2026-10-28): architect, QA and
security independently selected the next functional gate: bind exclusive
resource ownership evidence to the existing registry verifier without treating
receipts or process presence as proof. `RegistryAdapter` now accepts an
optional injected attestor and only accepts a matching lab ID, exact verified
resource set, `exclusive=true`, no cross-lab conflict and
`evidence_status=synthetic`; absent, unknown, malformed and conflicting evidence
remain fail-closed. Added valid/negative offline tests and corrected stale
single-NIC documentation to reflect current dual-NIC source topology. Live
ownership, cleanup authority, provenance and dedicated-host execution remain
NOT TESTED and are not implied by this contract. A follow-up integration fixture
now drives the attested `RegistryAdapter` through the full seven-stage offline
orchestrator, proving the contract is consumed at configure and later stages
rather than only in an isolated probe.

Release bundle limit guard cycle (offline, 2026-10-28): independent security
review found that `opla-release-bundle.py` checked `MAX_FILES` before accepting
the current source member, allowing one oversized entry beyond the limit.
Verification now counts the candidate member before accepting it, with a
1501-entry regression fixture. The artifact remains inert and untrusted; no
signature, activation or installation policy was changed.

Path-integrity guard cycle (offline, 2026-10-28): independent architecture and
security review found three fail-closed consistency gaps. Bundle verification
now rejects non-canonical tar member paths before extraction; private lifecycle
journals reject symlink ancestors, not only a symlink leaf/parent; and the
reviewed engineering command subset includes its explicit `policy` ledger action.
Regression tests cover `./`/duplicate-slash entries, nested journal symlinks and
policy CLI classification. No trust, activation or host permissions changed.

Registry evidence-file guard cycle (offline, 2026-10-28): architecture review
found that registry receipts and `state.env` accepted hardlinks or writable
evidence files. Shared `_trusted_file` validation now requires regular,
single-link, invoking-user-owned files with no group/other write bits; receipts
also require private mode. Read-only verifier and registry inspection both use
the guard, with hardlink/writable temp-fixture regressions. Ownership and
cleanup semantics remain unchanged and no host registry was touched.

Journal/inspector fail-closed cycle (offline, 2026-10-28): architecture review
found that a generic PASS journal record could omit durable evidence/timestamp
and still be accepted on resume. The journal now requires serializable evidence
and `finished_at` for every PASS stage, while boolean executors persist explicit
evidence. Registry verification also converts injected inspector exceptions and
malformed results into blocked, non-deletion-authorizing records. Regression
tests cover both corruption paths without catching process interrupts or running
host probes.

Evidence-integrity race cycle (offline, 2026-10-28): architecture/security
review found that hardlinked evidence could pass regular-file checks and that
the incident reporter inputs were not all revalidated after dispatch. Bundle
inventory now requires regular single-link files, hashes through an
O_NOFOLLOW-pinned descriptor, and runs the reporter against a temporary immutable
snapshot; original interval, counter, EVE, JSONL and client inputs are rechecked
afterwards. Incident and artifact readers reject hardlinks as well. Regression
tests cover EVE/client mutation during report generation and hardlink rejection.
No live telemetry, provenance trust or deployment activation is implied.

Subprocess-supervision completion cycle (offline, 2026-10-28): call-graph audit
found that `vm-disk.py` bypassed lifecycle timeout supervision for `qemu-img`,
`systemctl` and retained-guest launch commands. A shared finite-timeout,
owned-process-group executor with injected runners now covers offline checks,
image validation, backup/restore and resume; injected nonzero results preserve
`check=True` failure semantics. Initial `communicate()`/`wait()` OSError paths in
the lifecycle and configure launcher now perform TERM/KILL/reap cleanup and
persist configure reconciliation evidence. Focused fault-injection tests,
offline acceptance and portable checks passed. No VM, systemd, network or
privileged operation was executed.

Create-launcher supervision cycle (offline, 2026-10-28): the privileged create
entrypoint no longer dispatches an unbounded `create-lab.sh`. It validates a
finite aggregate budget, owns and reaps the child process group, persists an
atomic file-and-directory-fsynced `RECONCILIATION_REQUIRED` receipt on timeout,
initial errors or malformed injected results, and blocks retries until manual
reconciliation. Lock order, trusted-source checks and nonzero child exit
semantics are unchanged. Offline fault-injection tests and full checks passed;
no create, VM, systemd or host mutation was executed.

Active-recovery preflight timeout cycle (offline, 2026-10-28): the read-only
creation recovery audit now bounds its default `systemctl`/`ip`/`nft` probe
dispatch at ten seconds and exposes an injected timeout-aware runner for tests.
Invalid budgets fail before dispatch; existing `execution_allowed=false` and
non-mutating recovery semantics remain unchanged. Focused and full offline
checks are required before completion; no host probe was executed.

XDP scan-policy timeout cycle (offline, 2026-10-28): `bpftool` map ABI
inspection and policy update now share a finite, NaN-safe five-second timeout.
ABI validation and `check=True` update semantics remain unchanged, and timeout
or ABI failures cannot mutate the policy. Regression tests verify timeout
propagation and rejection of invalid budgets; no BPF map or host interface was
accessed.

Unified CLI supervision cycle (offline, 2026-10-28): the user-facing Make
dispatcher now applies an explicit seven-thousand-two-hundred-second aggregate
budget, owns the child process group and performs TERM/KILL/reap on timeout or
initial errors. Target-specific launchers retain their own stage budgets and
reconciliation contracts; the CLI budget is only an outer bound. Injected
runner tests preserve exact nonzero Make exit codes, confirmation guards and
safe argv construction. No Make target, VM, network or host mutation was run.

## Integration readiness preparation cycle (offline, 2026-10-28)

Prepared the Trust gate B ADR, dedicated three-VM host specification, E2E test
plan, and controlled integration runbook from the actual create/configure,
image-verification, XDP, telemetry, registry, and release paths. Added
`tests/test_integration_readiness_docs.py` to keep the documents explicit about
`BLOCKED` and `NOT TESTED` live status and to prevent claims of trust activation.
The engineering-ledger task was independently reviewed; no production trust root or
verifier was selected, and no VM, QEMU/KVM, SSH, network, Docker, or privileged
operation was executed. Gate B remains a proposed design pending approval;
gates C/D remain externally blocked pending a dedicated authorized host.

## Cross-platform compatibility assessment cycle (offline, 2026-10-28)

Audited control-plane, VM-hosting and Linux guest-runtime portability with
platform, virtualization and eBPF/security reviewers. Added the read-only
`bin/opla-platform.py` detector and fail-closed capability checks, plus
contract tests and the platform, multi-architecture and backend architecture
documents. Source evidence confirms the current implementation is Linux,
systemd, QEMU/KVM, Debian amd64-oriented; no other distribution, ISA, HVF,
WHPX, TCG or Firecracker runtime is supported or tested. ARM64/RISC-V remain
unverified. No live or privileged operation was executed and existing Linux
backend behavior was not changed.

## CI/CD and release practice cycle (offline, 2026-10-28)

Documented the separation between portable PR checks, inert artifact packaging,
manual protected Gate C, Trust B and Deployment Gate D in
`docs/ci-cd-release-practices.md`. Added the safe `ci-offline` Make target and a
GitHub `platform-contract` job that records read-only capability evidence and
readiness contract tests. No hosted workflow was executed from this checkout;
no live runner, VM, Docker, SSH, network or deployment operation was used.

## Deliverable A — Offline end-to-end simulation
- Existing Makefile and scripts mapped to transition graph including actual privileges and lock order.
- Consolidated orchestration module with adapters: resource preflight, lab creation, readiness, configure, health, scenario, evidence/report; secure state journal.
- Adapter tests with pure mocks (no root, SSH, QEMU) simulate valid execution and failures at EVERY boundary.
- Resume rules: only skip steps where resources independently verified; creation never blindly retried after ambiguous failure.
- Deterministic sample acceptance JSON: per-step status PASS / FAILED / BLOCKED / NOT TESTED, evidence files and commands, errors/timeouts, exit code.
- Existing 381+ tests green plus new orchestration tests. Offline completion is explicitly distinguished from live acceptance.

## Deliverable B — Trusted deployment integration
- Inert DEB reviewed for file completeness, executable bits, dependencies, permissions, postinst absence; no /opt or /var installation on dev host.
- Trusted installed code path separately approved and versioned; launcher resolves immutable version, not user checkout. Preserve lock order/global lifecycle lock, real user drop where applicable.
- Tests for malicious source, symlinks, hardlinks, interrupted activation, concurrent maintenance, compromised package, mismatch identity.

## Deliverable C — Real isolated acceptance (requires explicit go-ahead)
- Dedicated test host or VM with KVM and >= 5GiB **free** RAM, adequate disk/network isolation; never developer Debian 13.
- Rebuild victim image with verified Suricata and XDP dependencies. Check image hashes and installed packages.
- Execute create -> ready -> configure -> health -> benign traffic -> bounded security scenarios -> telemetry/report -> safe teardown.
- Capture stdout/stderr, machine state, unit logs, BPF attach proof, counters, Suricata eve alerts, scenario correlation, failure report and reproducible commands.
- Confirm idempotent rerun, fail-closed when a stage is broken, cleanup ownership/receipts.

## Deliverable D — Bring-your-own-infrastructure
- User YAML defines every node IP/DNS, components, network interfaces, SSH and optional bastion; no fixed real IPs or forced VPS provider.
- Implement direct SSH deploy with host-key pinning, reversible changes/rollback and per-node health, then optional transports/VPN LAST.

## Acceptance gates
A: offline integrated fake-adapter tests pass, no false READY, no side effects.
B: trustworthy install plus privilege boundaries audited and tested on isolated system.
C: full 3 VM chain actually succeeds with evidence; real failures are diagnosed and safe recovery tested.
D: deploy selected modules to an explicitly approved external Linux target, no secrets in YAML/logs.

Stop announcing "fully operational" until gate C. Do not replace entire architecture without evidence and tests.
