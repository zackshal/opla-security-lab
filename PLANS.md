# OPLA accelerated engineering and acceptance roadmap

**Inspected baseline (2026-10-29):** HEAD `99d5cad4583e11944402c603b0ae72cab661ff8d`.
The worktree already contained dirty tracked and untracked project files when
this cycle began; they were preserved without reset, clean, stash or commit.

## Current work package and next gates

## Repository hygiene and selection recovery (offline, 2026-10-28)

The lab CLI now clears a user-owned regular selection file when its referenced
lab has disappeared, while malformed or symlinked selection files remain
fail-closed. The engineering ledger and role contracts were made provider
neutral; public documentation and tests no longer name a specific AI vendor.
The local checkout cannot remove the read-only `.agents` and `.codex` mounts;
their tracked removal must be completed from a normal writable checkout before
the cleanup commit. No live lab or host state was touched.

**Completed offline package: local engineering ledger.**
Preserve all lab work below and last commit `1e6aa67`; do not replace the lab
orchestrator with an AI scheduler. Audit/ADR, file plan and acceptance are in
`docs/engineering-workflow.md`. Keep role contracts, reviewable policy gates,
local locked task/evidence support and offline fixtures. No DB/framework,
permission override, automatic commits or live infrastructure. Policy activation
remains an explicit user action.
Independent read-only agents audit/review; the parent alone edits this dirty tree.
After engineering-ledger acceptance, resume the next OPLA functional integration gate below.

**Completed offline package: runtime observation evidence integrity.** Preserve
the full deployment-validation goal, but do not run live host operations on this
Debian 13 system. A dedicated host remains necessary for P14--P21.

**Current gate: dedicated-host runtime acceptance (BLOCKED ON LIVE ENVIRONMENT).**
The offline reporter supervision package and the later P14--P21 fault,
ownership, platform, and evidence checks are recorded below as completed.
Continue only with a separately authorized dedicated-host cycle; do not use
this Debian 13 development host for live provisioning. Until that environment
and approval exist, P14--P21 live verdicts remain `NOT TESTED`.

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

### Current offline acceptance recheck (2026-10-29)

On the current dirty worktree, `make acceptance-offline` passed 115 lifecycle,
artifact, client-continuity, timeout, lock, and process-evidence tests.
`make acceptance-check` returned a read-only JSON result with
`assessment_scope=fixture_and_source_only`,
`physical_host_assessment=NOT TESTED`,
`ready_for_automatic_execution=false`, and `overall_status=NOT TESTED`.
Source/fixture contracts were present; guest identity/provisioning/idempotency,
kernel verifier, XDP, Suricata, Zabbix delivery, three-VM experiment, and
authorization remained `NOT TESTED`. The output is evidence of the preflight
run only, not proof of runtime readiness. No VM, SSH, network, Docker,
systemd, or privileged operation was run.

### Host Admission evidence cycle (offline, 2026-10-28)

Implemented a separate, reproducible physical-host admission boundary without
running it from the development sandbox. A normal user on the candidate host
may export bounded read-only CPU/KVM/RAM/disk/network/Docker/process/tool
observations; the importer validates a fresh report, required evidence,
independently recorded machine ID and a source SHA-256 without probing the
host again. Missing visibility remains `UNKNOWN`; known insufficient RAM/disk,
absent KVM, unsupported built-in architecture or address-pool overlap is
`REJECTED`. The old Ansible fixture preflight now says explicitly that its
physical-host assessment is `NOT TESTED`. Unit tests cover those outcomes and
no VM, network, Docker, systemd or privileged command was executed. Storage
root configurability is an approved design direction only: existing labs stay
under their recorded root; no automatic migration is permitted.

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

### Host Admission namespace and path hardening (2026-10-29)

Host Admission now emits distinct `sandbox_capability_assessment` and
`host_assessment` fields. If namespace isolation is observed, capability failures
belong to that constrained view and physical-host status remains `NOT TESTED`;
unknown scope also cannot admit the host. Matching namespaces with local PID 1
is only a visibility observation, never proof of bare metal. A matching explicit
`--confirm-host-terminal MACHINE_ID` is also required before assigning a host
verdict, and is documented as operator assertion rather than cryptographic
authentication. Physical machine type remains `NOT TESTED`. Reports require collector fingerprint, host identity,
collection timestamp, execution-scope evidence, and all mandatory evidence
sections. Import remains read-only and binds its decision to the exact report
hash.

Security follow-up replaced path prechecks with directory-descriptor traversal
using `O_NOFOLLOW` for each parent component. Offline coverage includes missing
RAM/KVM/disk, overlapping networks, incomplete reports, limited namespaces, and
symlinked parent paths. After the independent review and operator-attestation
change, 46 focused Host Admission tests and 722 repository tests passed. Python
compileall, documentation validation, and `git diff --check` also passed.
Physical-host probes and VM/network/service operations were not run.

### Host Admission origin pin and storage layout decision (2026-10-29)

The importer now requires a collector source fingerprint supplied independently
of the report before it can issue a host assessment. A mismatch blocks import;
omitting the pin through the library API leaves host assessment `NOT TESTED`.
The command-line import requires the pin. The decision records the source
report SHA-256 and pin comparison. This is not cryptographic provenance: an
operator-supplied JSON can still be fabricated, and the reported machine ID and
collector hash can be copied. User-terminal collection now also requires a
non-root, non-setuid process and an interactive stdin TTY; this excludes
scheduled/noninteractive export but cannot prove absence of a container.

Added [storage layout ADR](docs/adr-opla-storage-layout.md) after inventorying
current `/var/lib/opla` assumptions in create, launcher, registry, selection,
state, lifecycle, resources, cleanup/recovery and scenario paths. It proposes
versioned `state_root`, `disk_root` and `artifact_root` for new labs, pins the
resolved roots in state/receipts and preserves legacy roots. No path migration,
configuration activation or host operation is included. Host Admission's
`--storage-root` remains a measurement input only.

Offline tests cover expected collector pin match/mismatch/absence, interactive
terminal context, RAM/KVM/disk failures, CPU virtualization flags, overlapping
route/interface/Docker networks, incomplete process/service/listener inventories,
stale identity/time and import without probes. The exporter and validator now
include running systemd services through the same bounded read-only probe
wrapper.

An independent security review approved this Host Admission package; details
and evidence are in
[`host-admission-security-review-20261029.md`](docs/evidence/host-admission-security-review-20261029.md).
Focused Host Admission/CLI/help tests passed 90; Host Admission alone passed 67.
The full `make check` attempted 767 tests but could not pass in this sandbox:
2 failures and 9 errors came from AF_UNIX socket creation denied with `EPERM`
in the existing service-process tests. No sandbox bypass was used. The
115-test `acceptance-offline`, compileall, docs validation and
`git diff --check` passed. Physical Debian assessment and Gate C remain
`NOT TESTED`.

### Host Admission malformed-input hardening (2026-10-29)

Review of the import boundary found that malformed evidence field types could
escape validation as Python exceptions, and deeply nested JSON could emit a
traceback. The importer now normalizes these cases to a stable `BLOCKED`
diagnostic. Independent security review also found that imported evidence could
falsely claim bare metal, duplicate route/Docker keys could hide a conflicting
subnet, a wait error could leave the diagnostic child running, and a root export
could be labelled as an ordinary user session. The importer now requires
`physical_machine_type=NOT TESTED`, rejects duplicate nested JSON keys, kills
and boundedly reaps the owned process after wait errors, and only identifies a
non-root non-setuid export as `user_terminal`. Regression tests cover each
finding. A follow-up also requires an absolute normalized storage path before
using disk capacity and rejects NaN/Infinity in nested network evidence. This
is parser and probe lifecycle hardening only: self-reported evidence remains
unauthenticated, and the result cannot authorize Gate C. Focused Host Admission
tests: 58 passed; final `make check`: 746 tests passed. The 115-test
`acceptance-offline`, compileall, documentation validation (79 Markdown files,
159 local links, 48 CLI examples) and `git diff --check` passed. No host probes
were run.

### Runtime observation diagnostic status preservation (2026-10-29)

Independent QA found `capture_live()` retained failed `ss`/`systemctl` results,
but `build_report()` flattened the snapshot into an exit status of 0 and the CLI
still returned success. Process snapshot failures also aborted before a partial
evidence report could be written. The report now records separate checks for
each process snapshot and diagnostic command, carries their exit status and
failure reason, persists partial observations, exposes `observation_status`,
and returns nonzero on a blocked observation. Filesystem and process snapshots
are individually represented; CLI selection requires unique process IDs.
Diagnostic children now have finite execution and reap deadlines, bounded
output storage, owned process-group termination, and recorded kill/reap errors.
Functional `overall_status` remains `NOT TESTED` even when inventory succeeds.
Offline regressions cover missing tools, timeouts, output overflow, kill/reap
failure, partial evidence, CLI exit status, and successful inventory without
readiness promotion. No host probes were run.

### Evidence reporter process supervision (2026-10-29)

Independent architecture and security review found that one failed pipe reader
could leave the other reader pending, `killpg()` failures prevented direct
fallback/reap, and `process.wait()` in cleanup had no deadline. The evidence
worker now supervises both bounded readers as tasks, cancels and joins them on
failure or request cancellation, terminates the process group even if its
leader has exited, falls back to direct-child kill, and applies a 1.5-second
cleanup deadline plus a 0.5-second post-fallback reap. Ordinary descendants
inherit the group created by `start_new_session=True`. A PGID is numeric rather
than a durable handle; if a descendant escapes the group while retaining a
pipe, reuse between leader exit and cleanup cannot be excluded. The trusted
incident reporter itself currently launches no child processes. Cleanup
uncertainty remains a failed operation. Offline fault tests cover spawn failure,
stdout/stderr overflow, timeout, caller cancellation, kill/reap failures, a
real temporary child timeout, and a pipe-holding descendant after its leader
exits. The service process suite passed 22/22; `make check` passed 757 tests and
`make acceptance-offline` passed 115. Compileall, documentation validation (80
Markdown files, 159 local links, 48 CLI examples), and `git diff --check` also
passed. This is not live service deployment or VM evidence.

### Runtime source inventory refresh (2026-10-29)

Rebuilt the source-bound static runtime inventory after the Host Admission and
runtime observation updates. All 13 component inventories pass and the report
verifies against the current source fingerprints. The report explicitly has
`execution_performed=false`, `host_mutated=false`, and `overall_status=NOT
TESTED`; it does not establish physical-host readiness or P14–P21 runtime
acceptance. Durable evidence:
[`runtime-static-audit-20261029-continuation.json`](docs/evidence/runtime-static-audit-20261029-continuation.json).
Focused runtime audit and service tests passed 29/29. No physical-host probes,
VM execution, or live service operations were performed.

Final regression check for this continuation: `python3 -m compileall -q bin
tests`, the focused runtime-audit/service suite (29 tests),
`make acceptance-offline` (115 tests), and `git diff --check` passed. `make
check` attempted all 767 tests and remains blocked by sandbox AF_UNIX restrictions:
9 service socket tests error with `PermissionError: [Errno 1] Operation not
permitted`, and 2 process acceptance tests consequently fail worker startup.
No sandbox bypass was attempted. This environmental limitation does not change
the live runtime status from `NOT TESTED`.

Host and platform admission regression recheck: `python3 -m unittest
tests.test_opla_host_admission tests.test_opla_runtime_audit
tests.test_opla_platform -q` passed 111 tests. This includes fixtures for
insufficient RAM/disk, missing KVM, overlapping route/Docker networks,
incomplete reports, namespace-limited visibility and preservation of
`UNKNOWN`/`NOT TESTED`; it does not collect physical-host evidence.

### Process snapshot PID reuse guard (2026-10-29)

Runtime-audit review found that a process could exit and its PID be reused
between procfs reads, mixing status/FD data with another process. The collector
now binds `status` to PID/PPID and compares `(PID, PPID, starttime)` from
`/proc/PID/stat` around all process-file reads, including I/O. A PID-reuse
fixture verifies fail-closed behavior. An independent security review checked
the Linux stat field indexes and found/fixed one ordering issue by ensuring
`/proc/PID/io` is read before the final identity check. Review and current
source-bound report are recorded in
[`runtime-proc-snapshot-review-20261029.md`](docs/evidence/runtime-proc-snapshot-review-20261029.md)
and
[`runtime-static-audit-20261029-process-identity-reviewed.json`](docs/evidence/runtime-static-audit-20261029-process-identity-reviewed.json).
The Host Admission/runtime/platform/documentation focused set passed 115 tests;
compileall, report verification and `git diff --check` passed. No physical
processes were inspected; live runtime remains `NOT TESTED`.

### Host Admission distribution identity (2026-10-29)

The admission export previously recorded kernel release and architecture but
omitted distribution ID/version, so reviewers could not tie a report to the
Debian-only built-in host profiles. The exporter now parses `ID` and
`VERSION_ID` from `/etc/os-release` as data without shell evaluation. Debian
12/13 are recognized source profiles; missing, malformed, duplicate or
unvalidated IDs/versions add `UNKNOWN`, not a technical `REJECTED`. Independent
review found and prompted a fix for duplicate/malformed last-wins parsing. The
review and refreshed static inventory are
[`host-admission-distro-review-20261029.md`](docs/evidence/host-admission-distro-review-20261029.md)
and
[`runtime-static-audit-20261029-distro-identity-reviewed.json`](docs/evidence/runtime-static-audit-20261029-distro-identity-reviewed.json).
Host Admission tests passed 72/72; the combined Host Admission/runtime/platform/
docs suite passed 120 after the parser regressions. `tools/check-documentation.py`
reported 84 Markdown files, 169 local links, 48 CLI examples and 0 errors.
Compileall, static-report verification and `git diff --check` passed. Full
discovery attempted 773 tests; it retained the same sandbox-only limitation of
9 AF_UNIX `EPERM` errors and 2 dependent worker-start failures (4 skipped). No
host data was collected; distro runtime support remains `NOT TESTED`.

### Systemd unit to process evidence binding (2026-10-29)

Runtime capture previously listed matching systemd units while requiring
operator-supplied PIDs separately, so it could not show that a PID/FD snapshot
belonged to the inspected unit. Added explicit `--unit` selection restricted
to exact built-in QEMU/DHCP unit name forms. A fixed bounded `systemctl show`
property query runs before and after process capture; MainPID is linked to its
snapshot and any unit/PID change or active unit without MainPID blocks the
observation. Unit names do not prove ownership and never promote readiness.
Independent review found no remaining issue; its evidence and refreshed static
source map are
[`runtime-unit-snapshot-review-20261029.md`](docs/evidence/runtime-unit-snapshot-review-20261029.md)
and
[`runtime-static-audit-20261029-unit-pid-reviewed.json`](docs/evidence/runtime-static-audit-20261029-unit-pid-reviewed.json).
The combined Host Admission/runtime/platform/docs suite passed 126 tests,
`make acceptance-offline` passed 115, and compileall, docs validation (85
Markdown files, 171 links, 48 CLI examples), report verification and
`git diff --check` passed. No systemd unit was queried; P14--P21 runtime remains
`NOT TESTED`.
The final full discovery run attempted 779 tests; 9 AF_UNIX socket cases were
denied by sandbox `EPERM`, causing 2 dependent worker-start tests to fail; 4
tests were skipped. This remains an environment restriction, not a passing full
suite, and was not bypassed.

### Unit selector matches launcher contract (2026-10-29)

Tightened `--unit` validation to the actual registry ID range and exact
`create-lab.sh` outputs: `dhcp-lab-<id>.service` and QEMU services for only the
three built-in roles. Independent review confirmed the patterns and checked
invalid role/length/trailing-input cases. The runtime-audit suite passed 36
tests. This rejects accidental inspection of unrelated units; names remain
observation selectors, not ownership proof.
The current Host Admission/runtime/platform/documentation set passed 127 tests;
compileall, documentation validation (85 Markdown files, 172 links, 48 CLI
examples), evidence verification and `git diff --check` passed. Full discovery
attempted 780 tests and repeated the same 9 AF_UNIX `EPERM` errors plus 2
dependent worker-start failures (4 skipped). No sandbox bypass or live service
inspection was performed.

### Platform preflight reflects source-supported profiles (2026-10-29)

Platform inventory showed two optimistic classifications: any Linux distribution
with tools/KVM could appear VM-host feasible, and Linux host identity yielded a
FEASIBLE guest preflight without examining a guest. VM preflight is now
FEASIBLE only for measured prerequisites plus the Debian 12/13 x86_64 profile;
unknown distro/version is UNKNOWN and known missing prerequisites stay BLOCKED.
Guest preflight remains UNKNOWN until checked inside guests. Independent review
also found malformed/duplicate `os-release` identity could be normalized; the
data parser now rejects ambiguous `ID`/`VERSION_ID`. Review evidence:
[`platform-profile-preflight-review-20261029.md`](docs/evidence/platform-profile-preflight-review-20261029.md).
The admission/runtime/platform/docs set passed 130 tests; full discovery
attempted 783 with the same 9 AF_UNIX sandbox `EPERM` errors, 2 consequent
worker-start failures and 4 skips. Compileall, docs validation (86 Markdown
files, 174 local links, 48 CLI examples), source-report verification and
`git diff --check` passed. No host probing was performed.

### Preserve uncertainty during capability lookup (2026-10-29)

Follow-up review found that the path-only dependency resolver mapped both a
missing executable and a failed metadata lookup to `None`, which could turn a
sandbox visibility restriction into a physical capability rejection. Added
per-tool `PRESENT`/`ABSENT`/`UNTRUSTED`/`UNKNOWN` evidence. Proven absence and
failed trust checks remain blocking; lookup/metadata errors and unavailable
`MemAvailable` now remain `UNKNOWN`, unless a separate measured hard blocker is
present. Added offline regressions for missing tools, denied metadata and
incomplete memory evidence. Runtime and physical-host status are unchanged.
The independent security review found the same visibility issue in `/dev/kvm`:
path/access checks could treat a sandbox-hidden node or current-UID denial as a
physical-host blocker. Replaced `exists()` with explicit stat evidence and
distinguished `ABSENT`, `INACCESSIBLE` and `UNKNOWN`; only confirmed absence is
a technical blocker, while denied current-UID access stays `UNKNOWN` because
the privileged launcher may differ. The report now states its current-process
scope and leaves physical-host status `NOT TESTED`. Independent review approved
the final delta with no remaining finding; regular-file, directory and symlink
fixtures verify KVM device type. The focused Host Admission/platform/runtime
suites pass 133 tests; compileall, documentation validation, evidence
fingerprint verification and `git diff --check` pass.
Full discovery ran 789 tests but is blocked by sandbox `EPERM` creating AF_UNIX
sockets (9 errors, 2 dependent worker-start failures; 4 skipped). No sandbox
bypass or host operation was attempted.

### Offline lifecycle and acceptance recheck (2026-10-29)

After the platform visibility fixes, `make acceptance-offline` passed all 115
fake-adapter lifecycle tests. `make acceptance-check` completed its
read-only fixture/source preflight at 2026-10-29T11:13:56Z: source contracts,
dual-NIC source separation and pinned guest inventory checks passed, while
physical-host admission, guest provisioning, XDP, Suricata, Zabbix delivery,
three-VM experiment and authorization remained `NOT TESTED`. It returned
`ready_for_automatic_execution=false` and `overall_status=NOT TESTED`. Neither
command launches a VM or performs live acceptance. The targeted current
Host Admission/platform/runtime suites remain 133/133; full repository check
remains constrained by AF_UNIX `EPERM` as recorded above.

### Broad offline regression outside sandbox-blocked AF_UNIX cases (2026-10-29)

To distinguish unrelated regressions from the sandbox socket restriction, ran
the complete discovered suite with only the 11 currently AF_UNIX-dependent
tests omitted: nine `ServiceRuntimeTests` that create/listen on Unix sockets
and two `ServiceProcessAcceptanceTests` that require the blocked workers.
Across 789 discovered cases, the remaining 778 passed with 4 existing skips
in two consecutive runs. One initial filtered attempt returned nonzero without
a retained summary; the two subsequent logged runs both passed, so that
transient result was not reproduced. The 11 omitted tests remain unverified in
this sandbox; the full `make check` is still not green and no claim of complete
suite acceptance is made.

### Keep P14 RAM preflight aligned with the VM launch contract (2026-10-29)

Source review confirmed the three allocations are 1024/2048/512 MiB and the
launcher reserves another 1536 MiB, so the 5120 MiB available-RAM gate is
consistent today. Added an offline contract regression that derives the
threshold from `create-lab.sh` VM arguments and checks both platform and
Host Admission thresholds plus the dedicated-host specification. This prevents
future VM sizing changes from leaving admission checks stale. The focused
Host Admission/platform/runtime suite passes 134 tests; the full test suite
with only the same 11 sandbox AF_UNIX-dependent cases omitted passes 779 tests
(4 skipped). `make check` still reports 790 tests with 9 `EPERM` socket errors
and 2 dependent worker startup failures. Compileall, documentation validation
(87 Markdown files, 178 links, 48 CLI examples), and diff checks pass. No VM or
host resources were used.

### Preserve unknown capability states in machine-readable output (2026-10-29)

Platform review found that `kvm.present` and `tools[*].available` serialized
unknown observations as `false`, which could be consumed as confirmed absence
despite a neighboring `status=UNKNOWN`. These fields now use `null` for unknown
visibility and reserve `false` for measured absence/unusable dependencies;
preflight decisions still key on the explicit status. Offline regression tests
cover both fields, and an independent security reviewer approved the change.
The Host Admission/platform/runtime focused suite passes 135 tests; compileall,
documentation validation (87 Markdown files, 180 links, 48 CLI examples),
source fingerprint verification and `git diff --check` pass. No host probes or
runtime operations were performed; live status remains `NOT TESTED`.
The final full `make check` attempted 791 tests and remains limited by the same
9 AF_UNIX `EPERM` errors and 2 dependent worker-start failures (4 skipped).

### Block default-route gateway overlap with OPLA pool (2026-10-29)

An offline fixture showed a false `CONDITIONALLY ADMITTED`: a default route
through IPv4 gateway `100.64.0.1` was ignored as `dst=default`, and the host
had no interface address inside the pool. Host Admission now parses route
gateway addresses as well as destination CIDRs; an IPv4 gateway overlapping
`100.64.0.0/10` is a conflict, valid IPv6 gateways do not overlap the IPv4
pool, and malformed gateway evidence yields `UNKNOWN`. Regression tests cover
the conflicting default route and malformed gateway. Independent security
review approved the change with no finding; Host Admission tests passed 74.
No route or host probe was run.
The combined Host Admission/platform/runtime suite passes 137; source-bound
inventory verification passes with runtime `NOT TESTED`. Documentation
validation reports 87 Markdown files, 181 local links and 48 CLI examples.
The final `make check` attempted 793 tests and remains restricted by 9 AF_UNIX
`EPERM` errors, 2 dependent worker-start failures and 4 skips.
Repeating discovery with only those 11 exact AF_UNIX-dependent cases excluded
ran 782 tests successfully (4 skipped); the omissions remain explicitly
unverified here.

### Use route gateways in lab subnet allocation (2026-10-29)

Source review found that Host Admission detected IPv4 gateways inside the
built-in `100.64.0.0/10` pool, while the create path's two subnet allocator
functions still considered only route destinations. A default route through
`100.64.0.1` could therefore collide with a newly selected lab subnet even
after admission reported the conflict. Both `bin/lib.sh` allocation paths now
call the shared bounded, read-only `bin/opla_network.py`; its pure selector
excludes IPv4 route destinations and gateway host routes, ignores IPv6 for this
IPv4 pool and fails closed on malformed route evidence. Follow-up security
review also rejected explicit null/empty destinations, explicit null gateways,
duplicate JSON keys and excessive JSON nesting, and found that checking an
output cap after `subprocess.run(capture_output=True)` did not bound memory.
The helper now streams a fixed maximum from a trusted
`ip` process group, enforces a deadline, and terminates/reaps the owned group on
failure. Offline tests cover malformed JSON, oversized output and timeout
cleanup. The static runtime inventory fingerprints the helper as part of
network management. Independent security review passed with no open findings;
the reviewed scope and source hashes are recorded in
`docs/evidence/network-allocator-security-review-20261029.md`.
Focused Host Admission/platform/runtime/allocator tests pass 149; compileall
and source fingerprint verification pass. The full regression run attempted
805 tests (4 skipped), with 9 AF_UNIX `EPERM` errors and 2 dependent worker-start failures
caused by sandbox restrictions. No host probes or live network operations were
performed; runtime remains `NOT TESTED`.

### Validate nft policy across lab resume (2026-10-29)

P14 source audit found that `lab-lifecycle start` accepted any existing nft
table with the expected OPLA name and then continued to TAP/DHCP/QEMU setup.
The actual rules were only checked during stop. Start now verifies both exact
data and management policies in preflight, again before network preparation,
and before each policy creation. Explicit ENOENT remains acceptable during
preparation so absent tables can be created; all other inspection failures and
unexpected rules block. A final joint check requires both tables to exist and
match immediately before QEMU resume. Tests cover foreign data and management
policies, probe failure, missing-table creation, final absent-table refusal and
no resume after detected drift. Independent security review found and helped
close an initially ignored final absence result and a preparation regression;
final review has no open blocking findings. Review evidence, the external-root
writer race and source fingerprints are in
`docs/evidence/p14-nft-resume-security-review-20261029.md`. The lifecycle/nft/
recovery focused set passes 48 tests; `make acceptance-offline` passes 115;
compileall and diff checks pass. The full `make check` attempted 813 tests
(4 skipped) and remains restricted by 9 AF_UNIX `EPERM` failures and 2
dependent worker-start failures. Static source inventory verifies, but runtime
remains `NOT TESTED`; no host or live network operations were performed.

### Distinguish sandbox and host admission (2026-10-29)

Host Admission export/import now keeps process-visible capability results
separate from the operator-attested host assessment. Reports require a pinned
exporter fingerprint, independently recorded machine ID, fresh timestamp,
ordinary user-terminal context and complete evidence before the host assessment
can inherit the measured result. Missing evidence stays `UNKNOWN` or
`NOT TESTED`. The exporter uses bounded fixed-argv read-only probes, writes a
new mode-0600 report and never creates VM/storage directories. Import runs no
system probes. The existing storage ADR defines future `state_root`,
`disk_root` and `artifact_root` contracts; it does not change current paths or
migrate existing labs.

Independent review closed an endpoint-absence ambiguity: no canonical
`/var/run/docker.sock` is recorded as endpoint `ABSENT`, while Docker network
inventory remains `UNKNOWN`; a successful inventory is explicitly limited to
that rootful socket. Tests cover missing/unknown Docker endpoint, unsafe socket
type/symlink, RAM/KVM/network/disk blockers and incomplete exports. Host
Admission passes 78 tests; documentation validation passes 89 Markdown files,
187 local links and 48 CLI examples. Full discovery attempted 817 tests (4
skipped), with 9 AF_UNIX `EPERM` errors and 2 dependent worker-start failures
under sandbox policy. `compileall` and `git diff --check` pass. Physical-host
readiness and live acceptance remain `NOT TESTED`; no VM, network, Docker,
systemd or host filesystem state was changed.

### P15 XDP ownership and lifecycle hardening (2026-10-29)

Offline review found that program identity and map pin names did not prove the
pinned map objects belonged to the loaded program, and load/unload/policy did
not share an operation lock. Receipts now bind program ID/tag and map IDs/types;
policy updates also match the live `ens3` attachment to the pinned program,
validate every map and ABI, and use the common lock. Unload detaches only the
matching program and rechecks before removing fixed pins. Legacy schema-1
receipts remain usable only when their recorded program identity matches the
live attachment and the complete live map inventory matches that program; they
are not rewritten. Lock validation permits root-owned sticky `/run/lock` only
for effective UID 0 and rejects non-root lock creation before open. The
non-cooperating root-writer race remains an explicit single-writer runtime
assumption.

Independent security review found no remaining findings. Focused P15,
fingerprint, scenario-fingerprint and static runtime-inventory tests pass 98;
shell syntax, compile checks and source inventory verification pass. Evidence is
in `docs/evidence/p15-xdp-ownership-review-20261029.md` and
`docs/evidence/runtime-static-audit-20261029-p15-final.json`. This is offline
evidence only; BTF/capabilities, verifier output, real attachment, policy
effect, counters and detach remain `NOT TESTED` pending the authorized
dedicated-host gate.

Final regression for this continuation: Host Admission passes 78 tests and
`make acceptance-offline` passes 115. Full `make check` attempted 848 tests
(4 skipped): 9 AF_UNIX socket tests errored and 2 process-worker acceptance
tests failed because the sandbox denies AF_UNIX socket creation (`EPERM`). No
other failures were reported. No sandbox limits were changed and no live VM,
host interface, BPF attachment or external service was used.

Host Admission continuation (2026-10-29): the existing export/import and storage
ADR were re-audited against the requested host-vs-sandbox distinction. The
collector emits fixed-argv bounded observations from an ordinary user session;
the importer parses only the supplied file and checks schema, required evidence,
machine ID, age, namespace consistency and an independently supplied exporter
SHA-256. Missing capabilities remain `UNKNOWN`, while limited visibility keeps
the physical-host assessment `NOT TESTED`. Reports remain operator-supplied,
not signed attestations. The storage ADR proposes separate state, disk and
artifact roots for new labs and explicitly leaves existing `/var/lib/opla`
labs unmigrated. No physical-host report was available in this checkout, so no
host admission verdict is claimed.

Validation: Host Admission tests pass 78/78; combined Host Admission/CLI/help/
XDP offline tests pass 124/124; `make acceptance-offline` passes 115; compileall
and documentation links pass (89 Markdown files, 187 links, 48 CLI examples).
Full `make check` attempted 830 tests (4 skipped): 9 service-socket tests errored
and 2 process-worker acceptance tests failed because this sandbox denies AF_UNIX
socket creation (`EPERM`). A separate XDP policy test-only lock was redirected
to a temporary directory so tests no longer attempt writes under read-only
`/run/lock`; production locking is unchanged. No system services, network,
Docker, VM or disk resources were touched. Independent review found no concrete
issue in this continuation; prior Host Admission review details are recorded in
`docs/evidence/host-admission-security-review-20261029.md`.

Host Admission follow-up regression (2026-10-29): independent review found a
non-advancing ancestor loop in trusted executable validation, which could hang
before probe timeouts. The walk now advances at each parent and a bounded-call
regression test covers termination. Independent re-review found no remaining
Host Admission findings. Host Admission tests pass 79/79; combined
Host Admission/EVE/lifecycle evidence tests pass 144/144; offline acceptance
passes 115/115. Documentation validation passes 90 Markdown files, 192 local
links and 48 CLI examples. Full discovery attempted 855 tests (4 skipped), with
9 AF_UNIX `EPERM` errors and 2 dependent worker-start failures under sandbox
policy. Physical-host readiness remains `NOT TESTED`.

Host Admission continuation verification (2026-10-29): an additional
independent read-only security review found no findings. It reconfirmed source
pin and machine identity checks, freshness, fail-closed import, tri-state
handling of incomplete visibility, and the storage ADR's no-migration boundary.
Current regression results: Host Admission 79/79, `make acceptance-offline`
115/115, compileall and diff check pass, documentation validation reports 92
Markdown files/199 links/48 CLI examples. Full discovery attempted 882 tests
(4 skipped); 9 AF_UNIX `EPERM` errors and 2 dependent worker startup failures
remain sandbox restrictions. Exact commands, file fingerprints and review scope
are recorded in `docs/evidence/host-admission-security-review-20261029.md`.
No physical-host export was collected; physical-host readiness remains
`NOT TESTED`.

Current Host Admission regression snapshot (2026-10-29): focused Host
Admission/CLI/help tests pass 102/102; offline lifecycle acceptance passes
115/115; compileall, documentation checks (94 Markdown files/202 links/48 CLI
examples) and `git diff --check` pass. Full `make check` ran 900 tests (4
skipped) and ended with 10 errors and 2 failures: nine AF_UNIX binds were
denied with sandbox `EPERM`, two dependent service-worker acceptance tests
could not start, and one process-supervision test observed its child had
already exited before reading `/proc`. No sandbox rule was bypassed. The
independent Host Admission review and source hashes are in
`docs/evidence/host-admission-validation-20261029.md`. No physical-host export
was supplied, so physical-host readiness remains `NOT TESTED`.

### P16 Suricata ownership and evidence bounds (2026-10-29)

P16 static review found Suricata deleting guest table `inet opla_ips` by name.
New OPLA tables now carry an explicit owner marker, and manager/runtime changes
refuse to delete or replace unmarked/malformed table inspection. A validated
guest-local nft lock serializes OPLA policy operations; a separate manager
lifecycle lock serializes apply/off without deadlocking the service startup
hook. Off now stops/verifies the unit before table removal and retains
`mode.json` on any failed stop/state check. Existing unmarked tables are left
for manual review. Bounded EVE input now binds parsed bytes to a SHA-256 and
size, rejects hardlinks/symlinks/oversized lines/duplicate keys and malformed
alert identities, and continues to treat alert action as optional.

Independent security review found two OPLA transition races in off/apply and
off/systemd failure handling; both were fixed and re-reviewed. A direct,
non-cooperating privileged actor can still race nft or systemd state between
separate kernel API calls, so runtime assumes a single privileged writer.
Offline tests cover ownership and transitions (17 focused Suricata tests).
`make acceptance-offline` passes 115; full `make check` attempted 871 tests
(4 skipped), with 9 AF_UNIX `EPERM` errors and 2 dependent worker-start failures
under sandbox policy. Compileall, shell syntax, docs validation (91 Markdown
files, 196 links, 48 CLI examples) and diff checks pass. Current source-bound
static inventory verifies at
`docs/evidence/runtime-static-audit-20261029-p16-final-rollback.json`; Suricata
configuration parsing, capture, alert generation, NFQUEUE, restart and all
other P14--P21 live checks remain `NOT TESTED`.

### P17/P18 bounded scenario and reporter follow-up (offline, 2026-10-29)

Independent P17/P18 review found that live-stage `subprocess.run(timeout=...)`
did not own or terminate the nested local process group, its later 16 KiB
string slicing did not bound captured output, and the HTTP probe treated 3xx as
success. Standalone incident reporting also lacked whole-file, record-count and
match-count limits for scan JSONL. The live scenario adapter now runs in an
owned process group, bounds each output stream to 16 KiB, terminates/reaps the
group on timeout/interruption and fails closed when output reaches its cap. The
HTTP stage requires exactly `HTTP=200`. The incident reporter now parses a
no-follow, single-link stable file bounded to 32 MiB, 1 MiB per line, 100,000
records and 10,000 matches; duplicate keys/non-finite JSON values are treated
as malformed. Focused P17/P18 tests pass 28 cases, including an actual local
child process tree timeout fixture. This is offline evidence only: remote SSH
work may outlive local client cancellation, abrupt executor death may precede
final report persistence, and event-to-runtime attribution remains unverified.
P17/P18 live status remains `NOT TESTED` and blocked on the dedicated host.
The current source snapshot is
`docs/evidence/runtime-static-audit-20261029-p17-p18.json`; its fingerprints
verify but it does not change runtime verdicts.

### P19 monitoring collection and delivery hardening (offline, 2026-10-29)

The monitoring bridge now resolves victim data identity to the separate
management address, uses strict per-lab known-host checking after bootstrap,
and bounds SSH collection to 10 seconds and 128 KiB through the shared process
runner. Guest snapshots and Zabbix acknowledgements reject malformed JSON
shapes/types. The per-lab runtime directory, collector lock, event log and
outbox reject symlink substitutions; lock descriptors close on every exit.
Changed-state events use a durable atomic outbox with 1000-event/1 MiB bounds.
Send failure survives process restart; overflow fails visibly without dropping
older events. Advancing the comparison baseline after durable enqueue prevents
repeated unchanged samples from minting duplicate events. Delivery is
at-least-once: a lost ACK or crash after server acceptance but before clearing
the outbox may still duplicate an event. Initial guest host-key enrollment is
still `accept-new` TOFU; the strict collector check does not authenticate that
first enrollment.

Independent security re-review found no remaining findings in the changed
collector paths. QA's review-found duplicate transition generation was fixed
and covered. Combined P19/provisioning/purge/runtime-audit tests pass 79
(2 socket tests skipped); offline acceptance passes 115; compileall, docs
validation (93 Markdown files, 201 links, 48 CLI examples) and diff checks pass.
Full discovery attempted 900 tests (4 skipped): 9 AF_UNIX `EPERM` errors and 2
dependent worker startup failures remain because this sandbox forbids local
socket creation. Current source hashes verify in
`docs/evidence/runtime-static-audit-20261029-p19-final2.json`; every runtime
verdict remains `NOT TESTED`. SSH enrollment, systemd user-unit behavior, live
Zabbix API delivery and monitoring recovery remain blocked on a separately
authorized dedicated host.

### P20 manifest and connectivity preflight hardening (offline, 2026-10-29)

P20 manifest parsing now rejects duplicate YAML mapping keys. The connectivity
checker resolves `ssh` and `ssh-keygen` from fixed root-owned system paths,
limits host-key and identity file sizes, and uses `opla_process.run_bounded`
for both host-key lookup and explicit SSH. The commands have finite 5/20-second
deadlines, 16 KiB per-stream output limits and preserve strict host-key,
public-key-only and forwarding-disabled options. Timeouts, output overflow,
uncertain cleanup and missing trusted executables block. Bastion execution
remains disabled; this change does not implement remote deployment.

Independent security review found no remaining code findings. QA caught a
regression-test seam after dispatch moved from `subprocess.run` to
`run_bounded`: the SSH error test could start the actual client against its
TEST-NET fixture. All affected tests now mock `run_bounded`; the fixed focused
suite passes 49 tests. Several pre-fix test runs may have attempted a
non-authenticating SSH connection to `192.0.2.10:2222`; successful access or
remote execution is not evidenced, but outbound packets cannot be excluded.
The test harness issue is documented; all later tests used mocked dispatch.
Final `make check` ran 912 tests (4 skipped) after the seam correction and had
9 AF_UNIX `EPERM` errors and 2 dependent worker startup failures. P20 direct
SSH and remote deployment remain `NOT TESTED` / `BLOCKED ON LIVE ENVIRONMENT`.

### Host Admission hardening: nested routes and inventory scope

An independent review found that multipath route gateways could be missed.
The parser now includes every `nexthops[].gateway` in overlap detection and
returns `UNKNOWN` for malformed nested route evidence. A separate completeness
review found the Docker probe sees only `/var/run/docker.sock`; reports now
identify that scope and mark host-wide Docker inventory incomplete. Import keeps
the result `UNKNOWN` until all local endpoints are covered, but still returns
`REJECTED` when an already observed route or subnet conflicts. Because JSON is
unsigned, editing the report is not cryptographically detectable; the importer
does not claim attestation and operators must review provenance independently.

The storage ADR remains a proposal: VM disks, state and artifacts still use
historical `/var/lib/opla` assumptions; there is no automatic migration.
Validation on this worktree: Host Admission 82 tests; offline lifecycle
acceptance 115 tests; compileall and docs check (95 Markdown files, 204 local
links, 48 CLI examples) pass. Full `make check` attempted 925 tests (4 skipped)
and remains limited by 9 sandbox AF_UNIX `EPERM` errors plus 2 dependent
service-worker failures. The independent follow-up review found no remaining
bypass in nested gateway handling or the current exporter's incomplete Docker
scope. No physical-host report or live host result was collected.

### P21 active recovery and cleanup fault coverage (offline, 2026-10-29)

P21 probes now dispatch through the shared owned-process runner with a finite
deadline and 128 KiB output cap. Real local child fixtures confirm output
overflow is bounded and timeout is surfaced. Recovery checks data and
management firewall policy before stop/cleanup; clean stop repeats both checks
before each VM QMP request so drift during a partial stop blocks later guests.
Process inspection binds systemd MainPID to `/proc` executable, argv/cgroup and
starttime, then checks starttime around the FD scan. Deterministic fixtures cover
PID reuse at each sampling boundary and an unrelated process holding a lab disk
open. Default cleanup tests exercise success, verification failure, receipt
unlink partial state, and a retry that blocks at reconciliation audit.

Independent security review found no remaining P21 blocker. QA found and
prompted closure of process starttime, cleanup retry and per-VM QMP test gaps;
the final focused suite now passes 64 tests, including actual local bounded
runner overflow and timeout, and `make acceptance-offline` passes 118. The
current static source inventory is
`docs/evidence/runtime-static-audit-20261029-p21.json`; verification passes for
source freshness while runtime remains `NOT TESTED`. Non-cooperating privileged
writers can still race between separate `/proc`/nft operations, so no atomic or
exclusive kernel ownership guarantee is claimed. See
`docs/evidence/p21-recovery-offline-review-20261029.md`.
Final `make check` attempted 931 tests (4 skipped): 9 AF_UNIX socket cases
failed with sandbox `EPERM` and 2 dependent service-worker acceptance cases
could not start for the same restriction. The sandbox was not bypassed.

### Host Admission import FIFO hardening (2026-10-29)

Independent security review found that importing a named pipe could block on
`open()` before the importer checked for a regular file. `safe_read()` now
opens with `O_NONBLOCK`, then rejects non-regular files; an offline temporary
FIFO regression test covers the path. Independent re-review confirmed the fix
and found no other Host Admission-specific finding. It also confirmed that
real exports deliberately remain `UNKNOWN` until Docker endpoint coverage is
complete. Host Admission tests pass 83; combined Host Admission/platform/
runtime/CLI/help tests pass 176; `make acceptance-offline` passes 118.
Compileall, docs validation (96 Markdown files, 209 local links, 48 CLI
examples) and `git diff --check` pass. Full discovery attempted 932 tests (4
skipped), with 9 AF_UNIX sandbox `EPERM` errors and 2 dependent process-worker
failures. Details are in
[`host-admission-validation-20261029.md`](docs/evidence/host-admission-validation-20261029.md).
No physical-host export was supplied; readiness remains `NOT TESTED`.

### Sandbox socket test classification and Suricata unit trust review

The full suite's AF_UNIX bind denial is now detected by a harmless temporary
socket capability probe in the affected tests. Tests that need real local
sockets report `skipped` with the sandbox reason; pure protocol decoding still
runs. This preserves the runtime evidence boundary while avoiding environment
`EPERM` being reported as a product error.

Independent security review also found that Suricata management trusted a
marked systemd unit without requiring root ownership/protected modes. The
manager now checks the unit's root-owned, non-group/world-writable metadata and
the same properties for every parent directory before trusting, restoring, or
creating the unit, including on first installation when it is absent. Offline
tests cover unsafe file metadata, unsafe ancestors, and the absent-unit path;
temporary transaction fixtures explicitly inject trust checks. The reviewer
rechecked the fix with no remaining findings.

Final regression: `make check` passes **935 tests**, with **14 explicit skips**
(2 TCP socket, 2 QMP Unix socket, 10 service-process AF_UNIX cases unavailable
in this sandbox); offline acceptance passes 118; Suricata ownership tests pass
20; Host Admission tests pass 83. Compileall, docs validation (96 Markdown
files, 210 local links, 48 CLI examples) and `git diff --check` pass. All live
P14--P21 checks remain `NOT TESTED`.

Rebuilt the source-bound static runtime inventory after these changes at
`docs/evidence/runtime-static-audit-20261029-final.json`. Its `--verify` check
passes with no changed components; all source inventory entries are present,
while overall/runtime status correctly remains `NOT TESTED`. The runtime
readiness guide and evidence index now link to this latest snapshot. Final docs
recheck reports 96 Markdown files, 210 local links, 48 CLI examples and 0
errors.
