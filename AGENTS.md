# OPLA repository instructions for coding agents

## Mission
Finish the **working** OPLA eBPF/XDP/Suricata security lab end-to-end. Favor integrated functional deliverables over additional wrappers, documentation-only commands, and repeated micro-patches. Existing repository code is source of truth; audit it before editing. Don't confuse OPLA with the user's separate eBPF/Merkle/ClickHouse thesis.

## Host safety — mandatory
The developer's Debian 13 machine hosts valuable network and Docker workloads and must never be used for live lab provisioning. During development: do NOT use sudo, su, root, dpkg -i, apt install, systemctl start/stop, ip link/route, nft/iptables, VPN tools, QEMU/KVM execution, docker compose up/down, remote SSH commands, or commands that create/change/delete VM disks. Never change firewall, routes, bridges or interfaces. No changes under /opt/opla or /var/lib/opla. No live external endpoints. Work on source files and use Python mocks/temp dirs only. Get explicit user approval for live steps on a dedicated host after showing exact commands and consequences. Codex sandbox and approval settings are additional guardrails, not permission.

## Architecture invariants
- One built-in topology template ONLY: local QEMU academic lab attacker/victim/client. Distributed deployment topology is user-defined YAML, no hard-coded IPs in product code.
- Management connectivity separate from XDP-protected interface. Managed VPN/Xray/AmneziaWG postponed to last priority.
- Preserve security controls: trusted root-owned code for privileged launches; global `.opla-prune.lock`, create.lock, lab `maintenance.lock`, registry and receipts; never weaken ownership or SSH host-key checks to make tests green.
- Lab create is destructive to host environment; do not silently run or auto-enable it. Do not retry failed/interrupted create without resource reconciliation.
- Current release bundle/stage/promote/DEB are **review/inert** artifacts, NOT trusted activated installs. Do not imply otherwise. A source bundle's self-asserted manifest is not an authenticity signature.

## Implement in cohesive work packages
1. Repair malformed `bin/opla-lab-progress.py` and retain its tests; add guards/tests for corrupted journal and interrupted states.
2. Audit *actual* create/configure/readiness/registry call graph: Makefile, `bin/create-lab.sh`, `bin/opla-create-launcher.py`, `bin/opla-lab-configure-launcher.py`, `bin/opla-lab-configure.sh`, `bin/opla-registry.py`, `bin/lab-lifecycle.py`, `bin/opla-lifecycle-lock.py`, `bin/control.sh` and supporting tests. Document real behavior, not guesses.
3. Build a coherent orchestrator with injected adapters/executors, persistent state, failure records, timeouts, idempotency and ownership checks. Use existing operations, not duplicate implementations. First acceptance uses fake adapters; no actual VM/SSH.
4. Add offline acceptance suite simulating success, creation failure, concurrent lock, abrupt stop, resume after configure failure, partial resources, image/dependency mismatch, XDP verifier reject, Suricata inactive, telemetry missing; never report READY without probes.
5. Implement genuine trustworthy deployment/activation design (root-owned release, protected lifecycle locks, independently pinned or signed provenance) separately and test in an isolated dedicated VM, not this host.
6. On authorized dedicated test host with >= 5GiB free RAM, adequate disk, isolated network: 3 VM create -> cloud-init/SSH -> XDP -> Suricata -> scenario -> telemetry -> report -> cleanup. Record commands, logs, fingerprints, evidence, PASS/BLOCKED. Never claim this happened from mocks.
7. Then user-defined bare-metal/VM deployment (direct SSH) and finally optional VPN.

## Workflow
- Start `git status --short`, record HEAD. Do not overwrite unrelated user changes.
- Inspect code paths, then implement **multiple related edits** in one cohesive PR/commit, not one script per turn.
- Run `python3 -m compileall -q bin tests`, `make check`, and isolated integration tests; record exact counts. `make check` does NOT test clang verifier, KVM, live Zabbix.
- Verify no real host modifications, use `git diff --check`, annotate unresolved blockers.
- Never commit automatically unless user requested. Never mark a task PASS just because code path exists.
- All network activity / external installs require separate user approval. Favor clean failure over weakening guardrails.

## Native Codex engineering harness
- For an explicitly requested harness/team workflow, use native Codex subagents on demand and project roles in `.codex/agents`; consult `harness/roles.json` and `docs/agent-harness.md`. Do not build another agent loop.
- Parallel read-only investigations may share this tree. Only the parent integrator writes shared files. Parallel writers require separately verified snapshots/worktrees with the current dirty baseline, including these untracked instructions; HEAD alone is insufficient.
- Claim explicit paths and dependencies before assigning writers. Preserve existing changes; do not automatically stash, commit, reset, clean or cherry-pick.
- Role instructions do not grant tools or isolate permissions. All agents inherit the parent's current permissions; no role may broaden them.
- Treat agent test claims as unverified until actual command, tree fingerprint, exit status and log evidence are checked. Native Codex resume recovers conversation state; unresolved local checking records require inspection before retry.
- Independent reviewers must not approve their own implementation. Safety-rule/skill/hook changes are proposals until independent review and explicit human activation; never expand permissions or trust hooks automatically.
- Do not add AI authorship trailers. Never create a commit or publish without separate user authorization.
