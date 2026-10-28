---
name: opla-task
description: Coordinate bounded OPLA engineering tasks with native Codex subagents and verified offline evidence.
---

Read root AGENTS.md and PLANS.md, then inspect Git HEAD/status and the actual call graph.
Use Codex as orchestrator: launch only roles needed now, from .codex/agents and harness/roles.json.
Parallelize read-only research, domain and QA analysis. One integrator writes the shared tree.
Before a parallel writer starts, read [isolation](references/isolation.md). Never start from HEAD alone when dirty/untracked work exists.
Use harness/templates/task.md and implementation.md only when a package needs delegation.
Record scope and evidence with bin/opla-harness.py; keep the private ledger outside source or under ignored reports/.
Run existing offline checks; independent review must assess the actual current tree and captured logs.
Do not automatically trust hooks, change safety rules, commit or provision. Native Codex resume owns conversation recovery; inspect unresolved local records before retry.
