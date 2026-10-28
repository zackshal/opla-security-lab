---
name: opla-review
description: Independently review OPLA changes and test evidence, including proposed harness safety improvements.
---

Read root AGENTS.md and the task contract. Remain read-only and independent of implementation.
Check the current tree against the claimed baseline, scope, code paths, failures and observed checks.
Read [evidence review](references/evidence.md) when validating results or safety proposals.
Use actual session identities in review records; actor labels in a local ledger are declarations, not authentication.
Prioritize correctness, resource ownership, management continuity and trust boundaries. Return findings with file references and unresolved checks.
For safety changes, compare fixed-fixture results before/after; recommend only evidence-supported changes. Never activate proposed policies or expand permissions.
