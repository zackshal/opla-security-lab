# Public Git history

[Русский](git-history.md) · **English**

The initial GitHub release used a fresh source snapshot to avoid publishing historical reports and runtime data. Reviewed source-path ancestry was subsequently attached with an `ours` merge, preserving the current public file tree. The history import is complete; it is not a normal release step.

Attribution for the two Codex addresses was later rewritten in the public repository. Before this documentation update, public main was `56ec0e366bcb23666d97830df66008cd8cd89580`, with 41 commits. This is a historical checkpoint, not a requirement that future main retain the same hash or count.

A verified pre-attribution-rewrite bundle was saved privately. Filtering/rewrite changes commit IDs and invalidates historical signatures; a merge link is not independent proof of provenance. Author names, emails and messages can be public personal information.

```bash
git log --graph --oneline --decorate main
git shortlog -sne main
git log main --format='%h | %an <%ae> | %cn <%ce>'
```

Do not rerun old `history.py` kits or merge the private GitLab branch wholesale: that can reintroduce discarded paths or old attribution. Public and private histories now differ. Port changes selectively and review the exact diff, authorship and licensing.

For future edits, use a branch and regular pull request; do not force-push as part of routine publication. Before any necessary history rewrite, coordinate with collaborators, create and verify a private bundle, scan every reachable historical object for secrets, compare file trees, and use an explicit expected old remote SHA with force-with-lease.

Gitleaks returning no findings does not certify absence of all confidential information. Filtering current paths does not automatically follow every historical rename. Private backups and old clones are retained separately. GitHub contributor statistics may be cached after attribution changes; inspect the actual remote branch before rewriting again.
