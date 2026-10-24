# CI and delivery

[Русский](README.md) · **English**

The [root README](../README.md#cicd) records validation boundaries and observed results.

GitLab performs portable/configuration tests, BPF compilation and packaging. `bpf-build` uses `dependencies: []`; delivery fetches only its BPF artifacts through `needs`. `FF_USE_DIRECT_DOWNLOAD=false` avoids the direct-download path that produced an observed CDN 403.

GitHub Actions uses hosted runners, Debian containers and read-only repository permissions. It tests portable/configuration behavior, builds and uploads the BPF package. Check the current workflow run; earlier GitLab success does not certify a new GitHub revision.

`ci/package.sh` accepts `CI_COMMIT_SHA` (GitHub explicitly passes `github.sha`), validates the object checksum and packages only object/build metadata. SHA-256 is not a signature or independent provenance proof.

GitLab deployment requires `OPLA_DEPLOY_ENABLED=1`, a protected default branch, a manual job and a separate `opla-deploy` runner. Protected File variables: `OPLA_DEPLOY_INVENTORY`, `OPLA_DEPLOY_VARS`, `OPLA_SSH_PRIVATE_KEY`, `OPLA_SSH_KNOWN_HOSTS`. Review `deploy.sh` before configuring these; host key checking stays enabled. Real server deployment has not completed acceptance.

Source history has been attached to the public repository and its attribution subsequently corrected. Do not rerun old history-import instructions or merge the private branch wholesale. See [Git history](../docs/git-history.en.md).
