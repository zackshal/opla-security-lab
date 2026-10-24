# CI and delivery

[Root README](../README.md#cicd) describes validation boundaries and observed pipeline results.

GitLab runs portable/configuration tests, BPF compilation and package generation. `bpf-build` has `dependencies: []`; `delivery` fetches only its BPF artifacts via `needs`. `FF_USE_DIRECT_DOWNLOAD=false` avoids requesting the direct download mode that produced an observed CDN 403.

GitHub Actions uses hosted runners with Debian containers and read-only repository permissions. It runs equivalent portable/configuration checks, then builds and uploads the BPF package. GitHub's workflow is newly prepared; its first live run is not yet confirmed.

`ci/package.sh` accepts `CI_COMMIT_SHA` (GitHub passes `github.sha` explicitly), verifies the object checksum and packages only object/build metadata. SHA-256 detects changes but is not a signature or independent provenance proof.

GitLab staging deployment requires `OPLA_DEPLOY_ENABLED=1`, protected default branch, a manual job, and a separate runner tagged `opla-deploy`. Protected File variables are `OPLA_DEPLOY_INVENTORY`, `OPLA_DEPLOY_VARS`, `OPLA_SSH_PRIVATE_KEY`, `OPLA_SSH_KNOWN_HOSTS`; check `deploy.sh` before configuring them. Host key checking stays enabled. Deployment has not been accepted on a real server.

Public source releases use a fresh Git history. They do not mirror the private project's historical PDFs, reports or local runtime state. The private GitLab history remains unchanged.
