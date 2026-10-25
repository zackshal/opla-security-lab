# Publication and CI/CD boundaries

[Русский](delivery-status.md) · **English**

As of 2026-10-25, GitHub PR 1 added current RU/EN component maps and an acceptance matrix. The configuration job now installs Git before checkout; otherwise actions/checkout downloaded an archive without .git. All six push/PR portable/configuration/bpf-build checks passed. Merge `66b00e2` was fast-forwarded into the clean public working copy. This document does not independently confirm post-merge CI.

Public source: https://github.com/zackshal/opla-security-lab. The older GitLab.com OPLA copy was not synchronized by this GitHub PR; the historical GitLab pipeline linked in README is not evidence for every later main.

Local infra-delivery-lab is a different project. Its successful Compose/K3s jobs exercise llama.cpp, not production OPLA deployment. Do not mix metrics, kernels, topology or results between these labs.

The 25 older documentation/build-script changes remain in opla-ebpf-reviewed. They are not imported wholesale into public main. Do not rewrite history or attribution again; use normal branches and pull requests.

assets/demo/terminal-replay.* remains a historical replay. Current UI requires [a recording of the real interface](../assets/demo/README.en.md); no new recording has been provided yet. See [acceptance](acceptance.en.md) and [versions](versions.en.md).
