# Contributing

[Русский](CONTRIBUTING.md) · **English**

Use dedicated branches and small commits. Preserve licensing and attribution. Keep comments focused on invariants, boundary conditions and operational hazards.

Run `make check` and `git diff --check`. BPF changes also require `clang -target bpf` and an actual kernel verifier/attachment test. Suricata changes require `python3 tools/check-suricata.py`, followed by live IDS and IPS acceptance. Ansible syntax checks do not establish successful deployment, idempotence or reboot recovery.

Maintain the Russian and English document pair together. Update configuration instructions and actual evidence; do not present mock tests as live integration or invent performance improvements. No production hosts should be modified by pull-request CI.
