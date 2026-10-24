# Contributing

Use a dedicated branch and small commits. Preserve licensing and Git authorship. Keep comments focused on invariants, boundary conditions and operational hazards.

Run make check and git diff --check. Changes to BPF also require clang -target bpf and a real verifier/attach test. Suricata changes require tools/check-suricata.py, then IDS and IPS acceptance on a live sensor. Ansible syntax-check is distinct from deployment, repeated-run and reboot checks.

Update the root README with configuration changes and actual evidence. Do not report mock tests as live integration results or invent performance improvements.
