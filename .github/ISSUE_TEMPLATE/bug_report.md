---
name: Bug report
about: Something doesn't work as documented
title: "[bug] "
labels: bug
assignees: ""
---

**What happened?**
A clear description of the unexpected behavior (wrong/missing alert, crash,
hang, failed build/verify stage, wrong SIEM output...).

**What did you expect?**

**How to reproduce**
Steps, config (redact secrets), and the exact commands run. For detection
issues include the triggering activity — the adversary harness probes are
preferred (`EDR_EMULATION_CONFIRMED=1 ./emulation/adversary` on a disposable
host only).

**Environment**
- Daemon/BPF version: `curl -s 127.0.0.1:9400/metrics | grep build_info` or the release tag
- Distro + kernel: `uname -a`
- BTF present: `ls /sys/kernel/btf/vmlinux`
- Active LSM list: `cat /sys/kernel/security/lsm` (matters for file rules: LSM vs tracepoint mode)
- Output target/format: (file/stdout/syslog/webhook · json/ecs/ocsf/cef/leef)
- Relevant health line: `[health] ... degraded=? last_err=...`

**Logs**
Paste the relevant alert JSON lines, startup log
(`journalctl -u ebpf-edr -n 50`), or the failing `make verify` stage output.

**Security note:** vulnerability reports do NOT go here — see
[SECURITY.md](../SECURITY.md).
