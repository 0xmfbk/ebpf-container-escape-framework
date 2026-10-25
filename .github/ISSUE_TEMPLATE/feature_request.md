---
name: Detection / feature request
about: New detection action, tuning, or capability
title: "[feat] "
labels: enhancement
assignees: ""
---

**What should it detect / do?**
The threat or gap — e.g. a container-escape technique, evasion vector, output
format, or operational capability.

**MITRE ATT&CK mapping** (for detections): technique/sub-technique ID and name.

**Suggested signal**
Syscall / tracepoint / LSM hook / path pattern that carries the signal.
Note whether the target exists at attack time (attempt-based class) or not
(resolved-path class) — see the README coverage section for the split.

**Environment where this matters**
Kernel version, cgroup version, container runtime, SIEM — anything that
constrains the approach.

**False-positive risk**
What legitimate activity shares this signal, and how it should be tuned
(allowlists, disabled_actions, severity).
