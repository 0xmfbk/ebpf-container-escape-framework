# Threat Model & Security Assumptions

## 1. Scope and Assets Protected
This framework is an **audit-only** runtime sensor. It is designed to detect and alert on container escape attempts and runtime threats (T1611, T1003, T1055) targeting Linux hosts.
*   **Assets Protected:** Host Kernel, Container Runtimes (Docker/containerd), Node Credentials, Kubernetes Service Accounts.
*   **Assets NOT Protected:** The sensor does not block (enforce) syscalls. It does not protect against kernel 0-days or physical access attacks.

## 2. Trust Boundaries
The security model operates across three trust boundaries:
1.  **Untrusted Workload Containers:** Where attackers may have initial code execution (web shell, RCE).
2.  **Host Node (Kernel):** The trusted computing base (TCB). 
3.  **eBPF Sensor (Daemon/Userspace):** The observer.

## 3. Critical Assumption (eBPF as an Attack Vector)
**This framework assumes that untrusted workload containers are NOT granted `CAP_BPF`, `CAP_PERFMON`, or `CAP_SYS_ADMIN`.**
If an attacker inside a container possesses these capabilities, they can hijack the eBPF subsystem, detach our probes, or load their own malicious rootkits. This tool is a sensor, not a mitigation for privilege escalation.

## 4. Sensor Threat Model
*   **What if the sensor pod is compromised?** The sensor runs with minimal required capabilities (BPF, PERFMON, SYS_ADMIN, SYS_RESOURCE) and a read-only root filesystem. It does not have write access to `/proc/sys` or kernel memory (`bpf_probe_write_user` is disabled).
*   **What if the SIEM goes down?** The network queue is bounded. It drops events and trips a circuit breaker rather than OOMing the host.

## 5. Non-Goals
*   Preventing execution (Enforcement).
*   Scanning filesystem artifacts (like `clamav`).
*   Replacing seccomp, AppArmor, or SELinux.

## 6. Sensor Self-Exclusion
The daemon excludes its own syscalls from detection by publishing its tgid
into a kernel-side `self_tgid` map (checked in `is_filtered()`). This is
deliberately PID-based rather than comm-based: `prctl(PR_SET_NAME)` lets
any process claim an arbitrary 15-char comm, so a comm allowlist would be
an evasion primitive. Residual risk: after the daemon exits, its tgid can
be recycled by a new process; PID reuse within the sensor's uptime is not
practically exploitable because the map is updated at every daemon start.
