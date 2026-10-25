# Security Policy

## Supported Versions

The `main` branch and the latest release tag are supported with security
fixes. Older tags, forks, and downstream builds are not covered.

| Version                        | Supported |
|--------------------------------|-----------|
| `main` (latest)                | Yes       |
| `v3.1.x` (latest release tag)  | Yes       |
| Older releases                 | No        |

## Reporting a Vulnerability

**Do not open a public issue for security reports.**

Preferred channels:

1. **GitHub Security Advisories** -
   https://github.com/0xmfbk/ebpf-container-escape-framework/security/advisories/new
2. **Email** - mustafabanikhalaf772@gmail.com
   (PGP not required; encrypt on request.)

Please include:

- Affected commit / version
- Kernel version, distro, and BTF availability
- Reproduction steps or PoC (private)
- Impact assessment and suggested severity

### What to expect

| Stage                         | Target       |
|-------------------------------|--------------|
| Acknowledgement of report     | ≤ 3 days     |
| Initial triage / severity     | ≤ 7 days     |
| Fix or mitigation for HIGH+   | ≤ 30 days    |
| Public advisory (coordinated) | After fix    |

We follow coordinated disclosure. Reporters are credited in the advisory
unless they request otherwise.

## Scope

In scope:

- The eBPF kernel programs (`kernel/bpf_program.c`)
- The userspace daemon and loaders (`userspace/`)
- Build, install, and packaging scripts
- Container / Kubernetes deployment manifests
- Configuration parsing and event serialization

Out of scope:

- Kernel bugs in upstream Linux (report to the kernel security team)
- bpffs / BTF configuration issues on the host
- Attacks requiring an attacker who already holds
  `CAP_BPF`, `CAP_PERFMON`, or `CAP_SYS_ADMIN` (see threat model)
- Denial of service via privileged node access
- Vulnerabilities in third party SIEM endpoints or transports

## Threat Model and Audit Only Posture

This project is a **detection and audit** sensor. It does not block
syscalls. It does not run in enforce mode. `mode = "enforce"` is
rejected at startup by design.

For the full threat model, capability requirements, sandbox posture, and
failure modes, see:

- [`THREAT_MODEL.md`](THREAT_MODEL.md)
- [`docs/SECURITY.md`](docs/SECURITY.md)

## Hardening Baseline

The systemd unit and Kubernetes manifests ship with the minimum
capabilities required (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`) and
production hardening (`NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectKernelTunables`, `ProtectKernelModules`, `MemoryDenyWriteExecute`,
read only root filesystem in the pod). Operators are expected to review
`docs/OPERATIONS.md` before deploying to privileged nodes.

## Non Security Bugs

Ordinary bugs, detection tuning requests, and false positive reports go
through the normal issue tracker:
https://github.com/0xmfbk/ebpf-container-escape-framework/issues