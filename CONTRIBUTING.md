# Contributing

Thanks for contributing to `ebpf-container-escape-framework`. This is an
audit-only eBPF EDR; contributions are held to the same engineering
discipline the verification suite enforces.

## Ground Rules

- **Read-only posture is non-negotiable.** No PR may introduce enforcement,
  `-EPERM` return paths, or `mode = "enforce"` handling. Such PRs are
  closed without review. The optional `lsm/file_open` hook must always
  return `0`.
- **Kernel code must pass the verifier** on the supported kernel
  (Debian 13, kernel 6.12+, BTF enabled). PRs that only pass on newer
  kernels must update the compatibility matrix
  ([`docs/KERNEL_COMPATIBILITY.md`](docs/KERNEL_COMPATIBILITY.md)).
- **Wire format stability.** Event schema is **v4, 224 bytes** on the wire.
  Any layout change requires: bump `EVENT_VERSION`, update
  `common/common.h` (static assert), `userspace/main.go` + `layout_test.go`
  offsets, the `verify_phase2_0.sh` stage 3 expectations, and a paired
  daemon+object upgrade note — the daemon rejects mismatched versions at
  runtime (`ver_mismatch`), so both sides ship together.
- **Detection semantics:** file-path rules split into attempt-based
  (tracepoints, fires on nonexistent targets) and resolved-path (LSM when
  available) classes — see the README coverage section. Keep new file
  rules in the right class and avoid duplicate emissions.

## Prerequisites

- Go ≥ 1.26 · clang, gcc, bpftool, libbpf headers — `sudo make deps`
  bootstraps all of it; `make check-env` probes your kernel
- Root with `CAP_BPF CAP_PERFMON CAP_SYS_ADMIN` for `make verify`
- Debian 13 or an equivalent kernel ≥ 6.12 with `CONFIG_DEBUG_INFO_BTF=y`
  (`make verify` on 5.15–6.11 warns but runs)

## Local Workflow

```bash
git clone https://github.com/0xmfbk/ebpf-container-escape-framework.git
cd ebpf-container-escape-framework
git checkout -b feat/short-description

make check-env                    # probe before anything else
make deps                         # only if the toolchain is incomplete
make kernel userspace emulation   # build BOTH sides together (wire v4)
make test-race
sudo -E make verify               # 97 core + 7 SIEM checks — must be green
```

`make ci` runs the formatting/vet/race/fuzz gates locally; CI runs the
same on every push. `gofmt -l userspace emulation` must return nothing.

Notes:

- The Docker container smoke stage is **destructive** (removes all
  containers, restarts Docker) and only runs with
  `EDR_VERIFY_DESTRUCTIVE=1` — use a disposable host.
- The adversary emulation binary refuses to run without
  `EDR_EMULATION_CONFIRMED=1` (in-repo scripts set it for you); it fires
  real syscalls and belongs on throwaway machines only.
- `make demo` runs the record-ready feature walkthrough
  (`sudo asciinema rec -c ./demo.sh ...`).

## Pull Requests

1. One logical change per PR; describe *what* and *why*.
2. Paste the tail of your `make verify` summary (PASS/WARN/FAIL counts)
   and note your kernel version.
3. Kernel changes: include the `bpftool prog loadall` verifier result.
4. New detection actions need: kernel hook, userspace severity/MITRE
   mapping, `actionNames` entry, emulation probe, and a verify assertion.
5. Keep the README coverage table and `docs/MITRE_MATRIX.md` in sync.

## Reporting Issues

Bugs and detection-tuning requests →
[issue tracker](https://github.com/0xmfbk/ebpf-container-escape-framework/issues)
· security reports → [`SECURITY.md`](SECURITY.md) (never a public issue).
