# Contributing

Thanks for contributing to `ebpf-container-escape-framework`. This is an
audit only eBPF EDR, contributions are held to the same engineering
discipline the verification suite enforces.

## Ground Rules

- **Read only posture is non negotiable.** No PR may introduce
  enforcement, `-EPERM` return paths, or `mode = "enforce"` handling.
  Such PRs are closed without review.
- **Kernel code must pass the verifier** on the supported kernel
  (Debian 13, kernel 6.12+, BTF enabled). PRs that only pass on newer
  kernels must update the compatibility matrix.
- **Wire format stability.** Event schema is v3, 208 bytes on the wire.
  Any layout change requires a version bump, a `layout_check` update, and
  a migration note in `docs/OPERATIONS.md`.

## Prerequisites

- Go ≥ 1.21
- clang, gcc, bpftool, libbpf headers
- Root with `CAP_BPF CAP_PERFMON CAP_SYS_ADMIN` for `make verify`
- Debian 13 or an equivalent kernel ≥ 6.12 with `CONFIG_DEBUG_INFO_BTF=y`

## Local Workflow

```bash
git clone https://github.com/0xmfbk/ebpf-container-escape-framework.git
cd ebpf-container-escape-framework
git checkout -b feat/short-description

make kernel userspace emulation
make test-race
make ci        # gofmt, vet, race, fuzz, verify — this must pass