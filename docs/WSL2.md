# WSL2 (Windows Subsystem for Linux) Guide

The sensor builds and runs on WSL2. Verified on Debian 13 (trixie) with
kernel `6.18.33.2-microsoft-standard-WSL2`.

## Why it works

| Requirement | WSL2 status |
|-------------|-------------|
| Kernel >= 6.12 (tested floor) | WSL2 has shipped 6.x kernels for a long time; run `wsl --update` if older |
| `CONFIG_DEBUG_INFO_BTF` (CO-RE) | Present on current Microsoft kernels — `/sys/kernel/btf/vmlinux` exists (check with `make check-env`) |
| tracefs at `/sys/kernel/tracing` | Mounted read-write by default |
| cgroup v2 | Default (`stat -fc %T /sys/fs/cgroup` → `cgroup2fs`) |
| systemd | Available; must be enabled (default on modern distro WSL images) |

Older WSL2 kernels (5.15.x) may lack BTF entirely — those cannot load
CO-RE programs. `make check-env` detects this and points at the fix
(`wsl --update` or a custom kernel built with `CONFIG_DEBUG_INFO_BTF=y`).

## Setup

    sudo make deps          # clang, libbpf-dev, bpftool, official Go toolchain
    make check-env          # read-only probe: toolchain + kernel suitability

`make deps` installs Go from the official go.dev tarball (sha256-verified)
because Debian's packaged Go is older than the version `emulation/go.mod`
requires; it falls back to `golang-go` + toolchain auto-download if the
tarball fetch fails (e.g. offline).

## Build and run

    make kernel userspace emulation
    sudo make verify            # full runtime suite (needs root)
    sudo ./install.sh           # systemd service (requires systemd in WSL)

If systemd is not PID 1 in your distro (`ps -p 1 -o comm=`), either enable
it in `/etc/wsl.conf`:

    [boot]
    systemd=true

then `wsl --shutdown` from Windows and restart — or skip `install.sh` and
run the daemon in the foreground:

    sudo ./userspace/ebpf_controller --bpf-obj kernel/bpf_program.o

## WSL2-specific caveats

- **9p is slow.** Building/verifying under `/mnt/c/...` works but does
  filesystem I/O over the Windows bridge. For repeated heavy runs, clone
  or copy the repo into the ext4 filesystem (`~/`) inside WSL.
- **`EDR_VERIFY_DESTRUCTIVE=1`** gates the verify stage that removes all
  Docker containers and restarts the daemon — fine to leave off on a
  dev box.
- **Emulation harness** refuses to run without `EDR_EMULATION_CONFIRMED=1`
  (all in-repo callers set it automatically).
- The kernel is `microsoft-standard`, not a distro kernel: kprobe symbol
  names (`__x64_sys_*`) and tracepoints match mainline, but distro
  backports may differ. `make verify` catches any mismatch at load time.
