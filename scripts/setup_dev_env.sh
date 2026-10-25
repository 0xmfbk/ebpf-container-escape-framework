#!/usr/bin/env bash
# setup_dev_env.sh — one-shot toolchain bootstrap for the eBPF EDR.
#
# Installs the build dependencies (clang + libbpf headers, bpftool, Go)
# and probes the running kernel for runtime suitability (BTF, tracefs,
# cgroup v2, systemd). WSL2-aware: the stock Microsoft kernel is fine as
# long as it exposes BTF (kernel >= 5.15.153 / any 6.x WSL2 release).
#
# Usage:
#   sudo bash scripts/setup_dev_env.sh            # install + probe
#   bash scripts/setup_dev_env.sh --check         # probe only, no changes
#
# Exit codes: 0 ready / 1 build toolchain missing / 2 kernel unsuitable.
set -euo pipefail

CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

# Minimum Go toolchain: emulation/go.mod requires 1.26, userspace 1.25.
GO_MIN="1.26"

log()  { printf '[setup] %s\n' "$*"; }
warn() { printf '[setup] WARNING: %s\n' "$*" >&2; }
die()  { printf '[setup] ERROR: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

go_bin() {
    # Prefer a go on PATH, then a stock /usr/local/go install.
    if have go; then command -v go
    elif [[ -x /usr/local/go/bin/go ]]; then echo /usr/local/go/bin/go
    else return 1
    fi
}

go_ok() {
    local g v
    g="$(go_bin)" || return 1
    v="$("$g" version 2>/dev/null | awk '{print $3}' | sed 's/^go//')" # "1.24.2"
    [[ -z "$v" ]] && return 1
    [[ "$(printf '%s\n' "$GO_MIN" "$v" | sort -V | head -1)" == "$GO_MIN" ]]
}

is_wsl() { grep -qi microsoft /proc/version 2>/dev/null; }

# ---------- kernel / runtime probe ----------

probe_kernel() {
    local issues=0

    local kver kmaj kmin
    kver="$(uname -r)"
    kmaj="$(echo "$kver" | cut -d. -f1)"
    kmin="$(echo "$kver" | cut -d. -f2 | grep -o '^[0-9]*')"
    if (( kmaj < 6 )) || { (( kmaj == 6 )) && (( kmin < 12 )); }; then
        warn "kernel $kver is older than the tested floor (6.12); runtime stages will WARN"
        issues=1
    else
        log "kernel: $kver (>= 6.12 tested floor)"
    fi

    if [[ -s /sys/kernel/btf/vmlinux ]]; then
        log "BTF: /sys/kernel/btf/vmlinux present (CO-RE will load)"
    else
        warn "BTF missing at /sys/kernel/btf/vmlinux — the sensor CANNOT load on this kernel."
        if is_wsl; then
            warn "  on WSL2: run 'wsl --update' for a current Microsoft kernel (6.x ships BTF),"
            warn "  or build a custom WSL2 kernel with CONFIG_DEBUG_INFO_BTF=y"
        else
            warn "  install a kernel built with CONFIG_DEBUG_INFO_BTF=y (most distro kernels have it)"
        fi
        issues=2
    fi

    if grep -qs 'tracefs' /proc/mounts; then
        log "tracefs: mounted ($(grep -o 'tracefs [^ ]*' /proc/mounts | head -1))"
    else
        warn "tracefs not mounted; as root: mount -t tracefs none /sys/kernel/tracing"
        issues=$(( issues == 2 ? 2 : 1 ))
    fi

    if [[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" == "cgroup2fs" ]]; then
        log "cgroups: v2 (unified)"
    else
        warn "cgroup v2 not detected; container enrichment may degrade"
    fi

    if [[ "$(ps -p 1 -o comm= 2>/dev/null)" == "systemd" ]]; then
        log "init: systemd (install.sh / ebpf-edr.service flow available)"
    else
        warn "systemd is not PID 1 — run the daemon in the foreground instead of install.sh"
        if is_wsl; then
            warn "  on WSL2 enable it with: /etc/wsl.conf [boot] systemd=true, then 'wsl --shutdown'"
        fi
    fi

    if is_wsl; then
        log "environment: WSL2 detected — sensor runtime is supported (BTF + tracefs above)"
        case "$PWD" in
            /mnt/*) warn "building under $PWD goes through the 9p mount and is slow;" \
"  for heavy verify runs, copy the repo into the ext4 filesystem (~/)" ;;
        esac
    fi

    # Informational: docker is only needed for the (destructive-gated)
    # verify stage 16 container smoke test.
    if have docker; then
        log "docker: present (stage 16 available with EDR_VERIFY_DESTRUCTIVE=1)"
    else
        log "docker: not installed (verify stage 16 container smoke test will be skipped)"
    fi
    return "$issues"
}

# ---------- toolchain install ----------

install_apt_pkgs() {
    # python3: required by scripts/verify_siem.sh's mock SIEM server.
    log "installing apt packages: clang libbpf-dev libelf-dev bpftool make gcc pkg-config curl ca-certificates python3"
    apt-get update -qq
    apt-get install -y --no-install-recommends \
        clang libbpf-dev libelf-dev bpftool make gcc pkg-config curl ca-certificates python3
}

install_go_tarball() {
    # Install the current stable official toolchain into /usr/local/go.
    # The JSON listing carries the sha256 we verify against.
    local json ver arch sha url tmp
    arch="$(uname -m)"
    case "$arch" in
        x86_64) arch=amd64 ;;
        aarch64) arch=arm64 ;;
        *) return 1 ;;
    esac
    log "fetching current stable Go version from go.dev"
    json="$(curl -fsSL 'https://go.dev/dl/?mode=json')" || return 1
    ver="$(printf '%s' "$json" | grep -o '"version": *"go[0-9.]*"' | head -1 | grep -o 'go[0-9.]*')"
    [[ -n "$ver" ]] || return 1
    sha="$(printf '%s' "$json" | grep -A6 "\"${ver}.linux-${arch}.tar.gz\"" \
        | grep -o '"sha256": *"[0-9a-f]*"' | head -1 | grep -o '[0-9a-f]\{64\}')"
    url="https://go.dev/dl/${ver}.linux-${arch}.tar.gz"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' RETURN
    log "downloading $url"
    curl -fsSL -o "$tmp/go.tgz" "$url" || return 1
    if [[ -n "$sha" ]]; then
        echo "$sha  $tmp/go.tgz" | sha256sum -c - >/dev/null \
            || { warn "Go tarball sha256 mismatch; aborting tarball install"; return 1; }
        log "sha256 verified"
    else
        warn "could not extract sha256 from go.dev; continuing unverified"
    fi
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$tmp/go.tgz"
    cat > /etc/profile.d/golang.sh <<'EOF'
# Added by ebpf-edr setup_dev_env.sh
export PATH="$PATH:/usr/local/go/bin"
EOF
    chmod 0644 /etc/profile.d/golang.sh
    log "Go $ver installed to /usr/local/go (PATH via /etc/profile.d/golang.sh)"
}

install_go() {
    if install_go_tarball; then return 0; fi
    warn "official tarball install failed; falling back to distro golang-go"
    warn "Debian's Go may be older than go$GO_MIN; the go command will then"
    warn "auto-download the required toolchain on first build (needs network)"
    apt-get install -y --no-install-recommends golang-go
}

main() {
    if (( CHECK_ONLY )); then
        log "check mode: probing only, nothing will be installed"
    else
        [[ $EUID -eq 0 ]] || die "must run as root (try: sudo make deps)"
        have apt-get || die "this bootstrap supports Debian/Ubuntu (apt); install manually: clang libbpf-dev libelf-dev bpftool go >= $GO_MIN"
    fi

    local missing=()
    have clang     || missing+=(clang)
    have bpftool   || missing+=(bpftool)
    go_ok          || missing+=(go)
    [[ -f /usr/include/bpf/bpf_helpers.h ]] || missing+=(libbpf-dev)

    if (( CHECK_ONLY )); then
        if (( ${#missing[@]} )); then
            warn "missing build tools: ${missing[*]}  (fix with: sudo make deps)"
        else
            log "toolchain: complete"
        fi
    else
        if (( ${#missing[@]} )); then
            log "missing build tools: ${missing[*]}"
            install_apt_pkgs
        else
            log "apt toolchain already present"
        fi
        go_ok || install_go
        # Re-source profile for this shell so `go` resolves immediately.
        PATH="$PATH:/usr/local/go/bin"
        log "toolchain: clang=$(clang --version | head -1 | awk '{print $3}') go=$(go version | awk '{print $3}') bpftool=$(bpftool version 2>/dev/null | head -1 | awk '{print $2}')"
    fi

    local rc=0
    probe_kernel || rc=$?
    if (( CHECK_ONLY )); then
        if (( ${#missing[@]} )); then exit 1; fi
        exit "$rc"
    fi
    log "done. build with: make kernel && make userspace && make emulation"
    log "runtime check needs root: sudo make verify"
}

main
