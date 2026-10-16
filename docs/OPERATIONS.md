# Operations

## Install

    sudo ./install.sh              # prefix /usr/local
    sudo ./install.sh --dry-run    # print actions, do nothing
    sudo ./install.sh --uninstall  # remove everything except config

Created by install:

- /usr/local/sbin/ebpf-edr - binary
- /usr/local/lib/ebpf-edr/bpf_program.o - BPF object
- /etc/ebpf-edr/config.toml - config (existing preserved; new default at .new)
- /etc/systemd/system/ebpf-edr.service - hardened unit
- /etc/logrotate.d/ebpf-edr - rotation policy

## Config reload

    sudo systemctl reload ebpf-edr
    # or
    sudo kill -HUP $(pgrep ebpf-edr)

Reloadable: log.level, rates.*, filter.*, disabled_actions.
Requires restart: log.path, log.max_bytes, context.*, container.cache_max_entries.

## Health log

Every 60s (configurable via --health-interval), the daemon writes a single
line containing recv, written, dropped, rate_limited, parse_err,
ver_mismatch, ringbuf_err, reloads, reload_fail, chan, lineage_cache,
lineage_hits, lineage_misses, cgroup_cache.

Watch for:

- dropped and rate_limited near zero in steady state
- ver_mismatch always zero (nonzero means C and Go struct drift)
- lineage_cache staying below capacity

## Troubleshooting

Service will not start, condition failed: BTF missing at
/sys/kernel/btf/vmlinux, or BPF object missing at the unit's expected path.

Startup over 5s: the kernel verifier runs each of the 14 programs. First
boot can take seconds; subsequent starts are faster.

High idle CPU: check journalctl -u ebpf-edr and look for the health line.
If recv is high while the system is idle, a chatty action is firing. Add
it to disabled_actions in config.toml, then systemctl reload ebpf-edr.

## Configuration reference

mode = "audit" is the only supported value in this build.

[log]
path        = "/var/log/ebpf_edr.json"
max_bytes   = 52428800
max_backups = 5
level       = "info"

[filter]
comm_allowlist   = []
cgroup_allowlist = []

[rates]
events_per_sec = 200
burst          = 400

[container]
cache_max_entries = 5000

[context]
lineage_max_depth  = 16
lineage_cache_size = 20000
cgroup_cache_size  = 5000

disabled_actions = []
