### False-positive tuning: Actions 14 and 15

`Core_Pattern_Modification` (14) will fire on reads of
`/proc/sys/kernel/{core_pattern,modprobe,uevent_helper}` by `systemd`,
`systemd-sysctl`, `sysctl`, and container runtime setup paths. If this
noise is unacceptable, add the offending comms to `filter.comm_allowlist`:

    [filter]
    comm_allowlist = ["systemd-sysctl", "sysctl"]

`Cgroup_Release_Agent` (15) fires on `release_agent` and
`notify_on_release` accesses under `/sys/fs/cgroup/`. On cgroup v1 hosts,
`notify_on_release` is written by `systemd` and runtime tooling as part
of normal lifecycle consider allowlisting `systemd` and `systemd-logind`
if the volume is high. On cgroup v2 hosts (kernel 6.12 default) these
files typically do not exist, and the sensor fires only on attacker
attempts, which resolve to ENOENT.

**Do not disable actions 14 or 15 entirely.** The signal is in the
open syscall itself, not the write.