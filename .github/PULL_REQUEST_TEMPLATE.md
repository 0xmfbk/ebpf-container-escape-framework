## What & why

<!-- One-paragraph summary: what changes and the reason. -->

## Type

- [ ] Detection (new/tuned action)
- [ ] Kernel / wire format (requires paired daemon+object upgrade)
- [ ] Userspace daemon
- [ ] Deployment (systemd / Helm / manifests)
- [ ] Docs / CI
- [ ] Other

## Checklist

- [ ] `gofmt -l userspace emulation` returns nothing
- [ ] `make test-race` passes
- [ ] `sudo -E make verify` green on kernel 6.12 — summary below
- [ ] Kernel changes: `bpftool prog loadall` passes (paste result for new programs)
- [ ] Wire-format changes: `EVENT_VERSION` bumped, layout asserts + verify stage 3 updated, paired-upgrade note added
- [ ] New detection action: severity/MITRE mapping, `actionNames`, emulation probe, verify assertion, README coverage row
- [ ] No enforcement paths introduced (audit-only: no `-EPERM`, no `mode=enforce`)

## Verification evidence

```
# paste the SUMMARY block of your make verify run + kernel version
```
