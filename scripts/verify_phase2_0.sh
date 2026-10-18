#!/usr/bin/env bash
# Phase 2.0 + 2.2 verification harness - ebpf-container-escape-framework
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/verify_out"
BPF_OBJ="${ROOT}/kernel/bpf_program.o"
LAYOUT_BIN="${ROOT}/kernel/layout_check"
USER_BIN="${ROOT}/userspace/ebpf_controller"
EMUL_BIN="${ROOT}/emulation/adversary"
LOG_FILE="/var/log/ebpf_edr.json"
RUN_LOG="${OUT}/daemon.log"
HEALTH_WINDOW=15
DAEMON_GRACE=3

STAGE="all"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --stage) STAGE="$2"; shift 2 ;;
        *) echo "unknown arg: $1"; exit 2 ;;
    esac
done

if [[ -t 1 ]]; then
    R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[36m'; N=$'\e[0m'; BOLD=$'\e[1m'
else
    R=""; G=""; Y=""; B=""; N=""; BOLD=""
fi

PASS=0; FAIL=0; WARN=0
declare -a FAIL_MSGS=()
declare -a WARN_MSGS=()

pass() { echo "${G}[PASS]${N} $*"; PASS=$((PASS+1)); }
fail() { echo "${R}[FAIL]${N} $*"; FAIL=$((FAIL+1)); FAIL_MSGS+=("$*"); }
warn() { echo "${Y}[WARN]${N} $*"; WARN=$((WARN+1)); WARN_MSGS+=("$*"); }
info() { echo "${B}[INFO]${N} $*"; }
head2() { echo; echo "${BOLD}=== $* ===${N}"; }
have() { command -v "$1" >/dev/null 2>&1; }
run_stage() { [[ "$STAGE" == "all" || "$STAGE" == "$1" ]]; }

mkdir -p "$OUT"

require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "${R}Must run as root: sudo -E bash scripts/verify_phase2_0.sh${N}"
        exit 1
    fi
}

stage_env() {
    head2 "STAGE 1/10  Environment probe"
    local kver; kver="$(uname -r)"; info "kernel: $kver"
    local kmaj kmin; kmaj="$(echo "$kver" | cut -d. -f1)"; kmin="$(echo "$kver" | cut -d. -f2)"

	if (( kmaj > 6 )) || { (( kmaj == 6 )) && (( kmin >= 12 )); }; then
	    pass "kernel >= 6.12 ($kver)"
	elif (( kmaj > 5 )) || { (( kmaj == 5 )) && (( kmin >= 15 )); }; then
	    warn "kernel $kver is >= 5.15 but < 6.12. Structural support verified, but not primary test target."
	else
	    fail "kernel $kver is < 5.15. Unsupported."
	fi
	
    if [[ -r /sys/kernel/btf/vmlinux ]]; then
        pass "/sys/kernel/btf/vmlinux present"
        cp /sys/kernel/btf/vmlinux "${OUT}/vmlinux.btf" 2>/dev/null || true
    else
        fail "/sys/kernel/btf/vmlinux missing"
    fi

    for t in clang gcc go; do
        if have "$t"; then pass "toolchain: $t -> $(command -v $t)"; else fail "toolchain: $t not found"; fi
    done
    have bpftool && pass "toolchain: bpftool" || warn "bpftool missing (load stage will be skipped)"

    if have clang && clang --print-targets 2>/dev/null | grep -q bpf; then
        pass "clang has bpf target"
    else
        fail "clang missing bpf target"
    fi

    if have bpftool && [[ -r /sys/kernel/btf/vmlinux ]]; then
        if [[ ! -s "${OUT}/vmlinux.c" ]]; then
            bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${OUT}/vmlinux.c" 2>/dev/null || true
        fi
        for field in start_boottime real_parent tgid; do
            if grep -qw "$field" "${OUT}/vmlinux.c"; then
                pass "BTF has field: $field"
            else
                warn "BTF missing field: $field"
            fi
        done
    fi

    if have go; then
        local gv; gv="$(go version)"; info "$gv"
        if echo "$gv" | grep -qE 'go1\.(2[1-9]|[3-9][0-9])'; then
            pass "Go >= 1.21"
        else
            warn "Go < 1.21"
        fi
    fi

    local tproot=""
    [[ -r /sys/kernel/tracing/events/syscalls ]] && tproot="/sys/kernel/tracing"
    [[ -z "$tproot" && -r /sys/kernel/debug/tracing/events/syscalls ]] && tproot="/sys/kernel/debug/tracing"
    for tp in openat open execve connect ptrace unlinkat bpf perf_event_open mount setns chroot mprotect; do
        if [[ -n "$tproot" && -r "$tproot/events/syscalls/sys_enter_${tp}/id" ]]; then
            pass "tracepoint present: sys_enter_${tp}"
        else
            warn "tracepoint not listed: sys_enter_${tp}"
        fi
    done

    if [[ -r /proc/kallsyms ]]; then
        for kp in __x64_sys_unshare __x64_sys_pivot_root; do
            if grep -q " $kp\$" /proc/kallsyms 2>/dev/null; then
                pass "kallsyms has: $kp"
            else
                warn "kallsyms missing: $kp"
            fi
        done
    fi
}

stage_build() {
    head2 "STAGE 2/10  Build"
    cd "$ROOT" || return

    info "make kernel"
    if make kernel >"${OUT}/build_kernel.log" 2>&1; then
        pass "make kernel"
    else
        fail "make kernel (see ${OUT}/build_kernel.log)"
        tail -30 "${OUT}/build_kernel.log" | sed 's/^/    /'
        return
    fi

    [[ -s "$BPF_OBJ" ]] && pass "bpf_program.o ($(stat -c%s "$BPF_OBJ") bytes)" || fail "bpf_program.o missing"
    [[ -x "$LAYOUT_BIN" ]] && pass "layout_check built" || fail "layout_check not built"

    info "make userspace"
    if make userspace >"${OUT}/build_userspace.log" 2>&1; then
        pass "make userspace"
    else
        fail "make userspace (see ${OUT}/build_userspace.log)"
        tail -30 "${OUT}/build_userspace.log" | sed 's/^/    /'
    fi
    [[ -x "$USER_BIN" ]] && pass "ebpf_controller built" || fail "ebpf_controller missing"

    info "make emulation"
    if make emulation >"${OUT}/build_emulation.log" 2>&1; then
        pass "make emulation"
    else
        warn "make emulation failed - emulation stage will be skipped"
        tail -20 "${OUT}/build_emulation.log" | sed 's/^/    /'
    fi
}

stage_layout() {
    head2 "STAGE 3/10  Struct layout (C ↔ Go)"

    if [[ ! -x "$LAYOUT_BIN" ]]; then
        fail "layout_check not built"
        return
    fi

    "$LAYOUT_BIN" > "${OUT}/layout_c.txt" 2>&1
    local c_size c_ver
    c_size="$(grep '^SIZE=' "${OUT}/layout_c.txt" | cut -d= -f2)"
    c_ver="$(grep '^VERSION=' "${OUT}/layout_c.txt" | cut -d= -f2)"
    info "C: sizeof(event_t)=$c_size version=$c_ver"

    [[ "$c_size" == "208" ]] && pass "C sizeof(event_t) == 208" || fail "C sizeof(event_t) == $c_size, expected 208"
    [[ "$c_ver" == "3"   ]] && pass "C EVENT_VERSION == 3"   || fail "C EVENT_VERSION == $c_ver, expected 3"

    cd "${ROOT}/userspace" || return
    if go test -run TestEventLayout -v . > "${OUT}/layout_go.txt" 2>&1; then
        pass "Go layout test (TestEventLayout)"
    else
        fail "Go layout test failed (see ${OUT}/layout_go.txt)"
        tail -30 "${OUT}/layout_go.txt" | sed 's/^/    /'
    fi
    if go test -run TestEventVersion -v . >> "${OUT}/layout_go.txt" 2>&1; then
        pass "Go version test (TestEventVersion)"
    else
        fail "Go version test failed"
    fi

    info "C offsets:"
    grep '^OFF_' "${OUT}/layout_c.txt" | sed 's/^/    /'
}

stage_load() {
    head2 "STAGE 4/10  BPF verifier load (dry-run)"

    if [[ ! -f "$BPF_OBJ" ]]; then
        fail "bpf_program.o not built"
        return
    fi
    if ! have bpftool; then
        warn "bpftool not installed - verifier check deferred to runtime stage"
        return
    fi

    local pin="${OUT}/bpftool_pin"
    rm -rf "$pin"; mkdir -p "$pin"

    if bpftool prog loadall "$BPF_OBJ" "$pin" type kprobe 2>"${OUT}/bpftool_load.err"; then
        pass "bpftool prog loadall succeeded (all programs pass verifier)"
        ls "$pin" | sed 's/^/    pinned: /'
    else
        warn "bpftool loadall did not succeed - falling back to per-program load"
        local ok=0 bad=0
        for sec in trace_unshare trace_pivot_root trace_openat trace_open \
                   trace_execve trace_connect trace_ptrace trace_unlinkat; do
            rm -rf "$pin/$sec"
            if bpftool prog load "$BPF_OBJ" "$pin/$sec" 2>>"${OUT}/bpftool_load.err"; then
                pass "verifier: $sec"
                ok=$((ok+1))
            else
                fail "verifier: $sec (see ${OUT}/bpftool_load.err)"
                bad=$((bad+1))
            fi
        done
        info "verifier: ok=$ok bad=$bad"
    fi
    umount -l "$pin" 2>/dev/null || true
    rm -rf "$pin"
}

stage_runtime() {
    head2 "STAGE 5/10  Runtime smoke test"

    if [[ ! -x "$USER_BIN" ]]; then
        fail "ebpf_controller not built"
        return
    fi

    [[ -e "$LOG_FILE" ]] && mv "$LOG_FILE" "${LOG_FILE}.verify.bak.$(date +%s)" 2>/dev/null || true
    : > "$LOG_FILE" 2>/dev/null || true
    chmod 0640 "$LOG_FILE" 2>/dev/null || true

    info "launching daemon..."
    : > "$RUN_LOG"
    ( cd "${ROOT}/userspace" && "$USER_BIN" ) >>"$RUN_LOG" 2>&1 &
    local dpid=$!
    echo "$dpid" > "${OUT}/daemon.pid"
    sleep "$DAEMON_GRACE"

    if ! kill -0 "$dpid" 2>/dev/null; then
        fail "daemon exited early - see ${RUN_LOG}"
        tail -30 "$RUN_LOG" | sed 's/^/    /'
        return
    fi
    pass "daemon alive (pid=$dpid)"

    if grep -q "EDR Engine active" "$RUN_LOG"; then
        pass "daemon logged startup line"
    else
        warn "daemon did not log startup line (may be buffered)"
    fi

    info "emitting test syscalls..."
    cat /etc/shadow >/dev/null 2>&1 || true
    /bin/true 2>/dev/null || true
    (exec 3<>/dev/tcp/127.0.0.1/1) 2>/dev/null || true
    sleep 1

    local lines
    lines="$(wc -l < "$LOG_FILE" 2>/dev/null || echo 0)"
    if (( lines > 0 )); then
        pass "log file has $lines JSON lines after smoke test"
    else
        warn "log file empty after smoke test (host only fired /etc/shadow)"
    fi

    local bad=0
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if [[ "${line:0:1}" != "{" || "${line: -1}" != "}" ]]; then
            bad=$((bad+1))
        fi
    done < "$LOG_FILE"
    if (( bad == 0 )); then
        pass "all log lines are well-formed JSON objects"
    else
        fail "$bad malformed JSON lines"
    fi

    if grep -q '"ppid"' "$LOG_FILE"; then
        pass "log contains ppid field"
    else
        warn "log has no ppid field"
    fi
    if grep -q '"start_time_ns"' "$LOG_FILE"; then
        pass "log contains start_time_ns field"
    else
        warn "log has no start_time_ns field"
    fi

    info "sending SIGTERM..."
    kill -TERM "$dpid" 2>/dev/null || true
    local waited=0
    while kill -0 "$dpid" 2>/dev/null && (( waited < 25 )); do
        sleep 0.2; waited=$((waited+1))
    done
    if kill -0 "$dpid" 2>/dev/null; then
        kill -KILL "$dpid" 2>/dev/null || true
        fail "daemon did not exit on SIGTERM within 5s"
    else
        pass "daemon exited cleanly on SIGTERM"
    fi
}

stage_emulation() {
    head2 "STAGE 6/10  Adversary emulation"

    if [[ ! -x "$EMUL_BIN" ]]; then
        warn "emulation binary not built; skipping"
        return
    fi
    if [[ ! -x "$USER_BIN" ]]; then
        fail "ebpf_controller not built"
        return
    fi

    : > "$LOG_FILE"
    : > "$RUN_LOG"
    ( cd "${ROOT}/userspace" && "$USER_BIN" ) >>"$RUN_LOG" 2>&1 &
    local dpid=$!
    sleep "$DAEMON_GRACE"
    if ! kill -0 "$dpid" 2>/dev/null; then
        fail "daemon died before emulation - see ${RUN_LOG}"
        return
    fi
    pass "daemon up for emulation"

    info "running emulation..."
    "$EMUL_BIN" >"${OUT}/emulation.out" 2>"${OUT}/emulation.err" || \
        warn "emulation exited non-zero"
    sleep 2

    for action in Container_Namespace_Unshare Container_Pivot_Root_Escape \
                  Sensitive_File_Access Process_Execution Network_Connection \
                  Process_Injection Log_Tampering; do
        if grep -q "\"action\":\"$action\"" "$LOG_FILE"; then
            pass "coverage: $action"
        else
            warn "coverage: $action not observed"
        fi
    done

    for mitre in T1611 T1003.008 T1055.008 T1562.001 T1071 T1059.004; do
        if grep -q "\"mitre_id\":\"$mitre\"" "$LOG_FILE"; then
            pass "MITRE: $mitre"
        else
            warn "MITRE: $mitre not observed"
        fi
    done

    kill -TERM "$dpid" 2>/dev/null || true
    sleep 1
    kill -KILL "$dpid" 2>/dev/null || true
}

stage_perf() {
    head2 "STAGE 7/10  Performance (CPU/RSS)"

    if [[ ! -x "$USER_BIN" ]]; then
        fail "ebpf_controller not built"
        return
    fi

    : > "$LOG_FILE"
    : > "$RUN_LOG"
    ( cd "${ROOT}/userspace" && "$USER_BIN" ) >>"$RUN_LOG" 2>&1 &
    local dpid=$!
    sleep "$DAEMON_GRACE"
    if ! kill -0 "$dpid" 2>/dev/null; then
        fail "daemon died - see ${RUN_LOG}"
        return
    fi

    info "workload running for ${HEALTH_WINDOW}s..."
    local end=$(( $(date +%s) + HEALTH_WINDOW ))
    while (( $(date +%s) < end )); do
        cat /etc/shadow >/dev/null 2>&1 || true
        sleep 0.1
    done

    local cpu rss_kb rss_mb
    cpu="$(ps -o %cpu= -p "$dpid" 2>/dev/null | tr -d ' ')"
    rss_kb="$(ps -o rss= -p "$dpid" 2>/dev/null | tr -d ' ')"
    rss_mb=$(( ${rss_kb:-0} / 1024 ))
    info "daemon pid=$dpid  cpu=${cpu}%  rss=${rss_mb}MB"

    if awk -v c="${cpu:-0}" 'BEGIN{exit !(c < 1.0)}'; then
        pass "CPU < 1% (got ${cpu}%)"
    else
        warn "CPU >= 1% (got ${cpu}%) - may be noisy"
    fi

    if (( rss_mb < 50 )); then
        pass "RSS < 50MB (got ${rss_mb}MB)"
    else
        fail "RSS >= 50MB (got ${rss_mb}MB)"
    fi

    local health
    health="$(grep '\[health\]' "$RUN_LOG" | tail -1 || true)"
    if [[ -n "$health" ]]; then
        info "last health: $health"
        local drops
        drops="$(echo "$health" | grep -oE 'dropped=[0-9]+' | cut -d= -f2 || echo 0)"
        if (( drops == 0 )); then
            pass "ringbuf drops == 0"
        else
            warn "ringbuf drops = $drops"
        fi
    else
        info "no health line in window (interval 60s, window ${HEALTH_WINDOW}s)"
    fi

    kill -TERM "$dpid" 2>/dev/null || true
    sleep 1
    kill -KILL "$dpid" 2>/dev/null || true
}


stage_config_matrix() {
    head2 "STAGE 8/10  Config load matrix"
    local cfgs="${OUT}/configs"
    rm -rf "$cfgs"; mkdir -p "$cfgs"

    # 8.1 no config -> defaults
    : > "$RUN_LOG"
    ( cd "${ROOT}/userspace" && "$USER_BIN" --config "" ) >>"$RUN_LOG" 2>&1 &
    local p=$!; sleep 1
    if grep -q 'config loaded' "$RUN_LOG"; then
        pass "config: defaults (no file)"
    else
        fail "config: defaults (no file)"
    fi
    kill -TERM $p 2>/dev/null; sleep 1; kill -KILL $p 2>/dev/null

    # 8.2 minimal valid
    printf 'mode = "audit"\n' > "$cfgs/minimal.toml"
    : > "$RUN_LOG"
    ( cd "${ROOT}/userspace" && "$USER_BIN" --config "$cfgs/minimal.toml" ) >>"$RUN_LOG" 2>&1 &
    p=$!; sleep 1
    if grep -q 'config loaded' "$RUN_LOG"; then
        pass "config: minimal TOML accepted"
    else
        fail "config: minimal TOML rejected"
    fi
    kill -TERM $p 2>/dev/null; sleep 1; kill -KILL $p 2>/dev/null

    # 8.3 malformed -> clean rejection
    printf 'this is = not = valid = toml = at = all = @@@\n' > "$cfgs/bad.toml"
    : > "$RUN_LOG"
    ( cd "${ROOT}/userspace" && "$USER_BIN" --config "$cfgs/bad.toml" ) >>"$RUN_LOG" 2>&1
    if grep -qE 'config:|parse config' "$RUN_LOG"; then
        pass "config: malformed rejected with clear message"
    else
        fail "config: malformed not rejected cleanly"
    fi

    # 8.4 enforce mode -> explicit refusal
    printf 'mode = "enforce"\n' > "$cfgs/enforce.toml"
    : > "$RUN_LOG"
    ( cd "${ROOT}/userspace" && "$USER_BIN" --config "$cfgs/enforce.toml" ) >>"$RUN_LOG" 2>&1
    if grep -qE 'enforce.*is not implemented|mode=enforce' "$RUN_LOG"; then
        pass "config: enforce mode explicitly rejected"
    else
        fail "config: enforce mode not rejected"
    fi
}

stage_reload() {
    head2 "STAGE 9/10  SIGHUP hot reload"
    local cfg="${OUT}/reload.toml"
    cat > "$cfg" <<'EOF'
mode = "audit"
[rates]
events_per_sec = 100
burst = 200
EOF

    : > "$RUN_LOG"
    ( cd "${ROOT}/userspace" && "$USER_BIN" --config "$cfg" ) >>"$RUN_LOG" 2>&1 &
    local p=$!; sleep 2

    if ! kill -0 $p 2>/dev/null; then
        fail "reload: daemon did not start"
        return
    fi
    pass "reload: daemon started with custom rates"

    sed -i 's/events_per_sec = 100/events_per_sec = 50/' "$cfg"
    kill -HUP $p 2>/dev/null
    sleep 1

    if grep -q '\[reload\] applied' "$RUN_LOG"; then
        pass "reload: SIGHUP applied"
    else
        fail "reload: SIGHUP not applied"
        tail -10 "$RUN_LOG" | sed 's/^/    /'
    fi
    kill -TERM $p 2>/dev/null; sleep 1; kill -KILL $p 2>/dev/null
}

stage_idle() {
    head2 "STAGE 10/10  Idle CPU (median of 3 x 5s)"
    : > "$RUN_LOG"
    ( cd "${ROOT}/userspace" && exec "$USER_BIN" --config "" ) >>"$RUN_LOG" 2>&1 &
    local p=$!
    sleep 3
    if ! kill -0 $p 2>/dev/null; then
        fail "idle: daemon did not start"
        return
    fi

    local hz; hz="$(getconf CLK_TCK)"
    local s1 s2 s3
    local i t0 t1 delta cpu_x100
    for i in 1 2 3; do
        read -ra f0 < /proc/$p/stat
        t0=$(( f0[13] + f0[14] ))
        sleep 5
        read -ra f1 < /proc/$p/stat
        t1=$(( f1[13] + f1[14] ))
        delta=$(( t1 - t0 ))
        cpu_x100=$(( delta * 1000 / hz ))
        info "idle sample $i: delta_ticks=$delta cpu=$(( cpu_x100 / 100 )).$(printf '%02d' $(( cpu_x100 % 100 )))% over 5s"
        case $i in
            1) s1=$cpu_x100 ;;
            2) s2=$cpu_x100 ;;
            3) s3=$cpu_x100 ;;
        esac
    done

    # median of three integers via sorting network (no subprocess)
    local a=$s1 b=$s2 c=$s3 t
    if (( a > b )); then t=$a; a=$b; b=$t; fi
    if (( b > c )); then t=$b; b=$c; c=$t; fi
    if (( a > b )); then t=$a; a=$b; b=$t; fi
    local median=$b

    info "idle median: $(( median / 100 )).$(printf '%02d' $(( median % 100 )))%"
    if (( median < 100 )); then
        pass "idle CPU median < 1.0% (samples: $s1 $s2 $s3)"
    else
        fail "idle CPU median >= 1.0% (median=$(( median / 100 )).$(printf '%02d' $(( median % 100 )))%, samples: $s1 $s2 $s3)"
    fi

    kill -TERM $p 2>/dev/null; sleep 1; kill -KILL $p 2>/dev/null
}


stage_lineage() {
    head2 "STAGE 11/12  Lineage enrichment"
    : > "$RUN_LOG"
    : > "$LOG_FILE" 2>/dev/null || true
    ( cd "${ROOT}/userspace" && exec "$USER_BIN" --config "" ) >>"$RUN_LOG" 2>&1 &
    local p=$!
    sleep 3
    if ! kill -0 $p 2>/dev/null; then
        fail "lineage: daemon did not start"
        tail -15 "$RUN_LOG" | sed 's/^/    /'
        return
    fi

    # Trigger a short chain of forks
    for i in 1 2 3; do /bin/sh -c '/bin/sh -c true' 2>/dev/null || true; done
    sleep 2

    local total with_lineage with_deep
    total=$(grep -c '^{' "$LOG_FILE" 2>/dev/null || echo 0)
    with_lineage=$(grep -c '"lineage":\[' "$LOG_FILE" 2>/dev/null || echo 0)
    # Count events whose lineage array contains at least 2 entries: "lineage":[{...},{...
    with_deep=$(grep -cE '"lineage":\[\{[^]]*\},\{' "$LOG_FILE" 2>/dev/null) || true
    with_deep=${with_deep:-0}

    if (( total > 0 && with_lineage > 0 )); then
        pass "lineage: $with_lineage/$total events have lineage array"
    else
        fail "lineage: no events with lineage (total=$total with=$with_lineage)"
    fi
    if (( with_deep > 0 )); then
        pass "lineage: at least one event has depth >= 2"
    else
        warn "lineage: no multi-level lineage observed"
    fi
    if grep -q '"lineage_summary":"' "$LOG_FILE"; then
        pass "lineage: lineage_summary present"
    else
        warn "lineage: lineage_summary missing"
    fi
    if grep -q '"cgroup_path":"' "$LOG_FILE"; then
        pass "lineage: cgroup_path present"
    else
        warn "lineage: cgroup_path missing"
    fi

    kill -TERM $p 2>/dev/null; sleep 1; kill -KILL $p 2>/dev/null
}

stage_cache() {
    head2 "STAGE 12/12  Cache bounds (25k forks)"
    : > "$RUN_LOG"
    : > "$LOG_FILE" 2>/dev/null || true
    ( cd "${ROOT}/userspace" && exec "$USER_BIN" --config "" --health-interval 2s ) >>"$RUN_LOG" 2>&1 &
    local p=$!
    sleep 3
    if ! kill -0 $p 2>/dev/null; then
        fail "cache: daemon did not start"
        tail -15 "$RUN_LOG" | sed 's/^/    /'
        return
    fi

    info "cache: generating 25000 forks..."
    local t0; t0=$(date +%s)
    /bin/sh -c 'for i in $(seq 1 25000); do /bin/true; done' 2>/dev/null || true
    local t1; t1=$(date +%s)
    info "cache: fork burst done in $((t1 - t0))s"

    sleep 5

    local health lineage_size
    health="$(grep '\[health\]' "$RUN_LOG" | tail -1)"
    if [[ -z "$health" ]]; then
        fail "cache: no health line captured"
    else
        info "health: $health"
        lineage_size="$(echo "$health" | grep -oE 'lineage_cache=[0-9]+' | head -1 | cut -d= -f2)"
        if [[ -n "$lineage_size" ]]; then
            if (( lineage_size <= 20000 )); then
                pass "cache: lineage_cache bounded at $lineage_size <= 20000"
            else
                fail "cache: lineage_cache $lineage_size > 20000"
            fi
        else
            fail "cache: lineage_cache size not in health log"
        fi
    fi

    local rss_kb rss_mb
    rss_kb="$(ps -o rss= -p $p 2>/dev/null | tr -d ' ')"
    rss_mb=$(( ${rss_kb:-0} / 1024 ))
    if (( rss_mb < 50 )); then
        pass "cache: RSS ${rss_mb}MB < 50MB"
    else
        fail "cache: RSS ${rss_mb}MB >= 50MB"
    fi

    kill -TERM $p 2>/dev/null; sleep 1; kill -KILL $p 2>/dev/null
}


stage_new_hooks() {
    head2 "STAGE 13/13  New hooks (Phase 2.4)"
    : > "$RUN_LOG"
    : > "$LOG_FILE" 2>/dev/null || true

    local tmp_cfg="${OUT}/new_hooks_cfg.toml"
    cat > "$tmp_cfg" <<'NH_CFG_END'
mode = "audit"
disabled_actions = []

[rates]
events_per_sec = 500
burst          = 1000
NH_CFG_END

    ( cd "${ROOT}/userspace" && exec "$USER_BIN" --config "$tmp_cfg" ) >>"$RUN_LOG" 2>&1 &
    local p=$!
    sleep 3
    if ! kill -0 $p 2>/dev/null; then
        fail "new_hooks: daemon did not start"
        tail -15 "$RUN_LOG" | sed 's/^/    /'
        return
    fi
    pass "new_hooks: daemon started with all actions enabled"

        # If the emulation binary is available, run it to generate additional events.
    if [[ -x "$EMUL_BIN" ]]; then
        "$EMUL_BIN" >/dev/null 2>&1 || true
    fi

    # Actions 14 and 15 fire only when the target paths are opened.
    # emulation/adversary predates them; fire host-side reads here so the
    # hooks are exercised regardless of emulation coverage.
    cat /proc/sys/kernel/core_pattern >/dev/null 2>&1 || true
    cat /proc/sys/kernel/modprobe       >/dev/null 2>&1 || true
    cat /proc/sys/kernel/uevent_helper >/dev/null 2>&1 || true
    find /sys/fs/cgroup -maxdepth 4 \
        \( -name 'release_agent' -o -name 'notify_on_release' \) \
        -type f -exec cat {} \; >/dev/null 2>&1 || true
    cat /sys/fs/cgroup/release_agent >/dev/null 2>&1 || true

    sleep 2

    local required=(Ebpf_Tampering Perf_Event_Open Suspicious_Mount Namespace_Switch Chroot_Escape Executable_Memory Core_Pattern_Modification Cgroup_Release_Agent)
    local seen=0
    for action in "${required[@]}"; do
        if grep -q "\"action\":\"$action\"" "$LOG_FILE"; then
            pass "new_hooks: $action"
            seen=$((seen+1))
        else
            fail "new_hooks: $action not observed"
        fi
    done
    info "new_hooks coverage: $seen/${#required[@]}"

    kill -TERM $p 2>/dev/null; sleep 1; kill -KILL $p 2>/dev/null
}

stage_docker() {
    head2 "STAGE 16/16  Docker Container Build"
    if ! command -v docker &> /dev/null; then
        warn "Docker not installed, skipping container build test."
        return
    fi

    cd "$ROOT" || return

    # Force clean any stale BPF pins left by Stage 4
    umount -f "${OUT}/bpftool_pin" 2>/dev/null || true
    umount -l "${OUT}/bpftool_pin" 2>/dev/null || true
    rm -rf "${OUT}/bpftool_pin" 2>/dev/null || true

    info "Building Docker image (this may take a minute)..."
    if ! docker build -t ebpf-edr:test . > /tmp/docker_test_build.log 2>&1; then
        fail "Docker image failed to build (see /tmp/docker_test_build.log)"
        tail -10 /tmp/docker_test_build.log | sed 's/^/    /'
        return
    fi
    pass "Docker image built successfully"

    info "Testing container startup (detached, 120s observation window)..."
    local cname="ebpf-edr-verify-$$"
    docker rm -f "$cname" >/dev/null 2>&1 || true

    # Give the system 10s to cool down after the 25k forks test in Stage 12
    info "Waiting for system to settle before launching container..."
    sleep 10

    local cid
    # Increased timeout to 60s because Docker daemon is slow on loaded VMs
    cid="$(timeout -k 5s 60s docker run -d \
        --name "$cname" \
        --privileged --pid=host --userns=host \
        --ulimit memlock=-1:-1 \
        -v /sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro \
        -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
        -v /sys/kernel/debug:/sys/kernel/debug:ro \
        ebpf-edr:test 2>/tmp/docker_test_run.err)" || {
        fail "docker run failed or timed out (see /tmp/docker_test_run.err)"
        cat /tmp/docker_test_run.err | sed 's/^/    /'
        return
    }

    local waited=0 status=""
    while (( waited < 120 )); do
        if timeout -k 2s 10s docker logs "$cid" 2>&1 | grep -q "EDR Engine active"; then
            break
        fi
        status="$(timeout -k 2s 10s docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || echo missing)"
        case "$status" in
            running|created) sleep 2; waited=$((waited+2)) ;;
            *) break ;;
        esac
    done

    # Capture everything BEFORE removal
    timeout -k 2s 10s docker logs "$cid" > /tmp/docker_test.log 2>&1 || true
    local exit_code oom
    exit_code="$(timeout -k 2s 10s docker inspect -f '{{.State.ExitCode}}' "$cid" 2>/dev/null || echo '?')"
    oom="$(timeout -k 2s 10s docker inspect -f '{{.State.OOMKilled}}' "$cid" 2>/dev/null || echo '?')"

    docker rm -f "$cname" >/dev/null 2>&1 || true

    if grep -q "EDR Engine active" /tmp/docker_test.log; then
        pass "Docker container started and attached successfully (${waited}s)"
    else
        fail "Docker container failed (${waited}s, status=$status, exit=$exit_code, oom=$oom)"
        tail -25 /tmp/docker_test.log | sed 's/^/    /'
    fi
}

require_root
head2 "ebpf-container-escape-framework - Phase 2.0 verification"
info "root: $ROOT"
info "out:  $OUT"
info "stage: $STAGE"

run_stage env       && stage_env
run_stage build     && stage_build
run_stage layout    && stage_layout
run_stage load      && stage_load
run_stage runtime   && stage_runtime
run_stage emulation && stage_emulation
run_stage perf      && stage_perf
run_stage config    && stage_config_matrix
run_stage reload    && stage_reload
run_stage idle      && stage_idle
run_stage lineage   && stage_lineage
run_stage cache     && stage_cache
run_stage new_hooks && stage_new_hooks
run_stage docker    && stage_docker


head2 "SUMMARY"
echo "  ${G}PASS${N}: $PASS"
echo "  ${Y}WARN${N}: $WARN"
echo "  ${R}FAIL${N}: $FAIL"

(( WARN > 0 )) && { echo; echo "${Y}Warnings:${N}"; for m in "${WARN_MSGS[@]}"; do echo "  - $m"; done; }
(( FAIL > 0 )) && { echo; echo "${R}Failures:${N}"; for m in "${FAIL_MSGS[@]}"; do echo "  - $m"; done; }
echo
echo "Artifacts: $OUT"
(( FAIL > 0 )) && exit 1
exit 0
