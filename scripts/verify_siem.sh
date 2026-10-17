#!/usr/bin/env bash
# Phase 2.6 SIEM verification — format matrix + webhook transport.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/verify_out"
USER_BIN="${ROOT}/userspace/ebpf_controller"
RUN_LOG="${OUT}/siem_daemon.log"

if [[ -t 1 ]]; then
    R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; B=$'\e[36m'; N=$'\e[0m'; BOLD=$'\e[1m'
else
    R=""; G=""; Y=""; B=""; N=""; BOLD=""
fi

PASS=0; FAIL=0; WARN=0
declare -a FAIL_MSGS=() WARN_MSGS=()
pass() { echo "${G}[PASS]${N} $*"; PASS=$((PASS+1)); }
fail() { echo "${R}[FAIL]${N} $*"; FAIL=$((FAIL+1)); FAIL_MSGS+=("$*"); }
warn() { echo "${Y}[WARN]${N} $*"; WARN=$((WARN+1)); WARN_MSGS+=("$*"); }
info() { echo "${B}[INFO]${N} $*"; }
head2() { echo; echo "${BOLD}=== $* ===${N}"; }

if [[ $EUID -ne 0 ]]; then echo "must run as root"; exit 1; fi
mkdir -p "$OUT"

# ============================================================
stage_format_matrix() {
    head2 "STAGE 14  Format matrix"
    local cfgs_dir="${OUT}/fmt_cfgs"
    rm -rf "$cfgs_dir"; mkdir -p "$cfgs_dir"

    for fmt in json ecs ocsf cef leef ; do
        local cfg="${cfgs_dir}/${fmt}.toml"
        printf 'mode = "audit"\n[output]\nformat = "%s"\ntarget = "file"\npath = "%s/fmt_%s.out"\n' \
            "$fmt" "$OUT" "$fmt" > "$cfg"

        : > "$RUN_LOG"
        : > "${OUT}/fmt_${fmt}.out"
        ( cd "${ROOT}/userspace" && exec "$USER_BIN" --config "$cfg" ) >>"$RUN_LOG" 2>&1 &
        local p=$!; sleep 3

        if ! kill -0 $p 2>/dev/null; then
            fail "fmt=$fmt: daemon did not start"
            tail -6 "$RUN_LOG" | sed 's/^/    /'
            kill -KILL $p 2>/dev/null
            continue
        fi

        cat /etc/shadow >/dev/null 2>&1 || true
        sleep 2
        kill -TERM $p 2>/dev/null; sleep 1; kill -KILL $p 2>/dev/null

        local lines
        lines=$(wc -l < "${OUT}/fmt_${fmt}.out" 2>/dev/null || echo 0)
        if (( lines == 0 )); then
            fail "fmt=$fmt: no output produced"
            continue
        fi

        local first
        first=$(head -1 "${OUT}/fmt_${fmt}.out")

        case "$fmt" in
            json|ecs|ocsf)
                if echo "$first" | python3 -c 'import sys,json; json.loads(sys.stdin.read())' 2>/dev/null; then
                    pass "fmt=$fmt: valid JSON ($lines lines)"
                else
                    fail "fmt=$fmt: not parseable as JSON"
                fi
                ;;
            cef)
                if [[ "$first" == CEF:0\|* ]]; then
                    pass "fmt=cef: header OK ($lines lines)"
                else
                    fail "fmt=cef: bad header: ${first:0:40}"
                fi
                ;;
            leef)
                if [[ "$first" == LEEF:2.0\|* ]]; then
                    pass "fmt=leef: header OK ($lines lines)"
                else
                    fail "fmt=leef: bad header: ${first:0:40}"
                fi
                ;;
        esac
    done
}

# ============================================================
stage_webhook() {
    head2 "STAGE 15  Webhook delivery + resilience"
    local port=18888
    local cfg="${OUT}/webhook.toml"
    local countfile="${OUT}/webhook_count"
    : > "$countfile"

    # Mock SIEM: counts POSTs to /collect
    python3 -u -c "
import http.server, socketserver, sys
port = $port
path = '$countfile'
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get('Content-Length', 0) or 0)
        _ = self.rfile.read(n)
        with open(path, 'a') as f: f.write('1\n')
        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
srv = socketserver.TCPServer(('127.0.0.1', port), H)
srv.serve_forever()
" &
    local mock_pid=$!
    sleep 1

    printf 'mode = "audit"\n[output]\nformat = "json"\ntarget = "webhook"\n[output.webhook]\nurl = "http://127.0.0.1:%d/collect"\nbatch_style = "ndjson"\nbatch_size = 20\nflush_interval = "1s"\ntimeout = "2s"\n' \
        "$port" > "$cfg"

    : > "$RUN_LOG"
    ( cd "${ROOT}/userspace" && exec "$USER_BIN" --config "$cfg" ) >>"$RUN_LOG" 2>&1 &
    local p=$!; sleep 3

    if ! kill -0 $p 2>/dev/null; then
        fail "webhook: daemon did not start"
        tail -6 "$RUN_LOG" | sed 's/^/    /'
        kill -KILL $mock_pid 2>/dev/null
        return
    fi

    # Generate enough events to trigger at least one batch
    for i in 1 2 3 4 5 6 7 8 9 10; do cat /etc/shadow >/dev/null 2>&1 || true; done
    sleep 3

    local received
    received=$(wc -l < "$countfile" 2>/dev/null || echo 0)
    if (( received >= 1 )); then
        pass "webhook: mock SIEM received $received POST(s)"
    else
        fail "webhook: no POSTs received by mock SIEM"
    fi

    # Kill the mock; daemon must survive and drop rather than crash
    kill -KILL $mock_pid 2>/dev/null; sleep 1
    for i in $(seq 1 50); do cat /etc/shadow >/dev/null 2>&1 || true; done
    sleep 3

    if kill -0 $p 2>/dev/null; then
        pass "webhook: daemon survives dead SIEM (queue + circuit breaker)"
    else
        fail "webhook: daemon died when SIEM went away"
    fi

    kill -TERM $p 2>/dev/null; sleep 1; kill -KILL $p 2>/dev/null
}

# ============================================================
head2 "Phase 2.6 SIEM verification"
stage_format_matrix
stage_webhook

head2 "SIEM SUMMARY"
echo "  ${G}PASS${N}: $PASS"
echo "  ${Y}WARN${N}: $WARN"
echo "  ${R}FAIL${N}: $FAIL"
if (( WARN > 0 )); then
    echo; echo "${Y}Warnings:${N}"
    for m in "${WARN_MSGS[@]}"; do echo "  - $m"; done
fi
if (( FAIL > 0 )); then
    echo; echo "${R}Failures:${N}"
    for m in "${FAIL_MSGS[@]}"; do echo "  - $m"; done
    exit 1
fi
exit 0
