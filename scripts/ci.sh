#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export GOFLAGS=-buildvcs=false

RED=$'\e[31m'; GRN=$'\e[32m'; BLU=$'\e[36m'; BLD=$'\e[1m'; RST=$'\e[0m'
hdr() { echo; echo "${BLD}${BLU}=== $* ===${RST}"; }
ok()  { echo "${GRN}[OK]${RST}   $*"; }
bad() { echo "${RED}[FAIL]${RST} $*"; exit 1; }

hdr "1/6 gofmt check"
UNFMT=$(gofmt -l userspace emulation 2>/dev/null || true)
if [[ -n "$UNFMT" ]]; then bad "unformatted: $UNFMT"; fi
ok "all Go files formatted"

hdr "2/6 go vet"
(cd userspace && go vet ./...) || bad "go vet (userspace)"
(cd emulation && go vet ./...) || bad "go vet (emulation)"
ok "go vet clean"

hdr "3/6 go test -race"
(cd userspace && go test -race -count=1 ./...) || bad "race test failed"
ok "race detector clean"

hdr "4/6 fuzz smoke (10s per target)"
(cd userspace && go test -run='^$' -fuzz=FuzzDecodeEvent    -fuzztime=10s .) || bad "FuzzDecodeEvent crash"
(cd userspace && go test -run='^$' -fuzz=FuzzSerializeAlert -fuzztime=10s .) || bad "FuzzSerializeAlert crash"
(cd userspace && go test -run='^$' -fuzz=FuzzConfigParse    -fuzztime=10s .) || bad "FuzzConfigParse crash"
ok "no fuzz crashes"

hdr "5/6 kernel build"
make kernel || bad "make kernel failed"
ok "bpf_program.o built"

hdr "6/6 full verification"
make verify || bad "make verify failed"
ok "verify passed"

echo
echo "${BLD}${GRN}CI passed.${RST}"
