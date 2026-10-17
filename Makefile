SHELL      := /bin/bash
CLANG      ?= clang
GO         ?= go
BPFTOOL    ?= bpftool
CC         ?= gcc

# Disable VCS stamping - required when building as root in a repo owned by
# another user. Exported so every recursive make and every `go` invocation
# inherits it.
export GOFLAGS := -buildvcs=false

KERNEL_DIR    := kernel
USERSPACE_DIR := userspace
COMMON_DIR    := common
EMULATION_DIR := emulation
SCRIPTS_DIR   := scripts

BPF_SRC    := $(KERNEL_DIR)/bpf_program.c
BPF_OBJ    := $(KERNEL_DIR)/bpf_program.o
VMLINUX_H  := $(KERNEL_DIR)/vmlinux.h
LAYOUT_C   := $(KERNEL_DIR)/layout_check.c
LAYOUT_BIN := $(KERNEL_DIR)/layout_check
USER_BIN   := $(USERSPACE_DIR)/ebpf_controller
EMUL_BIN   := $(EMULATION_DIR)/adversary

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86 \
              -I$(KERNEL_DIR) -I$(COMMON_DIR) \
              -Wall -Werror -Wno-unused-function -Wno-address-of-packed-member

.PHONY: all kernel userspace emulation verify test clean help

all: kernel userspace

help:
	@echo "Targets: kernel userspace emulation verify test clean"

$(VMLINUX_H):
	@if [ ! -f $@ ]; then \
		echo "[make] generating $@"; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@; \
	fi

kernel: $(BPF_OBJ) $(LAYOUT_BIN)

$(BPF_OBJ): $(BPF_SRC) $(COMMON_DIR)/common.h $(VMLINUX_H)
	@echo "[make] $(CLANG) -> $@"
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(LAYOUT_BIN): $(LAYOUT_C) $(COMMON_DIR)/common.h
	@echo "[make] $(CC) -> $@"
	$(CC) -O0 -g -I$(COMMON_DIR) $< -o $@

userspace:
	@echo "[make] go build -> $(USER_BIN)"
	cd $(USERSPACE_DIR) && $(GO) build -trimpath -ldflags="-s -w" -o ebpf_controller .

emulation:
	@echo "[make] go build -> $(EMUL_BIN)"
	cd $(EMULATION_DIR) && $(GO) build -trimpath -o adversary .

test:
	cd $(USERSPACE_DIR) && $(GO) test -v ./...

verify: configs
	@bash $(SCRIPTS_DIR)/verify_phase2_0.sh
	@bash $(SCRIPTS_DIR)/verify_siem.sh

clean:
	rm -f $(BPF_OBJ) $(LAYOUT_BIN) $(USER_BIN) $(EMUL_BIN)
	cd $(USERSPACE_DIR) && $(GO) clean ./... 2>/dev/null || true

configs:
	@mkdir -p configs /etc/ebpf-edr
	@if [ ! -f configs/config.toml ]; then \
		echo "[make] WARN: configs/config.toml missing"; \
	fi
	@if [ ! -f /etc/ebpf-edr/config.toml ]; then \
		install -m 0644 configs/config.toml /etc/ebpf-edr/config.toml 2>/dev/null || true; \
	fi

# ---- Phase 2.2 ----
install:
	@bash install.sh

install-dry:
	@bash install.sh --dry-run

uninstall:
	@bash install.sh --uninstall

test-attacks:
	@bash scripts/test_attacks.sh

systemd-reload:
	@systemctl daemon-reload
	@systemctl restart ebpf-edr.service || true

.PHONY: install install-dry uninstall test-attacks systemd-reload

# ---- Phase 2.5 ----
.PHONY: ci fuzz test-race test-all clean-backups

ci:
	@bash scripts/ci.sh

fuzz:
	cd $(USERSPACE_DIR) && $(GO) test -run='^$$' -fuzz=FuzzDecodeEvent    -fuzztime=60s .
	cd $(USERSPACE_DIR) && $(GO) test -run='^$$' -fuzz=FuzzSerializeAlert -fuzztime=60s .
	cd $(USERSPACE_DIR) && $(GO) test -run='^$$' -fuzz=FuzzConfigParse    -fuzztime=60s .

test-race:
	cd $(USERSPACE_DIR) && $(GO) test -race -count=1 ./...

test-all: test test-race

clean-backups:
	find . -type f -name '*.bak.*' -delete 2>/dev/null || true
	find . -type d -name '.phase2_0_backup_*' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '.phase2_0_patch_*'  -exec rm -rf {} + 2>/dev/null || true

.PHONY: verify-all
verify-all:
	@bash $(SCRIPTS_DIR)/verify_phase2_0.sh
	@bash $(SCRIPTS_DIR)/verify_siem.sh
	@bash $(SCRIPTS_DIR)/verify_siem.sh

.PHONY: verify-siem
verify-siem:
	@bash $(SCRIPTS_DIR)/verify_siem.sh

# ---- Phase 2.7: Cloud-Native ----
.PHONY: docker-build k8s-apply k8s-delete

docker-build:
	docker build -t 0xmfbk/ebpf-container-escape-framework:v2.7.0 .

k8s-apply:
	kubectl apply -f deploy/kubernetes/namespace-config.yaml
	kubectl apply -f deploy/kubernetes/daemonset.yaml

k8s-delete:
	kubectl delete -f deploy/kubernetes/daemonset.yaml
	kubectl delete -f deploy/kubernetes/namespace-config.yaml
