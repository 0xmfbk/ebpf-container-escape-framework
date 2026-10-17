# ============================================================
# Stage 1: Builder (compile BPF and Go binary)
# ============================================================
FROM golang:1.25-bookworm AS builder

# Install BPF toolchain
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev libelf-dev make gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# Build the BPF object and the Go daemon
RUN make kernel
RUN make userspace

# ============================================================
# Stage 2: Runtime (minimal image)
# ============================================================
FROM debian:bookworm-slim

# The Go binary is statically linked, but we need ca-certificates
# for HTTPS webhook delivery (SIEM export)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ebpf-edr

# Copy the compiled artifacts
COPY --from=builder /build/userspace/ebpf_controller /usr/local/bin/ebpf_controller
COPY --from=builder /build/kernel/bpf_program.o /opt/ebpf-edr/bpf_program.o
COPY --from=builder /build/configs/config.toml /etc/ebpf-edr/config.toml

# Run as root (required for BPF)
USER root

ENTRYPOINT ["/usr/local/bin/ebpf_controller"]
CMD ["--config", "/etc/ebpf-edr/config.toml", "--bpf-obj", "/opt/ebpf-edr/bpf_program.o"]
