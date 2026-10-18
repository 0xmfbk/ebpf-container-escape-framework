# ============================================================
# Stage 1: Builder (compile Go binary only)
# ============================================================
FROM golang:1.25-bookworm AS builder

WORKDIR /build
COPY . .

# The BPF object is pre-compiled on the host (avoids clang verifier hangs).
# We only need to compile the Go daemon here.
RUN cd userspace && go build -trimpath -ldflags="-s -w" -o ebpf_controller .

# ============================================================
# Stage 2: Runtime (minimal image)
# ============================================================
FROM debian:bookworm-slim

# ca-certificates for HTTPS webhook delivery (SIEM export)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ebpf-edr

# Copy the compiled artifacts
COPY --from=builder /build/userspace/ebpf_controller /usr/local/bin/ebpf_controller
COPY kernel/bpf_program.o /opt/ebpf-edr/bpf_program.o
COPY configs/config.toml /etc/ebpf-edr/config.toml

# Run as root (required for BPF)
USER root

ENTRYPOINT ["/usr/local/bin/ebpf_controller"]
CMD ["--config", "/etc/ebpf-edr/config.toml", "--bpf-obj", "/opt/ebpf-edr/bpf_program.o"]