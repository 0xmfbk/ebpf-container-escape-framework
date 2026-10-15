# Enterprise eBPF EDR & Container Escape Detection Framework

A high performance, low resource Endpoint Detection and Response (EDR) agent built with **eBPF (Extended Berkeley Packet Filtering)** in kernel space (C) and a high efficiency user space daemon in **Go**. Designed specifically for modern Linux environments (Debian 13 / Kernel 6.12) to detect container escapes, process injections, sensitive file access, and log tampering in real time.

---

## 🚀 Key Features

- **Container Escape Detection**: Monitors kernel calls (`unshare`, `pivot_root`) to instantly flag container breakouts to the host.
- **Advanced MITRE ATT&CK Mapping**: Every security alert is automatically tagged with industry standard MITRE ATT&CK IDs and techniques.
- **Sensitive File Protection**: Detects unauthorized access to critical system files such as `/etc/shadow` and SSH keys.
- **Process Injection Tracking**: Intercepts `ptrace` system calls to detect debugger attachments and process injection (`T1055.008`).
- **Defense Evasion Prevention**: Monitors `unlinkat` syscalls to protect EDR logs from deletion (`T1562.001`).
- **Network Telemetry**: Tracks TCP/IP connections and flags suspicious ports (e.g., reverse shell ports like 4444).
- **Production Ready Daemon**: Packaged as a hardened `systemd` service with strict resource limits (`MemoryMax=384M`) and zero allocation JSON serialization via `sync.Pool`.

---

## 🛡️ MITRE ATT&CK Matrix Integration

| MITRE ID | Tactic | Technique / Action | Severity |
| :--- | :--- | :--- | :--- |
| **T1611** | Privilege Escalation | Escape to Host (`pivot_root` / `unshare`) | `CRITICAL` / `HIGH` |
| **T1003.008** | Credential Dumping | Sensitive File Access (`/etc/shadow`) | `HIGH` |
| **T1055.008** | Defense Evasion | Process Injection via PTRACE | `HIGH` |
| **T1562.001** | Defense Evasion | Impair Defenses: Log Tampering (`unlinkat`) | `HIGH` |
| **T1071** | Command and Control | Application Layer Protocol (Network Connection) | `HIGH` / `INFO` |
| **T1059.004** | Execution | Command and Scripting Interpreter (Shells/Tools) | `MEDIUM` / `INFO` |

---

## 📂 Project Architecture

```text
ebpf-container-escape-framework/
├── kernel/
│   ├── bpf_program.c       # eBPF kernel probes, tracepoints, and ring buffer
│   └── bpf_program.o       # Compiled eBPF object
├── userspace/
│   ├── main.go             # Main Go controller, event listener, & resolver
│   ├── serializer.go       # Zero-allocation high-speed JSON alert serializer
│   ├── logger.go           # File rotation & logging handler
│   └── container_resolver.go # Cgroup-to-container ID mapping
└── ebpf-edr.service        # Hardened systemd service unit file
```

## 🛠️ Prerequisites

- OS: Debian 13 (Trixie) or modern Linux distribution

- Kernel: Linux Kernel 6.12+ with BTF enabled

- Toolchain: Go 1.22+, Clang, LLVM, and libbpf-dev


## ⚙️ Installation & Deployment

### 1. Clone & Compile

```Bash
git clone 

cd ebpf-container-escape-framework

# Compile eBPF kernel program
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c kernel/bpf_program.c -o kernel/bpf_program.o

# Build userspace Go controller
cd userspace
go build -o ebpf_controller
```

### 2. Configure Systemd Service
Copy and register the systemd service file:

```Bash
sudo cp ../ebpf-edr.service /etc/systemd/system/ebpf-edr.service
sudo systemctl daemon-reload
sudo systemctl enable --now ebpf-edr
```

### 3. Check Status & Live Logs

```Bash
sudo systemctl status ebpf-edr
sudo journalctl -u ebpf-edr -f
```

## 📊 Output Telemetry Format (JSON)
Alerts are persistently streamed to /var/log/ebpf_edr.json:

```JSON
{
  "timestamp": "2026-10-15T15:32:20Z",
  "pid": 9196,
  "uid": 0,
  "command": "strace",
  "action": "Process_Injection",
  "severity": "HIGH",
  "mitre_id": "T1055.008",
  "mitre_technique": "Process Injection: PTRACE",
  "cgroup_id": 4076,
  "runtime": "host"
}
```

## 📄 License
### This project is licensed under the MIT License.
