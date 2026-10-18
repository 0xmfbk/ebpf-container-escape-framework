package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func emulateNamespaceEscape() {
	log.Println("[*] Emulating Container Namespace Escape (unshare)...")
	cmd := exec.Command("unshare", "--net", "--pid", "--fork", "echo",
		"[+] Namespace escape emulation executed")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("[-] Unshare emulation failed: %v", err)
	}
}

func emulatePivotRootEscape() {
	log.Println("[*] Emulating Container Root Filesystem Escape (pivot_root)...")
	if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
		log.Printf("[-] Unshare mount namespace failed: %v", err)
		return
	}
	cmd := exec.Command("mount", "--make-rprivate", "/")
	if err := cmd.Run(); err != nil {
		log.Printf("[-] Make rprivate failed: %v", err)
		return
	}
	_ = os.MkdirAll("/tmp/emul_root/put_old", 0755)
	cmdBind := exec.Command("mount", "--bind", "/tmp/emul_root", "/tmp/emul_root")
	if err := cmdBind.Run(); err != nil {
		log.Printf("[-] Bind mount failed: %v", err)
		return
	}
	err := syscall.PivotRoot("/tmp/emul_root", "/tmp/emul_root/put_old")
	if err != nil {
		log.Printf("[-] Pivot_root emulation triggered syscall (Expected alert generated): %v", err)
	} else {
		fmt.Println("[+] Pivot root executed successfully!")
	}
}

func emulateSensitiveFileAccess() {
	log.Println("[*] Emulating Sensitive File Access (Attempting to read /etc/shadow)...")
	file, err := os.Open("/etc/shadow")
	if err != nil {
		log.Printf("[-] Expected permission block or access attempt on /etc/shadow: %v", err)
		return
	}
	_ = file.Close()
	fmt.Println("[+] File opened successfully!")
}

func emulateNetworkConnection() {
	log.Println("[*] Emulating Network Connection (reverse-shell port 4444)...")
	conn, err := net.DialTimeout("tcp", "127.0.0.1:4444", 200*time.Millisecond)
	if err != nil {
		log.Printf("[-] Expected connect failure (syscall still fired): %v", err)
		return
	}
	_ = conn.Close()
}

func emulateProcessInjection() {
	log.Println("[*] Emulating Process Injection (ptrace)...")
	if err := syscall.PtraceAttach(1); err != nil {
		log.Printf("[-] Expected ptrace failure (syscall still fired): %v", err)
		return
	}
	_ = syscall.PtraceDetach(1)
}

func emulateLogTampering() {
	log.Println("[*] Emulating Log Tampering (unlinkat on EDR log)...")
	if err := os.Remove("/var/log/ebpf_edr.json.emul_probe"); err != nil {
		log.Printf("[-] Expected unlink failure (syscall still fired): %v", err)
	}
}

func emulateShellExecution() {
	log.Println("[*] Emulating Shell Execution (/bin/sh -c true)...")
	cmd := exec.Command("/bin/sh", "-c", "true")
	if err := cmd.Run(); err != nil {
		log.Printf("[-] Shell execution failed: %v", err)
	}
}

func emulateEbpfTampering() {
	log.Println("[*] Emulating eBPF Tampering (bpf syscall)...")
	_, _, errno := unix.Syscall(unix.SYS_BPF, 0, 0, 0)
	if errno != 0 {
		log.Printf("[-] Expected bpf failure (syscall still fired): %v", errno)
	}
}

func emulatePerfEventOpen() {
	log.Println("[*] Emulating perf_event_open...")
	_, _, errno := unix.Syscall(unix.SYS_PERF_EVENT_OPEN, 0, 0, 0)
	if errno != 0 {
		log.Printf("[-] Expected perf_event_open failure (syscall still fired): %v", errno)
	}
}

func emulateSuspiciousMount() {
	log.Println("[*] Emulating Suspicious Mount (bind of /tmp)...")
	err := unix.Mount("/tmp", "/tmp", "", unix.MS_BIND, "")
	if err != nil {
		log.Printf("[-] Expected mount failure (syscall still fired): %v", err)
	}
}

func emulateNamespaceSwitch() {
	log.Println("[*] Emulating Namespace Switch (setns)...")
	if err := unix.Setns(-1, 0); err != nil {
		log.Printf("[-] Expected setns failure (syscall still fired): %v", err)
	}
}

func emulateChrootEscape() {
	log.Println("[*] Emulating Chroot Escape (chroot /nonexistent)...")
	if err := unix.Chroot("/nonexistent-emul-probe"); err != nil {
		log.Printf("[-] Expected chroot failure (syscall still fired): %v", err)
	}
}

func emulateExecutableMemory() {
	log.Println("[*] Emulating Executable Memory (mmap RW -> mprotect RX)...")
	b, err := unix.Mmap(-1, 0, 4096,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		log.Printf("[-] mmap failed: %v", err)
		return
	}
	if err := unix.Mprotect(b, unix.PROT_READ|unix.PROT_EXEC); err != nil {
		log.Printf("[-] Expected mprotect failure (syscall still fired): %v", err)
	}
	_ = unix.Munmap(b)
}

// emulateCorePatternModification opens the three kernel helper hijack
// paths. Read-only opens are sufficient: sys_enter_openat fires before
// path resolution, so the tracepoint triggers regardless of EACCES/ENOENT.
// Writing is deliberately avoided so running this on a shared host as
// root cannot modify kernel state.
func emulateCorePatternModification() {
	log.Println("[*] Emulating Core Pattern Modification (open /proc/sys/kernel/{core_pattern,modprobe,uevent_helper})...")
	opened := 0
	for _, p := range []string{
		"/proc/sys/kernel/core_pattern",
		"/proc/sys/kernel/modprobe",
		"/proc/sys/kernel/uevent_helper",
	} {
		f, err := os.Open(p)
		if err != nil {
			log.Printf("[-] Expected open failure on %s (syscall still fired): %v", p, err)
			continue
		}
		_ = f.Close()
		opened++
	}
	log.Printf("[+] Core pattern emulation: %d/3 opens succeeded (all syscalls fired)", opened)
}

// emulateCgroupReleaseAgent opens release_agent / notify_on_release at
// the cgroup root and one level down (covers cgroup v1 hierarchies and
// delegated v2 subtrees). On cgroup v2 hosts the files do not exist and
// every open returns ENOENT — the tracepoint fires anyway, which is what
// the sensor detects.
func emulateCgroupReleaseAgent() {
	log.Println("[*] Emulating cgroup release_agent access...")
	candidates := []string{
		"/sys/fs/cgroup/release_agent",
		"/sys/fs/cgroup/notify_on_release",
	}
	if entries, err := os.ReadDir("/sys/fs/cgroup"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				base := "/sys/fs/cgroup/" + e.Name()
				candidates = append(candidates,
					base+"/release_agent",
					base+"/notify_on_release",
				)
			}
		}
	}
	opened := 0
	for _, p := range candidates {
		f, err := os.Open(p)
		if err != nil {
			continue // ENOENT is expected on cgroup v2; tracepoint already fired
		}
		_ = f.Close()
		opened++
	}
	if opened == 0 {
		log.Printf("[-] No release_agent/notify_on_release files opened (expected on cgroup v2 hosts); syscalls still fired")
	} else {
		log.Printf("[+] cgroup release_agent emulation: %d/%d opens succeeded", opened, len(candidates))
	}
}

func main() {
	fmt.Println("=== Starting Adversary Emulation Engine ===")
	emulateNamespaceEscape()
	emulateSensitiveFileAccess()
	emulateProcessInjection()
	emulateNetworkConnection()
	emulateLogTampering()
	emulateShellExecution()
	emulatePivotRootEscape()
	emulateEbpfTampering()
	emulatePerfEventOpen()
	emulateSuspiciousMount()
	emulateNamespaceSwitch()
	emulateChrootEscape()
	emulateExecutableMemory()
	emulateCorePatternModification()
	emulateCgroupReleaseAgent()
	fmt.Println("=== Emulation Completed Successfully ===")
}