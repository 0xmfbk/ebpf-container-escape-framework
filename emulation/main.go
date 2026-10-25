package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

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
	// Attach to a disposable child instead of host PID 1: a successful
	// attach SIGSTOPs the target, and stopping init — even briefly — is
	// not an acceptable side effect on a shared host.
	cmd := exec.Command("sleep", "1")
	if err := cmd.Start(); err != nil {
		log.Printf("[-] cannot start ptrace target: %v", err)
		return
	}
	time.Sleep(50 * time.Millisecond)
	if err := syscall.PtraceAttach(cmd.Process.Pid); err != nil {
		log.Printf("[-] Expected ptrace failure (syscall still fired): %v", err)
	} else {
		_ = syscall.PtraceDetach(cmd.Process.Pid)
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
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
		return
	}
	// As root the bind succeeds and would persist beyond this process,
	// stacking on every run. Detach immediately so the host mount
	// namespace is left as we found it.
	if err := unix.Unmount("/tmp", unix.MNT_DETACH); err != nil {
		log.Printf("[-] WARNING: bind mount succeeded but unmount failed: %v (manual cleanup: umount /tmp)", err)
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

// emulateOpenat2Bypass fires openat2 against a path that prefix-matches
// the /etc/shadow rule but does not exist. The sensor hooks
// sys_enter_openat2; before that hook existed this single syscall
// bypassed every file-based rule (canary, shadow, runtime sockets,
// core_pattern, release_agent). The unique target string lets the test
// suite attribute the resulting event to the openat2 hook specifically.
func emulateOpenat2Bypass() {
	log.Println("[*] Emulating openat2 file-rule bypass probe (/etc/shadow-openat2-probe)...")
	_, err := unix.Openat2(unix.AT_FDCWD, "/etc/shadow-openat2-probe", &unix.OpenHow{
		Flags: unix.O_RDONLY,
	})
	if err != nil {
		log.Printf("[-] Expected openat2 failure (syscall still fired): %v", err)
		return
	}
	fmt.Println("[+] openat2 open succeeded")
}

// emulateIPv6Connection: connect() with an AF_INET6 sockaddr — before
// Phase D the sensor silently dropped every IPv6 connection event.
func emulateIPv6Connection() {
	log.Println("[*] Emulating IPv6 network connection ([::1]:4444)...")
	conn, err := net.DialTimeout("tcp", "[::1]:4444", 200*time.Millisecond)
	if err != nil {
		log.Printf("[-] Expected connect failure (syscall still fired): %v", err)
		return
	}
	_ = conn.Close()
}

// emulateFilelessExecution: memfd_create + execveat are the fileless
// execution pair (T1055.012 / T1620). Both syscalls fire with invalid
// arguments; detection happens at sys_enter before validation.
func emulateFilelessExecution() {
	log.Println("[*] Emulating fileless execution (memfd_create + execveat)...")
	fd, err := unix.MemfdCreate("emul", 0)
	if err != nil {
		log.Printf("[-] memfd_create failed: %v", err)
	} else {
		_ = unix.Close(fd)
	}
	badPath := []byte("/nonexistent-emul-execveat\x00")
	dfd := unix.AT_FDCWD // through a variable: uintptr(-100) is not a legal constant conversion
	_, _, errno := unix.Syscall6(unix.SYS_EXECVEAT,
		uintptr(dfd), uintptr(unsafe.Pointer(&badPath[0])), 0, 0, 0, 0)
	if errno != 0 {
		log.Printf("[-] Expected execveat failure (syscall still fired): %v", errno)
	}
}

// emulateKernelModuleLoad fires init_module with NULL arguments (rejected
// immediately by the kernel; the tracepoint has already fired).
func emulateKernelModuleLoad() {
	log.Println("[*] Emulating kernel module load (init_module)...")
	_, _, errno := unix.Syscall(unix.SYS_INIT_MODULE, 0, 0, 0)
	if errno != 0 {
		log.Printf("[-] Expected init_module failure (syscall still fired): %v", errno)
	}
}

// emulateLogTamperV2: unlink was already covered; wipe/move via truncate
// and rename were invisible before Phase D. Paths prefix-match the EDR
// log rule; the files do not need to exist (sys_enter fires first).
func emulateLogTamperV2() {
	log.Println("[*] Emulating log tampering v2 (truncate + rename of EDR log path)...")
	p := "/var/log/ebpf_edr.json.emul_probe"
	if err := unix.Truncate(p, 0); err != nil {
		log.Printf("[-] Expected truncate failure (syscall still fired): %v", err)
	}
	if err := unix.Rename(p, "/tmp/ebpf_edr.json.moved"); err != nil {
		log.Printf("[-] Expected rename failure (syscall still fired): %v", err)
	}
}

// emulateNestedReleaseAgent opens a release_agent path one level below
// the cgroup root — outside the fixed path list the sensor matched on
// before Phase D's suffix scan. ENOENT on cgroup v2; fires regardless.
func emulateNestedReleaseAgent() {
	log.Println("[*] Emulating nested cgroup release_agent access...")
	if f, err := os.Open("/sys/fs/cgroup/emul-probe/release_agent"); err == nil {
		_ = f.Close()
	} else {
		log.Printf("[-] Expected open failure (syscall still fired): %v", err)
	}
}

func main() {
	// This harness fires real syscalls on the host it runs on. Require an
	// explicit opt-in so it is never executed against a production system
	// by accident (e.g. a stray `./adversary` as root).
	if os.Getenv("EDR_EMULATION_CONFIRMED") != "1" {
		fmt.Fprintln(os.Stderr, "refusing to run: this adversary harness executes real syscalls and,")
		fmt.Fprintln(os.Stderr, "as root, performs a temporary bind mount of /tmp and ptrace on a child.")
		fmt.Fprintln(os.Stderr, "Run it on a disposable host with: EDR_EMULATION_CONFIRMED=1 ./adversary")
		os.Exit(2)
	}
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
	emulateNestedReleaseAgent()
	emulateOpenat2Bypass()
	emulateIPv6Connection()
	emulateFilelessExecution()
	emulateKernelModuleLoad()
	emulateLogTamperV2()
	fmt.Println("=== Emulation Completed Successfully ===")
}
