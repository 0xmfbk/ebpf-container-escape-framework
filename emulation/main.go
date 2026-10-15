package main

import (
    "fmt"
    "log"
    "os"
    "os/exec"
    "syscall"
)

func emulateNamespaceEscape() {
    log.Println("[*] Emulating Container Namespace Escape (unshare)...")
    cmd := exec.Command("unshare", "--net", "--pid", "--fork", "echo", "[+] Namespace escape emulation executed")
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

    os.MkdirAll("/tmp/emul_root/put_old", 0755)
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
    defer file.Close()
    fmt.Println("[+] File opened successfully!")
}

func main() {
    fmt.Println("=== Starting Adversary Emulation Engine ===")
    emulateNamespaceEscape()
    emulateSensitiveFileAccess()
    emulatePivotRootEscape()
    fmt.Println("=== Emulation Completed Successfully ===")
}
