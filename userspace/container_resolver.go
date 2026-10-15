package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
)

type ContainerInfo struct {
	ContainerID string 
	Runtime     string
}

type containerResolver struct {
	mu    sync.RWMutex
	cache map[uint64]ContainerInfo
}

func newContainerResolver() *containerResolver {
	return &containerResolver{
		cache: make(map[uint64]ContainerInfo),
	}
}

func (cr *containerResolver) resolve(cgroupID uint64, pid uint32) ContainerInfo {
	if cgroupID == 0 {
		return ContainerInfo{Runtime: "unknown"}
	}

	cr.mu.RLock()
	info, ok := cr.cache[cgroupID]
	cr.mu.RUnlock()
	if ok {
		return info
	}

	info = resolveFromProc(pid)

	cr.mu.Lock()
	cr.cache[cgroupID] = info
	cr.mu.Unlock()

	return info
}

func resolveFromProc(pid uint32) ContainerInfo {
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	f, err := os.Open(path)
	if err != nil {
		return ContainerInfo{Runtime: "unknown"} // process likely already exited
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if id := longestHexRun(line); len(id) >= 12 {
			switch {
			case strings.Contains(line, "docker"):
				return ContainerInfo{ContainerID: id[:12], Runtime: "docker"}
			case strings.Contains(line, "containerd"):
				return ContainerInfo{ContainerID: id[:12], Runtime: "containerd"}
			case strings.Contains(line, "kubepods"):
				return ContainerInfo{ContainerID: id[:12], Runtime: "kubepod"}
			}
		}

		if strings.Contains(line, "kubepods") {
			return ContainerInfo{Runtime: "kubepod"} // pod cgroup without a clean container-ID segment
		}
	}

	return ContainerInfo{Runtime: "host"}
}

// longestHexRun returns the longest contiguous run of lowercase hex
// characters in s. Docker/containerd embed a 64-char hex container ID in
// the cgroup path (e.g. ".../docker-<64hex>.scope"); this is a
// best-effort extraction that works across the common path shapes without
// hardcoding every runtime's exact format.
func longestHexRun(s string) string {
	best, cur := "", ""
	isHex := func(b byte) bool {
		return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
	}
	for i := 0; i < len(s); i++ {
		if isHex(s[i]) {
			cur += string(s[i])
			if len(cur) > len(best) {
				best = cur
			}
		} else {
			cur = ""
		}
	}
	return best
}
