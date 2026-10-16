package main

import (
	"bufio"
	"container/list"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

type ContainerInfo struct {
	ContainerID string // 12-char short ID, Docker-CLI style; empty if host or unresolved
	Runtime     string // "docker", "containerd", "kubepod", "host", "unknown"
}

const defaultContainerCacheMaxEntries = 5000

func cacheSizeFromEnv() int {
	if v := os.Getenv("EDR_CONTAINER_CACHE_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultContainerCacheMaxEntries
}

type cacheEntry struct {
	cgroupID uint64
	info     ContainerInfo
}

type containerResolver struct {
	mu      sync.Mutex
	maxSize int
	ll      *list.List               // front = most recently used
	items   map[uint64]*list.Element // cgroupID -> element whose Value is *cacheEntry
}

func newContainerResolver() *containerResolver {
	return &containerResolver{
		maxSize: cacheSizeFromEnv(),
		ll:      list.New(),
		items:   make(map[uint64]*list.Element),
	}
}

func (cr *containerResolver) resolve(cgroupID uint64, pid uint32) ContainerInfo {
	if cgroupID == 0 {
		return ContainerInfo{Runtime: "unknown"}
	}

	cr.mu.Lock()
	if el, ok := cr.items[cgroupID]; ok {
		cr.ll.MoveToFront(el)
		info := el.Value.(*cacheEntry).info
		cr.mu.Unlock()
		return info
	}
	cr.mu.Unlock()

	info := resolveFromProc(pid)

	cr.mu.Lock()
	defer cr.mu.Unlock()

	if el, ok := cr.items[cgroupID]; ok {
		cr.ll.MoveToFront(el)
		return el.Value.(*cacheEntry).info
	}

	el := cr.ll.PushFront(&cacheEntry{cgroupID: cgroupID, info: info})
	cr.items[cgroupID] = el

	if cr.ll.Len() > cr.maxSize {
		oldest := cr.ll.Back()
		if oldest != nil {
			cr.ll.Remove(oldest)
			delete(cr.items, oldest.Value.(*cacheEntry).cgroupID)
		}
	}

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
