package main

import (
	"container/list"
	"fmt"
	"os"
	"strings"
	"sync"
)

type cgroupCacheEntry struct {
	cgroupID uint64
	path     string
}

type cgroupPathCache struct {
	mu      sync.Mutex
	maxSize int
	ll      *list.List
	items   map[uint64]*list.Element
	hits    uint64
	misses  uint64
}

func newCgroupPathCache(maxSize int) *cgroupPathCache {
	if maxSize <= 0 {
		maxSize = 5000
	}
	return &cgroupPathCache{
		maxSize: maxSize,
		ll:      list.New(),
		items:   make(map[uint64]*list.Element, 512),
	}
}

func (cp *cgroupPathCache) get(cgroupID uint64) (string, bool) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if el, ok := cp.items[cgroupID]; ok {
		cp.ll.MoveToFront(el)
		cp.hits++
		return el.Value.(*cgroupCacheEntry).path, true
	}
	cp.misses++
	return "", false
}

func (cp *cgroupPathCache) put(cgroupID uint64, path string) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if el, ok := cp.items[cgroupID]; ok {
		el.Value.(*cgroupCacheEntry).path = path
		cp.ll.MoveToFront(el)
		return
	}
	el := cp.ll.PushFront(&cgroupCacheEntry{cgroupID: cgroupID, path: path})
	cp.items[cgroupID] = el
	if cp.ll.Len() > cp.maxSize {
		oldest := cp.ll.Back()
		if oldest != nil {
			cp.ll.Remove(oldest)
			delete(cp.items, oldest.Value.(*cgroupCacheEntry).cgroupID)
		}
	}
}

func (cp *cgroupPathCache) size() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.ll.Len()
}

func (cp *cgroupPathCache) capacity() int { return cp.maxSize }

// readCgroupPath returns the cgroup v2 path for a pid from /proc/<pid>/cgroup.
// Format on cgroup v2: "0::/path". Returns ("", false) if unavailable.
func readCgroupPath(pid uint32) (string, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			return line[3:], true
		}
	}
	return "", false
}
