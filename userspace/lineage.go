package main

import (
	"container/list"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// USER_HZ on x86_64. /proc/<pid>/stat starttime is in clock ticks, so
// nanoseconds = ticks * (1e9 / 100) = ticks * 10_000_000.
const userHZ = 100

type procInfo struct {
	Pid         uint32
	Ppid        uint32
	StartTimeNs uint64
	Comm        string
	Exe         string
}

type lineageEntry struct {
	Pid         uint32 `json:"pid"`
	Ppid        uint32 `json:"ppid"`
	Comm        string `json:"comm"`
	Exe         string `json:"exe,omitempty"`
	StartTimeNs uint64 `json:"start_time_ns"`
}

type lineageCache struct {
	mu      sync.Mutex
	maxSize int
	ll      *list.List
	items   map[uint32]*list.Element
	hits    uint64
	misses  uint64
}

func newLineageCache(maxSize int) *lineageCache {
	if maxSize <= 0 {
		maxSize = 20000
	}
	return &lineageCache{
		maxSize: maxSize,
		ll:      list.New(),
		items:   make(map[uint32]*list.Element, 1024),
	}
}

func (lc *lineageCache) get(pid uint32) (procInfo, bool) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if el, ok := lc.items[pid]; ok {
		lc.ll.MoveToFront(el)
		lc.hits++
		return *el.Value.(*procInfo), true
	}
	lc.misses++
	return procInfo{}, false
}

func (lc *lineageCache) put(info procInfo) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	if el, ok := lc.items[info.Pid]; ok {
		*el.Value.(*procInfo) = info
		lc.ll.MoveToFront(el)
		return
	}
	el := lc.ll.PushFront(&info)
	lc.items[info.Pid] = el
	if lc.ll.Len() > lc.maxSize {
		oldest := lc.ll.Back()
		if oldest != nil {
			lc.ll.Remove(oldest)
			delete(lc.items, oldest.Value.(*procInfo).Pid)
		}
	}
}

func (lc *lineageCache) getOrRead(pid uint32) (procInfo, bool) {
	if info, ok := lc.get(pid); ok {
		return info, true
	}
	info, ok := readProcInfo(pid)
	if !ok {
		return procInfo{}, false
	}
	lc.put(info)
	return info, true
}

func (lc *lineageCache) size() int {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.ll.Len()
}

func (lc *lineageCache) capacity() int { return lc.maxSize }

func (lc *lineageCache) stats() (uint64, uint64) {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.hits, lc.misses
}

func readProcInfo(pid uint32) (procInfo, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return procInfo{}, false
	}
	s := string(data)
	lp := strings.LastIndexByte(s, ')')
	if lp < 0 || lp+2 >= len(s) {
		return procInfo{}, false
	}
	comm := ""
	if fp := strings.IndexByte(s, '('); fp >= 0 && fp < lp {
		comm = s[fp+1 : lp]
	}
	fields := strings.Fields(s[lp+2:])
	// fields[0]=state, fields[1]=ppid, ... fields[19]=starttime (22nd field overall)
	if len(fields) < 20 {
		return procInfo{}, false
	}
	ppid, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return procInfo{}, false
	}
	tick, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return procInfo{}, false
	}
	exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	return procInfo{
		Pid:         pid,
		Ppid:        uint32(ppid),
		StartTimeNs: tick * (1_000_000_000 / userHZ),
		Comm:        comm,
		Exe:         exe,
	}, true
}

// buildLineage fills out (reused slice, zero alloc) with leaf-first entries.
// Returns (entries, complete). complete==true means we reached a root or PID 1.
func (lc *lineageCache) buildLineage(out []lineageEntry, leafPid, leafPpid uint32, leafStart uint64, leafComm string, maxDepth int) ([]lineageEntry, bool) {
	if maxDepth < 1 {
		maxDepth = 1
	}
	leafExe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", leafPid))
	out = append(out, lineageEntry{
		Pid: leafPid, Ppid: leafPpid, Comm: leafComm,
		Exe: leafExe, StartTimeNs: leafStart,
	})
	lc.put(procInfo{Pid: leafPid, Ppid: leafPpid, StartTimeNs: leafStart, Comm: leafComm, Exe: leafExe})

	cur := leafPpid
	for depth := 1; depth < maxDepth; depth++ {
		if cur == 0 {
			return out, true
		}
		info, ok := lc.getOrRead(cur)
		if !ok {
			return out, false
		}
		out = append(out, lineageEntry{
			Pid: info.Pid, Ppid: info.Ppid, Comm: info.Comm,
			Exe: info.Exe, StartTimeNs: info.StartTimeNs,
		})
		if info.Ppid == 0 || info.Ppid == info.Pid {
			return out, true
		}
		cur = info.Ppid
	}
	return out, false
}

// buildLineageSummary joins comm names root-first, e.g. "sshd > bash > cat".
func buildLineageSummary(entries []lineageEntry) string {
	if len(entries) == 0 {
		return ""
	}
	var b strings.Builder
	for i := len(entries) - 1; i >= 0; i-- {
		if b.Len() > 0 {
			b.WriteString(" > ")
		}
		b.WriteString(entries[i].Comm)
	}
	return b.String()
}
