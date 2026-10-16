package main

import (
	"sync"
	"time"
)

type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64
	last     time.Time
}

func newTokenBucket(rate, burst int) *tokenBucket {
	return &tokenBucket{
		tokens:   float64(burst),
		capacity: float64(burst),
		rate:     float64(rate),
		last:     time.Now(),
	}
}

func (tb *tokenBucket) allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	now := time.Now()
	tb.tokens += now.Sub(tb.last).Seconds() * tb.rate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	tb.last = now
	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

type rateLimiter struct {
	mu      sync.RWMutex
	buckets map[uint32]*tokenBucket
}

func newRateLimiter(rate, burst int) *rateLimiter {
	rl := &rateLimiter{}
	rl.setRates(rate, burst)
	return rl
}

func (rl *rateLimiter) setRates(rate, burst int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rate <= 0 || burst <= 0 {
		rl.buckets = nil
		return
	}
	rl.buckets = make(map[uint32]*tokenBucket, 8)
	for id := uint32(1); id < ActionMaxID; id++ {
		rl.buckets[id] = newTokenBucket(rate, burst)
	}
}

func (rl *rateLimiter) allow(actionID uint32) bool {
	rl.mu.RLock()
	b, ok := rl.buckets[actionID]
	rl.mu.RUnlock()
	if !ok {
		return true
	}
	return b.allow()
}
