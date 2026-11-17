package policy

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu       sync.Mutex
	counters map[string]*windowCounter
	limit    int // max calls per window
	window   time.Duration
}

type windowCounter struct {
	count     int
	resetTime time.Time
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		counters: make(map[string]*windowCounter),
		limit:    limit,
		window:   window,
	}
}

// Allow checks if an agent has exceeded its rate limit.
func (rl *RateLimiter) Allow(agentID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	counter, exists := rl.counters[agentID]

	if !exists || now.After(counter.resetTime) {
		rl.counters[agentID] = &windowCounter{
			count:     1,
			resetTime: now.Add(rl.window),
		}
		return true
	}

	if counter.count >= rl.limit {
		return false
	}

	counter.count++
	return true
}
