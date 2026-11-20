package policy

import (
	"errors"
	"sync"
	"time"
)

// RateLimitConfig is mandatory in effect; absent YAML uses DefaultRateLimit.
type RateLimitConfig struct {
	RequestsPerMinute int `yaml:"requests_per_minute"`
	Burst int `yaml:"burst"`
	MaxAgents int `yaml:"max_agents"`
}

func DefaultRateLimit() RateLimitConfig {
	return RateLimitConfig{RequestsPerMinute:120,Burst:40,MaxAgents:4096}
}

func (c RateLimitConfig) Validate() error {
	if c.RequestsPerMinute<1 || c.RequestsPerMinute>6000 || c.Burst<1 || c.Burst>1000 || c.MaxAgents<1 || c.MaxAgents>16384 {
		return errors.New("rate_limit requires requests_per_minute 1..6000, burst 1..1000, max_agents 1..16384")
	}
	return nil
}

var ErrRateLimited = errors.New("agent rate limit exceeded")
var ErrRateCapacity = errors.New("agent rate limiter capacity reached")

// One token costs a minute in integer credits. Each elapsed nanosecond
// earns RequestsPerMinute credits. This avoids floating-point drift.
const tokenCost = int64(time.Minute)

type bucket struct {
	credit int64
	last time.Time
}

type RateLimiter struct {
	mu sync.Mutex
	cfg RateLimitConfig
	buckets map[string]*bucket
	nextSweep time.Time
}

func NewRateLimiter(cfg RateLimitConfig) (*RateLimiter,error) {
	if err:=cfg.Validate(); err!=nil { return nil,err }
	return &RateLimiter{cfg:cfg,buckets:make(map[string]*bucket)},nil
}

// Allow returns a conservative integer Retry-After in seconds on denial.
// The caller must supply an authenticated, stable registered agent ID.
func (l *RateLimiter) Allow(agent string) (int,error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.allowLocked(agent,time.Now())
}

func (l *RateLimiter) refill(b *bucket,now time.Time) {
	if !now.After(b.last) { return }
	max:=int64(l.cfg.Burst)*tokenCost
	need:=max-b.credit
	rate:=int64(l.cfg.RequestsPerMinute)
	elapsed:=now.Sub(b.last).Nanoseconds()
	// Compare before multiplying so arbitrarily long idle times are safe.
	if elapsed>=(need+rate-1)/rate { b.credit=max } else { b.credit+=elapsed*rate }
	b.last=now
}

func (l *RateLimiter) allowLocked(agent string,now time.Time) (int,error) {
	if !visible(agent,256) { return 1,ErrRateCapacity }
	max:=int64(l.cfg.Burst)*tokenCost
	b:=l.buckets[agent]
	if b==nil {
		if len(l.buckets)>=l.cfg.MaxAgents && !now.Before(l.nextSweep) {
			// Only fully replenished buckets may be evicted. Limit the
			// scan frequency, including when all identities are active.
			for id,current:=range l.buckets {
				l.refill(current,now)
				if current.credit==max { delete(l.buckets,id) }
			}
			l.nextSweep=now.Add(time.Second)
		}
		if len(l.buckets)>=l.cfg.MaxAgents { return 1,ErrRateCapacity }
		b=&bucket{credit:max,last:now}
		l.buckets[agent]=b
	}
	l.refill(b,now)
	if b.credit<tokenCost {
		rate:=int64(l.cfg.RequestsPerMinute)
		ns:=(tokenCost-b.credit+rate-1)/rate
		seconds:=int((ns+int64(time.Second)-1)/int64(time.Second))
		return seconds,ErrRateLimited
	}
	b.credit-=tokenCost
	return 0,nil
}
