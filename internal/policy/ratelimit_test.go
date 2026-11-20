package policy

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTokenBucket(t *testing.T) {
	l,err:=NewRateLimiter(RateLimitConfig{RequestsPerMinute:60,Burst:2,MaxAgents:2})
	if err!=nil { t.Fatal(err) }
	now:=time.Unix(1000,0)
	check:=func(id string,at time.Time,want error,retry int) {
		t.Helper()
		got,e:=l.allowLocked(id,at)
		if !errors.Is(e,want) || got!=retry { t.Fatalf("agent %s: retry=%d err=%v want %d %v",id,got,e,retry,want) }
	}
	check("a",now,nil,0)
	check("a",now,nil,0)
	check("a",now,ErrRateLimited,1)
	check("b",now,nil,0)
	check("c",now,ErrRateCapacity,1)
	check("a",now.Add(500*time.Millisecond),ErrRateLimited,1)
	check("a",now.Add(time.Second),nil,0)
	check("a",now.Add(time.Second),ErrRateLimited,1)
	check("a",now,ErrRateLimited,1) // backwards time cannot mint credit
	// b has completely refilled, so it can safely be evicted.
	check("c",now.Add(2*time.Second),nil,0)
	if len(l.buckets)>2 { t.Fatal("capacity exceeded") }
	check("a",now.Add(2*time.Second),nil,0)
	check("a",now.Add(2*time.Second),ErrRateLimited,1)
}

func TestRateLimiterConcurrent(t *testing.T) {
	l,err:=NewRateLimiter(RateLimitConfig{RequestsPerMinute:1,Burst:16,MaxAgents:1})
	if err!=nil { t.Fatal(err) }
	var wg sync.WaitGroup
	var passed atomic.Int32
	for i:=0;i<100;i++ {
		wg.Add(1)
		go func(){ defer wg.Done(); if _,err:=l.Allow("a"); err==nil { passed.Add(1) } }()
	}
	wg.Wait()
	if got:=passed.Load(); got!=16 { t.Fatalf("accepted %d want 16",got) }
}

func TestRateRetryAndLongIdle(t *testing.T) {
	l,err:=NewRateLimiter(RateLimitConfig{RequestsPerMinute:1,Burst:1,MaxAgents:1})
	if err!=nil { t.Fatal(err) }
	now:=time.Unix(1000,0)
	if _,err:=l.allowLocked("a",now); err!=nil { t.Fatal(err) }
	if retry,err:=l.allowLocked("a",now.Add(time.Second)); retry!=59 || !errors.Is(err,ErrRateLimited) { t.Fatalf("retry %d %v",retry,err) }
	if _,err:=l.allowLocked("a",now.Add(100*365*24*time.Hour)); err!=nil { t.Fatal(err) }
	if _,err:=NewRateLimiter(RateLimitConfig{}); err==nil { t.Fatal("invalid limits accepted") }
}
