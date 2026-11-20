package proxy

import (
	"errors"
	"sync"
	"time"
)

const maxVaultLease = 15*time.Second

var errLeaseExpired = errors.New("vault lease expired or consumed")

// A lease is internal to one admitted request, not a transferable token
// or a persistent session. Ownership of its secret buffer transfers once.
type credentialLease struct {
	mu sync.Mutex
	secret []byte
	deadline time.Time
	used bool
}

func newCredentialLease(secret []byte,credentialExpiry,passportExpiry,now time.Time)(*credentialLease,error) {
	if len(secret)==0 || !now.Before(credentialExpiry) || !now.Before(passportExpiry) {
		clear(secret)
		return nil,errLeaseExpired
	}
	// Use a local monotonic deadline where available. Never extend the
	// operator-declared credential or passport validity window.
	duration:=min(maxVaultLease,credentialExpiry.Sub(now),passportExpiry.Sub(now))
	return &credentialLease{secret:secret,deadline:now.Add(duration)},nil
}

func (l *credentialLease) consume(now time.Time)([]byte,time.Time,error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used || !now.Before(l.deadline) {
		clear(l.secret)
		l.secret=nil
		l.used=true
		return nil,time.Time{},errLeaseExpired
	}
	l.used=true
	secret:=l.secret
	l.secret=nil
	return secret,l.deadline,nil
}

func (l *credentialLease) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	clear(l.secret)
	l.secret=nil
	l.used=true
}
