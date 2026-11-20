package proxy

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/Leonidas144k/kgaga/internal/policy"
)

const MaxOpenConnections = 128
const MaxActiveRequests = 64
const MaxUpstreamConnections = 32

// The aggregate limiter covers all routes, including public JWKS and
// requests without a passport, before expensive work. No request queue.
func boundAdmission(next http.Handler,active,rpm,burst int) (http.Handler,error) {
	if active<1 || active>MaxActiveRequests { return nil,errors.New("invalid active request limit") }
	limiter,err:=policy.NewRateLimiter(policy.RateLimitConfig{RequestsPerMinute:rpm,Burst:burst,MaxAgents:1})
	if err!=nil { return nil,err }
	slots:=make(chan struct{},active)
	return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		select {
		case slots<-struct{}{}:
			defer func(){ <-slots }()
		default:
			w.Header().Set("Retry-After","1")
			w.Header().Set("Cache-Control","no-store")
			http.Error(w,"gateway busy",http.StatusServiceUnavailable)
			return
		}
		if retry,err:=limiter.Allow("gateway"); err!=nil {
			w.Header().Set("Retry-After",strconv.Itoa(retry))
			w.Header().Set("Cache-Control","no-store")
			http.Error(w,"gateway admission rate limited",http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w,r)
	}),nil
}

// LimitListener bounds accepted TCP connections, including incomplete
// headers and idle keepalive connections. excess connections remain in
// the OS backlog; Close unblocks any waiting Accept.
func LimitListener(inner net.Listener,max int) (net.Listener,error) {
	if inner==nil || max<1 || max>MaxOpenConnections { return nil,errors.New("invalid listener limit") }
	return &limitedListener{Listener:inner,slots:make(chan struct{},max),done:make(chan struct{})},nil
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
	done chan struct{}
	once sync.Once
}

func (l *limitedListener) Accept() (net.Conn,error) {
	select {
	case l.slots<-struct{}{}:
	case <-l.done: return nil,net.ErrClosed
	}
	c,err:=l.Listener.Accept()
	if err!=nil { <-l.slots; return nil,err }
	return &limitedConn{Conn:c,release:func(){ <-l.slots }},nil
}

func (l *limitedListener) Close() error {
	l.once.Do(func(){ close(l.done) })
	return l.Listener.Close()
}

type limitedConn struct {
	net.Conn
	once sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err:=c.Conn.Close()
	c.once.Do(c.release)
	return err
}
