package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestAggregateAdmission(t *testing.T) {
	entered:=make(chan struct{})
	release:=make(chan struct{})
	done:=make(chan struct{})
	var calls atomic.Int32
	h,err:=boundAdmission(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if calls.Add(1)==1 { close(entered); <-release }
		w.WriteHeader(204)
	}),1,1,2)
	if err!=nil { t.Fatal(err) }
	go func(){ defer close(done); h.ServeHTTP(httptest.NewRecorder(),httptest.NewRequest("GET","/",nil)) }()
	select { case <-entered: case <-time.After(2*time.Second): close(release); t.Fatal("handler did not enter") }
	w:=httptest.NewRecorder()
	h.ServeHTTP(w,httptest.NewRequest("GET","/",nil))
	close(release)
	<-done
	if w.Code!=503 || w.Header().Get("Retry-After")!="1" { t.Fatal("active request saturation not rejected") }
	w=httptest.NewRecorder()
	h.ServeHTTP(w,httptest.NewRequest("GET","/",nil))
	if w.Code!=204 { t.Fatal("slot not released") }
	w=httptest.NewRecorder()
	h.ServeHTTP(w,httptest.NewRequest("GET","/",nil))
	if w.Code!=429 || w.Header().Get("Retry-After")=="" || calls.Load()!=2 { t.Fatal("aggregate quota not enforced") }
}

func TestLimitedListener(t *testing.T) {
	raw,err:=net.Listen("tcp","127.0.0.1:0")
	if err!=nil { t.Fatal(err) }
	l,err:=LimitListener(raw,1)
	if err!=nil { raw.Close(); t.Fatal(err) }
	defer l.Close()
	client,err:=net.DialTimeout("tcp",raw.Addr().String(),time.Second)
	if err!=nil { t.Fatal(err) }
	defer client.Close()
	c,err:=l.Accept()
	if err!=nil { t.Fatal(err) }
	defer c.Close()
	client2,err:=net.DialTimeout("tcp",raw.Addr().String(),time.Second)
	if err!=nil { t.Fatal(err) }
	defer client2.Close()
	type result struct{c net.Conn; err error}
	next:=make(chan result,1)
	go func(){ c,e:=l.Accept(); next<-result{c,e} }()
	select {
	case r:=<-next: if r.c!=nil { r.c.Close() }; t.Fatal("accepted above connection limit")
	case <-time.After(30*time.Millisecond):
	}
	_ = c.Close()
	_ = c.Close()
	select {
	case r:=<-next: if r.err!=nil { t.Fatal(r.err) }; defer r.c.Close()
	case <-time.After(2*time.Second): t.Fatal("connection slot not released")
	}
	go func(){ c,e:=l.Accept(); next<-result{c,e} }()
	_ = l.Close()
	select {
	case r:=<-next: if r.c!=nil { r.c.Close(); t.Fatal("accepted after close") }; if r.err==nil { t.Fatal("missing close error") }
	case <-time.After(2*time.Second): t.Fatal("blocked accept not released")
	}
}

func TestUpstreamConnectionBound(t *testing.T) {
	tr:=newUpstreamTransport()
	if tr.MaxConnsPerHost!=MaxUpstreamConnections { t.Fatal("missing upstream connection cap") }
}
