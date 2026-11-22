package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Leonidas144k/kgaga/internal/passport"
)

func TestCredentialLeaseBounds(t *testing.T) {
	now:=time.Now()
	for _,tc:=range []struct{credential,passport,want time.Duration}{{time.Minute,time.Minute,15*time.Second},{3*time.Second,time.Minute,3*time.Second},{time.Minute,2*time.Second,2*time.Second}} {
		l,err:=newCredentialLease([]byte("synthetic-token"),now.Add(tc.credential),now.Add(tc.passport),now)
		if err!=nil { t.Fatal(err) }
		p,deadline,err:=l.consume(now)
		if err!=nil || !bytes.Equal(p,[]byte("synthetic-token")) || deadline.Sub(now)!=tc.want { t.Fatal("incorrect lease") }
		if p,_,err:=l.consume(now); p!=nil || !errors.Is(err,errLeaseExpired) { t.Fatal("lease reused") }
		clear(p); l.close()
	}
	for _,exp:=range []time.Time{now,now.Add(-time.Second)} {
		if l,err:=newCredentialLease([]byte("synthetic-token"),exp,now.Add(time.Minute),now); l!=nil || err==nil { t.Fatal("expired credential leased") }
	}
	secret:=[]byte("synthetic-token")
	l,err:=newCredentialLease(secret,now.Add(time.Second),now.Add(time.Minute),now); if err!=nil { t.Fatal(err) }
	if p,_,err:=l.consume(now.Add(time.Second)); p!=nil || !errors.Is(err,errLeaseExpired) || !bytes.Equal(secret,make([]byte,len(secret))) { t.Fatal("expired lease returned secret") }
	l,err=newCredentialLease([]byte("synthetic-token"),now.Add(time.Minute),now.Add(time.Minute),now); if err!=nil { t.Fatal(err) }
	l.close()
	if p,_,err:=l.consume(now); p!=nil || err==nil { t.Fatal("closed lease reused") }
}

func TestCredentialLeaseConcurrent(t *testing.T) {
	now:=time.Now()
	l,err:=newCredentialLease([]byte("synthetic-token"),now.Add(time.Minute),now.Add(time.Minute),now); if err!=nil { t.Fatal(err) }
	var wg sync.WaitGroup
	var accepted atomic.Int32
	for i:=0;i<16;i++ {
		wg.Add(1)
		go func(){ defer wg.Done(); p,_,err:=l.consume(now); if err==nil { accepted.Add(1); clear(p) } else if !errors.Is(err,errLeaseExpired) { t.Error(err) } }()
	}
	wg.Wait()
	if accepted.Load()!=1 { t.Fatal("lease consumed more than once") }
}

// This tests the actual exchange deadline independently of disk timing.
func TestVaultExchangeDeadline(t *testing.T) {
	var calls atomic.Int32
	entered:=make(chan struct{},1)
	up:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		calls.Add(1)
		entered<-struct{}{}
		<-r.Context().Done()
	}))
	defer up.Close()
	target,err:=url.Parse(up.URL); if err!=nil { t.Fatal(err) }
	tr:=newUpstreamTransport()
	tr.TLSClientConfig=up.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	tr.TLSClientConfig.MinVersion=tls.VersionTLS12
	defer tr.CloseIdleConnections()
	r:=httptest.NewRequest("GET","/api",nil)
	claims:=&passport.AgentClaims{AgentID:"agent",Owner:"owner"}
	secret:=[]byte("synthetic-token")
	if _,err:=exchange(r,target,tr,claims,nil,nil,true,secret,time.Now().Add(-time.Second)); !errors.Is(err,errLeaseExpired) || calls.Load()!=0 { t.Fatal("expired exchange dispatched") }
	parent,cancel:=context.WithTimeout(context.Background(),5*time.Second)
	defer cancel()
	result:=make(chan error,1)
	go func(){ _,err:=exchange(r.WithContext(parent),target,tr,claims,nil,nil,true,secret,time.Now().Add(time.Second)); result<-err }()
	select {
	case <-entered:
	case err:=<-result: t.Fatalf("exchange did not dispatch: %v",err)
	case <-parent.Done(): t.Fatal("exchange did not start")
	}
	select {
	case err:=<-result: if !errors.Is(err,context.DeadlineExceeded) { t.Fatalf("expected deadline: %v",err) }
	case <-parent.Done(): t.Fatal("lease deadline not enforced")
	}
}
