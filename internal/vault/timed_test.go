package vault

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestTimedBearerWindow(t *testing.T) {
	token:=[]byte("synthetic-credential-012345")
	start:=int64(1800000000)
	raw,err:=encodeTimedBearer(token,start,start+60)
	if err!=nil { t.Fatal(err) }
	for _,tc:=range []struct{now int64;valid bool}{{start-1,false},{start,true},{start+59,true},{start+60,false},{start+61,false}} {
		p,expiry,err:=decodeTimedBearer(raw,time.Unix(tc.now,0))
		if tc.valid { if err!=nil || !bytes.Equal(p,token) || expiry.Unix()!=start+60 { t.Fatal("valid window rejected") } } else if p!=nil || !errors.Is(err,ErrCredentialValidity) { t.Fatal("invalid window accepted") }
	}
	for _,w:=range [][2]int64{{0,1},{-1,1},{start,start},{start,start-1},{start,start+3601}} {
		if _,err:=encodeTimedBearer(token,w[0],w[1]); err==nil { t.Fatal("invalid window encoded") }
	}
	if _,err:=encodeTimedBearer(token,start,start+3600); err!=nil { t.Fatal(err) }
	for i:=0;i<timedHeader+16;i++ { if p,_,err:=decodeTimedBearer(raw[:i],time.Unix(start,0)); err==nil || p!=nil { t.Fatal("truncated record accepted") } }
	if p,_,err:=decodeTimedBearer(token,time.Unix(start,0)); err==nil || p!=nil { t.Fatal("untimed token accepted") }
}

func TestTimedBearerPersistence(t *testing.T) {
	m,s,id,keyPath:=managedFixture(t)
	now:=time.Now().Unix()
	token:=[]byte("synthetic-credential-012345")
	if err:=m.PutBearer("timed",1,token,now-5,now+600); err!=nil { t.Fatal(err) }
	if err:=m.PutBearer("timed",2,token,now+600,now+1200); err!=nil { t.Fatal(err) }
	if err:=m.PutBearer("timed",3,token,now-100,now-10); !errors.Is(err,ErrCredentialValidity) { t.Fatal("expired provisioning accepted") }
	// Construct an expired authenticated fixture without waiting for a clock.
	raw,err:=encodeTimedBearer(token,now-100,now-10)
	if err!=nil { t.Fatal(err) }
	if err:=m.Put("timed",3,raw); err!=nil { t.Fatal(err) }
	if err:=m.Put("timed",4,token); err!=nil { t.Fatal(err) }
	reopened,err:=Open(s.dir,s.id); if err!=nil { t.Fatal(err) }
	n,err:=reopened.OpenManaged(keyPath,id); if err!=nil { t.Fatal(err) }
	p,expiry,err:=n.GetBearer("timed",1)
	if err!=nil || !bytes.Equal(p,token) || expiry.Unix()!=now+600 { t.Fatal("reopen lost validity metadata") }
	for _,version:=range []uint64{2,3,4} {
		if p,_,err:=n.GetBearer("timed",version); err==nil || p!=nil { t.Fatal("invalid record unlocked") }
	}
}
