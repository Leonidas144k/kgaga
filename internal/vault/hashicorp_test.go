package vault

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const providerAuth = "hvs.synthetic-provider-auth"
const importedToken = "synthetic-downstream-token"
const validKV2 = `{"request_id":"fixture","lease_duration":0,"data":{"data":{"token":"synthetic-downstream-token","other":"not-selected"},"metadata":{"version":7,"destroyed":false,"deletion_time":"","custom_metadata":null}}}`

func TestKV2StrictResponse(t *testing.T) {
	p,err:=parseKV2([]byte(validKV2),"token",7)
	if err!=nil || string(p)!=importedToken { t.Fatal("valid response denied") }
	clear(p)
	for _,raw:=range []string{
		strings.Replace(validKV2,`"version":7`,`"version":8`,1),
		strings.Replace(validKV2,`"version":7`,`"version":7.0`,1),
		strings.Replace(validKV2,`"version":7`,`"version":"7"`,1),
		strings.Replace(validKV2,`"version":7`,`"version":7,"Version":7`,1),
		strings.Replace(validKV2,`"destroyed":false`,`"destroyed":true`,1),
		strings.Replace(validKV2,`"destroyed":false`,`"destroyed":null`,1),
		strings.Replace(validKV2,`"deletion_time":""`,`"deletion_time":"2030-01-01T00:00:00Z"`,1),
		strings.Replace(validKV2,`"deletion_time":""`,`"unknown":""`,1),
		strings.Replace(validKV2,`"token":`,`"token":"duplicate","token":`,1),
		strings.Replace(validKV2,`"token":`,`"\u0074oken":"duplicate","token":`,1),
		strings.Replace(validKV2,`"token":`,`"Token":`,1),
		strings.Replace(validKV2,`"synthetic-downstream-token"`,`"invalid token\r\n"`,1),
		validKV2+" {}",
		strings.Repeat("[",40)+strings.Repeat("]",40),
		strings.Repeat(" ",maxProviderResponse+1),
	} {
		if p,err:=parseKV2([]byte(raw),"token",7); p!=nil || !errors.Is(err,ErrProvider) { t.Fatal("ambiguous or invalid response accepted") }
	}
	if p,err:=parseKV2([]byte(validKV2),"missing",7); p!=nil || err==nil { t.Fatal("missing field accepted") }
}

func TestKV2Configuration(t *testing.T) {
	base:=HashiCorpKV2Config{Origin:"https://vault.example",Mount:"secret",Path:"service/api",Field:"token",Version:7}
	if _,err:=NewHashiCorpKV2(base); err!=nil { t.Fatal(err) }
	for _,mutate:=range []func(*HashiCorpKV2Config){
		func(c *HashiCorpKV2Config){c.Origin="http://127.0.0.1"},
		func(c *HashiCorpKV2Config){c.Origin="https://user@vault.example"},
		func(c *HashiCorpKV2Config){c.Origin="https://vault.example/"},
		func(c *HashiCorpKV2Config){c.Origin="https://vault.example?x=1"},
		func(c *HashiCorpKV2Config){c.Origin="https://vault.example:0443"},
		func(c *HashiCorpKV2Config){c.Mount="../secret"},
		func(c *HashiCorpKV2Config){c.Path="service/../api"},
		func(c *HashiCorpKV2Config){c.Path="service/%2fapi"},
		func(c *HashiCorpKV2Config){c.Path="service//api"},
		func(c *HashiCorpKV2Config){c.Field=""},
		func(c *HashiCorpKV2Config){c.Version=0},
	} {
		bad:=base; mutate(&bad)
		if h,err:=NewHashiCorpKV2(bad); h!=nil || err==nil { t.Fatal("unsafe provider configuration accepted") }
	}
}

func TestKV2ImportLifecycle(t *testing.T) {
	m,_,_,_:=managedFixture(t)
	var calls,mode,redirected atomic.Int32
	other:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){redirected.Add(1); w.WriteHeader(200)}))
	defer other.Close()
	up:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		calls.Add(1)
		if r.TLS==nil || r.Method!="GET" || r.URL.RequestURI()!="/v1/secret/data/service/api?version=7" ||
			r.Header.Get("X-Vault-Token")!=providerAuth || r.Header.Get("Authorization")!="" { t.Error("unexpected provider request") }
		w.Header().Set("Content-Type","application/json")
		switch mode.Load() {
		case 1: w.Header().Set("Location",other.URL); w.WriteHeader(307)
		case 2: w.WriteHeader(403); _,_=w.Write([]byte(providerAuth))
		case 3: _,_=w.Write([]byte(strings.Replace(validKV2,`"version":7`,`"version":8`,1)))
		case 4: _,_=w.Write([]byte(strings.Repeat("x",maxProviderResponse+1)))
		case 5: w.Header().Set("Content-Encoding","gzip"); _,_=w.Write([]byte(validKV2))
		case 6: _,_=w.Write([]byte(strings.Replace(validKV2,importedToken,providerAuth,1)))
		default: _,_=w.Write([]byte(validKV2))
		}
	}))
	defer up.Close()
	ca:=filepath.Join(t.TempDir(),"ca.pem")
	if err:=os.WriteFile(ca,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:up.Certificate().Raw}),0600); err!=nil { t.Fatal(err) }
	cfg:=HashiCorpKV2Config{Origin:up.URL,CAFile:ca,Mount:"secret",Path:"service/api",Field:"token",Version:7}
	source,err:=NewHashiCorpKV2(cfg)
	if err!=nil { t.Fatal(err) }
	auth:=[]byte(providerAuth)
	now:=time.Now().Unix()
	importVersion:=func(v uint64)error{return m.ImportBearer(context.Background(),source,auth,"service",v,now-5,now+600)}
	if err:=importVersion(1); err!=nil { t.Fatal(err) }
	if err:=m.CheckActive("service",1); !errors.Is(err,ErrInactiveVersion) { t.Fatal("import auto-activated") }
	if err:=m.Activate("service",1); err!=nil { t.Fatal(err) }
	p,_,err:=m.GetActiveBearer("service",1)
	if err!=nil || !bytes.Equal(p,[]byte(importedToken)) { t.Fatal("imported token unavailable") }
	clear(p)
	if err:=importVersion(1); !errors.Is(err,ErrRecordExists) || calls.Load()!=1 { t.Fatal("existing slot caused remote fetch or overwrite") }
	for i:=int32(1);i<=6;i++ {
		mode.Store(i)
		if err:=importVersion(2); !errors.Is(err,ErrProvider) { t.Fatal("provider failure did not fail closed") }
		if _,err:=m.Get("service",2); !errors.Is(err,ErrRecordNotFound) { t.Fatal("failed import published record") }
	}
	if redirected.Load()!=0 { t.Fatal("provider redirect followed") }
	if err:=m.CheckActive("service",1); err!=nil { t.Fatal("failed import modified live version") }
	cfg.CAFile=""
	untrusted,err:=NewHashiCorpKV2(cfg); if err!=nil { t.Fatal(err) }
	if p,err:=untrusted.ReadBearer(context.Background(),auth); p!=nil || !errors.Is(err,ErrProvider) { t.Fatal("untrusted peer accepted") }
	ctx,cancel:=context.WithCancel(context.Background()); cancel()
	before:=calls.Load()
	if err:=m.ImportBearer(ctx,source,auth,"service",2,now-5,now+600); !errors.Is(err,ErrProvider) || calls.Load()!=before { t.Fatal("cancelled import dispatched") }
	if err:=m.RevokeVersion("service",1); err!=nil { t.Fatal(err) }
	if p,_,err:=m.GetActiveBearer("service",1); p!=nil || !errors.Is(err,ErrInactiveVersion) { t.Fatal("import bypassed revocation") }
}
