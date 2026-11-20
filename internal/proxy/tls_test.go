package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
)

func TestTransportRestrictions(t *testing.T) {
	for _,tc:=range []struct{target string; opt UpstreamTLSOptions; allow bool}{
		{"http://127.0.0.1:3000",UpstreamTLSOptions{},false},
		{"http://127.0.0.1:3000",UpstreamTLSOptions{AllowLoopbackHTTP:true},true},
		{"http://[::1]:3000",UpstreamTLSOptions{AllowLoopbackHTTP:true},true},
		{"http://localhost:3000",UpstreamTLSOptions{AllowLoopbackHTTP:true},false},
		{"http://192.0.2.1:3000",UpstreamTLSOptions{AllowLoopbackHTTP:true},false},
		{"http://127.0.0.1",UpstreamTLSOptions{AllowLoopbackHTTP:true,CAFile:"unused"},false},
		{"https://example.test",UpstreamTLSOptions{AllowLoopbackHTTP:true},false},
		{"https://example.test",UpstreamTLSOptions{ClientCertFile:"unused"},false},
		{"https://example.test",UpstreamTLSOptions{},true},
	} {
		u,err:=url.Parse(tc.target); if err!=nil { t.Fatal(err) }
		cfg,err:=upstreamTLS(u,tc.opt)
		if (err==nil)!=tc.allow { t.Fatalf("%s allowed=%v want=%v: %v",tc.target,err==nil,tc.allow,err) }
		if cfg!=nil && (cfg.InsecureSkipVerify || cfg.MinVersion!=tls.VersionTLS12 || cfg.ServerName!=u.Hostname()) { t.Fatal("unsafe TLS config") }
	}
	for _,address:=range []string{":8080","0.0.0.0:8080","localhost:8080","[::]:8080"} {
		if _,err:=ListenerTLS(address,"",""); err==nil { t.Fatalf("accepted plaintext listener %s",address) }
	}
	if _,err:=ListenerTLS("127.0.0.1:8080","",""); err!=nil { t.Fatal(err) }
	if _,err:=ListenerTLS("127.0.0.1:8080","only-cert",""); err==nil { t.Fatal("accepted incomplete TLS pair") }
}

func TestVerifiedUpstreamTLS(t *testing.T) {
	dir:=t.TempDir()
	// Generate an isolated root and distinct server/client leaves.
	type certKey struct { cert *x509.Certificate; key ed25519.PrivateKey; certFile,keyFile string }
	makeCert:=func(name string,serial int64,parent *certKey,usage x509.ExtKeyUsage) certKey {
		t.Helper()
		pub,key,err:=ed25519.GenerateKey(rand.Reader); if err!=nil { t.Fatal(err) }
		tmpl:=&x509.Certificate{SerialNumber:big.NewInt(serial),Subject:pkix.Name{CommonName:name},NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),BasicConstraintsValid:true,KeyUsage:x509.KeyUsageDigitalSignature}
		issuer,issuerKey:=tmpl,key
		if parent==nil { tmpl.IsCA=true; tmpl.KeyUsage|=x509.KeyUsageCertSign } else {
			issuer,issuerKey=parent.cert,parent.key
			tmpl.ExtKeyUsage=[]x509.ExtKeyUsage{usage}
			if usage==x509.ExtKeyUsageServerAuth { tmpl.IPAddresses=[]net.IP{net.ParseIP("127.0.0.1")} }
		}
		der,err:=x509.CreateCertificate(rand.Reader,tmpl,issuer,pub,issuerKey); if err!=nil { t.Fatal(err) }
		cert,err:=x509.ParseCertificate(der); if err!=nil { t.Fatal(err) }
		pk,err:=x509.MarshalPKCS8PrivateKey(key); if err!=nil { t.Fatal(err) }
		cf,kf:=filepath.Join(dir,name+".pem"),filepath.Join(dir,name+".key")
		if err:=os.WriteFile(cf,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),0600); err!=nil { t.Fatal(err) }
		if err:=os.WriteFile(kf,pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:pk}),0600); err!=nil { t.Fatal(err) }
		return certKey{cert,key,cf,kf}
	}
	ca:=makeCert("ca",1,nil,0)
	server:=makeCert("server",2,&ca,x509.ExtKeyUsageServerAuth)
	client:=makeCert("client",3,&ca,x509.ExtKeyUsageClientAuth)
	wrong:=makeCert("wrong",4,nil,0)
	if _,err:=ListenerTLS("0.0.0.0:8080",server.certFile,server.keyFile); err!=nil { t.Fatal(err) }
	serverTLS,err:=loadPair(server.certFile,server.keyFile); if err!=nil { t.Fatal(err) }
	roots:=x509.NewCertPool(); roots.AddCert(ca.cert)
	var calls atomic.Int32
	up:=httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		calls.Add(1)
		if r.TLS==nil || len(r.TLS.VerifiedChains)==0 || r.TLS.PeerCertificates[0].Subject.CommonName!="client" { t.Error("missing verified client certificate") }
		if r.Header.Get("X-Kgaga-Verified-Agent")!="agent" { t.Error("missing verified identity") }
		w.WriteHeader(204)
	}))
	up.TLS=&tls.Config{MinVersion:tls.VersionTLS12,Certificates:[]tls.Certificate{serverTLS},ClientAuth:tls.RequireAndVerifyClientCert,ClientCAs:roots}
	up.StartTLS(); defer up.Close()
	issuerPriv,issuerPub:=filepath.Join(dir,"issuer.key"),filepath.Join(dir,"issuer.pub")
	if err:=passport.GenerateKeyPair(issuerPriv,issuerPub); err!=nil { t.Fatal(err) }
	pub,err:=passport.LoadPublicKey(issuerPub); if err!=nil { t.Fatal(err) }
	token,err:=passport.Mint(issuerPriv,"agent","owner",[]string{"read"},time.Minute); if err!=nil { t.Fatal(err) }
	cfg:=&policy.Config{Version:"2",Rules:[]policy.Rule{{PathPrefix:"/api",AllowedMethods:[]string{"GET"},AllowedScopes:[]string{"read"}}}}
	for _,tc:=range []struct{name,target string; options UpstreamTLSOptions; want int}{
		{"verified mTLS",up.URL,UpstreamTLSOptions{CAFile:ca.certFile,ClientCertFile:client.certFile,ClientKeyFile:client.keyFile},204},
		{"missing client cert",up.URL,UpstreamTLSOptions{CAFile:ca.certFile},502},
		{"untrusted server",up.URL,UpstreamTLSOptions{CAFile:wrong.certFile,ClientCertFile:client.certFile,ClientKeyFile:client.keyFile},502},
		{"wrong hostname","https://localhost:"+strconv.Itoa(up.Listener.Addr().(*net.TCPAddr).Port),UpstreamTLSOptions{CAFile:ca.certFile,ClientCertFile:client.certFile,ClientKeyFile:client.keyFile},502},
	} {
		t.Run(tc.name,func(t *testing.T){
			h,err:=NewHandler(tc.target,pub,cfg,tc.options); if err!=nil { t.Fatal(err) }
			r:=httptest.NewRequest("GET","/api",nil); r.Header.Set("X-Agent-Passport",token)
			w:=httptest.NewRecorder(); h.ServeHTTP(w,r)
			if w.Code!=tc.want { t.Fatalf("status %d want %d",w.Code,tc.want) }
		})
	}
	if calls.Load()!=1 { t.Fatalf("unexpected upstream calls: %d",calls.Load()) }
	if _,err:=loadRoots(server.certFile); err==nil { t.Fatal("accepted non-CA certificate as root") }
	if _,err:=loadPair(server.certFile,client.keyFile); err==nil { t.Fatal("accepted mismatched key") }
}
