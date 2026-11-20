package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
)

const maxTLSFile = 1<<20

// Paths are operator-controlled. Trust is snapshotted at startup.
// No insecure certificate verification mode is exposed.
type UpstreamTLSOptions struct {
	CAFile string
	ClientCertFile string
	ClientKeyFile string
	AllowLoopbackHTTP bool
}

func literalLoopback(host string) bool {
	ip:=net.ParseIP(host)
	return ip!=nil && ip.IsLoopback()
}

func readTLSFile(path string)([]byte,error) {
	info,err:=os.Stat(path)
	if err!=nil { return nil,err }
	if !info.Mode().IsRegular() || info.Size()<1 || info.Size()>maxTLSFile { return nil,errors.New("invalid TLS file size or type") }
	f,err:=os.Open(path)
	if err!=nil { return nil,err }
	defer f.Close()
	info,err=f.Stat()
	if err!=nil { return nil,err }
	if !info.Mode().IsRegular() { return nil,errors.New("TLS file must be regular") }
	raw,err:=io.ReadAll(io.LimitReader(f,maxTLSFile+1))
	if err!=nil { return nil,err }
	if len(raw)==0 || len(raw)>maxTLSFile { return nil,errors.New("invalid TLS file size") }
	return raw,nil
}

func loadPair(certFile,keyFile string)(tls.Certificate,error) {
	cert,err:=readTLSFile(certFile)
	if err!=nil { return tls.Certificate{},err }
	key,err:=readTLSFile(keyFile)
	if err!=nil { return tls.Certificate{},err }
	pair,err:=tls.X509KeyPair(cert,key)
	if err!=nil { return tls.Certificate{},errors.New("invalid TLS certificate/key pair") }
	return pair,nil
}

func loadRoots(path string)(*x509.CertPool,error) {
	raw,err:=readTLSFile(path)
	if err!=nil { return nil,err }
	pool:=x509.NewCertPool()
	count:=0
	for len(bytes.TrimSpace(raw))>0 {
		raw=bytes.TrimSpace(raw)
		if !bytes.HasPrefix(raw,[]byte("-----BEGIN CERTIFICATE-----")) { return nil,errors.New("invalid CA PEM bundle") }
		block,rest:=pem.Decode(raw)
		if block==nil || block.Type!="CERTIFICATE" || len(block.Headers)!=0 { return nil,errors.New("invalid CA PEM certificate") }
		// pem.Decode may skip a malformed leading block; reject that case.
		end:=bytes.Index(raw,[]byte("-----END CERTIFICATE-----"))
		if end<0 || bytes.Contains(raw[len("-----BEGIN CERTIFICATE-----"):end],[]byte("-----BEGIN")) { return nil,errors.New("invalid CA PEM certificate") }
		cert,err:=x509.ParseCertificate(block.Bytes)
		if err!=nil || !cert.IsCA || !cert.BasicConstraintsValid { return nil,errors.New("CA bundle requires valid CA certificates") }
		pool.AddCert(cert)
		count++
		if count>128 { return nil,errors.New("too many CA certificates") }
		raw=rest
	}
	if count==0 { return nil,errors.New("empty CA bundle") }
	return pool,nil
}

func upstreamTLS(target *url.URL,options ...UpstreamTLSOptions)(*tls.Config,error) {
	if len(options)>1 { return nil,errors.New("multiple upstream TLS options") }
	var o UpstreamTLSOptions
	if len(options)==1 { o=options[0] }
	if target.Scheme=="http" {
		if !o.AllowLoopbackHTTP || !literalLoopback(target.Hostname()) { return nil,errors.New("plaintext upstream requires explicit loopback HTTP opt-in and literal loopback IP") }
		if o.CAFile!="" || o.ClientCertFile!="" || o.ClientKeyFile!="" { return nil,errors.New("TLS options cannot be used with plaintext HTTP") }
		return nil,nil
	}
	if target.Scheme!="https" { return nil,errors.New("unsupported upstream scheme") }
	if o.AllowLoopbackHTTP { return nil,errors.New("loopback HTTP opt-in is only valid for HTTP targets") }
	cfg:=&tls.Config{MinVersion:tls.VersionTLS12,ServerName:target.Hostname()}
	if o.CAFile!="" {
		roots,err:=loadRoots(o.CAFile)
		if err!=nil { return nil,err }
		cfg.RootCAs=roots
	}
	if (o.ClientCertFile=="")!=(o.ClientKeyFile=="") { return nil,errors.New("upstream client certificate and key must be supplied together") }
	if o.ClientCertFile!="" {
		cert,err:=loadPair(o.ClientCertFile,o.ClientKeyFile)
		if err!=nil { return nil,err }
		cfg.Certificates=[]tls.Certificate{cert}
	}
	return cfg,nil
}

// ListenerTLS enforces encrypted transport on any non-loopback bind.
// Plaintext on a literal loopback IP is for isolated development only.
func ListenerTLS(address,certFile,keyFile string)(*tls.Config,error) {
	host,_,err:=net.SplitHostPort(address)
	if err!=nil { return nil,errors.New("invalid listen address") }
	if (certFile=="")!=(keyFile=="") { return nil,errors.New("listener certificate and key must be supplied together") }
	if certFile=="" {
		if !literalLoopback(host) { return nil,errors.New("non-loopback listener requires TLS certificate and key") }
		return nil,nil
	}
	pair,err:=loadPair(certFile,keyFile)
	if err!=nil { return nil,err }
	return &tls.Config{MinVersion:tls.VersionTLS12,Certificates:[]tls.Certificate{pair}},nil
}
