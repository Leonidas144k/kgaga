package vault

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const maxProviderResponse = 128<<10
const providerTimeout = 10*time.Second
const maxProviderCA = 1<<20

// HashiCorpKV2Config is supplied by a trusted operator, never an agent.
// Mount is one unescaped segment. Path is a slash-separated sequence
// of unescaped segments. Version must be explicitly positive.
type HashiCorpKV2Config struct {
	Origin string
	CAFile string
	Mount string
	Path string
	Field string
	Version uint64
}

type HashiCorpKV2 struct {
	endpoint string
	field string
	version uint64
	tlsConfig *tls.Config
}

func providerSegment(s string) bool {
	if len(s)==0 || len(s)>128 || s=="." || s==".." { return false }
	for _,b:=range []byte(s) {
		if !(b>='a'&&b<='z'||b>='A'&&b<='Z'||b>='0'&&b<='9'||b=='-'||b=='_'||b=='.') { return false }
	}
	return true
}

func providerOrigin(raw string)(*url.URL,error) {
	if len(raw)==0 || len(raw)>512 { return nil,ErrProvider }
	u,err:=url.Parse(raw)
	if err!=nil || u.Scheme!="https" || u.Hostname()=="" || u.User!=nil || u.Opaque!="" ||
		u.Path!="" || u.RawPath!="" || u.RawQuery!="" || u.ForceQuery || u.Fragment!="" || u.String()!=raw {
		return nil,ErrProvider
	}
	host:=u.Hostname()
	expected:=host
	if ip:=net.ParseIP(host); ip!=nil {
		if strings.Contains(host,":") { expected="["+host+"]" }
	} else {
		if len(host)>253 || strings.ToLower(host)!=host { return nil,ErrProvider }
		for _,label:=range strings.Split(host,".") {
			if len(label)==0 || len(label)>63 || label[0]=='-' || label[len(label)-1]=='-' { return nil,ErrProvider }
			for _,b:=range []byte(label) {
				if !(b>='a'&&b<='z'||b>='0'&&b<='9'||b=='-') { return nil,ErrProvider }
			}
		}
	}
	if p:=u.Port(); p!="" {
		n,e:=strconv.Atoi(p)
		if e!=nil || n<1 || n>65535 || strconv.Itoa(n)!=p { return nil,ErrProvider }
		expected+=":"+p
	}
	if u.Host!=expected { return nil,ErrProvider }
	return u,nil
}

// CA material is public but must be trusted operator configuration.
// A supplied private trust bundle replaces, not extends, system roots.
func providerRoots(path string)(*x509.CertPool,error) {
	if path=="" { return nil,nil }
	before,err:=os.Lstat(path)
	if err!=nil || !before.Mode().IsRegular() || before.Size()<1 || before.Size()>maxProviderCA { return nil,ErrProvider }
	f,err:=os.Open(path)
	if err!=nil { return nil,ErrProvider }
	defer f.Close()
	info,err:=f.Stat()
	if err!=nil || !info.Mode().IsRegular() || !os.SameFile(before,info) { return nil,ErrProvider }
	raw,err:=io.ReadAll(io.LimitReader(f,maxProviderCA+1))
	if err!=nil || len(raw)>maxProviderCA { return nil,ErrProvider }
	pool:=x509.NewCertPool()
	if !pool.AppendCertsFromPEM(raw) { return nil,ErrProvider }
	return pool,nil
}

func NewHashiCorpKV2(cfg HashiCorpKV2Config)(*HashiCorpKV2,error) {
	u,err:=providerOrigin(cfg.Origin)
	if err!=nil || !providerSegment(cfg.Mount) || !providerSegment(cfg.Field) ||
		len(cfg.Path)==0 || len(cfg.Path)>1024 || cfg.Version==0 || cfg.Version>9007199254740991 { return nil,ErrProvider }
	for _,segment:=range strings.Split(cfg.Path,"/") {
		if !providerSegment(segment) { return nil,ErrProvider }
	}
	roots,err:=providerRoots(cfg.CAFile)
	if err!=nil { return nil,err }
	u.Path="/v1/"+cfg.Mount+"/data/"+cfg.Path
	u.RawQuery="version="+strconv.FormatUint(cfg.Version,10)
	return &HashiCorpKV2{endpoint:u.String(),field:cfg.Field,version:cfg.Version,
		tlsConfig:&tls.Config{MinVersion:tls.VersionTLS12,ServerName:u.Hostname(),RootCAs:roots}},nil
}

// ReadBearer performs one bounded HTTPS GET. No proxy environment,
// redirects, response compression, write operations, latest-version
// fallback or logging of provider responses/authentication material.
func (h *HashiCorpKV2) ReadBearer(parent context.Context,auth []byte)([]byte,error) {
	if h==nil || h.tlsConfig==nil || parent==nil || ValidateBearer(auth)!=nil { return nil,ErrProvider }
	ctx,cancel:=context.WithTimeout(parent,providerTimeout)
	defer cancel()
	tr:=&http.Transport{
		Proxy:nil,
		DialContext:(&net.Dialer{Timeout:5*time.Second}).DialContext,
		TLSClientConfig:h.tlsConfig.Clone(),
		TLSHandshakeTimeout:5*time.Second,
		ResponseHeaderTimeout:5*time.Second,
		MaxResponseHeaderBytes:32<<10,
		MaxConnsPerHost:1,
		DisableCompression:true,
		DisableKeepAlives:true,
	}
	defer tr.CloseIdleConnections()
	req,err:=http.NewRequestWithContext(ctx,http.MethodGet,h.endpoint,nil)
	if err!=nil { return nil,ErrProvider }
	req.Header.Set("X-Vault-Token",string(auth))
	req.Header.Set("X-Vault-Request","true")
	req.Header.Set("Accept","application/json")
	req.Header.Set("Accept-Encoding","identity")
	defer req.Header.Del("X-Vault-Token")
	resp,err:=tr.RoundTrip(req)
	if err!=nil { return nil,ErrProvider }
	defer resp.Body.Close()
	if resp.StatusCode!=http.StatusOK || len(resp.Header.Values("Content-Encoding"))!=0 ||
		len(resp.Header.Values("Content-Type"))!=1 || resp.ContentLength>maxProviderResponse { return nil,ErrProvider }
	kind,params,err:=mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err!=nil || kind!="application/json" || len(params)>1 { return nil,ErrProvider }
	for k,v:=range params { if k!="charset" || !strings.EqualFold(v,"utf-8") { return nil,ErrProvider } }
	raw,err:=io.ReadAll(io.LimitReader(resp.Body,maxProviderResponse+1))
	defer clear(raw)
	if err!=nil || len(raw)>maxProviderResponse || ctx.Err()!=nil { return nil,ErrProvider }
	token,err:=parseKV2(raw,h.field,h.version)
	if err!=nil || ctx.Err()!=nil { clear(token); return nil,ErrProvider }
	return token,nil
}

// A bounded token walk rejects duplicate and case-aliased JSON keys
// before selection. Unknown provider metadata may be present, but the
// response data and required version metadata must have exact types.
func providerJSON(d *json.Decoder,depth int,budget *int)(any,error) {
	*budget-=1
	if *budget<0 || depth>32 { return nil,ErrProvider }
	t,err:=d.Token()
	if err!=nil { return nil,ErrProvider }
	switch v:=t.(type) {
	case json.Delim:
		switch v {
		case '{':
			obj:=map[string]any{}
			seen:=map[string]bool{}
			for d.More() {
				*budget-=1
				k,err:=d.Token()
				key,ok:=k.(string)
				if *budget<0 || err!=nil || !ok || strings.ContainsRune(key,utf8.RuneError) || seen[strings.ToLower(key)] { return nil,ErrProvider }
				seen[strings.ToLower(key)]=true
				value,err:=providerJSON(d,depth+1,budget)
				if err!=nil { return nil,err }
				obj[key]=value
			}
			end,err:=d.Token()
			if err!=nil || end!=json.Delim('}') { return nil,ErrProvider }
			return obj,nil
		case '[':
			var arr []any
			for d.More() {
				value,err:=providerJSON(d,depth+1,budget)
				if err!=nil { return nil,err }
				arr=append(arr,value)
			}
			end,err:=d.Token()
			if err!=nil || end!=json.Delim(']') { return nil,ErrProvider }
			return arr,nil
		default: return nil,ErrProvider
		}
	case string:
		if strings.ContainsRune(v,utf8.RuneError) { return nil,ErrProvider }
		return v,nil
	case nil,bool,json.Number:
		return v,nil
	default:
		return nil,ErrProvider
	}
}

func parseKV2(raw []byte,field string,version uint64)([]byte,error) {
	if len(raw)==0 || len(raw)>maxProviderResponse || !utf8.Valid(raw) { return nil,ErrProvider }
	d:=json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	budget:=16384
	value,err:=providerJSON(d,0,&budget)
	if err!=nil { return nil,ErrProvider }
	if _,err:=d.Token(); err!=io.EOF { return nil,ErrProvider }
	root,ok:=value.(map[string]any)
	if !ok { return nil,ErrProvider }
	data,ok:=root["data"].(map[string]any)
	if !ok { return nil,ErrProvider }
	metadata,ok:=data["metadata"].(map[string]any)
	if !ok { return nil,ErrProvider }
	v,ok:=metadata["version"].(json.Number)
	if !ok || string(v)!=strconv.FormatUint(version,10) { return nil,ErrProvider }
	destroyed,ok:=metadata["destroyed"].(bool)
	if !ok || destroyed { return nil,ErrProvider }
	deleted,ok:=metadata["deletion_time"].(string)
	if !ok || deleted!="" { return nil,ErrProvider }
	fields,ok:=data["data"].(map[string]any)
	if !ok { return nil,ErrProvider }
	token,ok:=fields[field].(string)
	if !ok { return nil,ErrProvider }
	p:=[]byte(token)
	if ValidateBearer(p)!=nil { clear(p); return nil,ErrProvider }
	return p,nil
}
