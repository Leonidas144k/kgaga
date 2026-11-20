package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Leonidas144k/kgaga/internal/mcp"
	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
)

const maxResponseBytes = 1<<20
const upstreamTimeout = 30*time.Second

var errSecret = errors.New("recognized secret pattern")

// The preview only forwards selected headers and bounded text/JSON. It
// deliberately does not act as a transparent HTTP reverse proxy.
func newUpstreamTransport() *http.Transport {
	return &http.Transport{
		DialContext: (&net.Dialer{Timeout:5*time.Second,KeepAlive:30*time.Second}).DialContext,
		TLSHandshakeTimeout:5*time.Second,
		ResponseHeaderTimeout:10*time.Second,
		IdleConnTimeout:30*time.Second,
		MaxIdleConns:32,MaxIdleConnsPerHost:8,
		MaxResponseHeaderBytes:32<<10,
		DisableCompression:true,
		ForceAttemptHTTP2:true,
	}
}

func contentKind(header http.Header,required bool) (string,error) {
	values:=header.Values("Content-Type")
	if len(values)==0 && !required { return "",nil }
	if len(values)!=1 { return "",errors.New("ambiguous or missing content type") }
	media,params,err:=mime.ParseMediaType(values[0])
	if err!=nil || (media!="application/json" && media!="text/plain") { return "",errors.New("unsupported content type") }
	for k,v:=range params {
		if k!="charset" || !strings.EqualFold(v,"utf-8") { return "",errors.New("unsupported content type parameter") }
	}
	return media,nil
}

func checkMetadata(values []string,inspectSecrets bool) error {
	for _,value:=range values {
		if inspectSecrets && policy.InspectText(value) { return errSecret }
	}
	return nil
}

func inspectRequest(r *http.Request,body []byte,inspectSecrets bool) error {
	if len(r.Header.Values("Content-Encoding"))>0 || len(r.Trailer)>0 { return errors.New("unsupported request encoding or trailer") }
	kind,err:=contentKind(r.Header,len(body)>0)
	if err!=nil { return err }
	if inspectSecrets {
		q,err:=url.ParseQuery(r.URL.RawQuery)
		if err!=nil { return err }
		if policy.InspectText(r.URL.Path) || policy.InspectText(r.URL.RawQuery) { return errSecret }
		for key,values:=range q {
			if policy.InspectText(key) { return errSecret }
			if err:=checkMetadata(values,true); err!=nil { return err }
		}
		for _,name:=range []string{"Content-Type","MCP-Protocol-Version","Mcp-Method","Mcp-Session-Id"} {
			if err:=checkMetadata(r.Header.Values(name),true); err!=nil { return err }
		}
	}
	if len(body)>0 {
		if err:=policy.InspectPayload(body,kind=="application/json",inspectSecrets); err!=nil {
			if err.Error()==errSecret.Error() { return errSecret }
			return err
		}
	}
	return nil
}

type inspectedResponse struct {
	status int
	headers http.Header
	body []byte
}

// exchange never follows redirects, forwards 1xx messages or streams
// uninspected bytes. TLS peer validation is Go's normal verification.
func exchange(r *http.Request,target *url.URL,transport *http.Transport,claims *passport.AgentClaims,body []byte,info *mcp.InspectionResult,inspectSecrets bool) (*inspectedResponse,error) {
	ctx,cancel:=context.WithTimeout(r.Context(),upstreamTimeout)
	defer cancel()
	u:=*target
	u.Path=r.URL.Path
	u.RawQuery=r.URL.RawQuery
	u.ForceQuery=r.URL.ForceQuery
	out,err:=http.NewRequestWithContext(ctx,r.Method,u.String(),bytes.NewReader(body))
	if err!=nil { return nil,err }
	// Do not propagate client auth, cookies, routing metadata, Range,
	// compression or arbitrary unsigned headers.
	if v:=r.Header.Get("Content-Type"); v!="" { out.Header.Set("Content-Type",v) }
	out.Header.Set("User-Agent","Kgaga-development-preview")
	out.Header.Set("Accept","application/json, text/plain")
	if info!=nil {
		out.Header.Set("Accept","application/json")
		for _,name:=range []string{"MCP-Protocol-Version","Mcp-Method","Mcp-Session-Id"} {
			if v:=r.Header.Get(name); v!="" { out.Header.Set(name,v) }
		}
	}
	out.Header.Set("X-Pangolin-Verified-Agent",claims.AgentID)
	out.Header.Set("X-Pangolin-Agent-Owner",claims.Owner)
	out.Header.Set("X-Kgaga-Verified-Agent",claims.AgentID)
	out.Header.Set("X-Kgaga-Agent-Owner",claims.Owner)
	// Prevent automatic body replay via GetBody; the transport may still
	// retry eligible zero-body idempotent requests under its own rules.
	out.GetBody=nil
	resp,err:=transport.RoundTrip(out)
	if err!=nil { return nil,err }
	defer resp.Body.Close()
	if resp.StatusCode<200 || resp.StatusCode>599 || (resp.StatusCode>=300 && resp.StatusCode<400) || resp.StatusCode==206 {
		return nil,errors.New("unsupported upstream status")
	}
	if len(resp.Header.Values("Content-Encoding"))>0 || len(resp.Trailer)>0 ||
		(resp.ContentLength>maxResponseBytes && r.Method!="HEAD") || resp.Uncompressed {
		return nil,errors.New("unsupported upstream encoding, trailer or size")
	}
	data,err:=io.ReadAll(io.LimitReader(resp.Body,maxResponseBytes+1))
	if err!=nil || len(data)>maxResponseBytes || len(resp.Trailer)>0 { return nil,errors.New("invalid upstream response body") }
	kind,err:=contentKind(resp.Header,len(data)>0)
	if err!=nil { return nil,err }
	if len(data)>0 {
		if err:=policy.InspectPayload(data,kind=="application/json",inspectSecrets); err!=nil { return nil,err }
	}
	if info!=nil {
		if info.Notification {
			if len(data)!=0 || (resp.StatusCode!=202 && resp.StatusCode!=204) { return nil,errors.New("invalid MCP notification response") }
		} else if resp.StatusCode!=200 || kind!="application/json" || mcp.ValidateResponse(data,info.ID)!=nil {
			return nil,errors.New("invalid MCP response")
		}
	}
	headers:=make(http.Header)
	// Only explicitly permitted response metadata is released, with a
	// fixed cache policy. All cookies, locations and other headers vanish.
	if v:=resp.Header.Get("Content-Type"); v!="" {
		if err:=checkMetadata([]string{v},inspectSecrets); err!=nil { return nil,err }
		headers.Set("Content-Type",v)
	}
	if info!=nil {
		for _,name:=range []string{"Mcp-Session-Id","MCP-Protocol-Version"} {
			values:=resp.Header.Values(name)
			if len(values)>1 { return nil,errors.New("ambiguous MCP response header") }
			if err:=checkMetadata(values,inspectSecrets); err!=nil { return nil,err }
			if len(values)==1 { headers.Set(name,values[0]) }
		}
	}
	headers.Set("Cache-Control","no-store")
	headers.Set("X-Content-Type-Options","nosniff")
	if resp.StatusCode!=204 && resp.StatusCode!=205 && r.Method!="HEAD" {
		headers.Set("Content-Length",strconv.Itoa(len(data)))
	}
	return &inspectedResponse{status:resp.StatusCode,headers:headers,body:data},nil
}
