package proxy

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"strconv"
	"time"

	"github.com/Leonidas144k/kgaga/internal/audit"
	"github.com/Leonidas144k/kgaga/internal/mcp"
	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
	"github.com/Leonidas144k/kgaga/internal/revocation"
	"github.com/Leonidas144k/kgaga/internal/vault"
	"github.com/Leonidas144k/kgaga/internal/registry"
	"github.com/Leonidas144k/kgaga/internal/keyring"
	"github.com/Leonidas144k/kgaga/internal/delegation"
)

type AuditEvent struct {
	Timestamp string   `json:"ts"`
	AgentID   string   `json:"agent_id"`
	Owner     string   `json:"owner"`
	PassportID string  `json:"passport_id,omitempty"`
	Method    string   `json:"method"`
	Path      string   `json:"path"`
	Decision  string   `json:"decision"`
	Reason    string   `json:"reason,omitempty"`
	Redacted  bool     `json:"secrets_redacted"`
	Scopes    []string `json:"scopes"`
}

func emitAudit(ev AuditEvent) {
	ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(ev)
	log.Println(string(b))
}

const maxRequestBytes = 1 << 20

// NewHandler retains the legacy verifier for explicit internal compatibility.
func NewHandler(targetURL string, pubKey ed25519.PublicKey, cfg *policy.Config, options ...UpstreamTLSOptions) (http.Handler, error) {
	return newHandler(targetURL, pubKey, cfg, "", nil, nil, nil, nil,nil, options...)
}

// NewHandlerForAudience enforces v2 passports without a legacy fallback.
func NewHandlerForAudience(targetURL string, trust *keyring.Store, cfg *policy.Config, audience string, store *revocation.Store, reg *registry.Store, replay *revocation.Store, options ...UpstreamTLSOptions) (http.Handler, error) {
	return newAudienceHandler(targetURL,trust,cfg,audience,store,reg,replay,nil,options...)
}

// NewHandlerWithVault requires the additional policy for every protected
// request. A nil broker cannot accidentally enable plain gateway mode.
func NewHandlerWithVault(targetURL string, trust *keyring.Store, cfg *policy.Config, audience string, store *revocation.Store, reg *registry.Store, replay *revocation.Store, broker *VaultGateway, options ...UpstreamTLSOptions) (http.Handler,error) {
	if broker==nil { return nil,errors.New("vault configuration required") }
	return newAudienceHandler(targetURL,trust,cfg,audience,store,reg,replay,broker,options...)
}

func newAudienceHandler(targetURL string, trust *keyring.Store, cfg *policy.Config, audience string, store *revocation.Store, reg *registry.Store, replay *revocation.Store, broker *VaultGateway, options ...UpstreamTLSOptions) (http.Handler,error) {
	if err := passport.ValidateAudience(audience); err != nil {
		return nil, err
	}
	if err := store.Ready(); err != nil { return nil, err }
	if err:=reg.Ready(); err!=nil { return nil,err }
	if err:=trust.Ready(); err!=nil { return nil,err }
	if err:=replay.Ready(); err!=nil { return nil,err }
	if store.SameDirectory(replay) { return nil,errors.New("replay and revocation stores must be separate") }
	return newHandler(targetURL, nil, cfg, audience, store, reg, trust, replay,broker,options...)
}

func newHandler(targetURL string, pubKey ed25519.PublicKey, cfg *policy.Config, audience string, store *revocation.Store, reg *registry.Store, trust *keyring.Store, replay *revocation.Store, broker *VaultGateway, options ...UpstreamTLSOptions) (http.Handler, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	if (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" || target.User != nil || target.Fragment != "" {
		return nil, errors.New("upstream must be an HTTP(S) URL with a host and no userinfo or fragment")
	}
	if (target.Path!="" && target.Path!="/") || target.RawPath!="" || target.RawQuery!="" || target.ForceQuery || target.Opaque!="" { return nil,errors.New("upstream must be an origin URL without a base path or query") }
	tlsConfig,err:=upstreamTLS(target,options...)
	if err!=nil { return nil,err }
	cfg,err=cfg.Snapshot()
	if err!=nil { return nil,err }
	if broker!=nil {
		if audience=="" || target.Scheme!="https" || tlsConfig==nil || !cfg.RedactSecrets { return nil,errors.New("vault requires authenticated HTTPS and enabled secret inspection") }
		if err:=broker.bind(targetURL,audience); err!=nil { return nil,err }
	}
	// Copy the supplied key so later caller mutations cannot desynchronise JWKS.
	pubKey = append(ed25519.PublicKey(nil), pubKey...)
	var jwks *passport.JWKS
	if audience != "" {
		_,err=trust.JWKS()
	} else {
		jwks,err=passport.JWKSForKey(pubKey)
	}
	if err != nil { return nil,err }

	limiter,err:=policy.NewRateLimiter(*cfg.RateLimit)
	if err!=nil { return nil,err }
	transport:=newUpstreamTransport()
	transport.TLSClientConfig=tlsConfig
	serveJWKS := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		current:=jwks
		if audience!="" {
			var err error
			current,err=trust.JWKS()
			if err!=nil { http.Error(w,"trust store unavailable",http.StatusServiceUnavailable); return }
		}
		w.Header().Set("Cache-Control","no-store")
		json.NewEncoder(w).Encode(current)
	}

	serveProtected := func(w http.ResponseWriter, r *http.Request) {
		tokens := r.Header.Values("X-Agent-Passport")
		if len(tokens) > 1 {
			http.Error(w, "ambiguous agent passport", http.StatusBadRequest)
			return
		}
		rawToken := r.Header.Get("X-Agent-Passport")
		if rawToken == "" {
			emitAudit(AuditEvent{Method: r.Method, Path: r.URL.Path, Decision: "BLOCK", Reason: "missing X-Agent-Passport header"})
			http.Error(w, `{"error":"Kgaga: missing X-Agent-Passport"}`, http.StatusUnauthorized)
			return
		}

		var claims *passport.AgentClaims
		var err error
		if audience != "" {
			claims, err = trust.Verify(rawToken, audience)
		} else {
			claims, err = passport.Verify(rawToken, pubKey)
		}
		if err != nil {
			if audience!="" && !errors.Is(err,keyring.ErrDenied) {
				emitAudit(AuditEvent{Method:r.Method,Path:r.URL.Path,Decision:"BLOCK",Reason:"trust store unavailable"})
				http.Error(w,"trust store unavailable",http.StatusServiceUnavailable)
				return
			}
			emitAudit(AuditEvent{Method: r.Method, Path: r.URL.Path, Decision: "BLOCK", Reason: "passport verification failed"})
			http.Error(w, `{"error":"Kgaga: invalid or expired agent passport"}`, http.StatusForbidden)
			return
		}

		if audience != "" {
			if err := store.Check(claims.ID); err != nil {
				status := http.StatusServiceUnavailable
				reason := "revocation store unavailable"
				if errors.Is(err, revocation.ErrRevoked) {
					status = http.StatusForbidden
					reason = "passport revoked"
				}
				emitAudit(AuditEvent{AgentID: claims.AgentID, Owner: claims.Owner, PassportID: claims.ID, Method: r.Method, Path: r.URL.Path, Decision: "BLOCK", Reason: reason})
				http.Error(w, reason, status)
				return
			}
		}

		var holder ed25519.PublicKey
		if audience != "" {
			var err error
			holder,err=reg.BoundHolder(claims,audience)
			if err!=nil {
				status:=http.StatusServiceUnavailable
				reason:="agent registry unavailable"
				if errors.Is(err,registry.ErrDenied) { status=http.StatusForbidden; reason="agent authorization denied" }
				emitAudit(AuditEvent{AgentID:claims.AgentID,Owner:claims.Owner,PassportID:claims.ID,Method:r.Method,Path:r.URL.Path,Decision:"BLOCK",Reason:reason})
				http.Error(w,reason,status)
				return
			}
		}

		if audience!="" {
			if err:=delegation.Check(claims,audience,trust,reg,store); err!=nil {
				status:=http.StatusServiceUnavailable
				reason:="delegation state unavailable"
				if errors.Is(err,delegation.ErrDenied) { status=http.StatusForbidden; reason="delegation denied" }
				emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:r.Method,Path:r.URL.Path,Decision:"BLOCK",Reason:reason})
				http.Error(w,reason,status)
				return
			}
		}

		var bodyBytes []byte
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
			defer r.Body.Close()
			bodyBytes, err = io.ReadAll(r.Body)
			if err != nil {
				status := http.StatusBadRequest
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					status = http.StatusRequestEntityTooLarge
				}
				emitAudit(AuditEvent{AgentID: claims.AgentID, Owner: claims.Owner, Method: r.Method, Path: r.URL.Path, Decision: "BLOCK", Reason: "request body rejected", Scopes: claims.Scopes})
				http.Error(w, "request body rejected", status)
				return
			}
		}

		var binding passport.RequestBinding
		if audience!="" {
			// Reject ambiguous bound headers, content encodings and request-target
			// normalization before validating the exact received body.
			for _,name:=range []string{passport.ProofHeader,"Content-Type","MCP-Protocol-Version","Mcp-Method","Mcp-Session-Id"} {
				if len(r.Header.Values(name))>1 { http.Error(w,"ambiguous proof header",400); return }
			}
			if r.Header.Get("Content-Encoding")!="" || r.RequestURI!=r.URL.RequestURI() || len(r.Trailer)>0 {
				http.Error(w,"unsupported request encoding or target",400); return
			}
			binding=passport.RequestBinding{Method:r.Method,Target:r.URL.RequestURI(),ContentType:r.Header.Get("Content-Type"),MCPVersion:r.Header.Get("MCP-Protocol-Version"),MCPMethod:r.Header.Get("Mcp-Method"),MCPSession:r.Header.Get("Mcp-Session-Id"),Body:bodyBytes}
			nonce,err:=passport.VerifyRequest(r.Header.Get(passport.ProofHeader),rawToken,holder,binding,time.Now())
			if err!=nil {
				emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:r.Method,Path:r.URL.Path,Decision:"BLOCK",Reason:"request proof rejected"})
				http.Error(w,"request proof rejected",403); return
			}
			if retry,err:=limiter.Allow(claims.AgentID); err!=nil {
				status:=http.StatusTooManyRequests
				if errors.Is(err,policy.ErrRateCapacity) { status=http.StatusServiceUnavailable }
				w.Header().Set("Retry-After",strconv.Itoa(retry))
				w.Header().Set("Cache-Control","no-store")
				emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:r.Method,Decision:"BLOCK",Reason:err.Error()})
				if r.URL.Path=="/mcp" { writeMCPError(w,status,-32603,"agent admission rate limited") } else { http.Error(w,"agent admission rate limited",status) }
				return
			}
			if err:=replay.Consume(nonce); err!=nil {
				status:=503
				reason:="replay store unavailable"
				if errors.Is(err,revocation.ErrRevoked) { status=403; reason="request proof replayed" }
				emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:r.Method,Path:r.URL.Path,Decision:"BLOCK",Reason:reason})
				http.Error(w,reason,status); return
			}
		}

		isMCP := r.URL.Path == "/mcp"
		var mcpInfo *mcp.InspectionResult

		if isMCP {
			mcpInfo, err = mcp.Inspect(r, bodyBytes)
			if err != nil {
				emitAudit(AuditEvent{
					AgentID: claims.AgentID, Owner: claims.Owner, Method: r.Method,
					Path: r.URL.Path, Decision: "BLOCK", Reason: err.Error(), Scopes: claims.Scopes,
				})
				writeMCPError(w,http.StatusBadRequest,-32600,"invalid MCP request")
				return
			}

			allowed, reason := cfg.AuthorizeMCP(mcpInfo.Method, mcpInfo.ToolName, mcpInfo.RequiredScope, claims.Scopes)
			if !allowed {
				emitAudit(AuditEvent{
					AgentID: claims.AgentID, Owner: claims.Owner, Method: mcpInfo.Method + ":" + mcpInfo.ToolName,
					Path: r.URL.Path, Decision: "BLOCK", Reason: reason, Scopes: claims.Scopes,
				})
				writeMCPError(w,http.StatusForbidden,-32603,"MCP request denied")
				return
			}
		} else {
			allowed, reason := cfg.Authorize(r.Method, r.URL.Path, claims.Scopes)
			if !allowed {
				emitAudit(AuditEvent{
					AgentID: claims.AgentID, Owner: claims.Owner, Method: r.Method,
					Path: r.URL.Path, Decision: "BLOCK", Reason: reason, Scopes: claims.Scopes,
				})
				http.Error(w, `{"error":"Kgaga policy block: `+reason+`"}`, http.StatusForbidden)
				return
			}
		}

		if err:=inspectRequest(r,bodyBytes,cfg.RedactSecrets); err!=nil {
			status:=http.StatusBadRequest
			if errors.Is(err,errSecret) { status=http.StatusForbidden }
			emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:r.Method,Decision:"BLOCK",Reason:"request inspection rejected"})
			if isMCP { writeMCPError(w,status,-32600,"MCP payload rejected by inspection") } else { http.Error(w,"request inspection rejected",status) }
			return
		}
		if audience!="" {
			e:=checkLive(rawToken,audience,trust,reg,store)
			if e==nil { _,e=passport.VerifyRequest(r.Header.Get(passport.ProofHeader),rawToken,holder,binding,time.Now()) }
			if e!=nil {
				emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:r.Method,Decision:"BLOCK",Reason:"final admission check failed"})
				if isMCP { writeMCPError(w,403,-32603,"final admission denied") } else { http.Error(w,"final admission denied",403) }
				return
			}
		}
		var secret []byte
		var leaseDeadline time.Time
		var selection policy.VaultSelection
		var event audit.Event
		// Return generic errors; audit failures must never cause a fallback
		// to the ordinary non-Vault gateway.
		writeAudit:=func(phase string,status int) error {
			if broker==nil { return nil }
			event.Phase,event.Status=phase,status
			return broker.audit.Record(event)
		}
		auditUnavailable:=func(){
			if isMCP { writeMCPError(w,503,-32603,"vault audit unavailable") } else { http.Error(w,"vault audit unavailable",503) }
		}
		if broker!=nil {
			id,e:=audit.NewID()
			if e!=nil { auditUnavailable(); return }
			event=audit.Event{AttemptID:id,Action:"credential_use",Actor:"agent",AgentID:claims.AgentID,Owner:claims.Owner,PassportID:claims.ID,Audience:audience,VaultID:broker.id,Method:r.Method}
			if e:=writeAudit("attempt",0); e!=nil { auditUnavailable(); return }
			lease,err:=broker.credential(claims,audience,targetURL,r,mcpInfo,&event)
			if err!=nil {
				status:=http.StatusServiceUnavailable
				if errors.Is(err,policy.ErrVaultDenied) || errors.Is(err,vault.ErrInactiveVersion) { status=http.StatusForbidden }
				emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:r.Method,Decision:"BLOCK",Reason:"vault credential unavailable or denied"})
				phase:="credential_unavailable"
				if status==403 { phase="denied" }
				if e:=writeAudit(phase,status); e!=nil { auditUnavailable(); return }
				if isMCP { writeMCPError(w,status,-32603,"vault credential unavailable or denied") } else { http.Error(w,"vault credential unavailable or denied",status) }
				return
			}
			defer lease.close()
			selection=lease.selection
			// Record intent, not proof that any network bytes were sent.
			// Perform final live checks AFTER writing to the sink.
			if e:=writeAudit("dispatch_intent",0); e!=nil { auditUnavailable(); return }
			// Storage lookup is potentially slow. Repeat live checks after
			// the lookup so a stale decision cannot authorize injection.
			e=checkLive(rawToken,audience,trust,reg,store)
			if e==nil { _,e=passport.VerifyRequest(r.Header.Get(passport.ProofHeader),rawToken,holder,binding,time.Now()) }
			if e==nil { e=broker.checkActive(selection) }
			if e==nil { _,e=passport.VerifyRequest(r.Header.Get(passport.ProofHeader),rawToken,holder,binding,time.Now()) }
			if e==nil { secret,leaseDeadline,e=lease.consume(time.Now()) }
			if e!=nil {
				emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:r.Method,Decision:"BLOCK",Reason:"vault final admission denied"})
				if e:=writeAudit("denied_before_dispatch",403); e!=nil { auditUnavailable(); return }
				if isMCP { writeMCPError(w,403,-32603,"vault final admission denied") } else { http.Error(w,"vault final admission denied",403) }
				return
			}
			defer clear(secret)
		}
		response,err:=exchange(r,target,transport,claims,bodyBytes,mcpInfo,cfg.RedactSecrets,secret,leaseDeadline)
		if err!=nil {
			emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:r.Method,Decision:"BLOCK",Reason:"upstream response rejected or unavailable"})
			if e:=writeAudit("exchange_failed_or_rejected",502); e!=nil { auditUnavailable(); return }
			if isMCP { writeMCPError(w,http.StatusBadGateway,-32603,"upstream response rejected") } else { http.Error(w,"upstream response rejected",http.StatusBadGateway) }
			return
		}
		// Requests already dispatched cannot be undone. Do not release
		// their response after credential lifecycle validation fails.
		if audience!="" {
			if e:=checkLive(rawToken,audience,trust,reg,store); e!=nil {
				emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:r.Method,Decision:"BLOCK",Reason:"credential lifecycle check failed before response"})
				if e:=writeAudit("response_withheld",403); e!=nil { auditUnavailable(); return }
				if isMCP { writeMCPError(w,403,-32603,"response access denied") } else { http.Error(w,"response access denied",403) }
				return
			}
		}
		if broker!=nil && (broker.checkActive(selection)!=nil || !time.Now().Before(leaseDeadline)) {
			emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:r.Method,Decision:"BLOCK",Reason:"vault lifecycle or lease check failed before response"})
			if e:=writeAudit("response_withheld",403); e!=nil { auditUnavailable(); return }
			if isMCP { writeMCPError(w,403,-32603,"response access denied") } else { http.Error(w,"response access denied",403) }
			return
		}
		if broker!=nil {
			// This event records intended release, not delivery or business success.
			if e:=writeAudit("response_release_intent",response.status); e!=nil { auditUnavailable(); return }
			// Logging may block. Recheck after the sink accepts the intent.
			if checkLive(rawToken,audience,trust,reg,store)!=nil || broker.checkActive(selection)!=nil || !time.Now().Before(leaseDeadline) {
				if e:=writeAudit("response_withheld",403); e!=nil { auditUnavailable(); return }
				if isMCP { writeMCPError(w,403,-32603,"response access denied") } else { http.Error(w,"response access denied",403) }
				return
			}
		}
		// Vault already recorded checked release intent. Do not introduce
		// another potentially blocking log write after its final live check.
		if broker==nil { emitAudit(AuditEvent{AgentID:claims.AgentID,Owner:claims.Owner,PassportID:claims.ID,Method:r.Method,Path:r.URL.Path,Decision:"ALLOW",Scopes:claims.Scopes}) }
		for key,values:=range response.headers { for _,value:=range values { w.Header().Add(key,value) } }
		w.WriteHeader(response.status)
		if r.Method!="HEAD" && response.status!=204 && response.status!=205 { _,_=w.Write(response.body) }

	}

	// Do not use ServeMux here: its path-cleaning redirects can precede
	// authentication and differ from the resource actually authorized.
	return boundAdmission(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
		if err:=validateRoute(r); err!=nil { http.Error(w,"invalid or unsupported HTTP route",http.StatusBadRequest); return }
		if r.URL.Path=="/.well-known/jwks.json" {
			if r.Method!="GET" { w.Header().Set("Allow","GET"); http.Error(w,"method not allowed",405); return }
			serveJWKS(w,r); return
		}
		serveProtected(w,r)
	}),MaxActiveRequests,6000,128)
}

 // validateRoute rejects alternate path interpretations and user-controlled
 // HTTP/MCP mode switching before admission. Upstream must use the same
 // case-sensitive literal path semantics and ignore alternate routing inputs.
func validateRoute(r *http.Request) error {
	bad:=errors.New("invalid HTTP route")
	if r.URL==nil || !policy.StandardMethod(r.Method) || !policy.CanonicalPath(r.URL.Path) || r.URL.IsAbs() || r.URL.Host!="" || r.URL.Opaque!="" || r.URL.Fragment!="" || r.URL.RawPath!="" { return bad }
	raw,_,_:=strings.Cut(r.RequestURI,"?")
	if raw!=r.URL.Path || r.RequestURI!=r.URL.RequestURI() { return bad }
	if _,err:=url.ParseQuery(r.URL.RawQuery); err!=nil { return bad }
	for _,name:=range []string{"X-HTTP-Method-Override","X-HTTP-Method","X-Method-Override","X-Original-URL","X-Rewrite-URL","X-Original-URI","X-Forwarded-Uri","Upgrade"} {
		if len(r.Header.Values(name))>0 { return bad }
	}
	// Header presence does not select the MCP authorization path.
	if r.URL.Path=="/mcp" {
		if r.Method!="POST" { return bad }
	} else {
		if strings.HasPrefix(r.URL.Path,"/mcp/") { return bad }
		for _,name:=range []string{"MCP-Protocol-Version","Mcp-Method","Mcp-Name","Mcp-Session-Id"} {
			for _,value:=range r.Header.Values(name) { if value!="" { return bad } }
		}
	}
	return nil
}

// Reject messages without reflecting attacker-controlled fields or IDs.
func writeMCPError(w http.ResponseWriter,status,code int,message string) {
	w.Header().Set("Content-Type","application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc":"2.0","id":nil,"error":map[string]any{"code":code,"message":message}})
}
