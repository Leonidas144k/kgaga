package proxy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/Leonidas144k/kgaga/internal/mcp"
	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
	"github.com/Leonidas144k/kgaga/internal/revocation"
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
func NewHandler(targetURL string, pubKey ed25519.PublicKey, cfg *policy.Config) (http.Handler, error) {
	return newHandler(targetURL, pubKey, cfg, "", nil, nil, nil, nil)
}

// NewHandlerForAudience enforces v2 passports without a legacy fallback.
func NewHandlerForAudience(targetURL string, trust *keyring.Store, cfg *policy.Config, audience string, store *revocation.Store, reg *registry.Store, replay *revocation.Store) (http.Handler, error) {
	if err := passport.ValidateAudience(audience); err != nil {
		return nil, err
	}
	if err := store.Ready(); err != nil { return nil, err }
	if err:=reg.Ready(); err!=nil { return nil,err }
	if err:=trust.Ready(); err!=nil { return nil,err }
	if err:=replay.Ready(); err!=nil { return nil,err }
	return newHandler(targetURL, nil, cfg, audience, store, reg, trust, replay)
}

func newHandler(targetURL string, pubKey ed25519.PublicKey, cfg *policy.Config, audience string, store *revocation.Store, reg *registry.Store, trust *keyring.Store, replay *revocation.Store) (http.Handler, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	if (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" || target.User != nil || target.Fragment != "" {
		return nil, errors.New("upstream must be an HTTP(S) URL with a host and no userinfo or fragment")
	}
	if cfg == nil {
		return nil, errors.New("policy configuration is required")
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

	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
			// These values have already been overwritten with verified claims.
			// Add them after hop-by-hop header stripping.
			for _, name := range []string{"X-Pangolin-Verified-Agent", "X-Pangolin-Agent-Owner", "X-Kgaga-Verified-Agent", "X-Kgaga-Agent-Owner"} {
				pr.Out.Header.Set(name, pr.In.Header.Get(name))
			}
			pr.Out.Header.Del("X-Agent-Passport")
			pr.Out.Header.Del("X-Kgaga-Passport")
			pr.Out.Header.Del(passport.ProofHeader)
		},
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		current:=jwks
		if audience!="" {
			var err error
			current,err=trust.JWKS()
			if err!=nil { http.Error(w,"trust store unavailable",http.StatusServiceUnavailable); return }
		}
		w.Header().Set("Cache-Control","no-store")
		json.NewEncoder(w).Encode(current)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
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

		if audience!="" {
			// Reject ambiguous bound headers, content encodings and request-target
			// normalization before validating the exact received body.
			for _,name:=range []string{passport.ProofHeader,"Content-Type","MCP-Protocol-Version","Mcp-Method","Mcp-Session-Id"} {
				if len(r.Header.Values(name))>1 { http.Error(w,"ambiguous proof header",400); return }
			}
			if r.Header.Get("Content-Encoding")!="" || r.RequestURI!=r.URL.RequestURI() || len(r.Trailer)>0 {
				http.Error(w,"unsupported request encoding or target",400); return
			}
			binding:=passport.RequestBinding{Method:r.Method,Target:r.URL.RequestURI(),ContentType:r.Header.Get("Content-Type"),MCPVersion:r.Header.Get("MCP-Protocol-Version"),MCPMethod:r.Header.Get("Mcp-Method"),MCPSession:r.Header.Get("Mcp-Session-Id"),Body:bodyBytes}
			nonce,err:=passport.VerifyRequest(r.Header.Get(passport.ProofHeader),rawToken,holder,binding,time.Now())
			if err!=nil {
				emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:r.Method,Path:r.URL.Path,Decision:"BLOCK",Reason:"request proof rejected"})
				http.Error(w,"request proof rejected",403); return
			}
			if err:=replay.Consume(nonce); err!=nil {
				status:=503
				reason:="replay store unavailable"
				if errors.Is(err,revocation.ErrRevoked) { status=403; reason="request proof replayed" }
				emitAudit(AuditEvent{AgentID:claims.AgentID,PassportID:claims.ID,Method:r.Method,Path:r.URL.Path,Decision:"BLOCK",Reason:reason})
				http.Error(w,reason,status); return
			}
		}

		isMCP := r.URL.Path == "/mcp" || r.Header.Get("MCP-Protocol-Version") != "" || r.Header.Get("Mcp-Method") != ""

		if isMCP {
			mcpInfo, err := mcp.Inspect(r, bodyBytes)
			if err != nil {
				emitAudit(AuditEvent{
					AgentID: claims.AgentID, Owner: claims.Owner, Method: r.Method,
					Path: r.URL.Path, Decision: "BLOCK", Reason: err.Error(), Scopes: claims.Scopes,
				})
				http.Error(w, `{"jsonrpc":"2.0","error":{"code":-32600,"message":"`+err.Error()+`"}}`, http.StatusBadRequest)
				return
			}

			allowed, reason := cfg.AuthorizeMCP(mcpInfo.Method, mcpInfo.ToolName, mcpInfo.RequiredScope, claims.Scopes)
			if !allowed {
				emitAudit(AuditEvent{
					AgentID: claims.AgentID, Owner: claims.Owner, Method: mcpInfo.Method + ":" + mcpInfo.ToolName,
					Path: r.URL.Path, Decision: "BLOCK", Reason: reason, Scopes: claims.Scopes,
				})
				http.Error(w, `{"jsonrpc":"2.0","error":{"code":-32603,"message":"Kgaga MCP block: `+reason+`"}}`, http.StatusForbidden)
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

		redacted := false
		if cfg.RedactSecrets && len(bodyBytes) > 0 {
			cleaned, didRedact := policy.Redact(string(bodyBytes))
			redacted = didRedact
			bodyBytes = []byte(cleaned)
		}
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))

		r.Header.Set("X-Pangolin-Verified-Agent", claims.AgentID)
		r.Header.Set("X-Pangolin-Agent-Owner", claims.Owner)
		r.Header.Set("X-Kgaga-Verified-Agent", claims.AgentID)
		r.Header.Set("X-Kgaga-Agent-Owner", claims.Owner)

		emitAudit(AuditEvent{
			AgentID: claims.AgentID, Owner: claims.Owner, Method: r.Method,
			Path: r.URL.Path, Decision: "ALLOW", PassportID: claims.ID, Redacted: redacted, Scopes: claims.Scopes,
		})

		rp.ServeHTTP(w, r)
	})

	return mux, nil
}
