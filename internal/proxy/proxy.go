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
	return newHandler(targetURL, pubKey, cfg, "", nil, nil)
}

// NewHandlerForAudience enforces v2 passports without a legacy fallback.
func NewHandlerForAudience(targetURL string, pubKey ed25519.PublicKey, cfg *policy.Config, audience string, store *revocation.Store, reg *registry.Store) (http.Handler, error) {
	if err := passport.ValidateAudience(audience); err != nil {
		return nil, err
	}
	if err := store.Ready(); err != nil { return nil, err }
	if err:=reg.Ready(); err!=nil { return nil,err }
	return newHandler(targetURL, pubKey, cfg, audience, store, reg)
}

func newHandler(targetURL string, pubKey ed25519.PublicKey, cfg *policy.Config, audience string, store *revocation.Store, reg *registry.Store) (http.Handler, error) {
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
	jwks, err := passport.JWKSForKey(pubKey)
	if audience != "" {
		jwks, err = passport.JWKSForKeyV2(pubKey)
	}
	if err != nil {
		return nil, err
	}

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
		},
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
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
			claims, err = passport.VerifyV2(rawToken, pubKey, audience)
		} else {
			claims, err = passport.Verify(rawToken, pubKey)
		}
		if err != nil {
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

		if audience != "" {
			if err:=reg.Authorize(claims.AgentID,claims.Owner,claims.Scopes,audience); err!=nil {
				status:=http.StatusServiceUnavailable
				reason:="agent registry unavailable"
				if errors.Is(err,registry.ErrDenied) { status=http.StatusForbidden; reason="agent authorization denied" }
				emitAudit(AuditEvent{AgentID:claims.AgentID,Owner:claims.Owner,PassportID:claims.ID,Method:r.Method,Path:r.URL.Path,Decision:"BLOCK",Reason:reason})
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
