package proxy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/pangolin-sec/pangolin/internal/mcp"
	"github.com/pangolin-sec/pangolin/internal/passport"
	"github.com/pangolin-sec/pangolin/internal/policy"
)

type AuditEvent struct {
	Timestamp string   `json:"ts"`
	AgentID   string   `json:"agent_id"`
	Owner     string   `json:"owner"`
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

func NewHandler(targetURL string, pubKey ed25519.PublicKey, cfg *policy.Config) (http.Handler, error) {
	target, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	rp := httputil.NewSingleHostReverseProxy(target)
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwks, err := passport.GetJWKS("pangolin.pub")
		if err != nil {
			http.Error(w, `{"error":"failed to load jwks"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rawToken := r.Header.Get("X-Agent-Passport")
		if rawToken == "" {
			emitAudit(AuditEvent{Method: r.Method, Path: r.URL.Path, Decision: "BLOCK", Reason: "missing X-Agent-Passport header"})
			http.Error(w, `{"error":"Pangolin: missing X-Agent-Passport"}`, http.StatusUnauthorized)
			return
		}

		claims, err := passport.Verify(rawToken, pubKey)
		if err != nil {
			emitAudit(AuditEvent{Method: r.Method, Path: r.URL.Path, Decision: "BLOCK", Reason: err.Error()})
			http.Error(w, `{"error":"Pangolin: invalid or expired agent passport"}`, http.StatusForbidden)
			return
		}

		var bodyBytes []byte
		if r.Body != nil {
			bodyBytes, _ = io.ReadAll(r.Body)
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
				http.Error(w, `{"jsonrpc":"2.0","error":{"code":-32603,"message":"Pangolin MCP block: `+reason+`"}}`, http.StatusForbidden)
				return
			}
		} else {
			allowed, reason := cfg.Authorize(r.Method, r.URL.Path, claims.Scopes)
			if !allowed {
				emitAudit(AuditEvent{
					AgentID: claims.AgentID, Owner: claims.Owner, Method: r.Method,
					Path: r.URL.Path, Decision: "BLOCK", Reason: reason, Scopes: claims.Scopes,
				})
				http.Error(w, `{"error":"Pangolin policy block: `+reason+`"}`, http.StatusForbidden)
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

		emitAudit(AuditEvent{
			AgentID: claims.AgentID, Owner: claims.Owner, Method: r.Method,
			Path: r.URL.Path, Decision: "ALLOW", Redacted: redacted, Scopes: claims.Scopes,
		})

		rp.ServeHTTP(w, r)
	})

	return mux, nil
}
