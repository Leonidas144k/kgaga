// Package audit provides the development-preview structured audit sink.
// Durability, log shipping, tamper evidence and retention belong to Ledger.
package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

var ErrUnavailable = errors.New("vault audit unavailable")

const maxEventBytes = 8192

// Event admits only explicitly selected metadata. No tokens, keys, proof
// material, bodies, raw provider responses, query strings or raw errors.
// Operators must not place secrets in configured identifiers or routes.
type Event struct {
	Schema string `json:"schema"`
	Timestamp string `json:"ts"`
	AttemptID string `json:"attempt_id"`
	Action string `json:"action"`
	Phase string `json:"phase"`
	Actor string `json:"actor"`
	AgentID string `json:"agent_id,omitempty"`
	Owner string `json:"owner,omitempty"`
	PassportID string `json:"passport_id,omitempty"`
	Audience string `json:"audience,omitempty"`
	VaultID string `json:"vault_id"`
	Name string `json:"secret_name,omitempty"`
	Version uint64 `json:"secret_version,omitempty"`
	Origin string `json:"origin,omitempty"`
	Method string `json:"method,omitempty"`
	Target string `json:"target,omitempty"`
	MCPMethod string `json:"mcp_method,omitempty"`
	Tool string `json:"tool,omitempty"`
	Provider string `json:"provider,omitempty"`
	ProviderVersion uint64 `json:"provider_version,omitempty"`
	Status int `json:"http_status,omitempty"`
}

func NewID()(string,error) {
	var b [16]byte
	if _,err:=rand.Read(b[:]); err!=nil { return "",ErrUnavailable }
	return hex.EncodeToString(b[:]),nil
}

type Recorder struct {
	mu sync.Mutex
	out io.Writer
	failed bool // protected by mu; no automatic reset after an ambiguous write
}

func NewRecorder(w io.Writer)*Recorder { return &Recorder{out:w} }

var standard = NewRecorder(os.Stderr)
func Default()*Recorder { return standard }

// Record checks synchronous write failures, including short writes. A
// successful return means the writer accepted bytes, not durable storage.
// Never automatically retry an ambiguous partial write.
func (r *Recorder) Record(e Event) error {
	if r==nil || r.out==nil || len(e.AttemptID)!=32 || e.Action=="" || e.Phase=="" || e.Actor=="" || e.VaultID=="" { return ErrUnavailable }
	e.Schema="kgaga.vault.audit.v1"
	e.Timestamp=time.Now().UTC().Format(time.RFC3339Nano)
	raw,err:=json.Marshal(e)
	if err!=nil || len(raw)+1>maxEventBytes { return ErrUnavailable }
	raw=append(raw,'\n')
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failed { return ErrUnavailable }
	n,err:=r.out.Write(raw)
	if err!=nil || n!=len(raw) {
		// A partial JSON line can corrupt subsequent framing. Do not
		// resume credential operations until the operator repairs the sink.
		r.failed=true
		return ErrUnavailable
	}
	return nil
}
