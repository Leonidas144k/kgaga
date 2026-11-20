package proxy

import (
	"errors"
	"net/http"
	"time"

	"github.com/Leonidas144k/kgaga/internal/audit"
	"github.com/Leonidas144k/kgaga/internal/mcp"
	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
	"github.com/Leonidas144k/kgaga/internal/vault"
)

// VaultGateway is a startup-bound local broker. Only trusted operator
// configuration may construct it. No agent-facing secret API is exposed.
type VaultGateway struct {
	policy *policy.VaultPolicy
	store *vault.ManagedStore
	id string
	audit *audit.Recorder
}

func OpenVaultGateway(policyPath,dir,id,keyPath,keyID string)(*VaultGateway,error) {
	vid,err:=vault.ParseID(id)
	if err!=nil { return nil,err }
	kid,err:=vault.ParseID(keyID)
	if err!=nil { return nil,err }
	p,err:=policy.LoadVaultPolicy(policyPath)
	if err!=nil { return nil,err }
	s,err:=vault.Open(dir,vid)
	if err!=nil { return nil,err }
	m,err:=s.OpenManaged(keyPath,kid)
	if err!=nil { return nil,err }
	return &VaultGateway{policy:p,store:m,id:id,audit:audit.Default()},nil
}

func (v *VaultGateway) bind(origin,audience string) error {
	if v==nil || v.store==nil || v.policy==nil || v.audit==nil { return errors.New("vault configuration required") }
	return v.policy.ValidateBinding(origin,audience,v.id)
}

func (v *VaultGateway) credential(c *passport.AgentClaims,audience,origin string,r *http.Request,info *mcp.InspectionResult,event *audit.Event)(*credentialLease,error) {
	op:=policy.VaultOperation{Origin:origin,Method:r.Method,Target:r.URL.RequestURI()}
	// First release supports stateless MCP tool calls only.
	if info!=nil {
		if len(r.Header.Values("Mcp-Session-Id"))>0 { return nil,policy.ErrVaultDenied }
		op.MCPMethod=info.Method
		op.Tool=info.ToolName
	}
	sel,err:=v.policy.Authorize(c,audience,op)
	if err!=nil { return nil,err }
	if sel.VaultID!=v.id { return nil,policy.ErrVaultDenied }
	// Only exact operator-configured grant metadata enters the audit event.
	event.Name,event.Version=sel.SecretName,sel.Version
	event.Origin,event.Target,event.MCPMethod,event.Tool=op.Origin,op.Target,op.MCPMethod,op.Tool
	secret,expiry,err:=v.store.GetActiveBearer(sel.SecretName,sel.Version)
	if err!=nil { return nil,err }
	lease,err:=newCredentialLease(secret,expiry,c.ExpiresAt.Time,time.Now())
	if err!=nil { return nil,err }
	lease.selection=sel
	return lease,nil
}

func (v *VaultGateway) checkActive(sel policy.VaultSelection) error {
	if sel.VaultID!=v.id { return policy.ErrVaultDenied }
	return v.store.CheckActive(sel.SecretName,sel.Version)
}
