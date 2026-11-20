// Package delegation enforces one-hop issuer-mediated delegation.
package delegation

import (
	"errors"
	"fmt"
	"time"

	"github.com/Leonidas144k/kgaga/internal/keyring"
	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/registry"
	"github.com/Leonidas144k/kgaga/internal/revocation"
)

var ErrDenied=errors.New("delegation denied")

// Check must run after validating the child signature, revocation and
// registered holder. It revalidates the original parent on every use.
func Check(c *passport.AgentClaims,audience string,trust *keyring.Store,reg *registry.Store,rev *revocation.Store) error {
	if c==nil { return ErrDenied }
	if c.Delegation==nil { return nil }
	p,err:=trust.Verify(c.Delegation.Parent,audience)
	if err!=nil {
		if errors.Is(err,keyring.ErrDenied) { return ErrDenied }
		return err
	}
	if p.Delegation!=nil { return ErrDenied }
	if err:=rev.Check(p.ID); err!=nil {
		if errors.Is(err,revocation.ErrRevoked) { return ErrDenied }
		return err
	}
	holder,err:=reg.BoundHolder(p,audience)
	if err!=nil {
		if errors.Is(err,registry.ErrDenied) { return ErrDenied }
		return err
	}
	if err:=passport.VerifyGrant(c,p,holder,audience,time.Now()); err!=nil { return fmt.Errorf("%w: invalid parent grant",ErrDenied) }
	return nil
}

// Issue is called only by a trusted issuer. The parent signature does not
// replace issuer approval. Grants are reusable within the authorized expiry.
func Issue(signingKey,child,owner string,scopes []string,audience string,d passport.Delegation,trust *keyring.Store,reg *registry.Store,rev *revocation.Store) (string,error) {
	holder,err:=reg.AuthorizedHolder(child,owner,scopes,audience)
	if err!=nil { return "",err }
	raw,err:=passport.MintDelegated(signingKey,child,owner,scopes,audience,holder,d)
	if err!=nil { return "",err }
	c,err:=trust.Verify(raw,audience)
	if err!=nil { return "",err }
	if err:=rev.Check(c.ID); err!=nil { return "",err }
	if _,err:=reg.BoundHolder(c,audience); err!=nil { return "",err }
	if err:=Check(c,audience,trust,reg,rev); err!=nil { return "",err }
	return raw,nil
}
