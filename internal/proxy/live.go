package proxy

import (
	"github.com/Leonidas144k/kgaga/internal/delegation"
	"github.com/Leonidas144k/kgaga/internal/keyring"
	"github.com/Leonidas144k/kgaga/internal/registry"
	"github.com/Leonidas144k/kgaga/internal/revocation"
)

// Recheck after potentially slow I/O and policy evaluation. This reduces
// the revocation race window, but cannot make dispatch and revocation atomic.
func checkLive(token,audience string,trust *keyring.Store,reg *registry.Store,rev *revocation.Store) error {
	c,err:=trust.Verify(token,audience)
	if err!=nil { return err }
	if err:=rev.Check(c.ID); err!=nil { return err }
	if _,err:=reg.BoundHolder(c,audience); err!=nil { return err }
	return delegation.Check(c,audience,trust,reg,rev)
}
