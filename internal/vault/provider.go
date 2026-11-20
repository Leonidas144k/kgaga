package vault

import (
	"context"
	"errors"
	"os"
	"time"
)

var ErrProvider = errors.New("external secret provider request failed")

// BearerSource is a trusted, operator-configured source for a specific
// credential. Implementations return a caller-owned bearer buffer and
// never expose provider authentication to agents. This is an import
// boundary, not a dynamic gateway credential or lease service.
type BearerSource interface {
	ReadBearer(context.Context, []byte) ([]byte,error)
}

// ImportBearer stages a new immutable local credential. The provider
// cannot select the local slot, validity window, or activate a version.
// auth is a caller-owned provider credential; the caller must clear it.
func (m *ManagedStore) ImportBearer(ctx context.Context,source BearerSource,auth []byte,name string,version uint64,start,end int64) error {
	if ctx==nil || source==nil || ValidateBearer(auth)!=nil { return ErrProvider }
	if !validWindow(start,end) || time.Now().Unix()>=end { return ErrCredentialValidity }
	_,path,err:=m.slot(name,version)
	if err!=nil { return err }
	if _,err:=os.Lstat(path); err==nil { return ErrRecordExists } else if !os.IsNotExist(err) { return ErrStoreUnavailable }
	if err:=ctx.Err(); err!=nil { return ErrProvider }
	token,err:=source.ReadBearer(ctx,auth)
	defer clear(token)
	if err!=nil || ctx.Err()!=nil || ValidateBearer(token)!=nil { return ErrProvider }
	// Do not accidentally import the provider's management credential.
	if string(token)==string(auth) { return ErrProvider }
	// PutBearer validates the window again and exclusively publishes.
	// A concurrent import cannot overwrite the existing version.
	return m.PutBearer(name,version,token,start,end)
}
