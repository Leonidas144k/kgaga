// Package keyring manages trusted public signing keys on one host.
package keyring

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Leonidas144k/kgaga/internal/passport"
)

const DefaultDir = "kgaga-trust"
var ErrDenied = errors.New("signing key or passport rejected")
var errRetired = fmt.Errorf("%w: retired signing key",ErrDenied)

type Store struct {
	dir string
	info os.FileInfo
}

// Init creates a new, empty trust store. Bootstrap trust separately.
func Init(path string) error { return os.Mkdir(path,0700) }

func Open(path string) (*Store,error) {
	if path=="" { return nil,errors.New("trust directory required") }
	abs,err:=filepath.Abs(path)
	if err!=nil { return nil,err }
	info,err:=os.Lstat(abs)
	if err!=nil { return nil,err }
	if !info.IsDir() { return nil,errors.New("trust store must be a real directory") }
	return &Store{dir:abs,info:info},nil
}

func (s *Store) Ready() error {
	if s==nil || s.info==nil { return errors.New("trust store unavailable") }
	info,err:=os.Lstat(s.dir)
	if err!=nil { return err }
	if !info.IsDir() || !os.SameFile(s.info,info) { return errors.New("trust directory replaced") }
	return nil
}

func validID(id string) bool {
	if len(id)!=43 { return false }
	raw,err:=base64.RawURLEncoding.Strict().DecodeString(id)
	return err==nil && len(raw)==32 && base64.RawURLEncoding.EncodeToString(raw)==id
}

func (s *Store) retired(id string) (bool,error) {
	_,err:=os.Lstat(filepath.Join(s.dir,id+".retired"))
	if err==nil { return true,nil }
	if !os.IsNotExist(err) { return false,err }
	return false,s.Ready()
}

// Trust publishes an immutable public key record. Retired keys cannot be
// reintroduced by this API. The operator must protect the directory.
func (s *Store) Trust(key ed25519.PublicKey) (string,error) {
	id,err:=passport.KeyID(key)
	if err!=nil { return "",err }
	if err:=s.Ready(); err!=nil { return "",err }
	retired,err:=s.retired(id)
	if err!=nil { return "",err }
	if retired { return "",errRetired }
	f,err:=os.CreateTemp(s.dir,".trust-*")
	if err!=nil { return "",err }
	defer os.Remove(f.Name())
	if _,err:=f.Write(key); err!=nil { _=f.Close(); return "",err }
	if err:=f.Sync(); err!=nil { _=f.Close(); return "",err }
	if err:=f.Close(); err!=nil { return "",err }
	if err:=s.Ready(); err!=nil { return "",err }
	if err:=os.Link(f.Name(),filepath.Join(s.dir,id+".pub")); err!=nil && !os.IsExist(err) { return "",err }
	if _,err:=s.lookup(id); err!=nil { return "",err }
	return id,nil
}

func (s *Store) lookup(id string) (ed25519.PublicKey,error) {
	if !validID(id) { return nil,ErrDenied }
	if err:=s.Ready(); err!=nil { return nil,err }
	retired,err:=s.retired(id)
	if err!=nil { return nil,err }
	if retired { return nil,errRetired }
	path:=filepath.Join(s.dir,id+".pub")
	info,err:=os.Lstat(path)
	if os.IsNotExist(err) {
		if err:=s.Ready(); err!=nil { return nil,err }
		return nil,ErrDenied
	}
	if err!=nil { return nil,err }
	if !info.Mode().IsRegular() || info.Size()!=ed25519.PublicKeySize { return nil,errors.New("invalid trust record") }
	raw,err:=os.ReadFile(path)
	if err!=nil { return nil,err }
	key:=ed25519.PublicKey(raw)
	actual,err:=passport.KeyID(key)
	if err!=nil || actual!=id { return nil,errors.New("trust record thumbprint mismatch") }
	retired,err=s.retired(id)
	if err!=nil { return nil,err }
	if retired { return nil,errRetired }
	return key,nil
}

func (s *Store) Retire(id string) error {
	if !validID(id) { return ErrDenied }
	if _,err:=s.lookup(id); err!=nil {
		if errors.Is(err,errRetired) { return nil }
		return err
	}
	f,err:=os.OpenFile(filepath.Join(s.dir,id+".retired"),os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
	if os.IsExist(err) { return s.Ready() }
	if err!=nil { return err }
	if err:=f.Sync(); err!=nil { _=f.Close(); return err }
	if err:=f.Close(); err!=nil { return err }
	return s.Ready()
}

// Verify uses the untrusted kid only as a bounded selector, then performs
// full signature, type, issuer, audience and claim validation.
func (s *Store) Verify(raw,audience string) (*passport.AgentClaims,error) {
	if len(raw)==0 || len(raw)>16<<10 { return nil,ErrDenied }
	header,_,ok:=strings.Cut(raw,".")
	if !ok { return nil,ErrDenied }
	data,err:=base64.RawURLEncoding.Strict().DecodeString(header)
	if err!=nil { return nil,ErrDenied }
	var h struct { Kid string `json:"kid"` }
	if err:=json.Unmarshal(data,&h); err!=nil || !validID(h.Kid) { return nil,ErrDenied }
	key,err:=s.lookup(h.Kid)
	if err!=nil { return nil,err }
	claims,err:=passport.VerifyV2(raw,key,audience)
	if err!=nil { return nil,ErrDenied }
	if _,err:=s.lookup(h.Kid); err!=nil { return nil,err }
	return claims,nil
}

// JWKS publishes a fresh view of trusted, non-retired public keys.
func (s *Store) JWKS() (*passport.JWKS,error) {
	if err:=s.Ready(); err!=nil { return nil,err }
	entries,err:=os.ReadDir(s.dir)
	if err!=nil { return nil,err }
	out:=&passport.JWKS{Keys:[]passport.JWK{}}
	for _,entry:=range entries {
		if !strings.HasSuffix(entry.Name(),".pub") { continue }
		id:=strings.TrimSuffix(entry.Name(),".pub")
		key,err:=s.lookup(id)
		if errors.Is(err,errRetired) { continue }
		if err!=nil { return nil,err }
		j,err:=passport.JWKSForKeyV2(key)
		if err!=nil { return nil,err }
		out.Keys=append(out.Keys,j.Keys[0])
	}
	if err:=s.Ready(); err!=nil { return nil,err }
	return out,nil
}
