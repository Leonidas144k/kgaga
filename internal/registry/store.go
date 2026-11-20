// Package registry implements an operator-controlled, single-host agent registry.
package registry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Leonidas144k/kgaga/internal/passport"
)

const DefaultDir = "kgaga-agents"
const maxRecord = 64 << 10

var ErrDenied = errors.New("agent authorization denied")

type Agent struct {
	ID string `json:"agent_id"`
	Owner string `json:"owner"`
	Scopes []string `json:"scopes"`
	Audiences []string `json:"audiences"`
}

type Store struct {
	dir string
	info os.FileInfo
}

func Init(path string) error {
	if path == "" { return errors.New("registry directory required") }
	return os.Mkdir(path,0700)
}

func Open(path string) (*Store,error) {
	if path == "" { return nil,errors.New("registry directory required") }
	abs,err:=filepath.Abs(path)
	if err!=nil { return nil,err }
	info,err:=os.Lstat(abs)
	if err!=nil { return nil,err }
	if !info.IsDir() { return nil,errors.New("registry must be a real directory") }
	return &Store{dir:abs,info:info},nil
}

func (s *Store) Ready() error {
	if s==nil || s.info==nil { return errors.New("registry unavailable") }
	info,err:=os.Lstat(s.dir)
	if err!=nil { return err }
	if !info.IsDir() || !os.SameFile(info,s.info) { return errors.New("registry directory replaced") }
	return nil
}

func validate(a Agent) error {
	if err:=passport.ValidateIdentity(a.ID,a.Owner,a.Scopes); err!=nil { return err }
	if len(a.Audiences)==0 || len(a.Audiences)>64 { return errors.New("expected 1 to 64 audiences") }
	seen:=map[string]bool{}
	for _,aud:=range a.Audiences {
		if err:=passport.ValidateAudience(aud); err!=nil { return err }
		if seen[aud] { return errors.New("duplicate audience") }
		seen[aud]=true
	}
	return nil
}

func (s *Store) base(id string) (string,error) {
	// Hash the key so identifiers cannot introduce filesystem paths.
	if err:=passport.ValidateIdentity(id,"owner",[]string{"read"}); err!=nil { return "",err }
	if err:=s.Ready(); err!=nil { return "",err }
	digest:=sha256.Sum256([]byte(id))
	return filepath.Join(s.dir,hex.EncodeToString(digest[:])),nil
}

// Register publishes a complete immutable record using an exclusive hard link.
// A local filesystem supporting hard links is required. Existing IDs cannot
// be overwritten, including suspended identities.
func (s *Store) Register(a Agent) error {
	if err:=validate(a); err!=nil { return err }
	base,err:=s.base(a.ID)
	if err!=nil { return err }
	raw,err:=json.Marshal(a)
	if err!=nil { return err }
	if len(raw)>maxRecord { return errors.New("registry record too large") }
	f,err:=os.CreateTemp(s.dir,".register-*")
	if err!=nil { return err }
	defer os.Remove(f.Name())
	if _,err:=f.Write(raw); err!=nil { _=f.Close(); return err }
	if err:=f.Sync(); err!=nil { _=f.Close(); return err }
	if err:=f.Close(); err!=nil { return err }
	if err:=s.Ready(); err!=nil { return err }
	if err:=os.Link(f.Name(),base+".json"); err!=nil { return fmt.Errorf("register agent (ID must be new): %w",err) }
	return s.Ready()
}

func (s *Store) Get(id string) (Agent,bool,error) {
	var a Agent
	base,err:=s.base(id)
	if err!=nil { return a,false,err }
	info,err:=os.Lstat(base+".json")
	if os.IsNotExist(err) {
		if err:=s.Ready(); err!=nil { return a,false,err }
		return a,false,fmt.Errorf("%w: unknown agent",ErrDenied)
	}
	if err!=nil { return a,false,err }
	if !info.Mode().IsRegular() { return a,false,errors.New("invalid agent record file") }
	f,err:=os.Open(base+".json")
	if err!=nil { return a,false,err }
	defer f.Close()
	raw,err:=io.ReadAll(io.LimitReader(f,maxRecord+1))
	if err!=nil { return a,false,err }
	if len(raw)>maxRecord { return a,false,errors.New("agent record too large") }
	if err:=json.Unmarshal(raw,&a); err!=nil { return a,false,err }
	if a.ID!=id { return a,false,errors.New("agent record identity mismatch") }
	if err:=validate(a); err!=nil { return a,false,err }
	_,err=os.Lstat(base+".suspended")
	suspended:=err==nil
	if err!=nil && !os.IsNotExist(err) { return a,false,err }
	if err:=s.Ready(); err!=nil { return a,false,err }
	return a,suspended,nil
}

// Suspend permanently disables an ID in this increment. No resume/delete
// operation is provided, so previously issued tokens cannot be reactivated.
func (s *Store) Suspend(id string) error {
	if _,_,err:=s.Get(id); err!=nil { return err }
	base,err:=s.base(id)
	if err!=nil { return err }
	f,err:=os.OpenFile(base+".suspended",os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
	if os.IsExist(err) { return s.Ready() }
	if err!=nil { return err }
	if err:=f.Sync(); err!=nil { _=f.Close(); return err }
	if err:=f.Close(); err!=nil { return err }
	return s.Ready()
}

func contains(values []string,want string) bool {
	for _,v:=range values { if v==want { return true } }
	return false
}

// Authorize checks registry membership, exact owner, explicit audience and
// scope subset. Only verified claims may be supplied during authentication.
func (s *Store) Authorize(id,owner string,scopes []string,audience string) error {
	if err:=passport.ValidateIdentity(id,owner,scopes); err!=nil { return ErrDenied }
	if err:=passport.ValidateAudience(audience); err!=nil { return ErrDenied }
	a,suspended,err:=s.Get(id)
	if err!=nil { return err }
	if suspended { return fmt.Errorf("%w: suspended agent",ErrDenied) }
	if a.Owner!=owner || !contains(a.Audiences,audience) { return ErrDenied }
	for _,scope:=range scopes { if !contains(a.Scopes,scope) { return ErrDenied } }
	return nil
}
