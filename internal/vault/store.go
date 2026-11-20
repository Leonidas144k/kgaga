package vault

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const DefaultDir = "kgaga-vault"
const manifestName = ".vault-id"
const manifestMagic = "KGS1"
const maxRecordBytes = MaxSecretBytes + len(recordMagic) + nonceBytes + tagBytes

var ErrStoreUnavailable = errors.New("vault store unavailable or unsafe")
var ErrRecordExists = errors.New("vault record version already exists")
var ErrRecordNotFound = errors.New("vault record version not found")

// Store is an immutable-record, operator-controlled local filesystem store.
// The caller must protect the parent directory and provide the expected vault
// ID and data keys from independent trusted state. It stores no plaintext keys.
type Store struct {
	dir string
	info os.FileInfo
	manifest os.FileInfo
	id ID
}

// Init creates an entirely new vault. Existing or partial directories are
// never replaced. Failure can leave a partial initialization for offline
// examination, not automatic recovery.
func Init(path string,id ID) error {
	if path=="" || id==(ID{}) { return ErrInvalidContext }
	abs,err:=filepath.Abs(path)
	if err!=nil { return err }
	if err:=os.Mkdir(abs,0700); err!=nil { return err }
	s:=append([]byte(manifestMagic),id[:]...)
	f,err:=os.OpenFile(filepath.Join(abs,manifestName),os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
	if err!=nil { return err }
	if _,err:=f.Write(s); err!=nil { _=f.Close(); return err }
	if err:=f.Sync(); err!=nil { _=f.Close(); return err }
	if err:=f.Close(); err!=nil { return err }
	if _,err:=Open(abs,id); err!=nil { return err }
	return nil
}

// Open requires an independently supplied expected ID. It never bootstraps
// missing state or accepts a different vault simply because the path exists.
func Open(path string,id ID)(*Store,error) {
	if path=="" || id==(ID{}) { return nil,ErrInvalidContext }
	abs,err:=filepath.Abs(path)
	if err!=nil { return nil,err }
	info,err:=os.Lstat(abs)
	if err!=nil || !privateDir(info) { return nil,ErrStoreUnavailable }
	raw,manifest,err:=readPrivate(filepath.Join(abs,manifestName),len(manifestMagic)+len(id))
	if err!=nil || !bytes.Equal(raw,append([]byte(manifestMagic),id[:]...)) { return nil,ErrStoreUnavailable }
	s:=&Store{dir:abs,info:info,manifest:manifest,id:id}
	if err:=s.Ready(); err!=nil { return nil,err }
	return s,nil
}

func privateDir(info os.FileInfo) bool {
	return info!=nil && info.IsDir() && info.Mode().Perm()==0700 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky)==0
}

func privateFile(info os.FileInfo) bool {
	return info!=nil && info.Mode().IsRegular() && info.Mode().Perm()==0600 && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky)==0
}

// readPrivate refuses symlinks, nonregular and over-permissive files,
// bounds reads and checks the opened file against its path identity.
// The path checks are not a defense against a malicious privileged writer
// racing filesystem operations; the operator must protect the hierarchy.
func readPrivate(path string,max int)([]byte,os.FileInfo,error) {
	before,err:=os.Lstat(path)
	if err!=nil { return nil,nil,err }
	if !privateFile(before) || before.Size()<1 || before.Size()>int64(max) { return nil,nil,ErrStoreUnavailable }
	f,err:=os.Open(path)
	if err!=nil { return nil,nil,err }
	defer f.Close()
	opened,err:=f.Stat()
	if err!=nil || !privateFile(opened) || !os.SameFile(before,opened) { return nil,nil,ErrStoreUnavailable }
	raw,err:=io.ReadAll(io.LimitReader(f,int64(max)+1))
	if err!=nil || len(raw)==0 || len(raw)>max { return nil,nil,ErrStoreUnavailable }
	after,err:=os.Lstat(path)
	if err!=nil || !privateFile(after) || !os.SameFile(opened,after) || after.Size()!=int64(len(raw)) { return nil,nil,ErrStoreUnavailable }
	return raw,after,nil
}

// Ready detects disappearance/replacement of the opened directory or
// manifest, permission changes and manifest corruption.
func (s *Store) Ready() error {
	if s==nil || s.info==nil || s.manifest==nil { return ErrStoreUnavailable }
	info,err:=os.Lstat(s.dir)
	if err!=nil || !privateDir(info) || !os.SameFile(info,s.info) { return ErrStoreUnavailable }
	raw,manifest,err:=readPrivate(filepath.Join(s.dir,manifestName),len(manifestMagic)+len(s.id))
	if err!=nil || !os.SameFile(manifest,s.manifest) || !bytes.Equal(raw,append([]byte(manifestMagic),s.id[:]...)) { return ErrStoreUnavailable }
	return nil
}

func (s *Store) recordPath(ctx RecordContext)(string,error) {
	if err:=ctx.validate(); err!=nil { return "",err }
	if err:=s.Ready(); err!=nil { return "",err }
	if ctx.VaultID!=s.id { return "",ErrInvalidContext }
	// The validated name cannot contain dots or path separators. Fixed-width
	// decimal version avoids aliases. KeyID is authenticated, not a path selector.
	return filepath.Join(s.dir,fmt.Sprintf("%s.%020d.kgv",ctx.Name,ctx.Version)),nil
}

// Put encrypts in memory and exclusively publishes one immutable version.
// A fresh, independent caller-owned data key is required for each version.
// No raw key or plaintext is written. Existing records are never overwritten.
// File Sync precedes publication, but power-loss durability is not promised.
func (s *Store) Put(key Key,ctx RecordContext,plaintext []byte) error {
	path,err:=s.recordPath(ctx)
	if err!=nil { return err }
	if _,err:=os.Lstat(path); err==nil { return ErrRecordExists } else if !os.IsNotExist(err) { return err }
	record,err:=SealRecord(key,ctx,plaintext)
	if err!=nil { return err }
	f,err:=os.CreateTemp(s.dir,".pending-")
	if err!=nil { return err }
	tmp:=f.Name()
	defer os.Remove(tmp)
	info,err:=f.Stat()
	if err!=nil || !privateFile(info) { _=f.Close(); return ErrStoreUnavailable }
	if _,err:=f.Write(record); err!=nil { _=f.Close(); return err }
	if err:=f.Sync(); err!=nil { _=f.Close(); return err }
	if err:=f.Close(); err!=nil { return err }
	if err:=s.Ready(); err!=nil { return err }
	// Hard-link creation is exclusive, including across cooperating writers.
	// Unlike rename, it cannot replace the destination.
	if err:=os.Link(tmp,path); err!=nil {
		if os.IsExist(err) { return ErrRecordExists }
		return err
	}
	// Once published, a later failure is ambiguous to the caller. Never undo
	// publication automatically: retry cannot overwrite the winning record.
	return s.Ready()
}

// Get authenticates the expected version and returns its plaintext only
// to the trusted caller. Missing state, wrong metadata or keys fail closed.
func (s *Store) Get(key Key,ctx RecordContext)([]byte,error) {
	path,err:=s.recordPath(ctx)
	if err!=nil { return nil,err }
	record,_,err:=readPrivate(path,maxRecordBytes)
	if err!=nil {
		if err:=s.Ready(); err!=nil { return nil,err }
		if os.IsNotExist(err) { return nil,ErrRecordNotFound }
		return nil,ErrStoreUnavailable
	}
	p,err:=OpenRecord(key,ctx,record)
	if err!=nil { return nil,err }
	if err:=s.Ready(); err!=nil { clear(p); return nil,err }
	return p,nil
}
