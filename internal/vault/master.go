package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const masterMagic = "KGM1"
const masterBytes = len(masterMagic)+16+16+32

var ErrMasterKey = errors.New("vault master key unavailable or mismatched")

// ManagedStore holds one operator-controlled KEK snapshot in memory.
// It is a trusted internal API, not an agent-facing secret retrieval API.
// Restart/reopen is required to change the key; no runtime retirement yet.
type ManagedStore struct {
	store *Store
	kek Key
	kekID ID
}

// masterPath requires a private external parent directory. The expected
// vault and key IDs are independent operator inputs, not read from untrusted
// encrypted records. The operator must protect the entire path hierarchy.
func (s *Store) masterPath(path string)(string,error) {
	if err:=s.Ready(); err!=nil { return "",err }
	if path=="" { return "",ErrMasterKey }
	abs,err:=filepath.Abs(path)
	if err!=nil { return "",ErrMasterKey }
	parent,err:=filepath.EvalSymlinks(filepath.Dir(abs))
	if err!=nil { return "",ErrMasterKey }
	info,err:=os.Lstat(parent)
	if err!=nil || !privateDir(info) { return "",ErrMasterKey }
	root,err:=filepath.EvalSymlinks(s.dir)
	if err!=nil { return "",ErrMasterKey }
	rel,err:=filepath.Rel(root,parent)
	if err!=nil || (rel!=".." && !strings.HasPrefix(rel,".."+string(os.PathSeparator))) { return "",ErrMasterKey }
	// Reject a physical directory alias to the opened store as well.
	if os.SameFile(info,s.info) { return "",ErrMasterKey }
	return filepath.Join(parent,filepath.Base(abs)),nil
}

// CreateMasterKey exclusively creates a private raw KEK file outside
// the encrypted store. The key is never printed or returned to the caller.
// This is local development custody, not hardware-backed key protection.
// A failed initialization must be examined offline; do not overwrite it.
func (s *Store) CreateMasterKey(path string,keyID ID) error {
	if keyID==(ID{}) { return ErrMasterKey }
	path,err:=s.masterPath(path)
	if err!=nil { return err }
	key,err:=GenerateKey()
	if err!=nil { return err }
	defer clear(key[:])
	raw:=make([]byte,0,masterBytes)
	raw=append(raw,masterMagic...)
	raw=append(raw,s.id[:]...)
	raw=append(raw,keyID[:]...)
	raw=append(raw,key[:]...)
	defer clear(raw)
	f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
	if err!=nil { return ErrMasterKey }
	info,err:=f.Stat()
	if err!=nil || !privateFile(info) { _=f.Close(); return ErrMasterKey }
	if _,err=f.Write(raw); err!=nil { _=f.Close(); return ErrMasterKey }
	if err=f.Sync(); err!=nil { _=f.Close(); return ErrMasterKey }
	if err=f.Close(); err!=nil { return ErrMasterKey }
	return s.Ready()
}

// OpenManaged loads the exact expected external key once. Removing the
// source file does not revoke the already loaded key. No fallback key,
// automatic creation, fallback to raw records, or password derivation.
func (s *Store) OpenManaged(path string,expectedKeyID ID)(*ManagedStore,error) {
	if expectedKeyID==(ID{}) { return nil,ErrMasterKey }
	path,err:=s.masterPath(path)
	if err!=nil { return nil,err }
	raw,_,err:=readPrivate(path,masterBytes)
	if err!=nil { return nil,ErrMasterKey }
	defer clear(raw)
	if len(raw)!=masterBytes || string(raw[:4])!=masterMagic ||
		!bytes.Equal(raw[4:20],s.id[:]) || !bytes.Equal(raw[20:36],expectedKeyID[:]) { return nil,ErrMasterKey }
	var key Key
	copy(key[:],raw[36:])
	defer clear(key[:])
	if key==(Key{}) { return nil,ErrMasterKey }
	if err:=s.Ready(); err!=nil { return nil,err }
	return &ManagedStore{store:s,kek:key,kekID:expectedKeyID},nil
}

func (m *ManagedStore) ready() error {
	if m==nil || m.store==nil || m.kek==(Key{}) || m.kekID==(ID{}) { return ErrMasterKey }
	return m.store.Ready()
}
