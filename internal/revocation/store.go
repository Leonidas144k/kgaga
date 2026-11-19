// Package revocation implements a single-host, operator-controlled passport denylist.
package revocation

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const DefaultDir = "kgaga-revocations"

var ErrRevoked = errors.New("passport revoked")

// Store pins the directory identity for the lifetime of the process.
// Its directory and parent must be protected from untrusted writes.
type Store struct {
	dir string
	info os.FileInfo
}

// Init creates a new store, never replacing an existing one. Do not recreate
// a missing store after data loss; restore the trusted state instead.
func Init(path string) error {
	if path == "" {
		return errors.New("revocation directory is required")
	}
	return os.Mkdir(path, 0700)
}

// Open requires an existing directory; no implicit empty-store fallback.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("revocation directory is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil { return nil, err }
	info, err := os.Lstat(abs)
	if err != nil { return nil, fmt.Errorf("open revocation store: %w", err) }
	if !info.IsDir() { return nil, errors.New("revocation store must be a real directory") }
	s := &Store{dir:abs,info:info}
	if err := s.ready(); err != nil { return nil, err }
	return s,nil
}

func (s *Store) ready() error {
	if s == nil || s.info == nil { return errors.New("revocation store unavailable") }
	current, err := os.Lstat(s.dir)
	if err != nil { return fmt.Errorf("revocation store unavailable: %w",err) }
	if !current.IsDir() || !os.SameFile(current,s.info) {
		return errors.New("revocation store was replaced")
	}
	return nil
}

func (s *Store) marker(id string) (string,error) {
	// IDs are exactly 16 random bytes represented as lowercase hex.
	if len(id)!=32 || strings.ToLower(id)!=id {
		return "", errors.New("invalid passport ID")
	}
	if _,err:=hex.DecodeString(id); err!=nil {
		return "", errors.New("invalid passport ID")
	}
	if err:=s.ready(); err!=nil { return "",err }
	return filepath.Join(s.dir,id),nil
}

// Check returns ErrRevoked for an existing marker, nil for a valid lookup
// with no marker, or an error when the store cannot be checked.
func (s *Store) Check(id string) error {
	path,err:=s.marker(id)
	if err!=nil { return err }
	_,err=os.Lstat(path)
	if err==nil { return ErrRevoked }
	if !os.IsNotExist(err) { return fmt.Errorf("check revocation: %w",err) }
	// A missing directory must never look like an unrevoked ID.
	return s.ready()
}

// Ready verifies that the originally opened directory still exists.
func (s *Store) Ready() error { return s.ready() }

// Revoke creates an empty marker exclusively; concurrent writers cannot lose
// another revocation. An existing marker is already revoked. Normal process
// restarts preserve state; this is not a power-loss or tamper-proof database.
func (s *Store) Revoke(id string) error {
	path,err:=s.marker(id)
	if err!=nil { return err }
	f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
	if os.IsExist(err) { return s.ready() }
	if err!=nil { return fmt.Errorf("record revocation: %w",err) }
	if err:=f.Sync(); err!=nil { _=f.Close(); return err }
	if err:=f.Close(); err!=nil { return err }
	return s.ready()
}
