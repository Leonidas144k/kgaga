package vault

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"
)

const lifecycleMagic = "KGC1"
const maxFutureRevocations = 256
const lifecycleHeader = len(lifecycleMagic)+8+1+2
const maxLifecycleBytes = lifecycleHeader+8*maxFutureRevocations+sha256.Size

var ErrInactiveVersion = errors.New("vault credential version is not active")
var ErrLifecycleState = errors.New("invalid vault lifecycle state")
var ErrLifecycleBusy = errors.New("vault lifecycle update busy")
var ErrLifecycleCapacity = errors.New("vault future revocation capacity reached")

// high is the highest ever activated version. All lower versions are
// permanently retired within maintained state. A revoked high version
// stays as the high-water mark. Future revocations are sorted and bounded.
type lifecycleState struct {
	high uint64
	revoked bool
	future []uint64
}

func (m *ManagedStore) lifecyclePath(name string)(string,error) {
	if _,_,err:=m.slot(name,1); err!=nil { return "",err }
	return filepath.Join(m.store.dir,".lifecycle-"+name),nil
}

// Derive a separate MAC key, then authenticate format, vault identity,
// KEK identity, exact name and state payload. This detects modification
// and cross-record substitution, not rollback of a valid state file.
func (m *ManagedStore) lifecycleMAC(name string,payload []byte) []byte {
	kdf:=hmac.New(sha256.New,m.kek[:])
	kdf.Write([]byte("kgaga-vault:lifecycle-mac-key:v1"))
	key:=kdf.Sum(nil)
	defer clear(key)
	mac:=hmac.New(sha256.New,key)
	mac.Write([]byte("kgaga-vault:lifecycle:v1\x00"))
	mac.Write(m.store.id[:])
	mac.Write(m.kekID[:])
	mac.Write([]byte{byte(len(name))})
	mac.Write([]byte(name))
	mac.Write(payload)
	return mac.Sum(nil)
}

func (m *ManagedStore) encodeLifecycle(name string,s lifecycleState) []byte {
	raw:=make([]byte,lifecycleHeader+8*len(s.future))
	copy(raw,lifecycleMagic)
	binary.BigEndian.PutUint64(raw[4:12],s.high)
	if s.revoked { raw[12]=1 }
	binary.BigEndian.PutUint16(raw[13:15],uint16(len(s.future)))
	for i,v:=range s.future { binary.BigEndian.PutUint64(raw[15+8*i:23+8*i],v) }
	return append(raw,m.lifecycleMAC(name,raw)...)
}

func (m *ManagedStore) decodeLifecycle(name string,raw []byte)(lifecycleState,error) {
	var s lifecycleState
	if len(raw)<lifecycleHeader+sha256.Size || len(raw)>maxLifecycleBytes || string(raw[:4])!=lifecycleMagic { return s,ErrLifecycleState }
	payload:=raw[:len(raw)-sha256.Size]
	if !hmac.Equal(raw[len(payload):],m.lifecycleMAC(name,payload)) { return s,ErrLifecycleState }
	n:=int(binary.BigEndian.Uint16(payload[13:15]))
	if n>maxFutureRevocations || len(payload)!=lifecycleHeader+8*n || payload[12]>1 { return s,ErrLifecycleState }
	s.high=binary.BigEndian.Uint64(payload[4:12])
	s.revoked=payload[12]==1
	if s.high==0 && s.revoked { return lifecycleState{},ErrLifecycleState }
	last:=s.high
	for i:=0;i<n;i++ {
		v:=binary.BigEndian.Uint64(payload[15+8*i:23+8*i])
		if v<=last { return lifecycleState{},ErrLifecycleState }
		s.future=append(s.future,v)
		last=v
	}
	return s,nil
}

func (m *ManagedStore) readLifecycle(name,path string)(lifecycleState,error) {
	raw,_,err:=readPrivate(path,maxLifecycleBytes)
	if check:=m.ready(); check!=nil { return lifecycleState{},check }
	if os.IsNotExist(err) { return lifecycleState{},nil }
	if err!=nil { return lifecycleState{},ErrLifecycleState }
	return m.decodeLifecycle(name,raw)
}

// CheckActive reads live state, never an in-memory cache. An absent state
// denies all versions. Trusted raw Get/GetBearer remain operator-only.
func (m *ManagedStore) CheckActive(name string,version uint64) error {
	if version==0 { return ErrInactiveVersion }
	path,err:=m.lifecyclePath(name)
	if err!=nil { return err }
	s,err:=m.readLifecycle(name,path)
	if err!=nil { return err }
	if s.high!=version || s.revoked { return ErrInactiveVersion }
	return nil
}

func (m *ManagedStore) GetActiveBearer(name string,version uint64)([]byte,time.Time,error) {
	if err:=m.CheckActive(name,version); err!=nil { return nil,time.Time{},err }
	p,expiry,err:=m.GetBearer(name,version)
	if err!=nil { return nil,time.Time{},err }
	if err:=m.CheckActive(name,version); err!=nil { clear(p); return nil,time.Time{},err }
	return p,expiry,nil
}

// Administrative changes are serialized across cooperating processes
// using exclusive mkdir. No automatic stale lock breaking or state
// recreation after detected corruption. Readers see an atomic snapshot
// or fail closed if a replacement races the file identity checks.
func (m *ManagedStore) updateLifecycle(name string,fn func(*lifecycleState) error)(result error) {
	path,err:=m.lifecyclePath(name)
	if err!=nil { return err }
	lock:=path+".lock"
	if err:=os.Mkdir(lock,0700); err!=nil {
		if os.IsExist(err) { return ErrLifecycleBusy }
		return ErrLifecycleState
	}
	defer func(){
		if err:=m.ready(); err!=nil { result=err; return }
		if err:=os.Remove(lock); err!=nil { result=ErrLifecycleState }
	}()
	s,err:=m.readLifecycle(name,path)
	if err!=nil { return err }
	if err:=fn(&s); err!=nil { return err }
	raw:=m.encodeLifecycle(name,s)
	f,err:=os.CreateTemp(m.store.dir,".lifecycle-pending-")
	if err!=nil { return err }
	tmp:=f.Name()
	defer os.Remove(tmp)
	info,err:=f.Stat()
	if err!=nil || !privateFile(info) { _=f.Close(); return ErrLifecycleState }
	if _,err:=f.Write(raw); err!=nil { _=f.Close(); return err }
	if err:=f.Sync(); err!=nil { _=f.Close(); return err }
	if err:=f.Close(); err!=nil { return err }
	if err:=m.ready(); err!=nil { return err }
	if err:=os.Rename(tmp,path); err!=nil { return err }
	// Publication has happened; a later I/O failure is ambiguous.
	// Do not roll the state back or remove an existing state file.
	d,err:=os.Open(m.store.dir)
	if err!=nil { return err }
	defer d.Close()
	if err:=d.Sync(); err!=nil { return err }
	return m.ready()
}

// Activate selects a strictly higher, already provisioned, currently
// valid timed version. Rotating retires every lower version. No fallback.
func (m *ManagedStore) Activate(name string,version uint64) error {
	if version==0 { return ErrInactiveVersion }
	return m.updateLifecycle(name,func(s *lifecycleState) error {
		if version<=s.high || slices.Contains(s.future,version) { return ErrInactiveVersion }
		p,_,err:=m.GetBearer(name,version)
		if err!=nil { return err }
		clear(p)
		s.high=version
		s.revoked=false
		s.future=slices.DeleteFunc(s.future,func(v uint64)bool{return v<version})
		return nil
	})
}

// RevokeVersion permanently denies the active or a future staged
// version. Future revocation does not disable the current active version.
// Revoking an already retired/revoked version is idempotent.
func (m *ManagedStore) RevokeVersion(name string,version uint64) error {
	if version==0 { return ErrInactiveVersion }
	return m.updateLifecycle(name,func(s *lifecycleState) error {
		if version<s.high { return nil }
		if version==s.high { s.revoked=true; return nil }
		if slices.Contains(s.future,version) { return nil }
		if len(s.future)>=maxFutureRevocations { return ErrLifecycleCapacity }
		s.future=append(s.future,version)
		slices.Sort(s.future)
		return nil
	})
}
