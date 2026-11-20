package vault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"
)

const timedMagic = "KGL1"
const timedHeader = len(timedMagic)+16
const MaxCredentialLifetime = time.Hour

var ErrCredentialValidity = errors.New("vault credential outside validity window")
var ErrCredentialFormat = errors.New("invalid timed vault credential")

// A timed bearer is an authenticated plaintext inside the existing KGE1
// envelope. These operator-declared times do not establish provider expiry.
func validWindow(start,end int64) bool {
	return start>0 && end>start && end-start<=int64(MaxCredentialLifetime/time.Second)
}

func encodeTimedBearer(token []byte,start,end int64)([]byte,error) {
	if !validWindow(start,end) { return nil,ErrCredentialValidity }
	if ValidateBearer(token)!=nil { return nil,ErrCredentialFormat }
	raw:=make([]byte,timedHeader+len(token))
	copy(raw,timedMagic)
	binary.BigEndian.PutUint64(raw[4:12],uint64(start))
	binary.BigEndian.PutUint64(raw[12:20],uint64(end))
	copy(raw[timedHeader:],token)
	return raw,nil
}

func decodeTimedBearer(raw []byte,now time.Time)([]byte,time.Time,error) {
	if len(raw)<timedHeader+16 || len(raw)>timedHeader+4096 || string(raw[:4])!=timedMagic { return nil,time.Time{},ErrCredentialFormat }
	start:=int64(binary.BigEndian.Uint64(raw[4:12]))
	end:=int64(binary.BigEndian.Uint64(raw[12:20]))
	if !validWindow(start,end) { return nil,time.Time{},ErrCredentialFormat }
	if ValidateBearer(raw[timedHeader:])!=nil { return nil,time.Time{},ErrCredentialFormat }
	if now.Unix()<start || now.Unix()>=end { return nil,time.Time{},ErrCredentialValidity }
	return bytes.Clone(raw[timedHeader:]),time.Unix(end,0),nil
}

// PutBearer publishes a new immutable timed credential. The caller
// supplies trusted issuer validity metadata; no automatic renewal occurs.
func (m *ManagedStore) PutBearer(name string,version uint64,token []byte,start,end int64) error {
	raw,err:=encodeTimedBearer(token,start,end)
	if err!=nil { return err }
	defer clear(raw)
	if time.Now().Unix()>=end { return ErrCredentialValidity }
	return m.Put(name,version,raw)
}

// GetBearer authenticates both the token and its validity metadata before
// returning a caller-owned buffer. Untimed legacy records are denied.
func (m *ManagedStore) GetBearer(name string,version uint64)([]byte,time.Time,error) {
	raw,err:=m.Get(name,version)
	if err!=nil { return nil,time.Time{},err }
	defer clear(raw)
	return decodeTimedBearer(raw,time.Now())
}
