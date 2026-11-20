package registry

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Leonidas144k/kgaga/internal/passport"
)

const EnrollmentTTL = 5*time.Minute

type enrollmentChallenge struct {
	AgentID string `json:"agent_id"`
	IssuedAt int64 `json:"issued_at"`
}

func (s *Store) challengePath(id string) (string,error) {
	if err:=passport.ValidateEnrollmentChallenge(id); err!=nil { return "",err }
	if err:=s.Ready(); err!=nil { return "",err }
	return filepath.Join(s.dir,"challenge-"+id),nil
}

// NewChallenge creates a short-lived challenge scoped to one proposed agent.
// This is an operator action, not a public self-registration endpoint.
func (s *Store) NewChallenge(agent string) (string,error) {
	return s.newChallengeAt(agent,time.Now())
}

func (s *Store) newChallengeAt(agent string,now time.Time) (string,error) {
	if _,err:=s.base(agent); err!=nil { return "",err }
	random:=make([]byte,32)
	if _,err:=rand.Read(random); err!=nil { return "",err }
	id:=hex.EncodeToString(random)
	path,err:=s.challengePath(id)
	if err!=nil { return "",err }
	raw,err:=json.Marshal(enrollmentChallenge{AgentID:agent,IssuedAt:now.Unix()})
	if err!=nil { return "",err }
	f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
	if err!=nil { return "",err }
	if _,err:=f.Write(raw); err!=nil { _=f.Close(); return "",err }
	if err:=f.Sync(); err!=nil { _=f.Close(); return "",err }
	if err:=f.Close(); err!=nil { return "",err }
	if err:=s.Ready(); err!=nil { return "",err }
	return id,nil
}

// RegisterAttested verifies an enrollment proof and atomically consumes its
// challenge before publishing the immutable agent record. A failure after
// consumption requires a fresh challenge, never reuse of the old one.
func (s *Store) RegisterAttested(a Agent,challenge,signature string) error {
	return s.registerAttestedAt(a,challenge,signature,time.Now())
}

func (s *Store) registerAttestedAt(a Agent,challenge,signature string,now time.Time) error {
	if err:=validate(a); err!=nil { return err }
	key,err:=decodeHolder(a.HolderKey)
	if err!=nil { return err }
	path,err:=s.challengePath(challenge)
	if err!=nil { return err }
	info,err:=os.Lstat(path)
	if err!=nil { return fmt.Errorf("enrolment challenge unavailable: %w",err) }
	if !info.Mode().IsRegular() || info.Size()>4096 { return errors.New("invalid enrolment challenge record") }
	f,err:=os.Open(path)
	if err!=nil { return err }
	raw,err:=io.ReadAll(io.LimitReader(f,4097))
	closeErr:=f.Close()
	if err!=nil { return err }
	if closeErr!=nil { return closeErr }
	if len(raw)>4096 { return errors.New("invalid enrolment challenge record") }
	var c enrollmentChallenge
	if err:=json.Unmarshal(raw,&c); err!=nil { return err }
	if c.AgentID!=a.ID || c.IssuedAt<=0 || c.IssuedAt>now.Unix() || c.IssuedAt<now.Unix()-int64(EnrollmentTTL/time.Second) {
		return errors.New("enrolment challenge expired or agent mismatch")
	}
	if err:=passport.VerifyEnrollment(signature,challenge,a.ID,a.Owner,a.Scopes,a.Audiences,key); err!=nil { return err }
	if err:=s.Ready(); err!=nil { return err }
	used,err:=os.OpenFile(path+".used",os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
	if os.IsExist(err) { return errors.New("enrolment challenge already consumed") }
	if err!=nil { return err }
	if err:=used.Sync(); err!=nil { _=used.Close(); return err }
	if err:=used.Close(); err!=nil { return err }
	return s.Register(a)
}
