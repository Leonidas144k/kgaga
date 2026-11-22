package ledger

import (
 "bytes"
 "crypto/hmac"
 "crypto/sha256"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "os"
 "path/filepath"
 "strings"
 "sync"

 "github.com/Leonidas144k/kgaga/internal/audit"
)

const checkpointFilename="checkpoint.json"
const checkpointLockName=".checkpoint-lock"
const checkpointSchema="kgaga.ledger.checkpoint.v1"
const maxCheckpointBytes=1024

var ErrAnchor=errors.New("ledger checkpoint storage unavailable or unsafe")
var ErrAnchorLocked=errors.New("ledger checkpoint writer lock unavailable")

type checkpointRecord struct {
 Schema string `json:"schema"`
 StreamID string `json:"stream_id"`
 Sequence uint64 `json:"sequence"`
 MAC string `json:"mac"`
 WitnessMAC string `json:"witness_mac"`
}

// CheckpointStore is a separate local authenticated snapshot of the latest
// journal head. Its authentication key must be independently protected.
// A valid old snapshot can be rolled back: an independently retained Head
// is REQUIRED by OpenCheckpoint. This is NOT an external trust service.
type CheckpointStore struct {
 mu sync.Mutex
 dir string
 dirInfo os.FileInfo
 lock string
 lockInfo os.FileInfo
 path string
 key Key
 id StreamID
 current Head
 failed bool
 closed bool
}

func checkpointMAC(key Key,id StreamID,h Head)([32]byte,error){
 var result [32]byte
 value,err:=parseJournalHead(h,id)
 if err!=nil {return result,ErrCheckpoint}
 m:=hmac.New(sha256.New,key[:])
 m.Write([]byte("kgaga-ledger:checkpoint:v1\x00"))
 m.Write(id[:])
 var seq [8]byte
 binary.BigEndian.PutUint64(seq[:],h.Sequence)
 m.Write(seq[:])
 m.Write(value[:])
 copy(result[:],m.Sum(nil))
 return result,nil
}

func checkpointBytes(key Key,id StreamID,h Head)([]byte,error){
 mac,err:=checkpointMAC(key,id,h)
 if err!=nil{return nil,err}
 r:=checkpointRecord{Schema:checkpointSchema,StreamID:h.StreamID,
 Sequence:h.Sequence,MAC:h.MAC,WitnessMAC:hex.EncodeToString(mac[:])}
 raw,err:=json.Marshal(r)
 if err!=nil || len(raw)+1>maxCheckpointBytes{return nil,ErrAnchor}
 return append(raw,'\n'),nil
}

func parseCheckpoint(raw []byte,key Key,id StreamID)(Head,error){
 if len(raw)==0 || len(raw)>maxCheckpointBytes || raw[len(raw)-1]!='\n'{
  return Head{},ErrCheckpoint
 }
 var r checkpointRecord
 if json.Unmarshal(raw[:len(raw)-1],&r)!=nil{return Head{},ErrCheckpoint}
 canonical,err:=json.Marshal(r)
 if err!=nil || !bytes.Equal(canonical,raw[:len(raw)-1]) || r.Schema!=checkpointSchema{
  return Head{},ErrCheckpoint
 }
 h:=Head{StreamID:r.StreamID,Sequence:r.Sequence,MAC:r.MAC}
 expected,err:=checkpointMAC(key,id,h)
 if err!=nil{return Head{},ErrCheckpoint}
 provided,err:=hex.DecodeString(r.WitnessMAC)
 if err!=nil || len(provided)!=len(expected) ||
 r.WitnessMAC!=hex.EncodeToString(provided) ||
 !hmac.Equal(provided,expected[:]){return Head{},ErrCheckpoint}
 return h,nil
}

func checkedCheckpointFile(path string)([]byte,error){
 before,err:=os.Lstat(path)
 if err!=nil || !journalFile(before) || before.Size()>maxCheckpointBytes{return nil,ErrAnchor}
 f,err:=os.Open(path)
 if err!=nil{return nil,ErrAnchor}
 defer f.Close()
 actual,err:=f.Stat()
 if err!=nil || !journalFile(actual) || !os.SameFile(before,actual){return nil,ErrAnchor}
 raw,err:=io.ReadAll(io.LimitReader(f,maxCheckpointBytes+1))
 if err!=nil || len(raw)>maxCheckpointBytes{return nil,ErrAnchor}
 after,err:=os.Lstat(path)
 if err!=nil || !journalFile(after) || !os.SameFile(before,after){return nil,ErrAnchor}
 return raw,nil
}

func checkpointDirectory(dir string)(string,error){
 abs,err:=journalParent(dir)
 if err!=nil{return "",ErrAnchor}
 return abs,nil
}

func openCheckpointStore(abs string,key Key,id StreamID,h Head)(*CheckpointStore,error){
 di,err:=os.Lstat(abs)
 if err!=nil || !journalDir(di){return nil,ErrAnchor}
 li,err:=os.Lstat(filepath.Join(abs,checkpointLockName))
 if err!=nil || !journalDir(li){return nil,ErrAnchor}
 return &CheckpointStore{dir:abs,dirInfo:di,lock:filepath.Join(abs,checkpointLockName),
 lockInfo:li,path:filepath.Join(abs,checkpointFilename),key:key,id:id,current:h},nil
}

// InitCheckpoint initializes an entirely new directory, with a private lock
// and authenticated genesis. Failure may leave a partial directory/lock.
// Never reinitialize an existing directory without controlled inspection.
func InitCheckpoint(dir string,key Key,id StreamID,genesis Head)(*CheckpointStore,error){
 if key==(Key{}) || id==(StreamID{}){return nil,ErrInvalid}
 raw,err:=checkpointBytes(key,id,genesis)
 if err!=nil{return nil,err}
 abs,err:=checkpointDirectory(dir)
 if err!=nil{return nil,err}
 if err:=os.Mkdir(abs,0700);err!=nil{return nil,ErrAnchor}
 if err:=os.Mkdir(filepath.Join(abs,checkpointLockName),0700);err!=nil{return nil,ErrAnchor}
 path:=filepath.Join(abs,checkpointFilename)
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return nil,ErrAnchor}
 n,err:=f.Write(raw)
 if err!=nil || n!=len(raw){_ =f.Close();return nil,ErrAnchor}
 if err:=f.Sync();err!=nil{_ =f.Close();return nil,ErrAnchor}
 if err:=f.Close();err!=nil{return nil,ErrAnchor}
 if err:=syncJournalDir(abs);err!=nil{return nil,err}
 if err:=syncJournalDir(filepath.Dir(abs));err!=nil{return nil,err}
 return openCheckpointStore(abs,key,id,genesis)
}

// OpenCheckpoint requires the EXPECTED Head from a genuinely independent
// trust source. Replaying an older authentic checkpoint fails against that
// external expectation. Opening is exclusive across cooperating writers.
func OpenCheckpoint(dir string,key Key,id StreamID,expected Head)(*CheckpointStore,error){
 if key==(Key{}) || id==(StreamID{}){return nil,ErrInvalid}
 if _,err:=checkpointMAC(key,id,expected);err!=nil{return nil,err}
 abs,err:=checkpointDirectory(dir)
 if err!=nil{return nil,err}
 di,err:=os.Lstat(abs)
 if err!=nil || !journalDir(di){return nil,ErrAnchor}
 lock:=filepath.Join(abs,checkpointLockName)
 if err:=os.Mkdir(lock,0700);err!=nil{return nil,ErrAnchorLocked}
 acquired:=false
 defer func(){if !acquired{_ =os.Remove(lock)}}()
 raw,err:=checkedCheckpointFile(filepath.Join(abs,checkpointFilename))
 if err!=nil{return nil,err}
 actual,err:=parseCheckpoint(raw,key,id)
 if err!=nil{return nil,err}
 if actual!=expected{return nil,ErrCheckpoint}
 s,err:=openCheckpointStore(abs,key,id,actual)
 if err!=nil{return nil,err}
 acquired=true
 return s,nil
}

func(s *CheckpointStore)check()error{
 if s==nil || s.failed || s.closed{return ErrAnchor}
 di,err:=os.Lstat(s.dir)
 if err!=nil || !journalDir(di) || !os.SameFile(di,s.dirInfo){return ErrAnchor}
 li,err:=os.Lstat(s.lock)
 if err!=nil || !journalDir(li) || !os.SameFile(li,s.lockInfo){return ErrAnchor}
 raw,err:=checkedCheckpointFile(s.path)
 if err!=nil{return err}
 actual,err:=parseCheckpoint(raw,s.key,s.id)
 if err!=nil || actual!=s.current{return ErrCheckpoint}
 return nil
}

// Publish requires the next sequential journal head. The caller MUST
// separately verify that the journal has fsynced this exact head.
// It syncs an exclusive temp file, atomically replaces the snapshot and
// syncs the checkpoint directory. Errors are ambiguous and latch storage.
func(s *CheckpointStore)Publish(next Head)error{
 if s==nil{return ErrAnchor}
 s.mu.Lock();defer s.mu.Unlock()
 if err:=s.check();err!=nil{s.failed=true;return err}
 if next.StreamID!=s.current.StreamID || next.Sequence!=s.current.Sequence+1 {
  return ErrCheckpoint
 }
 raw,err:=checkpointBytes(s.key,s.id,next)
 if err!=nil{return err}
 f,err:=os.CreateTemp(s.dir,".checkpoint-pending-")
 if err!=nil{s.failed=true;return ErrAnchor}
 tmp:=f.Name()
 defer os.Remove(tmp)
 info,err:=f.Stat()
 if err!=nil || !journalFile(info){s.failed=true;_ =f.Close();return ErrAnchor}
 n,err:=f.Write(raw)
 if err!=nil || n!=len(raw){s.failed=true;_ =f.Close();return ErrAnchor}
 if err:=f.Sync();err!=nil{s.failed=true;_ =f.Close();return ErrAnchor}
 if err:=f.Close();err!=nil{s.failed=true;return ErrAnchor}
 if err:=s.check();err!=nil{s.failed=true;return err}
 if err:=os.Rename(tmp,s.path);err!=nil{s.failed=true;return ErrAnchor}
 s.current=next
 if err:=syncJournalDir(s.dir);err!=nil{s.failed=true;return ErrAnchor}
 return nil
}

func(s *CheckpointStore)Head()(Head,error){
 if s==nil{return Head{},ErrAnchor}
 s.mu.Lock();defer s.mu.Unlock()
 if err:=s.check();err!=nil{s.failed=true;return Head{},err}
 return s.current,nil
}

// Close does not clear a crash lock after ambiguous writes or integrity
// failures. A clean close syncs the directory before returning success.
func(s *CheckpointStore)Close()error{
 if s==nil{return ErrAnchor}
 s.mu.Lock();defer s.mu.Unlock()
 if err:=s.check();err!=nil{s.failed=true;return err}
 s.closed=true
 if err:=os.Remove(s.lock);err!=nil{return ErrAnchor}
 if err:=syncJournalDir(s.dir);err!=nil{return ErrAnchor}
 clear(s.key[:])
 return nil
}

// AnchoredJournal orders journal fsync BEFORE checkpoint publication.
// Crashes between these two operations intentionally require offline
// investigation rather than automatic truncation or replay.
type AnchoredJournal struct{
 mu sync.Mutex
 journal *Journal
 checkpoint *CheckpointStore
 failed bool
 closed bool
}

func separatedDirs(journalDir,checkpointDir string)bool{
 j,err:=filepath.Abs(journalDir)
 if err!=nil{return false}
 c,err:=filepath.Abs(checkpointDir)
 if err!=nil{return false}
 nested:=func(parent,child string)bool {
  relative,e:=filepath.Rel(parent,child)
  if e!=nil{return true}
  return relative=="." || (relative!=".." && !strings.HasPrefix(relative,".."+string(os.PathSeparator)))
 }
 return !nested(j,c) && !nested(c,j)
}

func InitAnchoredJournal(journalDir,checkpointDir string,chainKey,witnessKey Key,id StreamID)(*AnchoredJournal,error){
 if !separatedDirs(journalDir,checkpointDir) || chainKey==witnessKey{return nil,ErrInvalid}
 j,err:=InitJournal(journalDir,chainKey,id)
 if err!=nil{return nil,err}
 genesis,err:=j.Head()
 if err!=nil{return nil,err}
 s,err:=InitCheckpoint(checkpointDir,witnessKey,id,genesis)
 if err!=nil{return nil,err}
 return &AnchoredJournal{journal:j,checkpoint:s},nil
}

func OpenAnchoredJournal(journalDir,checkpointDir string,chainKey,witnessKey Key,id StreamID,expected Head)(*AnchoredJournal,error){
 if !separatedDirs(journalDir,checkpointDir) || chainKey==witnessKey{return nil,ErrInvalid}
 s,err:=OpenCheckpoint(checkpointDir,witnessKey,id,expected)
 if err!=nil{return nil,err}
 j,err:=OpenJournal(journalDir,chainKey,id,expected)
 if err!=nil{
  // A mismatch may indicate an interrupted commit or tampering.
  // Leave checkpoint lock in place for offline investigation.
  return nil,err
 }
 return &AnchoredJournal{journal:j,checkpoint:s},nil
}

func(a *AnchoredJournal)Append(e audit.Event)(Head,error){
 if a==nil{return Head{},ErrAnchor}
 a.mu.Lock();defer a.mu.Unlock()
 if a.failed || a.closed{return Head{},ErrAnchor}
 if _,err:=a.checkpoint.Head();err!=nil{a.failed=true;return Head{},err}
 next,err:=a.journal.Append(e)
 if err!=nil{a.failed=true;return Head{},err}
 if err:=a.checkpoint.Publish(next);err!=nil{
  a.failed=true
  a.journal.failed=true // Preserve crash lock on uncertain commit.
  return Head{},err
 }
 return next,nil
}

func(a *AnchoredJournal)Head()(Head,error){
 if a==nil{return Head{},ErrAnchor}
 a.mu.Lock();defer a.mu.Unlock()
 if a.failed || a.closed{return Head{},ErrAnchor}
 journalHead,err:=a.journal.Head()
 if err!=nil{a.failed=true;return Head{},err}
 checkHead,err:=a.checkpoint.Head()
 if err!=nil || journalHead!=checkHead{a.failed=true;return Head{},ErrCheckpoint}
 return journalHead,nil
}

func(a *AnchoredJournal)Close()error{
 if a==nil{return ErrAnchor}
 a.mu.Lock();defer a.mu.Unlock()
 if a.failed || a.closed{return ErrAnchor}
 jhead,err:=a.journal.Head()
 if err!=nil{return err}
 chead,err:=a.checkpoint.Head()
 if err!=nil || jhead!=chead{return ErrCheckpoint}
 if err:=a.journal.Close();err!=nil{a.failed=true;return err}
 if err:=a.checkpoint.Close();err!=nil{a.failed=true;return err}
 a.closed=true
 return nil
}
