package ledger

import (
 "errors"
 "encoding/hex"

 "github.com/Leonidas144k/kgaga/internal/audit"
 "io"
 "os"
 "path/filepath"
 "sync"
)

const journalFilename="ledger.jsonl"
const journalLockName=".writer-lock"
const maxJournalBytes=int64(64<<20)

var ErrJournal=errors.New("ledger journal unavailable or unsafe")
var ErrJournalLocked=errors.New("ledger journal writer lock unavailable")
var ErrCheckpoint=errors.New("ledger checkpoint mismatch")

// Journal is a single-host, cooperating-writer POSIX development preview.
// It owns a private journal file and a directory lock for its whole life.
// Missing/abandoned locks must never be automatically broken on startup.
type Journal struct {
 mu sync.Mutex
 dir string
 dirInfo os.FileInfo
 lock string
 lockInfo os.FileInfo
 path string
 fileInfo os.FileInfo
 file *os.File
 chain *Writer
 failed bool
 closed bool
}

func journalDir(info os.FileInfo) bool {
 return info!=nil && info.IsDir() && info.Mode().Perm()==0700 &&
  info.Mode()&os.ModeSymlink==0
}

func journalFile(info os.FileInfo) bool {
 return info!=nil && info.Mode().IsRegular() && info.Mode().Perm()==0600 &&
  info.Mode()&os.ModeSymlink==0
}

func journalParent(dir string)(string,error) {
 if dir==""{return "",ErrJournal}
 abs,err:=filepath.Abs(dir)
 if err!=nil {return "",ErrJournal}
 parent,err:=os.Lstat(filepath.Dir(abs))
 if err!=nil || !journalDir(parent) {return "",ErrJournal}
 return abs,nil
}

func syncJournalDir(dir string)error{
 d,err:=os.Open(dir)
 if err!=nil{return ErrJournal}
 defer d.Close()
 if err:=d.Sync();err!=nil{return ErrJournal}
 return nil
}

func makeJournal(dir string,key Key,id StreamID,f *os.File,initial Head)(*Journal,error){
 dinfo,err:=os.Lstat(dir)
 if err!=nil || !journalDir(dinfo) {return nil,ErrJournal}
 lock:=filepath.Join(dir,journalLockName)
 linfo,err:=os.Lstat(lock)
 if err!=nil || !journalDir(linfo) {return nil,ErrJournal}
 path:=filepath.Join(dir,journalFilename)
 finfo,err:=os.Lstat(path)
 opened,openErr:=f.Stat()
 if err!=nil || openErr!=nil || !journalFile(finfo) || !journalFile(opened) ||
  !os.SameFile(finfo,opened) {return nil,ErrJournal}
 raw,err:=parseJournalHead(initial,id)
 if err!=nil{return nil,err}
 chain,err:=NewWriter(&syncJournalWriter{file:f},key,id)
 if err!=nil{return nil,err}
 chain.seq=initial.Sequence
 chain.prev=raw
 return &Journal{dir:dir,dirInfo:dinfo,lock:lock,lockInfo:linfo,
  path:path,fileInfo:finfo,file:f,chain:chain},nil
}

func parseJournalHead(h Head,id StreamID)([32]byte,error){
 var previous [32]byte
 if h.StreamID!=head(id,0,previous).StreamID{return previous,ErrCheckpoint}
 raw,err:=hex.DecodeString(h.MAC)
 if err!=nil || len(raw)!=len(previous) || hex.EncodeToString(raw)!=h.MAC{return previous,ErrCheckpoint}
 copy(previous[:],raw)
 if h.Sequence==0 && previous!=([32]byte{}) {return previous,ErrCheckpoint}
 if h.Sequence>0 && previous==([32]byte{}) {return previous,ErrCheckpoint}
 return previous,nil
}

// InitJournal must only be used for a NEW directory inside an existing
// private (0700) parent. A failed init may leave partial state and a lock;
// never delete or reinitialize such a directory without offline inspection.
// The caller must independently safeguard key, stream ID and returned Head.
func InitJournal(dir string,key Key,id StreamID)(*Journal,error){
 if key==(Key{}) || id==(StreamID{}){return nil,ErrInvalid}
 abs,err:=journalParent(dir)
 if err!=nil{return nil,err}
 if err:=os.Mkdir(abs,0700);err!=nil{return nil,ErrJournal}
 if err:=os.Mkdir(filepath.Join(abs,journalLockName),0700);err!=nil{return nil,ErrJournal}
 path:=filepath.Join(abs,journalFilename)
 f,err:=os.OpenFile(path,os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_EXCL,0600)
 if err!=nil{return nil,ErrJournal}
 if err:=f.Sync();err!=nil{_ = f.Close();return nil,ErrJournal}
 if err:=syncJournalDir(abs);err!=nil{_ = f.Close();return nil,err}
 var zero [32]byte
 j,err:=makeJournal(abs,key,id,f,head(id,0,zero))
 if err!=nil{_ = f.Close();return nil,err}
 return j,nil
}

// OpenJournal requires an independently retained expected checkpoint.
// It never derives trusted continuity solely from the journal it reads.
// Verification mismatches do not truncate or repair the journal.
func OpenJournal(dir string,key Key,id StreamID,expected Head)(*Journal,error){
 if key==(Key{}) || id==(StreamID{}){return nil,ErrInvalid}
 abs,err:=journalParent(dir)
 if err!=nil{return nil,err}
 dinfo,err:=os.Lstat(abs)
 if err!=nil || !journalDir(dinfo) {return nil,ErrJournal}
 lock:=filepath.Join(abs,journalLockName)
 if err:=os.Mkdir(lock,0700);err!=nil{return nil,ErrJournalLocked}
 acquired:=false
 defer func(){if !acquired{_ = os.Remove(lock)}}()
 path:=filepath.Join(abs,journalFilename)
 before,err:=os.Lstat(path)
 if err!=nil || !journalFile(before) {return nil,ErrJournal}
 f,err:=os.OpenFile(path,os.O_RDWR|os.O_APPEND,0)
 if err!=nil{return nil,ErrJournal}
 defer func(){if !acquired{_ = f.Close()}}()
 opened,err:=f.Stat()
 if err!=nil || !journalFile(opened) || !os.SameFile(before,opened) {return nil,ErrJournal}
 if opened.Size()>maxJournalBytes{return nil,ErrJournal}
 if _,err:=f.Seek(0,io.SeekStart);err!=nil{return nil,ErrJournal}
 observed,err:=Verify(f,key,id)
 if err!=nil{return nil,err}
 if _,err:=parseJournalHead(expected,id);err!=nil{return nil,err}
 if observed!=expected{return nil,ErrCheckpoint}
 after,err:=os.Lstat(path)
 if err!=nil || !journalFile(after) || !os.SameFile(before,after){return nil,ErrJournal}
 if _,err:=f.Seek(0,io.SeekEnd);err!=nil{return nil,ErrJournal}
 if err:=syncJournalDir(abs);err!=nil{return nil,err}
 j,err:=makeJournal(abs,key,id,f,observed)
 if err!=nil{return nil,err}
 acquired=true
 return j,nil
}

type syncJournalWriter struct {file *os.File}

// The chain advances its head only after the file accepts and syncs the
// entire line. An I/O failure leaves the journal unavailable for writes.
func(s *syncJournalWriter)Write(data []byte)(int,error){
 info,err:=s.file.Stat()
 if err!=nil || !journalFile(info) || info.Size()<0 ||
  int64(len(data))>maxJournalBytes-info.Size(){return 0,ErrJournal}
 n,err:=s.file.Write(data)
 if err!=nil || n!=len(data){return n,ErrJournal}
 if err:=s.file.Sync();err!=nil{return n,ErrJournal}
 return n,nil
}

func(j *Journal)check()error{
 if j==nil || j.file==nil || j.closed || j.failed{return ErrJournal}
 dir,err:=os.Lstat(j.dir)
 if err!=nil || !journalDir(dir) || !os.SameFile(dir,j.dirInfo){return ErrJournal}
 lock,err:=os.Lstat(j.lock)
 if err!=nil || !journalDir(lock) || !os.SameFile(lock,j.lockInfo){return ErrJournal}
 path,err:=os.Lstat(j.path)
 opened,openErr:=j.file.Stat()
 if err!=nil || openErr!=nil || !journalFile(path) || !journalFile(opened) ||
  !os.SameFile(path,j.fileInfo) || !os.SameFile(path,opened){return ErrJournal}
 return nil
}

// Append checks journal identity before and after the synced append.
// Invalid events do not poison the journal. Ambiguous storage failures do.
func(j *Journal)Append(e audit.Event)(Head,error){
 if j==nil{return Head{},ErrJournal}
 j.mu.Lock();defer j.mu.Unlock()
 if err:=j.check();err!=nil{j.failed=true;return Head{},err}
 result,err:=j.chain.Append(e)
 if err!=nil{
  if !errors.Is(err,ErrInvalid){j.failed=true}
  return Head{},err
 }
 if err:=j.check();err!=nil{j.failed=true;return Head{},err}
 return result,nil
}

func(j *Journal)Head()(Head,error){
 if j==nil{return Head{},ErrJournal}
 j.mu.Lock();defer j.mu.Unlock()
 if err:=j.check();err!=nil{j.failed=true;return Head{},err}
 return j.chain.Head()
}

// Close releases the lock only if all previous journal operations were
// acknowledged and the final file sync/close succeed. An ambiguous failure
// intentionally leaves a crash lock for controlled offline inspection.
func(j *Journal)Close()error{
 if j==nil{return ErrJournal}
 j.mu.Lock();defer j.mu.Unlock()
 if err:=j.check();err!=nil{
  j.failed=true
  if !j.closed{_ = j.file.Close();j.closed=true}
  return ErrJournal
 }
 if err:=j.file.Sync();err!=nil{j.failed=true;_ = j.file.Close();j.closed=true;return ErrJournal}
 if err:=j.file.Close();err!=nil{j.failed=true;j.closed=true;return ErrJournal}
 j.closed=true
 if err:=os.Remove(j.lock);err!=nil{return ErrJournal}
 if err:=syncJournalDir(j.dir);err!=nil{return ErrJournal}
 clear(j.chain.key[:])
 return nil
}
