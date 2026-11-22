package ledger

import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "testing"
 "time"
 "github.com/Leonidas144k/kgaga/internal/audit"
)

func journalEvent() audit.Event {
 return audit.Event{Schema:eventSchema,Timestamp:time.Now().UTC().Format(time.RFC3339Nano),
 AttemptID:"0123456789abcdef0123456789abcdef",Action:"credential_use",Phase:"dispatch_intent",
 Actor:"agent",VaultID:"fixture-vault",AgentID:"fixture-agent"}
}

func TestJournalRestartAndExpectedHead(t *testing.T){
 key,id,_:=fixture(t)
 dir:=filepath.Join(t.TempDir(),"journal")
 j,err:=InitJournal(dir,key,id); if err!=nil{t.Fatal(err)}
 genesis,err:=j.Head();if err!=nil||genesis.Sequence!=0{t.Fatal("invalid genesis")}
 if _,err:=OpenJournal(dir,key,id,genesis);!errors.Is(err,ErrJournalLocked){t.Fatal("concurrent writer accepted")}
 first,err:=j.Append(journalEvent());if err!=nil||first.Sequence!=1{t.Fatal(err)}
 second,err:=j.Append(journalEvent());if err!=nil||second.Sequence!=2{t.Fatal(err)}
 if err:=j.Close();err!=nil{t.Fatal(err)}
 if _,err:=j.Append(journalEvent());!errors.Is(err,ErrJournal){t.Fatal("closed writer accepted")}
 if _,err:=OpenJournal(dir,key,id,first);!errors.Is(err,ErrCheckpoint){t.Fatal("stale checkpoint accepted")}
 wrong,err:=GenerateKey();if err!=nil{t.Fatal(err)}
 if _,err:=OpenJournal(dir,wrong,id,second);!errors.Is(err,ErrCorrupt){t.Fatal("wrong key accepted")}
 reopened,err:=OpenJournal(dir,key,id,second);if err!=nil{t.Fatal(err)}
 third,err:=reopened.Append(journalEvent());if err!=nil||third.Sequence!=3{t.Fatal(err)}
 if err:=reopened.Close();err!=nil{t.Fatal(err)}
 f,err:=os.Open(filepath.Join(dir,journalFilename));if err!=nil{t.Fatal(err)}
 defer f.Close()
 observed,err:=Verify(f,key,id);if err!=nil||observed!=third{t.Fatal("restart continuity verification failed")}
}

func TestJournalTruncationAndCrashLock(t *testing.T){
 key,id,_:=fixture(t)
 dir:=filepath.Join(t.TempDir(),"journal")
 j,err:=InitJournal(dir,key,id);if err!=nil{t.Fatal(err)}
 expected,err:=j.Append(journalEvent());if err!=nil{t.Fatal(err)}
 path:=filepath.Join(dir,journalFilename)
 raw,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 if err:=os.Truncate(path,int64(len(raw)-1));err!=nil{t.Fatal(err)}
 if _,err:=j.Append(journalEvent());!errors.Is(err,ErrJournal){t.Fatal("external truncation accepted")}
 if err:=j.Close();!errors.Is(err,ErrJournal){t.Fatal("failed journal unlocked")}
 if _,err:=OpenJournal(dir,key,id,expected);!errors.Is(err,ErrJournalLocked){t.Fatal("crash lock bypassed")}
 // Explicit OFFLINE inspection of the isolated test directory only.
 if err:=os.Remove(filepath.Join(dir,journalLockName));err!=nil{t.Fatal(err)}
 if _,err:=OpenJournal(dir,key,id,expected);!errors.Is(err,ErrCorrupt){t.Fatal("truncation accepted")}
 if err:=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
 reopened,err:=OpenJournal(dir,key,id,expected);if err!=nil{t.Fatal(err)}
 if err:=reopened.Close();err!=nil{t.Fatal(err)}
}

func TestJournalUnsafeFilesystemAndExternalModification(t *testing.T){
 key,id,_:=fixture(t)
 dir:=filepath.Join(t.TempDir(),"journal")
 j,err:=InitJournal(dir,key,id);if err!=nil{t.Fatal(err)}
 h,err:=j.Head();if err!=nil{t.Fatal(err)}
 if err:=j.Close();err!=nil{t.Fatal(err)}
 path:=filepath.Join(dir,journalFilename)
 if err:=os.Chmod(path,0644);err!=nil{t.Fatal(err)}
 if _,err:=OpenJournal(dir,key,id,h);!errors.Is(err,ErrJournal){t.Fatal("weak journal permissions accepted")}
 if err:=os.Chmod(path,0600);err!=nil{t.Fatal(err)}
 if err:=os.Chmod(dir,0755);err!=nil{t.Fatal(err)}
 if _,err:=OpenJournal(dir,key,id,h);!errors.Is(err,ErrJournal){t.Fatal("weak directory permissions accepted")}
 if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
 reopened,err:=OpenJournal(dir,key,id,h);if err!=nil{t.Fatal(err)}
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_APPEND,0600);if err!=nil{t.Fatal(err)}
 if _,err:=f.Write([]byte("external\n"));err!=nil{t.Fatal(err)}
 if err:=f.Close();err!=nil{t.Fatal(err)}
 if _,err:=reopened.Head();!errors.Is(err,ErrJournal){t.Fatal("unexpected append accepted")}
}

func TestJournalRejectReplacementAndPrefixMismatch(t *testing.T){
 key,id,_:=fixture(t)
 dir:=filepath.Join(t.TempDir(),"journal")
 j,err:=InitJournal(dir,key,id);if err!=nil{t.Fatal(err)}
 h1,err:=j.Append(journalEvent());if err!=nil{t.Fatal(err)}
 h2,err:=j.Append(journalEvent());if err!=nil{t.Fatal(err)}
 if err:=j.Close();err!=nil{t.Fatal(err)}
 path:=filepath.Join(dir,journalFilename)
 raw,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 idx:=bytes.IndexByte(raw,'\n');if idx<0{t.Fatal("missing record")}
 if err:=os.Truncate(path,int64(idx+1));err!=nil{t.Fatal(err)}
 if _,err:=OpenJournal(dir,key,id,h2);!errors.Is(err,ErrCheckpoint){t.Fatal("lost suffix not detected against expected head")}
 reopened,err:=OpenJournal(dir,key,id,h1)
 if err!=nil{t.Fatal("valid prefix behavior changed: ",err)}
 if err:=reopened.Close();err!=nil{t.Fatal(err)}
 if err:=os.Remove(path);err!=nil{t.Fatal(err)}
 if err:=os.Symlink(filepath.Join(dir,"external"),path);err!=nil{t.Fatal(err)}
 if _,err:=OpenJournal(dir,key,id,h1);!errors.Is(err,ErrJournal){t.Fatal("symlink accepted")}
}
