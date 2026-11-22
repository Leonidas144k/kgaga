package ledger

import (
 "bytes"
 "errors"
 "os"
 "path/filepath"
 "testing"
)

func anchoredFixture(t *testing.T)(*AnchoredJournal,string,string,Key,Key,StreamID) {
 t.Helper()
 root:=privateJournalRoot(t)
 journalDir:=filepath.Join(root,"journal")
 witnessDir:=filepath.Join(root,"witness")
 chainKey,id,_:=fixture(t)
 witnessKey,err:=GenerateKey();if err!=nil{t.Fatal(err)}
 a,err:=InitAnchoredJournal(journalDir,witnessDir,chainKey,witnessKey,id)
 if err!=nil{t.Fatal(err)}
 return a,journalDir,witnessDir,chainKey,witnessKey,id
}

func TestAnchoredJournalRestartAndContinuity(t *testing.T){
 a,jdir,wdir,chainKey,witnessKey,id:=anchoredFixture(t)
 genesis,err:=a.Head()
 if err!=nil || genesis.Sequence!=0{t.Fatal("invalid anchored genesis",err)}
 if _,err:=OpenAnchoredJournal(jdir,wdir,chainKey,witnessKey,id,genesis);!errors.Is(err,ErrAnchorLocked){t.Fatal("parallel writer admitted")}
 for i:=0;i<3;i++ { if _,err:=a.Append(journalEvent());err!=nil{t.Fatal(err)} }
 expected,err:=a.Head()
 if err!=nil || expected.Sequence!=3{t.Fatal("incorrect head",err)}
 if err:=a.Close();err!=nil{t.Fatal(err)}
 if _,err:=OpenAnchoredJournal(jdir,wdir,chainKey,witnessKey,id,genesis);!errors.Is(err,ErrCheckpoint){t.Fatal("stale trusted head accepted")}
 wrongKey,err:=GenerateKey();if err!=nil{t.Fatal(err)}
 if _,err:=OpenAnchoredJournal(jdir,wdir,chainKey,wrongKey,id,expected);!errors.Is(err,ErrCheckpoint){t.Fatal("wrong checkpoint key accepted")}
 resumed,err:=OpenAnchoredJournal(jdir,wdir,chainKey,witnessKey,id,expected)
 if err!=nil{t.Fatal(err)}
 fourth,err:=resumed.Append(journalEvent())
 if err!=nil || fourth.Sequence!=4{t.Fatal("checkpoint continuity failed",err)}
 if err:=resumed.Close();err!=nil{t.Fatal(err)}
 f,err:=os.Open(filepath.Join(jdir,journalFilename));if err!=nil{t.Fatal(err)}
 defer f.Close()
 verified,err:=Verify(f,chainKey,id)
 if err!=nil || verified!=fourth{t.Fatal("journal does not match anchor")}
}

func TestCheckpointTamperAndIndependentExpectation(t *testing.T){
 a,jdir,wdir,key,witness,id:=anchoredFixture(t)
 first,err:=a.Append(journalEvent());if err!=nil{t.Fatal(err)}
 second,err:=a.Append(journalEvent());if err!=nil{t.Fatal(err)}
 path:=filepath.Join(wdir,checkpointFilename)
 old,err:=checkpointBytes(witness,id,first);if err!=nil{t.Fatal(err)}
 original,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 if err:=a.Close();err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(path,old,0600);err!=nil{t.Fatal(err)}
 if _,err:=OpenAnchoredJournal(jdir,wdir,key,witness,id,second);!errors.Is(err,ErrCheckpoint){t.Fatal("authenticated rollback accepted against external expectation")}
 bad:=bytes.Clone(original)
 bad[len(bad)-3]^=1
 if err:=os.WriteFile(path,bad,0600);err!=nil{t.Fatal(err)}
 if _,err:=OpenAnchoredJournal(jdir,wdir,key,witness,id,second);!errors.Is(err,ErrCheckpoint){t.Fatal("tampered witness accepted")}
 if err:=os.WriteFile(path,original,0600);err!=nil{t.Fatal(err)}
 recovered,err:=OpenAnchoredJournal(jdir,wdir,key,witness,id,second)
 if err!=nil{t.Fatal(err)}
 if err:=recovered.Close();err!=nil{t.Fatal(err)}
}

func TestInterruptedCheckpointPublicationFailsClosed(t *testing.T){
 a,jdir,wdir,chainKey,witness,id:=anchoredFixture(t)
 expected,err:=a.Head();if err!=nil{t.Fatal(err)}
 // Model a crash immediately after the journal fsync but before anchor
 // publication. No API should silently truncate the committed journal.
 if _,err:=a.journal.Append(journalEvent());err!=nil{t.Fatal(err)}
 if err:=a.Close();!errors.Is(err,ErrCheckpoint){t.Fatal("inconsistent layers closed successfully")}
 if _,err:=OpenAnchoredJournal(jdir,wdir,chainKey,witness,id,expected);!errors.Is(err,ErrAnchorLocked){t.Fatal("crash lock bypassed")}
 // Test-only explicit offline cleanup; production has no recovery API.
 if err:=os.Remove(filepath.Join(wdir,checkpointLockName));err!=nil{t.Fatal(err)}
 if err:=os.Remove(filepath.Join(jdir,journalLockName));err!=nil{t.Fatal(err)}
 if _,err:=OpenAnchoredJournal(jdir,wdir,chainKey,witness,id,expected);!errors.Is(err,ErrCheckpoint){t.Fatal("journal/checkpoint divergence accepted")}
}

func TestCheckpointStorageBoundsAndIdentity(t *testing.T){
 a,jdir,wdir,chainKey,witness,id:=anchoredFixture(t)
 if separatedDirs(jdir,filepath.Join(jdir,"nested")){t.Fatal("nested storage accepted")}
 if separatedDirs(jdir,jdir){t.Fatal("same directory accepted")}
 if _,err:=InitAnchoredJournal(jdir,jdir,chainKey,witness,id);!errors.Is(err,ErrInvalid){t.Fatal("same directory configuration accepted")}
 if _,err:=a.Append(journalEvent());err!=nil{t.Fatal(err)}
 old,err:=a.Head();if err!=nil{t.Fatal(err)}
 checkpointPath:=filepath.Join(wdir,checkpointFilename)
 if err:=os.Chmod(checkpointPath,0644);err!=nil{t.Fatal(err)}
 if _,err:=a.Head();!errors.Is(err,ErrCheckpoint){t.Fatal("unsafe checkpoint accepted")}
 if err:=a.Close();err==nil{t.Fatal("failed witness closed cleanly")}
 if _,err:=os.Lstat(filepath.Join(wdir,checkpointLockName));err!=nil{t.Fatal("failed witness released checkpoint lock")}
 if _,err:=os.Lstat(filepath.Join(jdir,journalLockName));err!=nil{t.Fatal("failed witness released journal lock")}
 if err:=os.Chmod(checkpointPath,0600);err!=nil{t.Fatal(err)}
 if _,err:=OpenAnchoredJournal(jdir,wdir,chainKey,witness,id,old);!errors.Is(err,ErrAnchorLocked){t.Fatal("unsafe close lost crash lock")}
}
