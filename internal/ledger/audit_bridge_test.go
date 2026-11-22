package ledger

import (
 "bytes"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "sync"
 "testing"

 "github.com/Leonidas144k/kgaga/internal/audit"
)

func TestVaultAuditBridgeRecordedAndVerified(t *testing.T){
 anchored,jdir,wdir,key,witness,id:=anchoredFixture(t)
 bridge,err:=NewAuditBridge(anchored)
 if err!=nil{t.Fatal(err)}
 recorder:=audit.NewRecorder(bridge)
 var wg sync.WaitGroup
 for i:=0;i<20;i++{
  wg.Add(1)
  go func(){
   defer wg.Done()
   e:=journalEvent()
   if err:=recorder.Record(e);err!=nil{t.Error(err)}
  }()
 }
 wg.Wait()
 expected,err:=anchored.Head()
 if err!=nil||expected.Sequence!=20{t.Fatal("missing audited events",err)}
 if err:=anchored.Close();err!=nil{t.Fatal(err)}
 source,err:=os.Open(filepath.Join(jdir,journalFilename))
 if err!=nil{t.Fatal(err)}
 observed,err:=Verify(source,key,id)
 _=source.Close()
 if err!=nil||observed!=expected{t.Fatal("audits not verifiable",err)}
 reopened,err:=OpenAnchoredJournal(jdir,wdir,key,witness,id,expected)
 if err!=nil{t.Fatal("reopen failed",err)}
 if err:=reopened.Close();err!=nil{t.Fatal(err)}
}

func TestVaultAuditBridgeRejectsNonCanonical(t *testing.T){
 a,_,_,_,_,_:=anchoredFixture(t)
 bridge,err:=NewAuditBridge(a);if err!=nil{t.Fatal(err)}
 valid,err:=json.Marshal(journalEvent());if err!=nil{t.Fatal(err)}
 bad:=bytes.Replace(valid,[]byte("\"schema\":\"kgaga.vault.audit.v1\""),[]byte("\"schema\": \"kgaga.vault.audit.v1\""),1)
 if bytes.Equal(bad,valid){t.Fatal("invalid test setup")}
 if n,err:=bridge.Write(append(bad,'\n'));n!=0||!errors.Is(err,ErrAuditBridge){t.Fatal("noncanonical input accepted")}
 if n,err:=bridge.Write(append(valid,'\n'));n!=0||!errors.Is(err,ErrAuditBridge){t.Fatal("failed bridge resumed")}
 h,err:=a.Head()
 if err!=nil||h.Sequence!=0{t.Fatal("invalid audit persisted")}
 if err:=a.Close();err!=nil{t.Fatal(err)}
}

func TestVaultAuditBridgeFailClosedOnJournalChange(t *testing.T){
 a,jdir,_,_,_,_:=anchoredFixture(t)
 bridge,err:=NewAuditBridge(a);if err!=nil{t.Fatal(err)}
 recorder:=audit.NewRecorder(bridge)
 if err:=recorder.Record(journalEvent());err!=nil{t.Fatal(err)}
 path:=filepath.Join(jdir,journalFilename)
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_APPEND,0600)
 if err!=nil{t.Fatal(err)}
 if _,err:=f.Write([]byte("external\n"));err!=nil{t.Fatal(err)}
 _=f.Close()
 if err:=recorder.Record(journalEvent());!errors.Is(err,audit.ErrUnavailable){t.Fatal("storage change did not reject audit")}
 if err:=recorder.Record(journalEvent());!errors.Is(err,audit.ErrUnavailable){t.Fatal("unavailable recorder resumed")}
 if n,err:=bridge.Write([]byte("invalid"));n!=0||!errors.Is(err,ErrAuditBridge){t.Fatal("bridge resumed after storage failure")}
 if err:=a.Close();err==nil{t.Fatal("invalid storage released lock")}
}
