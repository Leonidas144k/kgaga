package ledger

import(
 "bytes"
 "encoding/json"
 "errors"
 "io"
 "strings"
 "sync"
 "sync/atomic"
 "testing"
 "time"

 "github.com/Leonidas144k/kgaga/internal/audit"
)

func fixture(t *testing.T)(Key,StreamID,audit.Event){
 t.Helper()
 key,err:=GenerateKey();if err!=nil{t.Fatal(err)}
 id,err:=GenerateStreamID();if err!=nil{t.Fatal(err)}
 return key,id,audit.Event{Schema:eventSchema,Timestamp:time.Now().UTC().Format(time.RFC3339Nano),
 AttemptID:"1234567890abcdef1234567890abcdef",Action:"credential_use",
 Phase:"dispatch_intent",Actor:"agent",VaultID:"synthetic-vault",AgentID:"agent-a",
 Name:"token",Version:2}
}

func TestChainVerifyAndConcurrentAppend(t *testing.T){
 key,id,event:=fixture(t)
 var buf bytes.Buffer
 w,err:=NewWriter(&buf,key,id);if err!=nil{t.Fatal(err)}
 var wg sync.WaitGroup
 for i:=0;i<64;i++{wg.Add(1);go func(){defer wg.Done();if _,err:=w.Append(event);err!=nil{t.Error(err)}}()}
 wg.Wait()
 h,err:=w.Head()
 if err!=nil||h.Sequence!=64{t.Fatal("unexpected head")}
 got,err:=Verify(bytes.NewReader(buf.Bytes()),key,id)
 if err!=nil||got!=h{t.Fatalf("verification failed: %v",err)}
 if _,err:=Verify(bytes.NewReader(buf.Bytes()),Key{},id);!errors.Is(err,ErrInvalid){t.Fatal("zero key accepted")}
 other,err:=GenerateStreamID();if err!=nil{t.Fatal(err)}
 if _,err:=Verify(bytes.NewReader(buf.Bytes()),key,other);!errors.Is(err,ErrCorrupt){t.Fatal("wrong stream accepted")}
 wrong,err:=GenerateKey();if err!=nil{t.Fatal(err)}
 if _,err:=Verify(bytes.NewReader(buf.Bytes()),wrong,id);!errors.Is(err,ErrCorrupt){t.Fatal("wrong key accepted")}
}

func TestMutationDeletionReorderingAndCanonicality(t *testing.T){
 key,id,event:=fixture(t)
 var buf bytes.Buffer
 w,_:=NewWriter(&buf,key,id)
 for i:=0;i<3;i++{if _,err:=w.Append(event);err!=nil{t.Fatal(err)}}
 rows:=bytes.Split(bytes.TrimSuffix(buf.Bytes(),[]byte("\n")),[]byte("\n"))
 if len(rows)!=3{t.Fatal("expected three rows")}
 join:=func(rows ...[]byte)[]byte{return append(bytes.Join(rows,[]byte("\n")),'\n')}
 cases:=[][]byte{
 join(rows[1],rows[2]),join(rows[0],rows[2]),join(rows[1],rows[0],rows[2]),
 join(rows[0],rows[0],rows[2]),append(bytes.Clone(buf.Bytes()),'x'),
 bytes.TrimSuffix(buf.Bytes(),[]byte("\n")),
 append(bytes.Clone(buf.Bytes()),[]byte("x\n")...),
 }
 cases=append(cases,bytes.Replace(bytes.Clone(buf.Bytes()),[]byte("dispatch_intent"),[]byte("response_withheld"),1))
 cases=append(cases,bytes.Replace(bytes.Clone(buf.Bytes()),[]byte("\"sequence\":1"),[]byte("\"sequence\":2"),1))
 cases=append(cases,bytes.Replace(bytes.Clone(buf.Bytes()),[]byte("\"schema\":\"kgaga.ledger.record.v1\""),[]byte("\"schema\": \"kgaga.ledger.record.v1\""),1))
 cases=append(cases,bytes.Replace(bytes.Clone(buf.Bytes()),[]byte("\"sequence\":1"),[]byte("\"sequence\":1,\"sequence\":1"),1))
 for _,bad:=range cases{if _,err:=Verify(bytes.NewReader(bad),key,id);!errors.Is(err,ErrCorrupt){t.Fatalf("altered log accepted: %v",err)}}
 prefix,err:=Verify(bytes.NewReader(join(rows[0],rows[1])),key,id)
 if err!=nil||prefix.Sequence!=2{t.Fatal("complete-prefix truncation limitation changed")}
}

func TestInvalidEventAndLength(t *testing.T){
 key,id,event:=fixture(t)
 var buf bytes.Buffer
 w,_:=NewWriter(&buf,key,id)
 bad:=event;bad.Timestamp="2020-01-01T00:00:00+02:00"
 if _,err:=w.Append(bad);!errors.Is(err,ErrInvalid){t.Fatal("invalid timestamp accepted")}
 bad=event;bad.AttemptID="invalid"
 if _,err:=w.Append(bad);!errors.Is(err,ErrInvalid){t.Fatal("invalid correlation ID accepted")}
 bad=event;bad.Target=strings.Repeat("X",maxRecordBytes)
 if _,err:=w.Append(bad);!errors.Is(err,ErrInvalid){t.Fatal("oversized event accepted")}
 if buf.Len()!=0{t.Fatal("invalid preflight emitted data")}
 if _,err:=w.Append(event);err!=nil{t.Fatal("valid event after rejection failed")}
 row:=append(bytes.Repeat([]byte("x"),maxRecordBytes+10),'\n')
 if _,err:=Verify(bytes.NewReader(row),key,id);!errors.Is(err,ErrCorrupt){t.Fatal("oversized record accepted")}
 if _,err:=Verify(nil,key,id);!errors.Is(err,ErrInvalid){t.Fatal("nil reader accepted")}
}

type partialSink struct{b bytes.Buffer;fail atomic.Bool;calls atomic.Int32}
func(s *partialSink)Write(data []byte)(int,error){
 s.calls.Add(1)
 if s.fail.Load(){return s.b.Write(data[:len(data)/2])}
 return s.b.Write(data)
}
func TestWriterLatchesAfterShortWrite(t *testing.T){
 key,id,event:=fixture(t)
 sink:=&partialSink{}
 w,_:=NewWriter(sink,key,id)
 sink.fail.Store(true)
 if _,err:=w.Append(event);!errors.Is(err,ErrUnavailable){t.Fatal("short write accepted")}
 sink.fail.Store(false)
 var wg sync.WaitGroup
 for i:=0;i<12;i++{wg.Add(1);go func(){defer wg.Done();if _,err:=w.Append(event);!errors.Is(err,ErrUnavailable){t.Error("failed writer resumed")}}()}
 wg.Wait()
 if sink.calls.Load()!=1{t.Fatal("writer retried failed append")}
 if _,err:=w.Head();!errors.Is(err,ErrUnavailable){t.Fatal("unreliable checkpoint returned")}
 if _,err:=Verify(bytes.NewReader(sink.b.Bytes()),key,id);!errors.Is(err,ErrCorrupt){t.Fatal("partial record accepted")}
}

func TestCanonicalRecordFormat(t *testing.T){
 key,id,event:=fixture(t)
 var buf bytes.Buffer
 w,_:=NewWriter(&buf,key,id)
 h,err:=w.Append(event);if err!=nil{t.Fatal(err)}
 var obj map[string]json.RawMessage
 if err:=json.Unmarshal(bytes.TrimSuffix(buf.Bytes(),[]byte("\n")),&obj);err!=nil{t.Fatal(err)}
 if len(obj)!=6||h.Sequence!=1{t.Fatal("unexpected schema")}
 if _,err:=Verify(bytes.NewReader(buf.Bytes()),key,id);err!=nil{t.Fatal(err)}
 if _,err:=Verify(failingReader{},key,id);!errors.Is(err,ErrCorrupt){t.Fatal("reader error accepted")}
}
type failingReader struct{}
func(failingReader)Read([]byte)(int,error){return 0,io.ErrUnexpectedEOF}
