// Package ledger defines a development-preview authenticated chain for
// validated security events. This is not durable storage or a production sink.
package ledger

import (
 "bufio"
 "bytes"
 "crypto/hmac"
 "crypto/rand"
 "crypto/sha256"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "math"
 "sync"
 "time"

 "github.com/Leonidas144k/kgaga/internal/audit"
)

const Schema="kgaga.ledger.record.v1"
const eventSchema="kgaga.vault.audit.v1"
const maxRecordBytes=16<<10
const maxEventBytes=8192

var ErrInvalid=errors.New("invalid ledger event or configuration")
var ErrUnavailable=errors.New("ledger writer unavailable")
var ErrCorrupt=errors.New("ledger stream invalid or unverifiable")

type Key [32]byte
type StreamID [16]byte

// GenerateKey is for isolated development/testing; production key custody,
// backup, rotation and separation remain unimplemented.
func GenerateKey()(Key,error) {
 var k Key
 if _,err:=io.ReadFull(rand.Reader,k[:]);err!=nil{return Key{},ErrUnavailable}
 if k==(Key{}) {return Key{},ErrUnavailable}
 return k,nil
}

func GenerateStreamID()(StreamID,error) {
 var id StreamID
 if _,err:=io.ReadFull(rand.Reader,id[:]);err!=nil{return StreamID{},ErrUnavailable}
 if id==(StreamID{}) {return StreamID{},ErrUnavailable}
 return id,nil
}

// Head is a computed checkpoint, not an externally anchored checkpoint.
// A verifier cannot detect deletion of valid trailing rows without an
// independently retained, trusted expected Head.
type Head struct {
 StreamID string
 Sequence uint64
 MAC string
}

type record struct {
 Schema string `json:"schema"`
 StreamID string `json:"stream_id"`
 Sequence uint64 `json:"sequence"`
 Previous string `json:"previous_mac"`
 Event audit.Event `json:"event"`
 MAC string `json:"mac"`
}

// Writer serializes concurrent calls on one instance. It does not coordinate
// independent processes or recover chain state across process restarts.
type Writer struct {
 mu sync.Mutex
 sink io.Writer
 key Key
 id StreamID
 seq uint64
 prev [32]byte
 failed bool
}

func NewWriter(out io.Writer,key Key,id StreamID)(*Writer,error) {
 if out==nil || key==(Key{}) || id==(StreamID{}) {return nil,ErrInvalid}
 return &Writer{sink:out,key:key,id:id},nil
}

func validEvent(e audit.Event) bool {
 if e.Schema!=eventSchema || e.Timestamp=="" || len(e.AttemptID)!=32 ||
 len(e.Action)==0 || len(e.Action)>64 || len(e.Phase)==0 || len(e.Phase)>96 ||
 (e.Actor!="agent" && e.Actor!="local_operator") || len(e.VaultID)==0 || len(e.VaultID)>128 {return false}
 rawID,err:=hex.DecodeString(e.AttemptID)
 if err!=nil || len(rawID)!=16 || e.AttemptID!=hex.EncodeToString(rawID) {return false}
 stamp,err:=time.Parse(time.RFC3339Nano,e.Timestamp)
 return err==nil && stamp.UTC().Format(time.RFC3339Nano)==e.Timestamp
}

func marshalEvent(e audit.Event)([]byte,error) {
 if !validEvent(e){return nil,ErrInvalid}
 raw,err:=json.Marshal(e)
 if err!=nil || len(raw)>maxEventBytes {return nil,ErrInvalid}
 return raw,nil
}

func macFor(key Key,id StreamID,seq uint64,prev [32]byte,event []byte)[32]byte{
 mac:=hmac.New(sha256.New,key[:])
 mac.Write([]byte("kgaga-ledger:record:v1\x00"))
 mac.Write(id[:])
 var n [8]byte
 binary.BigEndian.PutUint64(n[:],seq)
 mac.Write(n[:])
 mac.Write(prev[:])
 var size [4]byte
 binary.BigEndian.PutUint32(size[:],uint32(len(event)))
 mac.Write(size[:])
 mac.Write(event)
 var digest [32]byte
 copy(digest[:],mac.Sum(nil))
 return digest
}

func head(id StreamID,seq uint64,mac [32]byte)Head{
 return Head{StreamID:hex.EncodeToString(id[:]),Sequence:seq,MAC:hex.EncodeToString(mac[:])}
}

func(w *Writer)Head()(Head,error){
 if w==nil{return Head{},ErrInvalid}
 w.mu.Lock();defer w.mu.Unlock()
 if w.failed {return Head{},ErrUnavailable}
 return head(w.id,w.seq,w.prev),nil
}

// Append writes one canonical JSON line. Success means the writer accepted
// the bytes, not that they were durably stored. Partial writes permanently
// latch this writer, with no implicit retry or recovery.
func(w *Writer)Append(e audit.Event)(Head,error){
 if w==nil{return Head{},ErrInvalid}
 body,err:=marshalEvent(e)
 if err!=nil{return Head{},err}
 w.mu.Lock();defer w.mu.Unlock()
 if w.failed || w.sink==nil || w.seq==math.MaxUint64 {return Head{},ErrUnavailable}
 next:=w.seq+1
 digest:=macFor(w.key,w.id,next,w.prev,body)
 r:=record{Schema:Schema,StreamID:hex.EncodeToString(w.id[:]),Sequence:next,
 Previous:hex.EncodeToString(w.prev[:]),Event:e,MAC:hex.EncodeToString(digest[:])}
 line,err:=json.Marshal(r)
 if err!=nil || len(line)+1>maxRecordBytes{return Head{},ErrInvalid}
 line=append(line,'\n')
 n,err:=w.sink.Write(line)
 if err!=nil || n!=len(line){w.failed=true;return Head{},ErrUnavailable}
 w.seq=next
 w.prev=digest
 return head(w.id,w.seq,w.prev),nil
}

// Verify requires an independently supplied verification key and stream ID.
// Strict canonical JSON prevents duplicate-key/unknown-field ambiguity.
// It validates the observed prefix only; externally anchored checkpoints,
// continuity across restarts and truncation defense are not implemented.
func Verify(source io.Reader,key Key,id StreamID)(Head,error){
 if source==nil || key==(Key{}) || id==(StreamID{}){return Head{},ErrInvalid}
 var prev [32]byte
 var seq uint64
 br:=bufio.NewReaderSize(source,maxRecordBytes+1)
 for{
  line,err:=br.ReadSlice('\n')
  if err==io.EOF && len(line)==0{return head(id,seq,prev),nil}
  if err!=nil || len(line)==0 || len(line)>maxRecordBytes || line[len(line)-1]!='\n'{return Head{},ErrCorrupt}
  raw:=line[:len(line)-1]
  var r record
  if json.Unmarshal(raw,&r)!=nil{return Head{},ErrCorrupt}
  canonical,e:=json.Marshal(r)
  if e!=nil || !bytes.Equal(raw,canonical) || r.Schema!=Schema ||
   r.StreamID!=hex.EncodeToString(id[:]) || r.Previous!=hex.EncodeToString(prev[:]) ||
   seq==math.MaxUint64 || r.Sequence!=seq+1{return Head{},ErrCorrupt}
  event,e:=marshalEvent(r.Event)
  if e!=nil{return Head{},ErrCorrupt}
  digest:=macFor(key,id,r.Sequence,prev,event)
  supplied,e:=hex.DecodeString(r.MAC)
  if e!=nil || len(supplied)!=32 || r.MAC!=hex.EncodeToString(supplied) ||
   !hmac.Equal(supplied,digest[:]){return Head{},ErrCorrupt}
  seq=r.Sequence
  prev=digest
 }
}
