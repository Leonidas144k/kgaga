package vault

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// Exercise untrusted binary and JSON parsing with both valid and malformed
// seeds. Synthetic fixed keys are used only for this regression fixture.
func FuzzVaultFormats(f *testing.F) {
	key:=Key{1,2,3}
	vid,kid:=ID{1},ID{2}
	ctx:=RecordContext{VaultID:vid,Name:"fixture",Version:1,KeyID:ID{3}}
	m:=&ManagedStore{store:&Store{id:vid},kek:key,kekID:kid}
	plain:=[]byte("synthetic-fuzz-token")
	now:=time.Unix(1800000000,0)
	record,err:=SealRecord(key,ctx,plain); if err!=nil { f.Fatal(err) }
	envelope,err:=sealEnvelope(key,kid,ctx,plain); if err!=nil { f.Fatal(err) }
	timed,err:=encodeTimedBearer(plain,now.Unix()-1,now.Unix()+60); if err!=nil { f.Fatal(err) }
	state:=m.encodeLifecycle(ctx.Name,lifecycleState{high:2,future:[]uint64{3,5}})
	f.Add(uint8(0),record)
	f.Add(uint8(1),envelope)
	f.Add(uint8(2),timed)
	f.Add(uint8(3),state)
	f.Add(uint8(4),[]byte(validKV2))
	for i:=uint8(0);i<5;i++ { f.Add(i,[]byte{}); f.Add(i,[]byte("invalid")) }
	f.Fuzz(func(t *testing.T,kind uint8,raw []byte){
		switch kind%5 {
		case 0:
			p,err:=OpenRecord(key,ctx,raw)
			if err!=nil && p!=nil { t.Fatal("record failure exposed plaintext") }
			if err==nil && (len(p)==0 || len(p)>MaxSecretBytes) { t.Fatal("record violated bounds") }
			clear(p)
		case 1:
			p,err:=openEnvelope(key,kid,ctx,raw)
			if err!=nil && p!=nil { t.Fatal("envelope failure exposed plaintext") }
			if err==nil && (len(p)==0 || len(p)>MaxSecretBytes) { t.Fatal("envelope violated bounds") }
			clear(p)
		case 2:
			p,expiry,err:=decodeTimedBearer(raw,now)
			if err!=nil && p!=nil { t.Fatal("invalid timed payload exposed token") }
			if err==nil {
				if ValidateBearer(p)!=nil || !now.Before(expiry) || len(raw)<timedHeader { t.Fatal("invalid timed payload accepted") }
				start:=int64(binary.BigEndian.Uint64(raw[4:12]))
				canonical,e:=encodeTimedBearer(p,start,expiry.Unix())
				if e!=nil || !bytes.Equal(canonical,raw) { t.Fatal("noncanonical timed payload") }
			}
			clear(p)
		case 3:
			s,err:=m.decodeLifecycle(ctx.Name,raw)
			if err==nil && !bytes.Equal(m.encodeLifecycle(ctx.Name,s),raw) { t.Fatal("noncanonical lifecycle accepted") }
		case 4:
			p,err:=parseKV2(raw,"token",7)
			if err!=nil && p!=nil { t.Fatal("provider failure exposed token") }
			if err==nil && ValidateBearer(p)!=nil { t.Fatal("invalid provider token accepted") }
			clear(p)
		}
	})
}
