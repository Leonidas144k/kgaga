package vault

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func fixture(t *testing.T)(Key,RecordContext) {
	t.Helper()
	key,err:=GenerateKey()
	if err!=nil { t.Fatal(err) }
	vid,err:=GenerateID()
	if err!=nil { t.Fatal(err) }
	kid,err:=GenerateID()
	if err!=nil { t.Fatal(err) }
	return key,RecordContext{VaultID:vid,Name:"backend-token",Version:1,KeyID:kid}
}

func TestRecordRoundTrip(t *testing.T) {
	key,ctx:=fixture(t)
	// Synthetic data, including bytes that are not valid UTF-8.
	for _,secret:=range [][]byte{[]byte("synthetic-token"),{0,255,1},bytes.Repeat([]byte{0x42},MaxSecretBytes)} {
		before:=bytes.Clone(secret)
		record,err:=SealRecord(key,ctx,secret)
		if err!=nil { t.Fatal(err) }
		if len(record)!=len(secret)+len(recordMagic)+nonceBytes+tagBytes { t.Fatal("wrong record length") }
		if !bytes.Equal(secret,before) { t.Fatal("changed plaintext input") }
		copyBefore:=bytes.Clone(record)
		got,err:=OpenRecord(key,ctx,record)
		if err!=nil || !bytes.Equal(got,secret) { t.Fatal("round trip failed") }
		got[0]^=1
		if !bytes.Equal(record,copyBefore) { t.Fatal("plaintext aliases ciphertext") }
	}
}

func TestRecordAuthentication(t *testing.T) {
	key,ctx:=fixture(t)
	secret:=[]byte("synthetic-token")
	record,err:=SealRecord(key,ctx,secret)
	if err!=nil { t.Fatal(err) }
	reject:=func(k Key,c RecordContext,r []byte) {
		t.Helper()
		p,err:=OpenRecord(k,c,r)
		if !errors.Is(err,ErrAuthentication) || p!=nil { t.Fatal("invalid record did not fail closed") }
	}
	// Alter every byte, including format, nonce, ciphertext and tag.
	for i:=range record {
		bad:=bytes.Clone(record)
		bad[i]^=1
		reject(key,ctx,bad)
	}
	for i:=0;i<len(record);i++ { reject(key,ctx,record[:i]) }
	reject(key,ctx,append(bytes.Clone(record),0))
	other,err:=GenerateKey()
	if err!=nil { t.Fatal(err) }
	reject(other,ctx,record)
	for _,mutate:=range []func(*RecordContext){
		func(c *RecordContext){ c.VaultID[0]^=1 },
		func(c *RecordContext){ c.KeyID[0]^=1 },
		func(c *RecordContext){ c.Name="different-token" },
		func(c *RecordContext){ c.Version++ },
	} {
		bad:=ctx
		mutate(&bad)
		reject(key,bad,record)
	}
}

func TestRecordBounds(t *testing.T) {
	key,ctx:=fixture(t)
	for _,bad:=range [][]byte{nil,make([]byte,MaxSecretBytes+1)} {
		if r,err:=SealRecord(key,ctx,bad); !errors.Is(err,ErrInvalidSecret)||r!=nil { t.Fatal("invalid size accepted") }
	}
	if _,err:=SealRecord(Key{},ctx,[]byte("test")); !errors.Is(err,ErrInvalidKey) { t.Fatal("zero key accepted") }
	for _,name:=range []string{"","../secret","Upper","with space","a/b",strings.Repeat("a",65)} {
		bad:=ctx
		bad.Name=name
		if _,err:=SealRecord(key,bad,[]byte("test")); !errors.Is(err,ErrInvalidContext) { t.Fatal("invalid name accepted") }
	}
	for _,bad:=range []RecordContext{
		{VaultID:ctx.VaultID,Name:ctx.Name,KeyID:ctx.KeyID},
		{VaultID:ctx.VaultID,Name:ctx.Name,Version:1},
		{Name:ctx.Name,Version:1,KeyID:ctx.KeyID},
	} {
		if _,err:=SealRecord(key,bad,[]byte("test")); !errors.Is(err,ErrInvalidContext) { t.Fatal("invalid context accepted") }
	}
	if p,err:=OpenRecord(key,ctx,make([]byte,MaxSecretBytes+33)); !errors.Is(err,ErrAuthentication)||p!=nil { t.Fatal("oversized record accepted") }
}

func TestIndependentNonces(t *testing.T) {
	key,ctx:=fixture(t)
	// Exercise random nonce generation even in this deliberately repeated
	// test key; operational record versions must have fresh data keys.
	seen:=map[string]bool{}
	for i:=0;i<128;i++ {
		record,err:=SealRecord(key,ctx,[]byte("same synthetic secret"))
		if err!=nil { t.Fatal(err) }
		nonce:=string(record[len(recordMagic):len(recordMagic)+nonceBytes])
		if seen[nonce] { t.Fatal("repeated random nonce") }
		seen[nonce]=true
	}
}
