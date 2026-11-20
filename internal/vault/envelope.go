package vault

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
)

const envelopeMagic = "KGE1"
const wrappedKeyBytes = 32+tagBytes
const envelopeHeader = len(envelopeMagic)+16+16+nonceBytes+wrappedKeyBytes
const maxEnvelopeBytes = envelopeHeader+maxRecordBytes

// wrapAAD is in a distinct domain from secret encryption. It binds the
// expected vault, name, version, DEK identity and KEK identity.
func wrapAAD(ctx RecordContext,kekID ID)([]byte,error) {
	if kekID==(ID{}) { return nil,ErrMasterKey }
	aad,err:=ctx.aad()
	if err!=nil { return nil,err }
	out:=append([]byte("kgaga-vault:wrap:v1\x00"+envelopeMagic),kekID[:]...)
	return append(out,aad...),nil
}

// sealEnvelope generates a fresh independent data key and ID for each
// attempted publication, including losing concurrent writers. Random
// GCM wrapping nonces share a KEK; operators must respect the documented
// lifetime wrapping budget (including failed attempts).
func sealEnvelope(kek Key,kekID ID,ctx RecordContext,plaintext []byte)([]byte,error) {
	if len(plaintext)==0 || len(plaintext)>MaxSecretBytes { return nil,ErrInvalidSecret }
	dek,err:=GenerateKey()
	if err!=nil { return nil,err }
	defer clear(dek[:])
	ctx.KeyID,err=GenerateID()
	if err!=nil { return nil,err }
	aad,err:=wrapAAD(ctx,kekID)
	if err!=nil { return nil,err }
	record,err:=SealRecord(dek,ctx,plaintext)
	if err!=nil { return nil,err }
	aead,err:=recordAEAD(kek)
	if err!=nil { return nil,err }
	out:=make([]byte,0,envelopeHeader+len(record))
	out=append(out,envelopeMagic...)
	out=append(out,kekID[:]...)
	out=append(out,ctx.KeyID[:]...)
	var nonce [nonceBytes]byte
	if _,err:=io.ReadFull(rand.Reader,nonce[:]); err!=nil { return nil,err }
	out=append(out,nonce[:]...)
	out=aead.Seal(out,nonce[:],dek[:],aad)
	return append(out,record...),nil
}

// openEnvelope authenticates the wrapped DEK against the expected record
// slot and KEK ID, then authenticates the secret against that same DEK ID.
// No decoded plaintext is returned on any authentication failure.
func openEnvelope(kek Key,kekID ID,ctx RecordContext,record []byte)([]byte,error) {
	const prefix=len(envelopeMagic)+16+16
	if len(record)<=envelopeHeader || len(record)>maxEnvelopeBytes ||
		string(record[:4])!=envelopeMagic || !bytes.Equal(record[4:20],kekID[:]) { return nil,ErrAuthentication }
	copy(ctx.KeyID[:],record[20:36])
	aad,err:=wrapAAD(ctx,kekID)
	if err!=nil { return nil,ErrAuthentication }
	aead,err:=recordAEAD(kek)
	if err!=nil { return nil,err }
	raw,err:=aead.Open(nil,record[prefix:prefix+nonceBytes],record[prefix+nonceBytes:envelopeHeader],aad)
	if err!=nil || len(raw)!=32 { clear(raw); return nil,ErrAuthentication }
	defer clear(raw)
	var dek Key
	copy(dek[:],raw)
	defer clear(dek[:])
	p,err:=OpenRecord(dek,ctx,record[envelopeHeader:])
	if err!=nil { return nil,ErrAuthentication }
	return p,nil
}

func (m *ManagedStore) slot(name string,version uint64)(RecordContext,string,error) {
	if err:=m.ready(); err!=nil { return RecordContext{},"",err }
	// KeyID here is only a nonzero placeholder for slot validation. The
	// actual generated DEK ID is bound inside the authenticated envelope.
	ctx:=RecordContext{VaultID:m.store.id,Name:name,Version:version,KeyID:m.kekID}
	path,err:=m.store.recordPath(ctx)
	return ctx,path,err
}

// Put generates and wraps a DEK, then publishes a single immutable file.
// The raw and managed APIs share one filename namespace.
func (m *ManagedStore) Put(name string,version uint64,plaintext []byte) error {
	ctx,path,err:=m.slot(name,version)
	if err!=nil { return err }
	if _,err:=os.Lstat(path); err==nil { return ErrRecordExists } else if !os.IsNotExist(err) { return err }
	record,err:=sealEnvelope(m.kek,m.kekID,ctx,plaintext)
	if err!=nil { return err }
	return m.store.publish(path,record)
}

// Get is for trusted callers only. It never exposes the DEK or KEK.
func (m *ManagedStore) Get(name string,version uint64)([]byte,error) {
	ctx,path,err:=m.slot(name,version)
	if err!=nil { return nil,err }
	raw,err:=m.store.readRecord(path,maxEnvelopeBytes)
	if err!=nil { return nil,err }
	p,err:=openEnvelope(m.kek,m.kekID,ctx,raw)
	if err!=nil { return nil,err }
	if err:=m.ready(); err!=nil { clear(p); return nil,err }
	return p,nil
}
