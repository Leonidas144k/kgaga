// Package vault contains development-preview cryptographic primitives.
// It does not yet provide persistent storage or an agent-facing secret API.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

const MaxSecretBytes = 64 << 10

const recordMagic = "KGV1"
const nonceBytes = 12
const tagBytes = 16

var ErrInvalidContext = errors.New("invalid vault record context")
var ErrInvalidKey = errors.New("invalid vault data key")
var ErrInvalidSecret = errors.New("invalid vault secret size")
var ErrAuthentication = errors.New("vault record authentication failed")

// Key is a 256-bit data encryption key. Generate a fresh key for each
// record version; never derive this key from an agent password or passport.
type Key [32]byte

// ID is an opaque, randomly generated identifier, not secret material.
type ID [16]byte

// RecordContext is trusted metadata supplied by the caller from the
// intended record identity, not chosen from an untrusted envelope.
// Version starts at one. KeyID identifies the intended data key.
type RecordContext struct {
	VaultID ID
	Name string
	Version uint64
	KeyID ID
}

func GenerateKey() (Key,error) {
	var key Key
	if _,err:=io.ReadFull(rand.Reader,key[:]); err!=nil { return Key{},err }
	if key==(Key{}) { return Key{},ErrInvalidKey }
	return key,nil
}

func GenerateID() (ID,error) {
	var id ID
	if _,err:=io.ReadFull(rand.Reader,id[:]); err!=nil { return ID{},err }
	if id==(ID{}) { return ID{},ErrInvalidContext }
	return id,nil
}

func (c RecordContext) validate() error {
	if c.VaultID==(ID{}) || c.KeyID==(ID{}) || c.Version==0 || len(c.Name)==0 || len(c.Name)>64 { return ErrInvalidContext }
	for _,b:=range []byte(c.Name) {
		if !(b>='a' && b<='z' || b>='0' && b<='9' || b=='-' || b=='_') { return ErrInvalidContext }
	}
	return nil
}

// aad is an unambiguous, domain-separated encoding. It binds the format,
// vault ID, record name, version and data key identifier to the ciphertext.
func (c RecordContext) aad() ([]byte,error) {
	if err:=c.validate(); err!=nil { return nil,err }
	out:=make([]byte,0,80+len(c.Name))
	out=append(out,[]byte("kgaga-vault:record:v1")...)
	out=append(out,0)
	out=append(out,recordMagic...)
	out=append(out,c.VaultID[:]...)
	out=append(out,c.KeyID[:]...)
	var version [8]byte
	binary.BigEndian.PutUint64(version[:],c.Version)
	out=append(out,version[:]...)
	out=append(out,byte(len(c.Name)))
	out=append(out,c.Name...)
	return out,nil
}

func recordAEAD(key Key) (cipher.AEAD,error) {
	if key==(Key{}) { return nil,ErrInvalidKey }
	block,err:=aes.NewCipher(key[:])
	if err!=nil { return nil,err }
	return cipher.NewGCM(block)
}

// SealRecord returns KGV1 || 12-byte random nonce || ciphertext and
// 16-byte GCM tag. The caller owns the data key and plaintext. This is a
// primitive, not a key manager: use a fresh random data key per version.
// The package does not persist, log or print either key or plaintext.
func SealRecord(key Key,ctx RecordContext,plaintext []byte) ([]byte,error) {
	if len(plaintext)==0 || len(plaintext)>MaxSecretBytes { return nil,ErrInvalidSecret }
	aad,err:=ctx.aad()
	if err!=nil { return nil,err }
	aead,err:=recordAEAD(key)
	if err!=nil { return nil,err }
	out:=make([]byte,len(recordMagic)+nonceBytes,len(recordMagic)+nonceBytes+len(plaintext)+tagBytes)
	copy(out,recordMagic)
	nonce:=out[len(recordMagic):]
	if _,err:=io.ReadFull(rand.Reader,nonce); err!=nil { return nil,err }
	return aead.Seal(out,nonce,plaintext,aad),nil
}

// OpenRecord authenticates the envelope and its expected metadata before
// returning any plaintext. Wrong keys, altered records and substituted
// metadata all fail without exposing decrypted bytes.
func OpenRecord(key Key,ctx RecordContext,record []byte) ([]byte,error) {
	const overhead=len(recordMagic)+nonceBytes+tagBytes
	if len(record)<=overhead || len(record)>overhead+MaxSecretBytes || string(record[:len(recordMagic)])!=recordMagic { return nil,ErrAuthentication }
	aad,err:=ctx.aad()
	if err!=nil { return nil,err }
	aead,err:=recordAEAD(key)
	if err!=nil { return nil,err }
	nonce:=record[len(recordMagic):len(recordMagic)+nonceBytes]
	plaintext,err:=aead.Open(nil,nonce,record[len(recordMagic)+nonceBytes:],aad)
	if err!=nil { return nil,ErrAuthentication }
	return plaintext,nil
}
