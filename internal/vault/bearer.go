package vault

import (
	"encoding/hex"
	"errors"
)

func ParseID(raw string)(ID,error) {
	var id ID
	b,err:=hex.DecodeString(raw)
	if err!=nil || len(b)!=len(id) || hex.EncodeToString(b)!=raw { return id,ErrInvalidContext }
	copy(id[:],b)
	if id==(ID{}) { return ID{},ErrInvalidContext }
	return id,nil
}

// ValidateBearer restricts the first gateway injection mechanism to
// bounded RFC 6750 b64token characters, with padding only at the end.
// It does not verify that an upstream has issued or accepts the token.
func ValidateBearer(value []byte) error {
	if len(value)<16 || len(value)>4096 { return errors.New("invalid vault bearer token") }
	padding:=false
	for i,b:=range value {
		if b=='=' {
			if i==0 { return errors.New("invalid vault bearer token") }
			padding=true
			continue
		}
		if padding || !(b>='A'&&b<='Z'||b>='a'&&b<='z'||b>='0'&&b<='9'||b=='-'||b=='.'||b=='_'||b=='~'||b=='+'||b=='/') {
			return errors.New("invalid vault bearer token")
		}
	}
	return nil
}
