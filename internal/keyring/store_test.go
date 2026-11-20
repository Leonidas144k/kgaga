package keyring

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Leonidas144k/kgaga/internal/passport"
)

func TestRotation(t *testing.T) {
	dir:=t.TempDir()
	path:=filepath.Join(dir,"trust")
	if err:=Init(path); err!=nil { t.Fatal(err) }
	s,err:=Open(path)
	if err!=nil { t.Fatal(err) }
	mint:=func(name string)(string,string){
		t.Helper()
		priv,pub:=filepath.Join(dir,name+".key"),filepath.Join(dir,name+".pub")
		if err:=passport.GenerateKeyPair(priv,pub); err!=nil { t.Fatal(err) }
		key,err:=passport.LoadPublicKey(pub)
		if err!=nil { t.Fatal(err) }
		id,err:=s.Trust(key)
		if err!=nil { t.Fatal(err) }
		raw,err:=passport.MintV2(priv,"agent","owner",[]string{"read"},"api",time.Minute)
		if err!=nil { t.Fatal(err) }
		return id,raw
	}
	oldID,old:=mint("old")
	newID,fresh:=mint("new")
	if oldID==newID { t.Fatal("key IDs collided") }
	for _,raw:=range []string{old,fresh} {
		if _,err:=s.Verify(raw,"api"); err!=nil { t.Fatal(err) }
	}
	if _,err:=s.Verify(fresh,"other"); !errors.Is(err,ErrDenied) { t.Fatal("accepted wrong audience") }
	j,err:=s.JWKS()
	if err!=nil || len(j.Keys)!=2 { t.Fatal("expected two trusted keys") }
	if err:=s.Retire(oldID); err!=nil { t.Fatal(err) }
	if err:=s.Retire(oldID); err!=nil { t.Fatal(err) }
	reopened,err:=Open(path)
	if err!=nil { t.Fatal(err) }
	if _,err:=reopened.Verify(old,"api"); !errors.Is(err,ErrDenied) { t.Fatal("retired key accepted") }
	if _,err:=reopened.Verify(fresh,"api"); err!=nil { t.Fatal(err) }
	j,err=reopened.JWKS()
	if err!=nil || len(j.Keys)!=1 || j.Keys[0].Kid!=newID { t.Fatal("retired key published") }
	key,err:=passport.LoadPublicKey(filepath.Join(dir,"old.pub"))
	if err!=nil { t.Fatal(err) }
	if _,err:=reopened.Trust(key); !errors.Is(err,ErrDenied) { t.Fatal("retired key reintroduced") }
	if err:=os.Rename(path,path+"-backup"); err!=nil { t.Fatal(err) }
	if _,err:=s.Verify(fresh,"api"); err==nil { t.Fatal("missing store accepted") }
	if err:=Init(path); err!=nil { t.Fatal(err) }
	if _,err:=s.JWKS(); err==nil { t.Fatal("replacement store accepted") }
}
