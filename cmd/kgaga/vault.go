package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/Leonidas144k/kgaga/internal/vault"
)

// Operator commands have no read/list endpoint. Never pass token material
// as CLI arguments, shell history, environment variables or log messages.
func runVaultOperator(command string,args []string) {
	fs:=flag.NewFlagSet(command,flag.ExitOnError)
	dir:=fs.String("vault-dir","","Encrypted record directory")
	vid:=fs.String("vault-id","","Expected vault identity (lowercase hex)")
	keyFile:=fs.String("vault-kek-file","","External KEK file")
	kid:=fs.String("vault-kek-id","","Expected KEK identity (lowercase hex)")
	name:=fs.String("name","","Secret name")
	version:=fs.Uint64("version",0,"Immutable secret version")
	start:=fs.Int64("not-before",0,"Credential not-before Unix seconds")
	end:=fs.Int64("expires-at",0,"Credential expiry Unix seconds")
	providerOrigin:=fs.String("provider-origin","","HashiCorp Vault HTTPS origin")
	providerCA:=fs.String("provider-ca","","Optional private provider CA bundle")
	providerMount:=fs.String("provider-mount","","KV v2 mount")
	providerPath:=fs.String("provider-path","","KV v2 secret path")
	providerField:=fs.String("provider-field","","Exact bearer field")
	providerVersion:=fs.Uint64("provider-version",0,"Exact remote KV version")
	fs.Parse(args)
	if fs.NArg()!=0 || *dir=="" || *keyFile=="" { log.Fatal("explicit vault paths and IDs required") }
	id,err:=vault.ParseID(*vid); if err!=nil { log.Fatal("invalid vault identity") }
	keyID,err:=vault.ParseID(*kid); if err!=nil { log.Fatal("invalid KEK identity") }
	if command!="vault-import" && (*providerOrigin!="" || *providerCA!="" || *providerMount!="" || *providerPath!="" || *providerField!="" || *providerVersion!=0) { log.Fatal("provider flags only valid for vault-import") }
	if command=="vault-init" {
		if *name!="" || *version!=0 || *start!=0 || *end!=0 { log.Fatal("record flags not valid for vault-init") }
		if err:=vault.Init(*dir,id); err!=nil { log.Fatal("vault initialization failed") }
		s,err:=vault.Open(*dir,id); if err!=nil { log.Fatal("vault initialization failed") }
		if err:=s.CreateMasterKey(*keyFile,keyID); err!=nil { log.Fatal("master key creation failed; inspect partial initialization offline") }
		fmt.Println("Initialized operator vault and external master key")
		return
	}
	if *name=="" || *version==0 { log.Fatal("name and positive version required") }
	if command=="vault-put" || command=="vault-import" {
		if *start<=0 || *end<=*start || *end-*start>3600 { log.Fatal("explicit validity window of at most 3600 seconds required") }
	} else if *start!=0 || *end!=0 { log.Fatal("validity flags only accepted by vault-put or vault-import") }
	s,err:=vault.Open(*dir,id); if err!=nil { log.Fatal("vault open failed") }
	m,err:=s.OpenManaged(*keyFile,keyID); if err!=nil { log.Fatal("master key open failed") }
	switch command {
	case "vault-activate":
		if err:=m.Activate(*name,*version); err!=nil { log.Fatal("vault activation failed") }
		fmt.Println("Activated credential version; lower versions retired")
		return
	case "vault-revoke":
		if err:=m.RevokeVersion(*name,*version); err!=nil { log.Fatal("vault revocation failed") }
		fmt.Println("Credential version revoked or already retired")
		return
	case "vault-put", "vault-import":
	default:
		log.Fatal("invalid vault command")
	}
	info,err:=os.Stdin.Stat()
	if err!=nil || info.Mode()&os.ModeCharDevice!=0 { log.Fatal("provide exact token bytes via protected stdin source, not terminal input") }
	token,err:=io.ReadAll(io.LimitReader(os.Stdin,4097))
	defer clear(token)
	if err!=nil || vault.ValidateBearer(token)!=nil { log.Fatal("invalid bearer token input") }
	if command=="vault-import" {
		source,err:=vault.NewHashiCorpKV2(vault.HashiCorpKV2Config{Origin:*providerOrigin,CAFile:*providerCA,Mount:*providerMount,Path:*providerPath,Field:*providerField,Version:*providerVersion})
		if err!=nil { clear(token); log.Fatal("invalid external provider configuration") }
		if err:=m.ImportBearer(context.Background(),source,token,*name,*version,*start,*end); err!=nil { clear(token); log.Fatal("external credential import failed") }
		clear(token)
		fmt.Println("Imported immutable staged credential; activation required")
		return
	}
	if err:=m.PutBearer(*name,*version,token,*start,*end); err!=nil { clear(token); log.Fatal("vault record publication failed") }
	fmt.Println("Published staged immutable encrypted vault record")
}
