package main

import (
	"encoding/json"
	"bytes"
	"github.com/Leonidas144k/kgaga/internal/mcp"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
	"github.com/Leonidas144k/kgaga/internal/proxy"
	"github.com/Leonidas144k/kgaga/internal/revocation"
	"github.com/Leonidas144k/kgaga/internal/registry"
	"github.com/Leonidas144k/kgaga/internal/keyring"
	"github.com/Leonidas144k/kgaga/internal/delegation"
	"path/filepath"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		for _, path := range []string{"kgaga.key", "kgaga.pub", "pangolin.key"} {
			if _, err := os.Lstat(path); !os.IsNotExist(err) {
				log.Fatalf("refusing to initialize: %s exists or cannot be inspected; migrate existing keys first", path)
			}
		}
		if err := passport.GenerateKeyPair("kgaga.key", "kgaga.pub"); err != nil {
			log.Fatalf("keygen failed: %v", err)
		}
		f, err := os.OpenFile("kgaga.yaml", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err == nil {
			if _, err := f.WriteString(policy.DefaultConfigYAML); err != nil {
				f.Close()
				log.Fatalf("write config failed: %v", err)
			}
			if err := f.Close(); err != nil {
				log.Fatalf("close config failed: %v", err)
			}
		} else if !os.IsExist(err) {
			log.Fatalf("create config failed: %v", err)
		}
		fmt.Println("Initialized Kgaga root keys (kgaga.key, kgaga.pub) and kgaga.yaml")

	case "keys-init":
		fs:=flag.NewFlagSet("keys-init",flag.ExitOnError)
		dir:=fs.String("trust",keyring.DefaultDir,"Public trust directory")
		fs.Parse(os.Args[2:])
		if err:=keyring.Init(*dir); err!=nil { log.Fatalf("initialize trust failed: %v",err) }
		fmt.Println("Initialized empty trust store; explicitly trust a public key")

	case "key-generate":
		fs:=flag.NewFlagSet("key-generate",flag.ExitOnError)
		out:=fs.String("out","","New private directory outside source control")
		fs.Parse(os.Args[2:])
		if *out=="" { log.Fatal("--out is required") }
		if err:=os.Mkdir(*out,0700); err!=nil { log.Fatalf("create key directory failed: %v",err) }
		if err:=passport.GenerateKeyPair(filepath.Join(*out,"kgaga.key"),filepath.Join(*out,"kgaga.pub")); err!=nil { log.Fatalf("key generation failed: %v",err) }
		fmt.Println("Generated signing key pair in",*out)

	case "key-trust":
		fs:=flag.NewFlagSet("key-trust",flag.ExitOnError)
		dir:=fs.String("trust",keyring.DefaultDir,"Public trust directory")
		pub:=fs.String("public","","Ed25519 public PEM path")
		fs.Parse(os.Args[2:])
		s,err:=keyring.Open(*dir)
		if err!=nil { log.Fatalf("open trust store failed: %v",err) }
		key,err:=passport.LoadPublicKey(*pub)
		if err!=nil { log.Fatalf("load key failed: %v",err) }
		id,err:=s.Trust(key)
		if err!=nil { log.Fatalf("trust failed: %v",err) }
		fmt.Println(id)

	case "key-retire":
		fs:=flag.NewFlagSet("key-retire",flag.ExitOnError)
		dir:=fs.String("trust",keyring.DefaultDir,"Public trust directory")
		id:=fs.String("kid","","Signing key thumbprint")
		fs.Parse(os.Args[2:])
		s,err:=keyring.Open(*dir)
		if err!=nil { log.Fatalf("open trust store failed: %v",err) }
		if err:=s.Retire(*id); err!=nil { log.Fatalf("retire failed: %v",err) }
		fmt.Println("Signing key retired:",*id)

	case "keys-list":
		fs:=flag.NewFlagSet("keys-list",flag.ExitOnError)
		dir:=fs.String("trust",keyring.DefaultDir,"Public trust directory")
		fs.Parse(os.Args[2:])
		s,err:=keyring.Open(*dir)
		if err!=nil { log.Fatalf("open trust store failed: %v",err) }
		j,err:=s.JWKS()
		if err!=nil { log.Fatalf("list keys failed: %v",err) }
		if err:=json.NewEncoder(os.Stdout).Encode(j); err!=nil { log.Fatalf("write keys failed: %v",err) }

	case "agents-init":
		fs := flag.NewFlagSet("agents-init", flag.ExitOnError)
		dir := fs.String("registry",registry.DefaultDir,"Agent registry directory")
		fs.Parse(os.Args[2:])
		if err:=registry.Init(*dir); err!=nil { log.Fatalf("initialize registry failed: %v",err) }
		fmt.Println("Initialized agent registry")

	case "agent-challenge":
		fs:=flag.NewFlagSet("agent-challenge",flag.ExitOnError)
		dir:=fs.String("registry",registry.DefaultDir,"Agent registry directory")
		id:=fs.String("agent","","Proposed agent identifier")
		fs.Parse(os.Args[2:])
		reg,err:=registry.Open(*dir)
		if err!=nil { log.Fatalf("open agent registry failed: %v",err) }
		challenge,err:=reg.NewChallenge(*id)
		if err!=nil { log.Fatalf("challenge failed: %v",err) }
		fmt.Println(challenge)

	case "agent-sign-enrolment":
		fs:=flag.NewFlagSet("agent-sign-enrolment",flag.ExitOnError)
		key:=fs.String("holder-key","","Agent private PEM path")
		challenge:=fs.String("challenge","","Operator-issued challenge")
		id:=fs.String("agent","","Proposed agent ID")
		owner:=fs.String("owner","","Proposed owner")
		scopes:=fs.String("scopes","","Proposed comma-separated scopes")
		audiences:=fs.String("audiences","","Proposed comma-separated audiences")
		fs.Parse(os.Args[2:])
		proof,err:=passport.SignEnrollment(*key,*challenge,*id,*owner,strings.Split(*scopes,","),strings.Split(*audiences,","))
		if err!=nil { log.Fatalf("sign enrolment failed: %v",err) }
		fmt.Println(proof)

	case "agent-register":
		fs := flag.NewFlagSet("agent-register",flag.ExitOnError)
		dir := fs.String("registry",registry.DefaultDir,"Agent registry directory")
		id := fs.String("agent","","Agent identifier")
		owner := fs.String("owner","","Owner identifier")
		scopes := fs.String("scopes","","Comma-separated allowed scopes")
		audiences := fs.String("audiences","","Comma-separated allowed audiences")
		holderPub:=fs.String("holder-public","","Required agent public PEM path")
		challenge:=fs.String("challenge","","Required operator-issued challenge")
		proof:=fs.String("enrolment-proof","","Required agent enrolment signature")
		fs.Parse(os.Args[2:])
		reg,err:=registry.Open(*dir)
		if err!=nil { log.Fatalf("open agent registry failed: %v",err) }
		holder,err:=passport.LoadPublicKey(*holderPub)
		if err!=nil { log.Fatalf("load holder public key failed: %v",err) }
		encoded,err:=registry.EncodeHolder(holder)
		if err!=nil { log.Fatalf("encode holder failed: %v",err) }
		if err:=reg.RegisterAttested(registry.Agent{ID:*id,Owner:*owner,Scopes:strings.Split(*scopes,","),Audiences:strings.Split(*audiences,","),HolderKey:encoded},*challenge,*proof); err!=nil { log.Fatalf("register agent failed: %v",err) }
		fmt.Println("Agent registered:",*id)

	case "agent-inspect":
		fs := flag.NewFlagSet("agent-inspect",flag.ExitOnError)
		dir := fs.String("registry",registry.DefaultDir,"Agent registry directory")
		id := fs.String("agent","","Agent identifier")
		fs.Parse(os.Args[2:])
		reg,err:=registry.Open(*dir)
		if err!=nil { log.Fatalf("open agent registry failed: %v",err) }
		a,suspended,err:=reg.Get(*id)
		if err!=nil { log.Fatalf("inspect agent failed: %v",err) }
		if err:=json.NewEncoder(os.Stdout).Encode(struct{
			registry.Agent
			Suspended bool `json:"suspended"`
		}{a,suspended}); err!=nil { log.Fatalf("write agent failed: %v",err) }

	case "agent-suspend":
		fs := flag.NewFlagSet("agent-suspend",flag.ExitOnError)
		dir := fs.String("registry",registry.DefaultDir,"Agent registry directory")
		id := fs.String("agent","","Agent identifier")
		fs.Parse(os.Args[2:])
		reg,err:=registry.Open(*dir)
		if err!=nil { log.Fatalf("open agent registry failed: %v",err) }
		if err:=reg.Suspend(*id); err!=nil { log.Fatalf("suspend agent failed: %v",err) }
		fmt.Println("Agent suspended:",*id)

	case "mint":
		fs := flag.NewFlagSet("mint", flag.ExitOnError)
		signingKey:=fs.String("signing-key","kgaga.key","Private signing key path")
		trustDir:=fs.String("trust",keyring.DefaultDir,"Public trust directory")
		registryDir := fs.String("registry",registry.DefaultDir,"Agent registry directory")
		agent := fs.String("agent", "default-agent", "Agent identifier")
		owner := fs.String("owner", "ops@company.com", "Human or service owner")
		scopes := fs.String("scopes", "db:read", "Comma-separated scopes")
		ttl := fs.Duration("ttl", 15*time.Minute, "Passport validity duration")
		audience := fs.String("audience", "", "Required service identifier")
		fs.Parse(os.Args[2:])

		reg,err:=registry.Open(*registryDir)
		if err!=nil { log.Fatalf("open agent registry failed: %v",err) }
		holder,err:=reg.AuthorizedHolder(*agent,*owner,strings.Split(*scopes,","),*audience)
		if err!=nil { log.Fatalf("mint rejected: %v",err) }
		token, err := passport.MintBoundV2(*signingKey, *agent, *owner, strings.Split(*scopes, ","), *audience, *ttl,holder)
		if err != nil {
			log.Fatalf("mint failed: %v", err)
		}
		trust,err:=keyring.Open(*trustDir)
		if err!=nil { log.Fatalf("open trust store failed: %v",err) }
		if _,err:=trust.Verify(token,*audience); err!=nil { log.Fatalf("mint rejected: %v",err) }
		fmt.Println(token)

	case "delegate-sign":
		fs:=flag.NewFlagSet("delegate-sign",flag.ExitOnError)
		key:=fs.String("holder-key","","Parent private signing key")
		child:=fs.String("child","","Child agent identifier")
		owner:=fs.String("owner","","Shared owner")
		scopes:=fs.String("scopes","","Exact delegated scopes")
		aud:=fs.String("audience","","Shared audience")
		pub:=fs.String("child-public","","Child public PEM")
		exp:=fs.Int64("expires",0,"Absolute Unix expiry seconds")
		fs.Parse(os.Args[2:])
		parent:=readPassport()
		holder,err:=passport.LoadPublicKey(*pub)
		if err!=nil { log.Fatalf("load child key failed: %v",err) }
		id,err:=passport.KeyID(holder)
		if err!=nil { log.Fatal(err) }
		sig,err:=passport.SignGrant(*key,parent,*child,*owner,strings.Split(*scopes,","),*aud,id,*exp)
		if err!=nil { log.Fatalf("sign grant failed: %v",err) }
		fmt.Println(sig)

	case "delegate":
		fs:=flag.NewFlagSet("delegate",flag.ExitOnError)
		signingKey:=fs.String("signing-key","kgaga.key","Issuer private key")
		trustDir:=fs.String("trust",keyring.DefaultDir,"Public trust directory")
		regDir:=fs.String("registry",registry.DefaultDir,"Registry directory")
		revDir:=fs.String("revocations",revocation.DefaultDir,"Revocation directory")
		child:=fs.String("child","","Child agent identifier")
		owner:=fs.String("owner","","Shared owner")
		scopes:=fs.String("scopes","","Exact delegated scopes")
		aud:=fs.String("audience","","Shared audience")
		exp:=fs.Int64("expires",0,"Absolute Unix expiry seconds")
		sig:=fs.String("grant","","Parent grant signature")
		fs.Parse(os.Args[2:])
		parent:=readPassport()
		trust,err:=keyring.Open(*trustDir)
		if err!=nil { log.Fatal(err) }
		reg,err:=registry.Open(*regDir)
		if err!=nil { log.Fatal(err) }
		rev,err:=revocation.Open(*revDir)
		if err!=nil { log.Fatal(err) }
		raw,err:=delegation.Issue(*signingKey,*child,*owner,strings.Split(*scopes,","),*aud,passport.Delegation{Parent:parent,Signature:*sig,Expires:*exp},trust,reg,rev)
		if err!=nil { log.Fatalf("delegate rejected: %v",err) }
		fmt.Println(raw)

	case "revocations-init":
		fs := flag.NewFlagSet("revocations-init", flag.ExitOnError)
		dir := fs.String("revocations", revocation.DefaultDir, "Revocation store directory")
		fs.Parse(os.Args[2:])
		if err := revocation.Init(*dir); err != nil {
			log.Fatalf("create revocation store failed: %v", err)
		}
		fmt.Println("Initialized revocation store")

	case "revoke":
		fs := flag.NewFlagSet("revoke", flag.ExitOnError)
		dir := fs.String("revocations", revocation.DefaultDir, "Revocation store directory")
		id := fs.String("id", "", "Passport credential ID (jti)")
		fs.Parse(os.Args[2:])
		store, err := revocation.Open(*dir)
		if err != nil { log.Fatalf("open revocation store failed: %v", err) }
		if err := store.Revoke(*id); err != nil { log.Fatalf("revoke failed: %v", err) }
		fmt.Println("Passport revoked:", *id)

	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		trustDir:=fs.String("trust",keyring.DefaultDir,"Public trust directory")
		registryDir := fs.String("registry",registry.DefaultDir,"Agent registry directory")
		dir := fs.String("revocations", revocation.DefaultDir, "Revocation store directory")
		audience := fs.String("audience", "", "Required service identifier")
		fs.Parse(os.Args[2:])
		// Read the token from stdin rather than command-line arguments.
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, (16<<10)+2))
		if err != nil {
			log.Fatalf("read passport failed: %v", err)
		}
		if len(raw) >= (16<<10)+2 {
			log.Fatal("passport input exceeds size limit")
		}
		trust,err:=keyring.Open(*trustDir)
		if err!=nil { log.Fatalf("open trust store failed: %v",err) }
		claims, err := trust.Verify(strings.TrimSpace(string(raw)), *audience)
		if err != nil {
			log.Fatal("passport verification failed")
		}
		store, err := revocation.Open(*dir)
		if err != nil { log.Fatalf("open revocation store failed: %v", err) }
		if err := store.Check(claims.ID); err != nil { log.Fatalf("passport rejected: %v", err) }
		reg,err:=registry.Open(*registryDir)
		if err!=nil { log.Fatalf("open agent registry failed: %v",err) }
		if _,err:=reg.BoundHolder(claims,*audience); err!=nil { log.Fatalf("passport rejected: %v",err) }
		if err:=delegation.Check(claims,*audience,trust,reg,store); err!=nil { log.Fatalf("passport rejected: %v",err) }
		if err := json.NewEncoder(os.Stdout).Encode(claims); err != nil {
			log.Fatalf("write claims failed: %v", err)
		}

	case "replay-init":
		fs:=flag.NewFlagSet("replay-init",flag.ExitOnError)
		dir:=fs.String("replay",passport.ReplayDir,"Dedicated replay store")
		fs.Parse(os.Args[2:])
		if err:=revocation.Init(*dir); err!=nil { log.Fatalf("initialize replay store failed: %v",err) }
		fmt.Println("Initialized replay store")

	case "proof":
		fs:=flag.NewFlagSet("proof",flag.ExitOnError)
		key:=fs.String("holder-key","","Agent private key path")
		method:=fs.String("method","GET","Exact HTTP method")
		target:=fs.String("target","","Exact origin-form request target including query")
		bodyFile:=fs.String("body-file","","Exact request body file")
		contentType:=fs.String("content-type","","Exact Content-Type header")
		mcpVersion:=fs.String("mcp-version","","MCP-Protocol-Version header")
		mcpMethod:=fs.String("mcp-method","","Mcp-Method header")
		mcpSession:=fs.String("mcp-session","","Mcp-Session-Id header")
		fs.Parse(os.Args[2:])
		raw,err:=io.ReadAll(io.LimitReader(os.Stdin,(16<<10)+2))
		if err!=nil || len(raw)>=(16<<10)+2 { log.Fatal("invalid passport input") }
		var body []byte
		if *bodyFile!="" {
			f,err:=os.Open(*bodyFile)
			if err!=nil { log.Fatalf("read body failed: %v",err) }
			defer f.Close()
			body,err=io.ReadAll(io.LimitReader(f,(1<<20)+1))
			if err!=nil || len(body)>1<<20 { log.Fatal("invalid request body") }
		}
		p,err:=passport.SignRequest(*key,strings.TrimSpace(string(raw)),passport.RequestBinding{Method:*method,Target:*target,ContentType:*contentType,MCPVersion:*mcpVersion,MCPMethod:*mcpMethod,MCPSession:*mcpSession,Body:body},time.Now())
		if err!=nil { log.Fatalf("proof failed: %v",err) }
		fmt.Println(p)

	case "policy-check":
		fs:=flag.NewFlagSet("policy-check",flag.ExitOnError)
		path:=fs.String("config","kgaga.yaml","Policy file to validate")
		fs.Parse(os.Args[2:])
		if fs.NArg()!=0 { log.Fatal("policy-check takes no positional arguments") }
		cfg,err:=policy.Load(*path)
		if err!=nil { log.Fatalf("invalid policy: %v",err) }
		fmt.Printf("PASS: policy version %s, %d HTTP rules, %d allowed MCP tools\n",cfg.Version,len(cfg.Rules),len(cfg.MCP.AllowedTools))

	case "proxy":
		fs := flag.NewFlagSet("proxy", flag.ExitOnError)
		configPath:=fs.String("config","kgaga.yaml","Policy file to validate and load")
		replayDir:=fs.String("replay",passport.ReplayDir,"Dedicated replay store")
		trustDir:=fs.String("trust",keyring.DefaultDir,"Public trust directory")
		registryDir := fs.String("registry",registry.DefaultDir,"Agent registry directory")
		dir := fs.String("revocations", revocation.DefaultDir, "Revocation store directory")
		listen := fs.String("listen", "127.0.0.1:8080", "Address for Kgaga proxy to listen on")
		target := fs.String("target", "http://localhost:3000", "Upstream backend or MCP server URL")
		audience := fs.String("audience", "", "Required service identifier")
		fs.Parse(os.Args[2:])

		trust,err:=keyring.Open(*trustDir)
		if err!=nil { log.Fatalf("open trust store failed: %v",err) }
		cfg, err := policy.Load(*configPath)
		if err != nil {
			log.Fatalf("load policy failed: %v", err)
		}

		store, err := revocation.Open(*dir)
		if err != nil { log.Fatalf("open revocation store failed: %v", err) }
		reg,err:=registry.Open(*registryDir)
		if err!=nil { log.Fatalf("open agent registry failed: %v",err) }
		replay,err:=revocation.Open(*replayDir)
		if err!=nil { log.Fatalf("open replay store failed: %v",err) }
		handler, err := proxy.NewHandlerForAudience(*target, trust, cfg, *audience, store, reg,replay)
		if err != nil {
			log.Fatalf("proxy setup failed: %v", err)
		}

		fmt.Fprintf(os.Stderr, "Kgaga Gateway active on %s -> %s\n", *listen, *target)
		server := &http.Server{
			Addr:              *listen,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			IdleTimeout:       30 * time.Second,
			WriteTimeout:      65 * time.Second,
			MaxHeaderBytes:    32 << 10,
		}
		listener,err:=net.Listen("tcp",*listen)
		if err!=nil { log.Fatalf("listen failed: %v",err) }
		bounded,err:=proxy.LimitListener(listener,proxy.MaxOpenConnections)
		if err!=nil { _=listener.Close(); log.Fatal(err) }
		log.Fatal(server.Serve(bounded))

	case "stdio-frame":
		fs:=flag.NewFlagSet("stdio-frame",flag.ExitOnError)
		key:=fs.String("holder-key","","Agent private PEM path")
		tokenFile:=fs.String("passport-file","","Protected passport file")
		fs.Parse(os.Args[2:])
		if fs.NArg()!=0 { log.Fatal("stdio-frame takes no positional arguments") }
		f,err:=os.Open(*tokenFile)
		if err!=nil { log.Fatal("cannot open passport file") }
		raw,err:=io.ReadAll(io.LimitReader(f,(16<<10)+2))
		_ = f.Close()
		if err!=nil || len(raw)>=(16<<10)+2 { log.Fatal("invalid passport file") }
		body,err:=io.ReadAll(io.LimitReader(os.Stdin,mcp.MaxPayload+3))
		if err!=nil || len(body)>mcp.MaxPayload+2 { log.Fatal("invalid stdio message input") }
		body=bytes.TrimSuffix(body,[]byte("\n"))
		body=bytes.TrimSuffix(body,[]byte("\r"))
		frame,err:=proxy.SignStdioFrame(*key,strings.TrimSpace(string(raw)),body)
		if err!=nil { log.Fatalf("stdio frame failed: %v",err) }
		fmt.Println(frame)

	case "wrap":
		fs:=flag.NewFlagSet("wrap",flag.ExitOnError)
		audience:=fs.String("audience","","Required distinct stdio service identifier")
		configPath:=fs.String("config","kgaga.yaml","Policy file")
		trustDir:=fs.String("trust",keyring.DefaultDir,"Public trust directory")
		regDir:=fs.String("registry",registry.DefaultDir,"Registry directory")
		revDir:=fs.String("revocations",revocation.DefaultDir,"Revocation directory")
		replayDir:=fs.String("replay",passport.ReplayDir,"Replay directory")
		fs.Parse(os.Args[2:])
		args:=fs.Args()
		if len(args)==0 || *audience=="" { log.Fatal("Usage: kgaga wrap --audience <service> -- <command> [args...]") }
		cfg,err:=policy.Load(*configPath)
		if err!=nil { log.Fatalf("load policy failed: %v",err) }
		trust,err:=keyring.Open(*trustDir)
		if err!=nil { log.Fatal(err) }
		reg,err:=registry.Open(*regDir)
		if err!=nil { log.Fatal(err) }
		rev,err:=revocation.Open(*revDir)
		if err!=nil { log.Fatal(err) }
		replay,err:=revocation.Open(*replayDir)
		if err!=nil { log.Fatal(err) }
		if err:=proxy.RunStdioProxy(args[0],args[1:],cfg,*audience,trust,reg,rev,replay,os.Stdin,os.Stdout); err!=nil { log.Fatalf("stdio session failed: %v",err) }

	default:
		printUsage()
		os.Exit(1)
	}
}

func readPassport() string {
	raw,err:=io.ReadAll(io.LimitReader(os.Stdin,(16<<10)+2))
	if err!=nil || len(raw)>=(16<<10)+2 { log.Fatal("invalid passport input") }
	return strings.TrimSpace(string(raw))
}

func printUsage() {
	fmt.Println(`Kgaga — Cryptographic Identity & Guardrails for AI Agents

Usage:
  kgaga init                                                Generate root Ed25519 keys & kgaga.yaml
  kgaga mint --agent <id> --owner <email> --scopes <s1,s2> --audience <service>  Mint an Agent Passport
  kgaga keys-init                                           Initialize empty public trust store
  kgaga key-generate --out <new-directory>                  Generate replacement signing key pair
  kgaga key-trust --public <pem-path>                       Trust a public key; print its kid
  kgaga keys-list                                           List non-retired keys as JWKS
  kgaga key-retire --kid <id>                                Permanently retire a signing key
  kgaga agents-init                                         Initialize the agent registry once
  kgaga agent-challenge --agent <id>                        Create 5-minute enrolment challenge
  kgaga agent-sign-enrolment --holder-key <pem> --challenge <id> --agent <id> --owner <id> --scopes <s1,s2> --audiences <a1,a2>
  kgaga agent-register --agent <id> --owner <id> --scopes <s1,s2> --audiences <a1,a2> --holder-public <pem> --challenge <id> --enrolment-proof <signature>
  kgaga agent-inspect --agent <id>                            Inspect a registered agent
  kgaga agent-suspend --agent <id>                            Permanently suspend an agent ID
  kgaga replay-init                                         Initialize the dedicated replay store
  kgaga proof --holder-key <pem> --method GET --target <path>  Sign request proof from passport on stdin
  kgaga delegate-sign --holder-key <pem> --child <id> --owner <id> --scopes <scopes> --audience <service> --child-public <pem> --expires <unix>  Sign grant using parent passport on stdin
  kgaga delegate --child <id> --owner <id> --scopes <scopes> --audience <service> --expires <unix> --grant <signature>  Issue delegated passport using parent on stdin
  kgaga revocations-init                                    Initialize the local revocation store once
  kgaga revoke --id <jti>                                    Revoke a passport
  kgaga verify --audience <service>                          Verify a passport from stdin and check revocation
  kgaga policy-check --config <file>                        Validate policy without starting gateway
  kgaga proxy --listen 127.0.0.1:8080 --target <url> --audience <service>                 Start the security gateway
  kgaga stdio-frame --holder-key <pem> --passport-file <file>  Sign a JSON-RPC message from stdin
  kgaga wrap --audience <service> -- <command> [args...]       Authenticated lockstep stdio wrapper`)
}
