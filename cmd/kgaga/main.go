package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
	"github.com/Leonidas144k/kgaga/internal/proxy"
	"github.com/Leonidas144k/kgaga/internal/revocation"
	"github.com/Leonidas144k/kgaga/internal/registry"
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

	case "agents-init":
		fs := flag.NewFlagSet("agents-init", flag.ExitOnError)
		dir := fs.String("registry",registry.DefaultDir,"Agent registry directory")
		fs.Parse(os.Args[2:])
		if err:=registry.Init(*dir); err!=nil { log.Fatalf("initialize registry failed: %v",err) }
		fmt.Println("Initialized agent registry")

	case "agent-register":
		fs := flag.NewFlagSet("agent-register",flag.ExitOnError)
		dir := fs.String("registry",registry.DefaultDir,"Agent registry directory")
		id := fs.String("agent","","Agent identifier")
		owner := fs.String("owner","","Owner identifier")
		scopes := fs.String("scopes","","Comma-separated allowed scopes")
		audiences := fs.String("audiences","","Comma-separated allowed audiences")
		fs.Parse(os.Args[2:])
		reg,err:=registry.Open(*dir)
		if err!=nil { log.Fatalf("open agent registry failed: %v",err) }
		if err:=reg.Register(registry.Agent{ID:*id,Owner:*owner,Scopes:strings.Split(*scopes,","),Audiences:strings.Split(*audiences,",")}); err!=nil { log.Fatalf("register agent failed: %v",err) }
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
		registryDir := fs.String("registry",registry.DefaultDir,"Agent registry directory")
		agent := fs.String("agent", "default-agent", "Agent identifier")
		owner := fs.String("owner", "ops@company.com", "Human or service owner")
		scopes := fs.String("scopes", "db:read", "Comma-separated scopes")
		ttl := fs.Duration("ttl", 15*time.Minute, "Passport validity duration")
		audience := fs.String("audience", "", "Required service identifier")
		fs.Parse(os.Args[2:])

		reg,err:=registry.Open(*registryDir)
		if err!=nil { log.Fatalf("open agent registry failed: %v",err) }
		if err:=reg.Authorize(*agent,*owner,strings.Split(*scopes,","),*audience); err!=nil { log.Fatalf("mint rejected: %v",err) }
		token, err := passport.MintV2("kgaga.key", *agent, *owner, strings.Split(*scopes, ","), *audience, *ttl)
		if err != nil {
			log.Fatalf("mint failed: %v", err)
		}
		fmt.Println(token)

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
		key, err := passport.LoadPublicKey("kgaga.pub")
		if err != nil {
			log.Fatalf("load public key failed: %v", err)
		}
		claims, err := passport.VerifyV2(strings.TrimSpace(string(raw)), key, *audience)
		if err != nil {
			log.Fatal("passport verification failed")
		}
		store, err := revocation.Open(*dir)
		if err != nil { log.Fatalf("open revocation store failed: %v", err) }
		if err := store.Check(claims.ID); err != nil { log.Fatalf("passport rejected: %v", err) }
		reg,err:=registry.Open(*registryDir)
		if err!=nil { log.Fatalf("open agent registry failed: %v",err) }
		if err:=reg.Authorize(claims.AgentID,claims.Owner,claims.Scopes,*audience); err!=nil { log.Fatalf("passport rejected: %v",err) }
		if err := json.NewEncoder(os.Stdout).Encode(claims); err != nil {
			log.Fatalf("write claims failed: %v", err)
		}

	case "proxy":
		fs := flag.NewFlagSet("proxy", flag.ExitOnError)
		registryDir := fs.String("registry",registry.DefaultDir,"Agent registry directory")
		dir := fs.String("revocations", revocation.DefaultDir, "Revocation store directory")
		listen := fs.String("listen", "127.0.0.1:8080", "Address for Kgaga proxy to listen on")
		target := fs.String("target", "http://localhost:3000", "Upstream backend or MCP server URL")
		audience := fs.String("audience", "", "Required service identifier")
		fs.Parse(os.Args[2:])

		pubKey, err := passport.LoadPublicKey("kgaga.pub")
		if err != nil {
			log.Fatalf("load public key failed (run 'kgaga init' first): %v", err)
		}
		cfg, err := policy.Load("kgaga.yaml")
		if err != nil {
			log.Fatalf("load policy failed: %v", err)
		}

		store, err := revocation.Open(*dir)
		if err != nil { log.Fatalf("open revocation store failed: %v", err) }
		reg,err:=registry.Open(*registryDir)
		if err!=nil { log.Fatalf("open agent registry failed: %v",err) }
		handler, err := proxy.NewHandlerForAudience(*target, pubKey, cfg, *audience, store, reg)
		if err != nil {
			log.Fatalf("proxy setup failed: %v", err)
		}

		fmt.Fprintf(os.Stderr, "Kgaga Gateway active on %s -> %s\n", *listen, *target)
		server := &http.Server{
			Addr:              *listen,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    32 << 10,
		}
		// Streaming responses require a deliberate write-deadline strategy.
		log.Fatal(server.ListenAndServe())

	case "wrap":
		args := []string{}
		foundDash := false
		for _, arg := range os.Args[2:] {
			if arg == "--" {
				foundDash = true
				continue
			}
			if foundDash {
				args = append(args, arg)
			}
		}
		if len(args) == 0 {
			log.Fatalf("Usage: kgaga wrap -- <command> [args...]")
		}

		pubKey, err := passport.LoadPublicKey("kgaga.pub")
		if err != nil {
			log.Fatalf("load public key failed (run 'kgaga init' first): %v", err)
		}
		cfg, err := policy.Load("kgaga.yaml")
		if err != nil {
			log.Fatalf("load policy failed: %v", err)
		}

		fmt.Fprintf(os.Stderr, "🛡️  Kgaga Stdio Wrapper active on: %s\n", strings.Join(args, " "))
		if err := proxy.RunStdioProxy(args[0], args[1:], pubKey, cfg); err != nil {
			log.Fatalf("wrapped process failed: %v", err)
		}

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Kgaga — Cryptographic Identity & Guardrails for AI Agents

Usage:
  kgaga init                                                Generate root Ed25519 keys & kgaga.yaml
  kgaga mint --agent <id> --owner <email> --scopes <s1,s2> --audience <service>  Mint an Agent Passport
  kgaga agents-init                                         Initialize the agent registry once
  kgaga agent-register --agent <id> --owner <id> --scopes <s1,s2> --audiences <a1,a2>
  kgaga agent-inspect --agent <id>                            Inspect a registered agent
  kgaga agent-suspend --agent <id>                            Permanently suspend an agent ID
  kgaga revocations-init                                    Initialize the local revocation store once
  kgaga revoke --id <jti>                                    Revoke a passport
  kgaga verify --audience <service>                          Verify a passport from stdin and check revocation
  kgaga proxy --listen 127.0.0.1:8080 --target <url> --audience <service>                 Start the security gateway
  kgaga wrap -- <command> [args...]                         Wrap a local stdio MCP server`)
}
