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

	case "mint":
		fs := flag.NewFlagSet("mint", flag.ExitOnError)
		agent := fs.String("agent", "default-agent", "Agent identifier")
		owner := fs.String("owner", "ops@company.com", "Human or service owner")
		scopes := fs.String("scopes", "db:read", "Comma-separated scopes")
		ttl := fs.Duration("ttl", 15*time.Minute, "Passport validity duration")
		audience := fs.String("audience", "", "Required service identifier")
		fs.Parse(os.Args[2:])

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
		if err := json.NewEncoder(os.Stdout).Encode(claims); err != nil {
			log.Fatalf("write claims failed: %v", err)
		}

	case "proxy":
		fs := flag.NewFlagSet("proxy", flag.ExitOnError)
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
		handler, err := proxy.NewHandlerForAudience(*target, pubKey, cfg, *audience, store)
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
  kgaga revocations-init                                    Initialize the local revocation store once
  kgaga revoke --id <jti>                                    Revoke a passport
  kgaga verify --audience <service>                          Verify a passport from stdin and check revocation
  kgaga proxy --listen 127.0.0.1:8080 --target <url> --audience <service>                 Start the security gateway
  kgaga wrap -- <command> [args...]                         Wrap a local stdio MCP server`)
}
