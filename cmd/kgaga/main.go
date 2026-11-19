package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Leonidas144k/kgaga/internal/passport"
	"github.com/Leonidas144k/kgaga/internal/policy"
	"github.com/Leonidas144k/kgaga/internal/proxy"
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
		fs.Parse(os.Args[2:])

		token, err := passport.Mint("kgaga.key", *agent, *owner, strings.Split(*scopes, ","), *ttl)
		if err != nil {
			log.Fatalf("mint failed: %v", err)
		}
		fmt.Println(token)

	case "proxy":
		fs := flag.NewFlagSet("proxy", flag.ExitOnError)
		listen := fs.String("listen", ":8080", "Address for Kgaga proxy to listen on")
		target := fs.String("target", "http://localhost:3000", "Upstream backend or MCP server URL")
		fs.Parse(os.Args[2:])

		pubKey, err := passport.LoadPublicKey("kgaga.pub")
		if err != nil {
			log.Fatalf("load public key failed (run 'kgaga init' first): %v", err)
		}
		cfg, err := policy.Load("kgaga.yaml")
		if err != nil {
			log.Fatalf("load policy failed: %v", err)
		}

		handler, err := proxy.NewHandler(*target, pubKey, cfg)
		if err != nil {
			log.Fatalf("proxy setup failed: %v", err)
		}

		fmt.Fprintf(os.Stderr, "Kgaga Gateway active on %s -> %s\n", *listen, *target)
		log.Fatal(http.ListenAndServe(*listen, handler))

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
  kgaga mint --agent <id> --owner <email> --scopes <s1,s2>  Mint an Agent Passport
  kgaga proxy --listen :8080 --target <url>                 Start the security gateway
  kgaga wrap -- <command> [args...]                         Wrap a local stdio MCP server`)
}
