package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pangolin-sec/pangolin/internal/passport"
	"github.com/pangolin-sec/pangolin/internal/policy"
	"github.com/pangolin-sec/pangolin/internal/proxy"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		if err := passport.GenerateKeyPair("pangolin.key", "pangolin.pub"); err != nil {
			log.Fatalf("keygen failed: %v", err)
		}
		if err := os.WriteFile("pangolin.yaml", []byte(policy.DefaultConfigYAML), 0644); err != nil {
			log.Fatalf("write config failed: %v", err)
		}
		fmt.Println("Initialized Pangolin root keys (pangolin.key, pangolin.pub) and pangolin.yaml")

	case "mint":
		fs := flag.NewFlagSet("mint", flag.ExitOnError)
		agent := fs.String("agent", "default-agent", "Agent identifier")
		owner := fs.String("owner", "ops@company.com", "Human or service owner")
		scopes := fs.String("scopes", "db:read", "Comma-separated scopes")
		ttl := fs.Duration("ttl", 15*time.Minute, "Passport validity duration")
		fs.Parse(os.Args[2:])

		token, err := passport.Mint("pangolin.key", *agent, *owner, strings.Split(*scopes, ","), *ttl)
		if err != nil {
			log.Fatalf("mint failed: %v", err)
		}
		fmt.Println(token)

	case "proxy":
		fs := flag.NewFlagSet("proxy", flag.ExitOnError)
		listen := fs.String("listen", ":8080", "Address for Pangolin proxy to listen on")
		target := fs.String("target", "http://localhost:3000", "Upstream backend or MCP server URL")
		fs.Parse(os.Args[2:])

		pubKey, err := passport.LoadPublicKey("pangolin.pub")
		if err != nil {
			log.Fatalf("load public key failed (run 'pangolin init' first): %v", err)
		}
		cfg, err := policy.Load("pangolin.yaml")
		if err != nil {
			log.Fatalf("load policy failed: %v", err)
		}

		handler, err := proxy.NewHandler(*target, pubKey, cfg)
		if err != nil {
			log.Fatalf("proxy setup failed: %v", err)
		}

		fmt.Fprintf(os.Stderr, "Pangolin Gateway active on %s -> %s\n", *listen, *target)
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
			log.Fatalf("Usage: pangolin wrap -- <command> [args...]")
		}

		pubKey, err := passport.LoadPublicKey("pangolin.pub")
		if err != nil {
			log.Fatalf("load public key failed (run 'pangolin init' first): %v", err)
		}
		cfg, err := policy.Load("pangolin.yaml")
		if err != nil {
			log.Fatalf("load policy failed: %v", err)
		}

		fmt.Fprintf(os.Stderr, "🛡️  Pangolin Stdio Wrapper active on: %s\n", strings.Join(args, " "))
		if err := proxy.RunStdioProxy(args[0], args[1:], pubKey, cfg); err != nil {
			log.Fatalf("wrapped process failed: %v", err)
		}

	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Pangolin — Cryptographic Identity & Guardrails for AI Agents

Usage:
  pangolin init                                                Generate root Ed25519 keys & pangolin.yaml
  pangolin mint --agent <id> --owner <email> --scopes <s1,s2>  Mint an Agent Passport
  pangolin proxy --listen :8080 --target <url>                 Start the security gateway
  pangolin wrap -- <command> [args...]                         Wrap a local stdio MCP server`)
}
