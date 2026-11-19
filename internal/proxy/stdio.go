package proxy

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/Leonidas144k/kgaga/internal/mcp"
	"github.com/Leonidas144k/kgaga/internal/policy"
)

// RunStdioProxy wraps a local child process (like an MCP server), inspecting stdio streams.
func RunStdioProxy(cmdPath string, cmdArgs []string, pubKey ed25519.PublicKey, cfg *policy.Config) error {
	cmd := exec.Command(cmdPath, cmdArgs...)

	// Setup pipes for stdin and stdout
	childStdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	childStdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start wrapped process: %w", err)
	}

	errChan := make(chan error, 2)

	// 1. Intercept Parent STDIN -> Child STDIN
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()

			cleanedLine, _ := policy.Redact(line)

			if strings.Contains(cleanedLine, "jsonrpc") {
				var rpc mcp.RPCRequest
				if err := json.Unmarshal([]byte(cleanedLine), &rpc); err == nil && rpc.Method == "tools/call" {
					toolName, _ := rpc.Params["name"].(string)
					
					if slicesContains(cfg.MCP.DeniedTools, toolName) {
						emitAudit(AuditEvent{
							AgentID: "local-stdio-agent", Method: "tools/call:" + toolName,
							Decision: "BLOCK", Reason: "Denied by kgaga.yaml policy",
						})
						fmt.Printf(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"Kgaga blocked tool: %s"},"id":%v}`+"\n", toolName, rpc.ID)
						continue
					}

					emitAudit(AuditEvent{
						AgentID: "local-stdio-agent", Method: "tools/call:" + toolName,
						Decision: "ALLOW", Redacted: cleanedLine != line,
					})
				}
			}

			_, err := io.WriteString(childStdin, cleanedLine+"\n")
			if err != nil {
				break
			}
		}
		childStdin.Close()
	}()

	// 2. Intercept Child STDOUT -> Parent STDOUT
	go func() {
		scanner := bufio.NewScanner(childStdout)
		for scanner.Scan() {
			line := scanner.Text()
			cleanedLine, _ := policy.Redact(line)
			fmt.Println(cleanedLine)
		}
		errChan <- nil
	}()

	return cmd.Wait()
}

func slicesContains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
