package policy

import (
	"os"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	PathPrefix    string   `yaml:"path_prefix"`
	AllowedScopes []string `yaml:"allowed_scopes"`
	DenyMethods   []string `yaml:"deny_methods"`
}

type MCPPolicy struct {
	AllowedTools []string `yaml:"allowed_tools"`
	DeniedTools  []string `yaml:"denied_tools"`
}

type Config struct {
	Version       string    `yaml:"version"`
	RedactSecrets bool      `yaml:"redact_secrets"`
	MCP           MCPPolicy `yaml:"mcp"`
	Rules         []Rule    `yaml:"rules"`
}

const DefaultConfigYAML = `version: "1"
redact_secrets: true

mcp:
  allowed_tools: ["search", "read_file", "postgres.query"]
  denied_tools: ["execute_shell", "drop_table"]

rules:
  - path_prefix: "/api/db"
    allowed_scopes: ["db:read", "admin"]
    deny_methods: ["DELETE"]
  - path_prefix: "/api/payments"
    allowed_scopes: ["payments:write", "admin"]
    deny_methods: []
`

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Authorize(method, path string, agentScopes []string) (bool, string) {
	for _, r := range c.Rules {
		if strings.HasPrefix(path, r.PathPrefix) {
			if slices.Contains(r.DenyMethods, strings.ToUpper(method)) {
				return false, "HTTP method explicitly denied by Kgaga policy"
			}
			for _, needed := range r.AllowedScopes {
				if slices.Contains(agentScopes, needed) {
					return true, "authorized"
				}
			}
			return false, "agent passport lacks required scope for " + r.PathPrefix
		}
	}
	return false, "no matching Kgaga policy rule (default deny)"
}

func (c *Config) AuthorizeMCP(method, toolName, requiredScope string, agentScopes []string) (bool, string) {
	if toolName != "" && slices.Contains(c.MCP.DeniedTools, toolName) {
		return false, "MCP tool explicitly denied by kgaga.yaml: " + toolName
	}

	if toolName != "" && len(c.MCP.AllowedTools) > 0 {
		if !slices.Contains(c.MCP.AllowedTools, toolName) && !slices.Contains(c.MCP.AllowedTools, "*") {
			return false, "MCP tool not in kgaga.yaml allowlist: " + toolName
		}
	}

	if slices.Contains(agentScopes, requiredScope) ||
		slices.Contains(agentScopes, "mcp:*") ||
		slices.Contains(agentScopes, "admin") {
		return true, "authorized"
	}

	return false, "agent passport lacks required MCP scope: " + requiredScope
}

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`sk-[a-zA-Z0-9]{20,}`),
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-\._~\+/]+=*`),
}

func Redact(input string) (string, bool) {
	redacted := input
	changed := false
	for _, re := range secretPatterns {
		if re.MatchString(redacted) {
			redacted = re.ReplaceAllString(redacted, "[REDACTED_BY_PANGOLIN]")
			changed = true
		}
	}
	return redacted, changed
}
