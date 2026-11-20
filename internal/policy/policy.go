package policy

import (
	"regexp"
	"slices"
	"strings"

)

type Rule struct {
	PathPrefix    string   `yaml:"path_prefix"`
	AllowedScopes []string `yaml:"allowed_scopes"`
	AllowedMethods []string `yaml:"allowed_methods"`
	DenyMethods   []string `yaml:"deny_methods"`
}

type MCPPolicy struct {
	AllowedTools []string `yaml:"allowed_tools"`
	DeniedTools  []string `yaml:"denied_tools"`
}

type Config struct {
	RateLimit *RateLimitConfig `yaml:"rate_limit,omitempty"`
	Version       string    `yaml:"version"`
	RedactSecrets bool      `yaml:"redact_secrets"`
	MCP           MCPPolicy `yaml:"mcp"`
	Rules         []Rule    `yaml:"rules"`
}

const DefaultConfigYAML = `version: "2"
redact_secrets: true

rate_limit:
  requests_per_minute: 120
  burst: 40
  max_agents: 4096

mcp:
  allowed_tools: ["search", "read_file", "postgres.query"]
  denied_tools: ["execute_shell", "drop_table"]

rules:
  - path_prefix: "/api/db"
    allowed_scopes: ["db:read", "admin"]
    allowed_methods: ["GET", "HEAD"]
    deny_methods: ["DELETE"]
  - path_prefix: "/api/payments"
    allowed_scopes: ["payments:write", "admin"]
    allowed_methods: ["POST"]
    deny_methods: []
`

// CanonicalPath accepts only literal ASCII unreserved path segments.
// No encoded paths, dot segments, matrix parameters, duplicate slashes or
// trailing slash aliases. This deliberately restricts the preview's routes.
func CanonicalPath(path string) bool {
	if path=="/" { return true }
	if len(path)==0 || len(path)>8192 || path[0]!='/' || strings.HasSuffix(path,"/") { return false }
	for _,segment:=range strings.Split(path[1:],"/") {
		if segment=="" || segment=="." || segment==".." { return false }
		for _,c:=range []byte(segment) {
			if !(c>='a' && c<='z' || c>='A' && c<='Z' || c>='0' && c<='9' || c=='-' || c=='_' || c=='.' || c=='~') { return false }
		}
	}
	return true
}

// StandardMethod excludes tunneling, tracing, custom methods and lowercase
// aliases. HEAD and OPTIONS need their own explicit grants.
func StandardMethod(method string) bool {
	switch method {
	case "GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS":
		return true
	}
	return false
}

func matches(prefix,path string) bool {
	return prefix=="/" || path==prefix || strings.HasPrefix(path,prefix+"/")
}

// Authorize uses the longest matching segment-boundary prefix. A denial
// never falls back to a broader rule; duplicate winning prefixes deny.
func (c *Config) Authorize(method,path string,agentScopes []string) (bool,string) {
	if c==nil || !CanonicalPath(path) || !StandardMethod(method) { return false,"invalid HTTP route or method" }
	var best *Rule
	tie:=false
	for i:=range c.Rules {
		r:=&c.Rules[i]
		if !CanonicalPath(r.PathPrefix) { return false,"invalid policy path" }
		if !matches(r.PathPrefix,path) { continue }
		if best==nil || len(r.PathPrefix)>len(best.PathPrefix) { best=r; tie=false
		} else if len(r.PathPrefix)==len(best.PathPrefix) { tie=true }
	}
	if best==nil { return false,"no matching Kgaga policy rule (default deny)" }
	if tie { return false,"ambiguous policy rule" }
	if slices.Contains(best.DenyMethods,method) || !slices.Contains(best.AllowedMethods,method) { return false,"HTTP method not allowed by policy" }
	for _,needed:=range best.AllowedScopes {
		if needed!="" && slices.Contains(agentScopes,needed) { return true,"authorized" }
	}
	return false,"agent passport lacks required scope"
}

func (c *Config) AuthorizeMCP(method, toolName, requiredScope string, agentScopes []string) (bool, string) {
	if toolName != "" && slices.Contains(c.MCP.DeniedTools, toolName) {
		return false, "MCP tool explicitly denied by kgaga.yaml: " + toolName
	}

	if toolName != "" {
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
