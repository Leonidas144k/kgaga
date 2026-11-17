package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type RPCRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      any            `json:"id,omitempty"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params,omitempty"`
}

type InspectionResult struct {
	Method        string
	ToolName      string
	RequiredScope string
}

func Inspect(r *http.Request, body []byte) (*InspectionResult, error) {
	if len(body) == 0 {
		return nil, errors.New("empty MCP payload")
	}

	var rpc RPCRequest
	if err := json.Unmarshal(body, &rpc); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC payload: %w", err)
	}

	if rpc.JSONRPC != "2.0" || rpc.Method == "" {
		return nil, errors.New("malformed JSON-RPC 2.0 envelope")
	}

	headerMethod := r.Header.Get("Mcp-Method")
	if headerMethod != "" && headerMethod != rpc.Method {
		return nil, fmt.Errorf("MCP protocol confusion blocked: header Mcp-Method (%s) != body method (%s)", headerMethod, rpc.Method)
	}

	res := &InspectionResult{
		Method: rpc.Method,
	}

	if rpc.Method == "tools/call" {
		toolName, ok := rpc.Params["name"].(string)
		if !ok || toolName == "" {
			return nil, errors.New("tools/call missing valid string params.name")
		}

		headerName := r.Header.Get("Mcp-Name")
		if headerName != "" && headerName != toolName {
			return nil, fmt.Errorf("MCP protocol confusion blocked: header Mcp-Name (%s) != body tool (%s)", headerName, toolName)
		}

		res.ToolName = toolName
		res.RequiredScope = "mcp:tool:" + toolName
	} else {
		res.RequiredScope = "mcp:method:" + rpc.Method
	}

	return res, nil
}
