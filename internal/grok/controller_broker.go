package grok

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/Dicklesworthstone/ntm/internal/provider"
)

// ControllerBroker keeps workspace execution in NTM, outside Grok's inherited
// sandbox. Implementations expose only the existing constrained MCP broker.
type ControllerBroker interface {
	Call(context.Context, json.RawMessage) (json.RawMessage, error)
	Close() error
}

type ControllerBrokerBinding struct {
	Worktree, Revision, AuditFile, ExecutableSHA256 string
	Commands                                        []string
}

type ControllerBrokerFactory func(context.Context, ControllerBrokerBinding) (ControllerBroker, error)

// WithControllerBroker changes transport, not the immutable workspace or
// executable binding. The factory is trusted controller code, never RPC data.
func (d WorkspaceBrokerDescriptor) WithControllerBroker(factory ControllerBrokerFactory) (*WorkspaceBrokerDescriptor, error) {
	if factory == nil || d.validate() != nil {
		return nil, errors.New("controller broker requires a valid descriptor and factory")
	}
	d.args = append([]string(nil), d.args...)
	d.controller = factory
	return &d, nil
}

func (d WorkspaceBrokerDescriptor) openController(ctx context.Context) (ControllerBroker, error) {
	binding := ControllerBrokerBinding{Worktree: d.args[4], Revision: d.args[6], Commands: strings.Split(d.args[8], ","), ExecutableSHA256: d.args[10]}
	if len(d.args) == 13 {
		binding.AuditFile = d.args[12]
	}
	return d.controller(ctx, binding)
}

// ACP ExtRequest prefixes custom methods with an underscore on the wire.
const controllerMCPMethod = "_x.ai/mcp/sdk_call"

type controllerMCPRegistration struct {
	Name     string `json:"name"`
	ServerID string `json:"serverId"`
}

func newControllerMCPID() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return "ntm-" + hex.EncodeToString(nonce[:]), nil
}

// This wire shape is pinned to grok-build bb7f39d5, acp_mcp.rs and
// xai-grok-mcp/acp_transport.rs. Only requests travel over the reverse channel;
// notification, sampling, elicitation and arbitrary server routes are absent.
func replyControllerMCP(ctx context.Context, writer io.Writer, broker ControllerBroker, serverID string, toolsEnabled bool, seen map[string]bool, message rpcMessage) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var number int64
	var str string
	if len(message.ID) == 0 || len(message.ID) > 128 || string(message.ID) == "null" || (json.Unmarshal(message.ID, &number) != nil && json.Unmarshal(message.ID, &str) != nil) {
		return protocolError(provider.ProtocolMalformedMessage)
	}
	if seen[string(message.ID)] || len(seen) >= 512 {
		return protocolError(provider.ProtocolUnexpectedRequest)
	}
	var params struct {
		ServerID string          `json:"serverId"`
		Message  json.RawMessage `json:"message"`
	}
	decoder := json.NewDecoder(bytes.NewReader(message.Params))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&params) != nil || decoder.Decode(&struct{}{}) != io.EOF || len(params.Message) > 1<<20 {
		return protocolError(provider.ProtocolMalformedMessage)
	}
	if serverID == "" || params.ServerID != serverID {
		return protocolError(provider.ProtocolSessionMismatch)
	}
	var request struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params,omitempty"`
	}
	decoder = json.NewDecoder(bytes.NewReader(params.Message))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || request.JSONRPC != "2.0" || len(request.ID) == 0 || string(request.ID) == "null" {
		return protocolError(provider.ProtocolMalformedMessage)
	}
	if len(request.ID) > 128 || (json.Unmarshal(request.ID, &number) != nil && json.Unmarshal(request.ID, &str) != nil) {
		return protocolError(provider.ProtocolMalformedMessage)
	}
	switch request.Method {
	case "initialize", "tools/list":
	case "tools/call":
		if !toolsEnabled {
			return protocolError(provider.ProtocolUnexpectedRequest)
		}
	default:
		return protocolError(provider.ProtocolUnknownMethod)
	}
	seen[string(message.ID)] = true
	response, err := broker.Call(ctx, params.Message)
	if err != nil || len(response) > 1<<20 || !json.Valid(response) {
		return errors.New("controller MCP broker failed")
	}
	payload, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{"2.0", message.ID, response})
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	written, err := writer.Write(payload)
	if err != nil {
		return errors.New("controller MCP response write failed")
	}
	if written != len(payload) {
		return io.ErrShortWrite
	}
	return nil
}
