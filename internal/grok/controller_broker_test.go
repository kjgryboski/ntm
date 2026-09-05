package grok

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

type fakeControllerBroker struct {
	calls  int
	closed bool
}

func (b *fakeControllerBroker) Call(context.Context, json.RawMessage) (json.RawMessage, error) {
	b.calls++
	return json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`), nil
}
func (b *fakeControllerBroker) Close() error { b.closed = true; return nil }

func TestControllerMCPRejectsWrongBindingReplayAndUnapprovedMethods(t *testing.T) {
	for _, tc := range []struct {
		name, server, method string
		enabled              bool
		id                   json.RawMessage
	}{
		{"wrong-session", "other-server", "tools/list", true, json.RawMessage(`1`)},
		{"tool-before-prompt", "bound-server", "tools/call", false, json.RawMessage(`1`)},
		{"sampling", "bound-server", "sampling/createMessage", true, json.RawMessage(`1`)},
		{"notification", "bound-server", "tools/list", true, json.RawMessage(`null`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broker := &fakeControllerBroker{}
			params, _ := json.Marshal(map[string]any{"serverId": tc.server, "message": map[string]any{"jsonrpc": "2.0", "id": 1, "method": tc.method, "params": map[string]any{}}})
			if err := replyControllerMCP(t.Context(), &bytes.Buffer{}, broker, "bound-server", tc.enabled, map[string]bool{}, rpcMessage{ID: tc.id, Params: params}); err == nil || broker.calls != 0 {
				t.Fatalf("unsafe dispatch: calls=%d error=%v", broker.calls, err)
			}
		})
	}
	broker, seen, output := &fakeControllerBroker{}, map[string]bool{}, &bytes.Buffer{}
	message := rpcMessage{ID: json.RawMessage(`"outer-1"`), Params: json.RawMessage(`{"serverId":"bound-server","message":{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}}`)}
	if err := replyControllerMCP(t.Context(), output, broker, "bound-server", false, seen, message); err != nil || broker.calls != 1 {
		t.Fatalf("bound discovery failed: %v", err)
	}
	if err := replyControllerMCP(t.Context(), output, broker, "bound-server", false, seen, message); err == nil || broker.calls != 1 {
		t.Fatal("duplicate reverse request executed")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := replyControllerMCP(ctx, output, broker, "bound-server", true, map[string]bool{}, message); !errors.Is(err, context.Canceled) || broker.calls != 1 {
		t.Fatal("cancelled request executed")
	}
	var response rpcMessage
	if json.Unmarshal(bytes.TrimSpace(output.Bytes()), &response) != nil || string(response.ID) != `"outer-1"` || !bytes.Contains(response.Result, []byte(`"tools":[]`)) {
		t.Fatal("outer response correlation lost")
	}
}

func TestControllerBrokerBindingAndFailureCleanup(t *testing.T) {
	descriptor, err := NewWorkspaceBrokerDescriptor("/tmp/linked", strings.Repeat("a", 40), []string{"go-test"})
	if err != nil {
		t.Fatal(err)
	}
	broker := &fakeControllerBroker{}
	bound, err := descriptor.WithControllerBroker(func(_ context.Context, binding ControllerBrokerBinding) (ControllerBroker, error) {
		if binding.Worktree != "/tmp/linked" || binding.Revision != strings.Repeat("a", 40) || len(binding.Commands) != 1 || binding.Commands[0] != "go-test" || len(binding.ExecutableSHA256) != 64 {
			t.Fatal("controller lost immutable binding")
		}
		return broker, nil
	})
	if err != nil || bound.BindingSHA256() == descriptor.BindingSHA256() {
		t.Fatal("transport is not bound")
	}
	servers, err := (Request{Broker: bound}).SessionMCPServers()
	if err != nil || len(servers) != 0 {
		t.Fatal("controller transport also spawned an agent-owned broker")
	}
	_, err = Run(t.Context(), controllerFailRunner{}, Request{Prompt: "test", CWD: "/tmp/linked", RuntimeVersion: "1.0.13", Broker: bound})
	if err == nil || !broker.closed {
		t.Fatal("startup failure leaked controller broker")
	}
}

type controllerFailRunner struct{}

func (controllerFailRunner) Start(context.Context, StartSpec) (Process, error) {
	return nil, errors.New("synthetic startup failure")
}

func TestControllerBrokerRunsThroughRegisteredACPReverseChannel(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	proc := newFakeProcess(reader, strings.NewReader(""))
	proc.kill = func() { _ = writer.Close() }
	broker := &fakeControllerBroker{}
	descriptor, err := NewWorkspaceBrokerDescriptor("/tmp/linked", strings.Repeat("a", 40), []string{"go-test"})
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err = descriptor.WithControllerBroker(func(context.Context, ControllerBrokerBinding) (ControllerBroker, error) { return broker, nil })
	if err != nil {
		t.Fatal(err)
	}
	serverID := ""
	emit := func(line string) {
		if _, err := io.WriteString(writer, line+"\n"); err != nil {
			t.Error(err)
		}
	}
	proc.onWrite = func(request wireRequest) {
		switch request.Method {
		case "initialize":
			emit(`{"jsonrpc":"2.0","id":1,"result":{"authMethods":[{"id":"cached_token"}]}}`)
		case "authenticate":
			emit(`{"jsonrpc":"2.0","id":2,"result":{}}`)
		case "session/new":
			var params sessionNewParams
			if json.Unmarshal(request.Params, &params) != nil || len(params.MCPServers) != 0 || len(params.Meta.MCPServers) != 1 || params.Meta.MCPServers[0].Name != WorkspaceBrokerMCPName {
				t.Fatal("wrong broker registration")
			}
			serverID = params.Meta.MCPServers[0].ServerID
			emit(`{"jsonrpc":"2.0","id":3,"result":{"sessionId":"s"}}`)
		case "session/prompt":
			packet, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "sdk-1", "method": "_x.ai/mcp/sdk_call", "params": map[string]any{"serverId": serverID, "message": map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "read_file", "arguments": map[string]any{"path": "main.go"}}}}})
			emit(string(packet))
			emit(`{"jsonrpc":"2.0","id":4,"result":{"stopReason":"end_turn","_meta":{"modelId":"grok-4.6","usage":{"inputTokens":1,"outputTokens":1,"modelUsage":{"grok-4.6-build":{}}}}}}`)
		}
	}
	_, err = Run(t.Context(), &fakeRunner{proc: proc}, Request{Prompt: "test", CWD: "/tmp/linked", Model: "grok-4.6", RuntimeVersion: "1.0.13", Broker: descriptor})
	if err != nil || broker.calls != 1 || !broker.closed || serverID == "" {
		t.Fatalf("reverse broker lifecycle: calls=%d closed=%v err=%v", broker.calls, broker.closed, err)
	}
	if !strings.Contains(proc.stdin.String(), `"id":"sdk-1","result":{"jsonrpc"`) {
		t.Fatal("reverse response did not preserve outer request ID")
	}
}
