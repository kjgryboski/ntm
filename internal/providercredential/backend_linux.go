//go:build linux

package providercredential

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
)

const (
	secretToolService   = "ntm-provider-credential-v1"
	secretToolAttribute = "credential-id"
)

type linuxSecretToolBackend struct{ path string }

func newNativeBackend() backend {
	path, err := exec.LookPath("secret-tool")
	if err != nil {
		return unavailableBackend{snapshot: unavailableStatus()}
	}
	return linuxSecretToolBackend{path: path}
}

func (b linuxSecretToolBackend) get(ctx context.Context, id string) ([]byte, error) {
	command := exec.CommandContext(ctx, b.path, "lookup", "service", secretToolService, secretToolAttribute, id)
	command.Stderr = io.Discard
	secret, err := command.Output()
	if err != nil {
		if exitCode(err) == 1 {
			return nil, ErrNotFound
		}
		return nil, ErrUnavailable
	}
	return bytes.TrimSuffix(secret, []byte("\n")), nil
}

func (b linuxSecretToolBackend) put(ctx context.Context, id string, secret []byte) error {
	// secret-tool reads the secret from stdin. It never appears in a command
	// line, environment variable, status, error, or receipt.
	command := exec.CommandContext(ctx, b.path, "store", "--label=NTM provider credential", "service", secretToolService, secretToolAttribute, id)
	command.Stdin = bytes.NewReader(secret)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Run(); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (b linuxSecretToolBackend) delete(ctx context.Context, id string) error {
	command := exec.CommandContext(ctx, b.path, "clear", "service", secretToolService, secretToolAttribute, id)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Run(); err != nil {
		if exitCode(err) == 1 {
			return ErrNotFound
		}
		return ErrUnavailable
	}
	return nil
}

func (b linuxSecretToolBackend) status(ctx context.Context, id string) (Status, error) {
	// Discard lookup output so Status can never return or print plaintext.
	command := exec.CommandContext(ctx, b.path, "lookup", "service", secretToolService, secretToolAttribute, id)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	err := command.Run()
	status := Status{Backend: BackendLinuxSecretTool, Available: true, Evidence: EvidenceOSProtectedProcessReadable}
	if err == nil {
		status.Present = true
		return status, nil
	}
	if exitCode(err) == 1 {
		return status, nil
	}
	return unavailableStatus(), nil
}

func exitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
