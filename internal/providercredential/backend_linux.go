//go:build linux

package providercredential

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/godbus/dbus/v5"
)

const (
	secretToolService                = "ntm-provider-credential-v1"
	secretToolAttribute              = "credential-id"
	secretServiceName                = "org.freedesktop.secrets"
	secretServicePath                = "/org/freedesktop/secrets"
	secretServiceAPI                 = "org.freedesktop.Secret.Service"
	secretCollectionAPI              = "org.freedesktop.Secret.Collection"
	secretItemAPI                    = "org.freedesktop.Secret.Item"
	sessionCollection                = "/org/freedesktop/secrets/collection/session"
	secretContentType                = "application/octet-stream"
	windowsProviderBridgeEnvironment = "NTM_WINDOWS_PROVIDER_BRIDGE"
	maxWindowsBridgeOutput           = (maxSecretBytes * 4 / 3) + 4096
)

var windowsBridgeNonce = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
var errLinuxDirectNoFallback = errors.New("direct Secret Service result must not fall back")

// linuxSecretToolBackend talks directly to the Secret Service. It resolves the
// default alias once per operation, verifies that exact collection is
// persistent and unlocked, and then uses only that object path. It never asks
// Secret Service to unlock, create a collection, change an alias, or service a
// prompt; those are intentionally owner-attended actions.
type linuxSecretToolBackend struct {
	open         func(context.Context) (linuxSecretService, error)
	bridgePath   string
	bridgeInvoke func(context.Context, string, windowsCredentialBridgeRequest) (windowsCredentialBridgeResponse, error)
}

type linuxSecretService interface {
	DefaultCollection(context.Context) (linuxSecretCollection, error)
	Close() error
}

type linuxSecretCollection interface {
	Search(context.Context, string) ([]linuxSecretItem, error)
	Create(context.Context, string, []byte) error
}

type linuxSecretItem interface {
	Secret(context.Context) ([]byte, error)
	Delete(context.Context) error
}

func newNativeBackend() backend {
	return newLinuxSecretToolBackend(openLinuxSecretService, isWSLHost(), os.Getenv(windowsProviderBridgeEnvironment), invokeWindowsCredentialBridge)
}

func newLinuxSecretToolBackend(open func(context.Context) (linuxSecretService, error), wsl bool, bridgePath string, invoke func(context.Context, string, windowsCredentialBridgeRequest) (windowsCredentialBridgeResponse, error)) linuxSecretToolBackend {
	backend := linuxSecretToolBackend{open: open}
	if wsl && validWindowsBridgePath(bridgePath) && invoke != nil {
		backend.bridgePath = bridgePath
		backend.bridgeInvoke = invoke
	}
	return backend
}

func (b linuxSecretToolBackend) get(ctx context.Context, id string) ([]byte, error) {
	secret, err := b.getDirect(ctx, id)
	if errors.Is(err, errLinuxDirectNoFallback) {
		return nil, ErrUnavailable
	}
	if (err != ErrUnavailable && err != ErrNotFound) || b.bridgeInvoke == nil || b.bridgePath == "" {
		return secret, err
	}
	return b.getWindowsBridge(ctx, id)
}

func (b linuxSecretToolBackend) getDirect(ctx context.Context, id string) ([]byte, error) {
	collection, close, err := b.collection(ctx)
	if err != nil {
		return nil, err
	}
	defer close()
	items, err := collection.Search(ctx, id)
	if err != nil || len(items) > 1 {
		return nil, errLinuxDirectNoFallback
	}
	if len(items) == 0 {
		return nil, ErrNotFound
	}
	secret, err := items[0].Secret(ctx)
	if err != nil || len(secret) == 0 {
		zeroLinuxSecret(secret)
		return nil, errLinuxDirectNoFallback
	}
	return secret, nil
}

func (b linuxSecretToolBackend) put(ctx context.Context, id string, secret []byte) error {
	collection, close, err := b.collection(ctx)
	if err != nil {
		return err
	}
	defer close()
	if err := collection.Create(ctx, id, secret); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (b linuxSecretToolBackend) delete(ctx context.Context, id string) error {
	collection, close, err := b.collection(ctx)
	if err != nil {
		return err
	}
	defer close()
	items, err := collection.Search(ctx, id)
	if err != nil || len(items) > 1 {
		return ErrUnavailable
	}
	if len(items) == 0 {
		return ErrNotFound
	}
	if err := items[0].Delete(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (b linuxSecretToolBackend) status(ctx context.Context, id string) (Status, error) {
	status, err := b.statusDirect(ctx, id)
	if errors.Is(err, errLinuxDirectNoFallback) {
		return unavailableStatus(), nil
	}
	if b.bridgeInvoke == nil || b.bridgePath == "" || (err == nil && status.Present) {
		return status, nil
	}
	return b.statusWindowsBridge(ctx, id)
}

func (b linuxSecretToolBackend) statusDirect(ctx context.Context, id string) (Status, error) {
	collection, close, err := b.collection(ctx)
	if err != nil {
		return unavailableStatus(), ErrUnavailable
	}
	defer close()
	items, err := collection.Search(ctx, id)
	if err != nil || len(items) > 1 {
		return unavailableStatus(), errLinuxDirectNoFallback
	}
	return Status{Backend: BackendLinuxSecretTool, Available: true, Present: len(items) == 1, Evidence: EvidenceOSProtectedProcessReadable}, nil
}

type windowsCredentialBridgeRequest struct {
	Operation    string `json:"operation"`
	CredentialID string `json:"credential_id"`
	Nonce        string `json:"nonce"`
}

type windowsCredentialBridgeResponse struct {
	Credential string  `json:"credential_base64,omitempty"`
	Status     *Status `json:"credential_status,omitempty"`
	Nonce      string  `json:"nonce,omitempty"`
	Error      string  `json:"error,omitempty"`
}

func (b linuxSecretToolBackend) getWindowsBridge(ctx context.Context, id string) ([]byte, error) {
	nonce, err := newWindowsBridgeNonce()
	if err != nil {
		return nil, ErrUnavailable
	}
	response, err := b.bridgeInvoke(ctx, b.bridgePath, windowsCredentialBridgeRequest{Operation: "credential_get", CredentialID: id, Nonce: nonce})
	if err != nil || response.Error != "" || response.Nonce != nonce || response.Status != nil || response.Credential == "" {
		return nil, ErrUnavailable
	}
	secret, err := base64.RawURLEncoding.DecodeString(response.Credential)
	if err != nil || len(secret) == 0 || len(secret) > maxSecretBytes {
		zeroLinuxSecret(secret)
		return nil, ErrUnavailable
	}
	return secret, nil
}

func (b linuxSecretToolBackend) statusWindowsBridge(ctx context.Context, id string) (Status, error) {
	nonce, err := newWindowsBridgeNonce()
	if err != nil {
		return unavailableStatus(), nil
	}
	response, err := b.bridgeInvoke(ctx, b.bridgePath, windowsCredentialBridgeRequest{Operation: "credential_status", CredentialID: id, Nonce: nonce})
	if err != nil || response.Error != "" || response.Nonce != nonce || response.Credential != "" || response.Status == nil || !validWindowsBridgeStatus(*response.Status) {
		return unavailableStatus(), nil
	}
	return *response.Status, nil
}

func validWindowsBridgeStatus(status Status) bool {
	return status.Backend == BackendWindowsCredentialManager && status.Available && status.Evidence == EvidenceOSProtectedProcessReadable
}

func newWindowsBridgeNonce() (string, error) {
	value := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		zeroLinuxSecret(value)
		return "", err
	}
	defer zeroLinuxSecret(value)
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func invokeWindowsCredentialBridge(ctx context.Context, path string, request windowsCredentialBridgeRequest) (windowsCredentialBridgeResponse, error) {
	if ctx == nil || ctx.Err() != nil || !validWindowsBridgePath(path) || !windowsBridgeNonce.MatchString(request.Nonce) || request.CredentialID == "" || (request.Operation != "credential_get" && request.Operation != "credential_status") {
		return windowsCredentialBridgeResponse{}, ErrUnavailable
	}
	input, err := json.Marshal(request)
	if err != nil {
		return windowsCredentialBridgeResponse{}, ErrUnavailable
	}
	defer zeroLinuxSecret(input)
	command := exec.CommandContext(ctx, path)
	command.Stdin = bytes.NewReader(input)
	command.Stderr = io.Discard
	output := &limitedWindowsBridgeOutput{limit: maxWindowsBridgeOutput}
	command.Stdout = output
	if err := command.Run(); err != nil || output.exceeded {
		zeroLinuxSecret(output.Bytes())
		return windowsCredentialBridgeResponse{}, ErrUnavailable
	}
	defer zeroLinuxSecret(output.Bytes())
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	decoder.DisallowUnknownFields()
	var response windowsCredentialBridgeResponse
	if err := decoder.Decode(&response); err != nil {
		return windowsCredentialBridgeResponse{}, ErrUnavailable
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return windowsCredentialBridgeResponse{}, ErrUnavailable
	}
	return response, nil
}

type limitedWindowsBridgeOutput struct {
	bytes.Buffer
	limit    int
	exceeded bool
}

func (b *limitedWindowsBridgeOutput) Write(value []byte) (int, error) {
	if b.Len()+len(value) > b.limit {
		b.exceeded = true
		return 0, ErrUnavailable
	}
	return b.Buffer.Write(value)
}

func validWindowsBridgePath(path string) bool {
	return filepath.IsAbs(path) && !strings.ContainsRune(path, '\x00')
}

func isWSLHost() bool {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	return err == nil && strings.Contains(strings.ToLower(string(data)), "microsoft")
}

func zeroLinuxSecret(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (b linuxSecretToolBackend) collection(ctx context.Context) (linuxSecretCollection, func(), error) {
	if ctx == nil || ctx.Err() != nil || b.open == nil {
		return nil, func() {}, ErrUnavailable
	}
	service, err := b.open(ctx)
	if err != nil {
		return nil, func() {}, ErrUnavailable
	}
	collection, err := service.DefaultCollection(ctx)
	if err != nil {
		_ = service.Close()
		return nil, func() {}, ErrUnavailable
	}
	return collection, func() { _ = service.Close() }, nil
}

type linuxDBusSecretService struct {
	conn    *dbus.Conn
	session dbus.ObjectPath
}

type linuxDBusSecretCollection struct {
	service *linuxDBusSecretService
	path    dbus.ObjectPath
}

type linuxDBusSecretItem struct {
	service *linuxDBusSecretService
	path    dbus.ObjectPath
}

// secretServiceSecret is the documented (oayays) Secret Service tuple.
type secretServiceSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func openLinuxSecretService(ctx context.Context) (linuxSecretService, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, ErrUnavailable
	}
	service := &linuxDBusSecretService{conn: conn}
	var ignored dbus.Variant
	var session dbus.ObjectPath
	if err := conn.Object(secretServiceName, dbus.ObjectPath(secretServicePath)).CallWithContext(ctx, secretServiceAPI+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&ignored, &session); err != nil || !validObjectPath(session) {
		_ = conn.Close()
		return nil, ErrUnavailable
	}
	service.session = session
	return service, nil
}

func (s *linuxDBusSecretService) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

func (s *linuxDBusSecretService) DefaultCollection(ctx context.Context) (linuxSecretCollection, error) {
	if ctx == nil || ctx.Err() != nil || s == nil || s.conn == nil {
		return nil, ErrUnavailable
	}
	var path dbus.ObjectPath
	if err := s.conn.Object(secretServiceName, dbus.ObjectPath(secretServicePath)).CallWithContext(ctx, secretServiceAPI+".ReadAlias", 0, "default").Store(&path); err != nil || !validObjectPath(path) || !persistentCollectionPath(string(path)) {
		return nil, ErrUnavailable
	}
	collection := &linuxDBusSecretCollection{service: s, path: path}
	locked, err := collection.locked(ctx)
	if err != nil || locked {
		return nil, ErrUnavailable
	}
	return collection, nil
}

func (c *linuxDBusSecretCollection) locked(ctx context.Context) (bool, error) {
	if ctx == nil || ctx.Err() != nil || c == nil || c.service == nil || c.service.conn == nil {
		return true, ErrUnavailable
	}
	var property dbus.Variant
	if err := c.service.conn.Object(secretServiceName, c.path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, secretCollectionAPI, "Locked").Store(&property); err != nil {
		return true, ErrUnavailable
	}
	locked, ok := property.Value().(bool)
	if !ok {
		return true, ErrUnavailable
	}
	return locked, nil
}

func (c *linuxDBusSecretCollection) Search(ctx context.Context, id string) ([]linuxSecretItem, error) {
	if ctx == nil || ctx.Err() != nil || c == nil || c.service == nil || c.service.conn == nil {
		return nil, ErrUnavailable
	}
	var paths []dbus.ObjectPath
	attributes := map[string]string{"service": secretToolService, secretToolAttribute: id}
	if err := c.service.conn.Object(secretServiceName, c.path).CallWithContext(ctx, secretCollectionAPI+".SearchItems", 0, attributes).Store(&paths); err != nil {
		return nil, ErrUnavailable
	}
	items := make([]linuxSecretItem, 0, len(paths))
	for _, path := range paths {
		if !validObjectPath(path) {
			return nil, ErrUnavailable
		}
		items = append(items, &linuxDBusSecretItem{service: c.service, path: path})
	}
	return items, nil
}

func (c *linuxDBusSecretCollection) Create(ctx context.Context, id string, value []byte) error {
	if ctx == nil || ctx.Err() != nil || c == nil || c.service == nil || c.service.conn == nil || len(value) == 0 {
		return ErrUnavailable
	}
	properties := map[string]dbus.Variant{
		secretItemAPI + ".Label":      dbus.MakeVariant("NTM provider credential"),
		secretItemAPI + ".Attributes": dbus.MakeVariant(map[string]string{"service": secretToolService, secretToolAttribute: id}),
	}
	secret := secretServiceSecret{Session: c.service.session, Parameters: []byte{}, Value: append([]byte(nil), value...), ContentType: secretContentType}
	defer zeroLinuxSecret(secret.Parameters)
	defer zeroLinuxSecret(secret.Value)
	var item, prompt dbus.ObjectPath
	err := c.service.conn.Object(secretServiceName, c.path).CallWithContext(ctx, secretCollectionAPI+".CreateItem", 0, properties, secret, true).Store(&item, &prompt)
	if err != nil || !validObjectPath(item) || !noPrompt(prompt) {
		return ErrUnavailable
	}
	return nil
}

func (i *linuxDBusSecretItem) Secret(ctx context.Context) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || i == nil || i.service == nil || i.service.conn == nil {
		return nil, ErrUnavailable
	}
	var secret secretServiceSecret
	if err := i.service.conn.Object(secretServiceName, i.path).CallWithContext(ctx, secretItemAPI+".GetSecret", 0, i.service.session).Store(&secret); err != nil || secret.Session != i.service.session || len(secret.Parameters) != 0 || secret.ContentType != secretContentType || len(secret.Value) == 0 {
		zeroLinuxSecret(secret.Parameters)
		zeroLinuxSecret(secret.Value)
		return nil, ErrUnavailable
	}
	value := append([]byte(nil), secret.Value...)
	zeroLinuxSecret(secret.Parameters)
	zeroLinuxSecret(secret.Value)
	return value, nil
}

func (i *linuxDBusSecretItem) Delete(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil || i == nil || i.service == nil || i.service.conn == nil {
		return ErrUnavailable
	}
	var prompt dbus.ObjectPath
	if err := i.service.conn.Object(secretServiceName, i.path).CallWithContext(ctx, secretItemAPI+".Delete", 0).Store(&prompt); err != nil || !noPrompt(prompt) {
		return ErrUnavailable
	}
	return nil
}

func persistentCollectionPath(path string) bool {
	if !validObjectPath(dbus.ObjectPath(path)) || path == "/" || !strings.HasPrefix(path, "/org/freedesktop/secrets/collection/") {
		return false
	}
	return path != sessionCollection && !strings.HasPrefix(path, sessionCollection+"/")
}

func validObjectPath(path dbus.ObjectPath) bool {
	return path != "" && path != "/" && path.IsValid()
}

func noPrompt(path dbus.ObjectPath) bool { return path == "/" }
