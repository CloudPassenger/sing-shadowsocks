package shadowaead

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
)

func TestNewMultiServiceRejectsUnknownMethod(t *testing.T) {
	_, err := NewMultiService[string]("not-a-method", 60, &multiServiceTestHandler{})
	if !errors.Is(err, os.ErrInvalid) {
		t.Fatalf("unknown method error = %v, want %v", err, os.ErrInvalid)
	}
}

func TestMultiServiceFailedUpdateKeepsPublishedState(t *testing.T) {
	service := newMultiServiceTestService(t, &multiServiceTestHandler{})
	if err := service.UpdateUsersWithPasswords([]string{"alice"}, []string{"alice-password"}); err != nil {
		t.Fatal(err)
	}
	published := service.users.Load()

	if err := service.UpdateUsers([]string{"alice", "bob"}, [][]byte{{0x01}}); err == nil {
		t.Fatal("mismatched user and key lists were accepted")
	}
	if service.users.Load() != published {
		t.Fatal("mismatched update changed the published state")
	}
	if err := service.UpdateUsers([]string{"alice"}, [][]byte{{0x01}}); err == nil {
		t.Fatal("wrong-length key was accepted")
	}
	if service.users.Load() != published {
		t.Fatal("invalid key update changed the published state")
	}
	if err := service.UpdateUsersWithPasswords([]string{"alice", "bob"}, []string{"alice-password"}); err == nil {
		t.Fatal("mismatched user and password lists were accepted")
	}
	if service.users.Load() != published {
		t.Fatal("failed password update changed the published state")
	}
}

func TestMultiServiceUpdateDeepCopiesKeys(t *testing.T) {
	handler := newMultiServiceCaptureHandler()
	service := newMultiServiceTestService(t, handler)
	key := make([]byte, 16)
	for index := range key {
		key[index] = byte(index + 1)
	}
	originalKey := append([]byte(nil), key...)
	if err := service.UpdateUsers([]string{"alice"}, [][]byte{key}); err != nil {
		t.Fatal(err)
	}
	key[0] ^= 0xff

	payload := []byte("deep-copy")
	request := makeMultiServiceTCPRequest(t, "aes-128-gcm", originalKey, "", payload)
	if err := runMultiServiceTCP(service, request, "alice"); err != nil {
		t.Fatal(err)
	}
	result := receiveMultiServiceTCPResult(t, handler)
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.user != "alice" || !bytes.Equal(result.payload, payload) {
		t.Fatalf("authenticated result = user %q payload %q", result.user, result.payload)
	}
}

func TestMultiServiceUpdateDuplicateHandling(t *testing.T) {
	service := newMultiServiceTestService(t, &multiServiceTestHandler{})
	keyA := bytes.Repeat([]byte{0x11}, 16)

	// Upstream parity: duplicate users and credentials are published as-is, and
	// the first matching candidate wins. sing-box rejects duplicates before the
	// managed-user transaction commits.
	if err := service.UpdateUsers([]string{"alice", "bob"}, [][]byte{keyA, keyA}); err != nil {
		t.Fatal(err)
	}
	state := service.users.Load()
	if len(state.candidates) != 2 {
		t.Fatalf("published candidate count = %d, want 2", len(state.candidates))
	}
	if err := service.UpdateUsersWithPasswords([]string{"alice"}, []string{""}); err == nil {
		t.Fatal("empty password was accepted")
	}
}

func TestMultiServicePreservesPublishedOrder(t *testing.T) {
	service := newMultiServiceTestService(t, &multiServiceTestHandler{})
	users := []string{"user-z", "user-a", "user-m"}
	if err := service.UpdateUsersWithPasswords(
		users,
		[]string{"password-z", "password-a", "password-m"},
	); err != nil {
		t.Fatal(err)
	}
	state := service.users.Load()
	for index, candidate := range state.candidates {
		if candidate.user != users[index] {
			t.Fatalf("candidate %d = %q, want %q", index, candidate.user, users[index])
		}
	}
	if state.hot.Load() != nil {
		t.Fatal("newly published state inherited a hot candidate")
	}
}

func TestMultiServiceTCPMatchesEveryCandidatePosition(t *testing.T) {
	users := []string{"first", "second", "middle", "fourth", "last"}
	passwords := []string{"password-1", "password-2", "password-3", "password-4", "password-5"}
	for _, testCase := range []struct {
		name  string
		index int
	}{
		{name: "first", index: 0},
		{name: "middle", index: 2},
		{name: "last after failed candidates", index: 4},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			handler := newMultiServiceCaptureHandler()
			service := newMultiServiceTestService(t, handler)
			if err := service.UpdateUsersWithPasswords(users, passwords); err != nil {
				t.Fatal(err)
			}
			payload := []byte{byte(testCase.index), 0xaa, 0x55}
			request := makeMultiServiceTCPRequest(t, "aes-128-gcm", nil, passwords[testCase.index], payload)
			if err := runMultiServiceTCP(service, request, users[testCase.index]); err != nil {
				t.Fatal(err)
			}
			result := receiveMultiServiceTCPResult(t, handler)
			if result.err != nil {
				t.Fatal(result.err)
			}
			if result.user != users[testCase.index] {
				t.Fatalf("authenticated user = %q, want %q", result.user, users[testCase.index])
			}
			if result.destination.String() != "example.com:443" {
				t.Fatalf("destination = %v, want example.com:443", result.destination)
			}
			if !bytes.Equal(result.payload, payload) {
				t.Fatalf("payload = %x, want %x", result.payload, payload)
			}
			state := service.users.Load()
			if state.hot.Load() != &state.candidates[testCase.index] {
				t.Fatal("successful TCP authentication did not update the hot candidate")
			}
		})
	}
}

func TestMultiServiceTCPRejectsUnknownCredential(t *testing.T) {
	handler := newMultiServiceCaptureHandler()
	service := newMultiServiceTestService(t, handler)
	if err := service.UpdateUsersWithPasswords([]string{"alice", "bob"}, []string{"alice-password", "bob-password"}); err != nil {
		t.Fatal(err)
	}
	request := makeMultiServiceTCPRequest(t, "aes-128-gcm", nil, "unknown-password", nil)
	if err := runMultiServiceTCP(service, request, ""); err == nil {
		t.Fatal("unknown TCP credential was accepted")
	}
	if service.users.Load().hot.Load() != nil {
		t.Fatal("unknown TCP credential changed the hot candidate")
	}
	select {
	case result := <-handler.tcpResults:
		t.Fatalf("handler received rejected TCP request: %+v", result)
	default:
	}
}

func TestMultiServiceHotHintIsStateLocal(t *testing.T) {
	handler := newMultiServiceCaptureHandler()
	service := newMultiServiceTestService(t, handler)
	users := []string{"first", "middle", "last"}
	passwords := []string{"password-1", "password-2", "password-3"}
	if err := service.UpdateUsersWithPasswords(users, passwords); err != nil {
		t.Fatal(err)
	}
	oldState := service.users.Load()

	request := makeMultiServiceTCPRequest(t, "aes-128-gcm", nil, passwords[1], nil)
	if err := runMultiServiceTCP(service, request, users[1]); err != nil {
		t.Fatal(err)
	}
	_ = receiveMultiServiceTCPResult(t, handler)
	if oldState.hot.Load() != &oldState.candidates[1] {
		t.Fatal("middle candidate was not installed as the hot hint")
	}

	request = makeMultiServiceTCPRequest(t, "aes-128-gcm", nil, passwords[2], nil)
	if err := runMultiServiceTCP(service, request, users[2]); err != nil {
		t.Fatal(err)
	}
	_ = receiveMultiServiceTCPResult(t, handler)
	if oldState.hot.Load() != &oldState.candidates[2] {
		t.Fatal("base-order fallback after a failed hot trial did not refresh the hint")
	}

	unknown := makeMultiServiceTCPRequest(t, "aes-128-gcm", nil, "unknown-password", nil)
	if err := runMultiServiceTCP(service, unknown, ""); err == nil {
		t.Fatal("unknown credential was accepted")
	}
	if oldState.hot.Load() != &oldState.candidates[2] {
		t.Fatal("failed authentication changed the hot hint")
	}

	if err := service.UpdateUsersWithPasswords(users, passwords); err != nil {
		t.Fatal(err)
	}
	newState := service.users.Load()
	if newState == oldState {
		t.Fatal("new generation reused the old state")
	}
	if newState.hot.Load() != nil {
		t.Fatal("new generation inherited the previous generation's hot hint")
	}
	if oldState.hot.Load() != &oldState.candidates[2] {
		t.Fatal("publishing a new state mutated the old state hint")
	}
}

func TestMultiServiceUDPMatchesEveryCandidatePosition(t *testing.T) {
	users := []string{"first", "second", "middle", "fourth", "last"}
	passwords := []string{"password-1", "password-2", "password-3", "password-4", "password-5"}
	for _, testCase := range []struct {
		name  string
		index int
	}{
		{name: "first", index: 0},
		{name: "middle", index: 2},
		{name: "last after failed candidates", index: 4},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			handler := newMultiServiceCaptureHandler()
			service := newMultiServiceTestService(t, handler)
			if err := service.UpdateUsersWithPasswords(users, passwords); err != nil {
				t.Fatal(err)
			}
			payload := []byte{byte(testCase.index), 0x10, 0x20, 0x30}
			request := makeMultiServiceUDPRequest(t, "aes-128-gcm", nil, passwords[testCase.index], payload)
			packet := buf.As(request)
			metadata := M.Metadata{Source: M.ParseSocksaddr(fmt.Sprintf("127.0.0.1:%d", 12000+testCase.index))}
			if err := service.newPacket(context.Background(), &multiServiceTestPacketConn{}, packet, metadata); err != nil {
				t.Fatal(err)
			}
			result := receiveMultiServiceUDPResult(t, handler)
			if result.err != nil {
				t.Fatal(result.err)
			}
			if result.user != users[testCase.index] {
				t.Fatalf("authenticated user = %q, want %q", result.user, users[testCase.index])
			}
			if result.destination.String() != "example.com:443" {
				t.Fatalf("destination = %v, want example.com:443", result.destination)
			}
			if !bytes.Equal(result.payload, payload) {
				t.Fatalf("payload = %x, want %x", result.payload, payload)
			}
			state := service.users.Load()
			if state.hot.Load() != &state.candidates[testCase.index] {
				t.Fatal("successful UDP authentication did not update the hot candidate")
			}
		})
	}
}

func TestMultiServiceUDPRejectsUnknownCredentialWithoutMutatingCiphertext(t *testing.T) {
	service := newMultiServiceTestService(t, newMultiServiceCaptureHandler())
	if err := service.UpdateUsersWithPasswords([]string{"alice", "bob", "carol"}, []string{"alice-password", "bob-password", "carol-password"}); err != nil {
		t.Fatal(err)
	}
	request := makeMultiServiceUDPRequest(t, "aes-128-gcm", nil, "unknown-password", []byte("payload"))
	original := append([]byte(nil), request...)
	packet := buf.As(request)
	metadata := M.Metadata{Source: M.ParseSocksaddr("127.0.0.1:13000")}
	if err := service.newPacket(context.Background(), &multiServiceTestPacketConn{}, packet, metadata); err == nil {
		t.Fatal("unknown UDP credential was accepted")
	}
	if !bytes.Equal(packet.Bytes(), original) {
		t.Fatal("failed UDP candidate trials mutated the ciphertext buffer")
	}
	if service.users.Load().hot.Load() != nil {
		t.Fatal("unknown UDP credential changed the hot candidate")
	}
}

func TestMultiServiceUDPSeparatesAuthenticatedCandidatesAndGenerations(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	handler := &multiServicePersistentPacketHandler{
		sessions: make(chan string, 3),
		release:  release,
	}
	service := newMultiServiceTestService(t, handler)
	users := []string{"alice", "bob"}
	passwords := []string{"alice-password", "bob-password"}
	if err := service.UpdateUsersWithPasswords(users, passwords); err != nil {
		t.Fatal(err)
	}

	metadata := M.Metadata{Source: M.ParseSocksaddr("127.0.0.1:14000")}
	send := func(password string) {
		t.Helper()
		request := makeMultiServiceUDPRequest(t, "aes-128-gcm", nil, password, []byte("payload"))
		if err := service.newPacket(context.Background(), &multiServiceTestPacketConn{}, buf.As(request), metadata); err != nil {
			t.Fatal(err)
		}
	}
	expectSession := func(expected string) {
		t.Helper()
		select {
		case user := <-handler.sessions:
			if user != expected {
				t.Fatalf("UDP session user = %q, want %q", user, expected)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for UDP session for %q", expected)
		}
	}

	send(passwords[0])
	expectSession("alice")
	if err := service.UpdateUsersWithPasswords(users, passwords); err != nil {
		t.Fatal(err)
	}
	send(passwords[0])
	select {
	case user := <-handler.sessions:
		t.Fatalf("identical republish created a new UDP session for %q", user)
	case <-time.After(100 * time.Millisecond):
	}
	send(passwords[1])
	expectSession("bob")

	passwords[0] = "alice-rotated"
	if err := service.UpdateUsersWithPasswords(users, passwords); err != nil {
		t.Fatal(err)
	}
	send(passwords[0])
	expectSession("alice")
}

func TestMultiServiceConcurrentAuthenticationAndUpdates(t *testing.T) {
	service := newMultiServiceTestService(t, &multiServiceTestHandler{})
	usersForward := []string{"alice", "bob"}
	passwordsForward := []string{"alice-password", "bob-password"}
	usersReverse := []string{"bob", "alice"}
	passwordsReverse := []string{"bob-password", "alice-password"}
	if err := service.UpdateUsersWithPasswords(usersForward, passwordsForward); err != nil {
		t.Fatal(err)
	}
	requests := [][]byte{
		makeMultiServiceTCPRequest(t, "aes-128-gcm", nil, passwordsForward[0], nil),
		makeMultiServiceTCPRequest(t, "aes-128-gcm", nil, passwordsForward[1], nil),
	}

	start := make(chan struct{})
	errors := make(chan error, 1)
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		<-start
		for iteration := 0; iteration < 1000; iteration++ {
			var err error
			if iteration%2 == 0 {
				err = service.UpdateUsersWithPasswords(usersReverse, passwordsReverse)
			} else {
				err = service.UpdateUsersWithPasswords(usersForward, passwordsForward)
			}
			if err != nil {
				reportMultiServiceTestError(errors, err)
				return
			}
		}
	}()
	for worker := 0; worker < 6; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			<-start
			userIndex := worker % len(requests)
			for iteration := 0; iteration < 300; iteration++ {
				if err := runMultiServiceTCP(service, requests[userIndex], usersForward[userIndex]); err != nil {
					reportMultiServiceTestError(errors, err)
					return
				}
			}
		}(worker)
	}
	close(start)
	group.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
}

func newMultiServiceTestService(t testing.TB, handler shadowsocks.Handler) *MultiService[string] {
	t.Helper()
	service, err := NewMultiService[string]("aes-128-gcm", 60, handler)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func runMultiServiceTCP(service *MultiService[string], request []byte, expectedUser string) error {
	ctx := context.WithValue(context.Background(), multiServiceExpectedUserKey{}, expectedUser)
	conn := &multiServiceTestConn{Reader: bytes.NewReader(request)}
	return service.newConnection(ctx, conn, M.Metadata{})
}

func makeMultiServiceTCPRequest(tb testing.TB, methodName string, key []byte, password string, payload []byte) []byte {
	tb.Helper()
	method, err := New(methodName, key, password)
	if err != nil {
		tb.Fatal(err)
	}
	salt := makeMultiServiceSalt(method.keySaltLength)
	requestCipher := makeMultiServiceRequestCipher(tb, method, salt)
	destination := M.ParseSocksaddr("example.com:443")
	plaintext := buf.NewSize(M.SocksaddrSerializer.AddrPortLen(destination) + len(payload))
	defer plaintext.Release()
	if err = M.SocksaddrSerializer.WriteAddrPort(plaintext, destination); err != nil {
		tb.Fatal(err)
	}
	if _, err = plaintext.Write(payload); err != nil {
		tb.Fatal(err)
	}

	var nonce [24]byte
	var length [PacketLengthBufferSize]byte
	binary.BigEndian.PutUint16(length[:], uint16(plaintext.Len()))
	request := make([]byte, len(salt), len(salt)+PacketLengthBufferSize+Overhead+plaintext.Len()+Overhead)
	copy(request, salt)
	request = requestCipher.Seal(request, nonce[:requestCipher.NonceSize()], length[:], nil)
	increaseNonce(nonce[:requestCipher.NonceSize()])
	request = requestCipher.Seal(request, nonce[:requestCipher.NonceSize()], plaintext.Bytes(), nil)
	return request
}

func makeMultiServiceUDPRequest(tb testing.TB, methodName string, key []byte, password string, payload []byte) []byte {
	tb.Helper()
	method, err := New(methodName, key, password)
	if err != nil {
		tb.Fatal(err)
	}
	salt := makeMultiServiceSalt(method.keySaltLength)
	requestCipher := makeMultiServiceRequestCipher(tb, method, salt)
	destination := M.ParseSocksaddr("example.com:443")
	plaintext := buf.NewSize(M.SocksaddrSerializer.AddrPortLen(destination) + len(payload))
	defer plaintext.Release()
	if err = M.SocksaddrSerializer.WriteAddrPort(plaintext, destination); err != nil {
		tb.Fatal(err)
	}
	if _, err = plaintext.Write(payload); err != nil {
		tb.Fatal(err)
	}

	request := make([]byte, len(salt), len(salt)+plaintext.Len()+Overhead)
	copy(request, salt)
	return requestCipher.Seal(request, rw.ZeroBytes[:requestCipher.NonceSize()], plaintext.Bytes(), nil)
}

func makeMultiServiceRequestCipher(tb testing.TB, method *Method, salt []byte) cipher.AEAD {
	tb.Helper()
	key := buf.NewSize(method.keySaltLength)
	defer key.Release()
	Kdf(method.key, salt, key)
	requestCipher, err := method.constructor(key.Bytes())
	if err != nil {
		tb.Fatal(err)
	}
	return requestCipher
}

func makeMultiServiceSalt(length int) []byte {
	salt := make([]byte, length)
	for index := range salt {
		salt[index] = byte(index*13 + 7)
	}
	return salt
}

type multiServiceExpectedUserKey struct{}

type multiServiceTestResult struct {
	user        string
	destination M.Socksaddr
	payload     []byte
	err         error
}

type multiServiceTestHandler struct {
	tcpResults chan multiServiceTestResult
	udpResults chan multiServiceTestResult
}

func newMultiServiceCaptureHandler() *multiServiceTestHandler {
	return &multiServiceTestHandler{
		tcpResults: make(chan multiServiceTestResult, 16),
		udpResults: make(chan multiServiceTestResult, 16),
	}
}

//nolint:staticcheck // The v0.2.8 handler contract still uses metadata.Metadata.
func (h *multiServiceTestHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	result := multiServiceTestResult{destination: metadata.Destination}
	result.user, _ = auth.UserFromContext[string](ctx)
	if result.user == "" {
		result.err = fmt.Errorf("authenticated user is missing")
	}
	if expected, loaded := ctx.Value(multiServiceExpectedUserKey{}).(string); loaded && expected != "" && result.user != expected {
		result.err = fmt.Errorf("authenticated user = %q, want %q", result.user, expected)
	}
	if h.tcpResults != nil {
		result.payload, _ = io.ReadAll(conn)
		h.tcpResults <- result
	}
	return result.err
}

//nolint:staticcheck // The v0.2.8 handler contract still uses metadata.Metadata.
func (h *multiServiceTestHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	result := multiServiceTestResult{destination: metadata.Destination}
	result.user, _ = auth.UserFromContext[string](ctx)
	if result.user == "" {
		result.err = fmt.Errorf("authenticated user is missing")
	}
	if h.udpResults != nil {
		packet := buf.NewPacket()
		destination, err := conn.ReadPacket(packet)
		if err != nil {
			result.err = err
		} else {
			result.destination = destination
			result.payload = append([]byte(nil), packet.Bytes()...)
		}
		packet.Release()
		h.udpResults <- result
	}
	return result.err
}

func (h *multiServiceTestHandler) NewError(context.Context, error) {}

type multiServicePersistentPacketHandler struct {
	sessions chan string
	release  <-chan struct{}
}

//nolint:staticcheck // The v0.2.8 handler contract still uses metadata.Metadata.
func (h *multiServicePersistentPacketHandler) NewConnection(context.Context, net.Conn, M.Metadata) error {
	return nil
}

//nolint:staticcheck // The v0.2.8 handler contract still uses metadata.Metadata.
func (h *multiServicePersistentPacketHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		return errors.New("authenticated UDP user is missing")
	}
	packet := buf.NewPacket()
	_, err := conn.ReadPacket(packet)
	packet.Release()
	if err != nil {
		return err
	}
	h.sessions <- user
	<-h.release
	return nil
}

func (h *multiServicePersistentPacketHandler) NewError(context.Context, error) {}

func receiveMultiServiceTCPResult(t testing.TB, handler *multiServiceTestHandler) multiServiceTestResult {
	t.Helper()
	select {
	case result := <-handler.tcpResults:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for TCP handler")
		return multiServiceTestResult{}
	}
}

func receiveMultiServiceUDPResult(t testing.TB, handler *multiServiceTestHandler) multiServiceTestResult {
	t.Helper()
	select {
	case result := <-handler.udpResults:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDP handler")
		return multiServiceTestResult{}
	}
}

func reportMultiServiceTestError(errors chan<- error, err error) {
	select {
	case errors <- err:
	default:
	}
}

type multiServiceTestConn struct {
	*bytes.Reader
}

func (c *multiServiceTestConn) Write(payload []byte) (int, error) { return len(payload), nil }
func (c *multiServiceTestConn) Close() error                      { return nil }
func (c *multiServiceTestConn) LocalAddr() net.Addr               { return multiServiceTestAddr("local") }
func (c *multiServiceTestConn) RemoteAddr() net.Addr              { return multiServiceTestAddr("remote") }
func (c *multiServiceTestConn) SetDeadline(time.Time) error       { return nil }
func (c *multiServiceTestConn) SetReadDeadline(time.Time) error   { return nil }
func (c *multiServiceTestConn) SetWriteDeadline(time.Time) error  { return nil }

type multiServiceTestPacketConn struct{}

func (c *multiServiceTestPacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, io.EOF
}

func (c *multiServiceTestPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	buffer.Release()
	return nil
}

func (c *multiServiceTestPacketConn) Close() error                    { return nil }
func (c *multiServiceTestPacketConn) LocalAddr() net.Addr             { return multiServiceTestAddr("packet") }
func (c *multiServiceTestPacketConn) SetDeadline(time.Time) error     { return nil }
func (c *multiServiceTestPacketConn) SetReadDeadline(time.Time) error { return nil }
func (c *multiServiceTestPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

type multiServiceTestAddr string

func (a multiServiceTestAddr) Network() string { return string(a) }
func (a multiServiceTestAddr) String() string  { return string(a) }
