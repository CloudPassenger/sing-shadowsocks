package shadowaead_2022

import (
	"bytes"
	"context"
	"crypto/aes"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"lukechampine.com/blake3"
)

func TestMultiServicePublishesCompleteUserState(t *testing.T) {
	t.Parallel()

	iPSK := bytes.Repeat([]byte{0x11}, 16)
	keyA := bytes.Repeat([]byte{0x22}, 16)
	keyB := bytes.Repeat([]byte{0x33}, 16)
	service, err := NewMultiService[string](
		"2022-blake3-aes-128-gcm",
		iPSK,
		60,
		atomicTestHandler{},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := service.UpdateUsers([]string{"alice", "bob"}, [][]byte{keyA, keyB}); err != nil {
		t.Fatal(err)
	}
	previous := service.users.Load()
	if err := service.UpdateUsers([]string{"alice"}, [][]byte{{0x01}}); err == nil {
		t.Fatal("wrong-length key was accepted")
	}
	if service.users.Load() != previous {
		t.Fatal("failed update changed the published state")
	}
	if err := service.UpdateUsersWithPasswords([]string{"alice"}, []string{"not-base64!"}); err == nil {
		t.Fatal("malformed user PSK was accepted")
	}
	if service.users.Load() != previous {
		t.Fatal("malformed-password update changed the published state")
	}
	if err := service.UpdateUsers([]string{"alice", "bob"}, [][]byte{keyA, keyA}); err == nil {
		t.Fatal("duplicate user PSK was accepted")
	}
	if service.users.Load() != previous {
		t.Fatal("duplicate-key update changed the published state")
	}

	preparedKey := append([]byte(nil), keyA...)
	prepared, err := service.PrepareUsers([]string{"alice"}, [][]byte{preparedKey})
	if err != nil {
		t.Fatal(err)
	}
	preparedKey[0] ^= 0xff
	service.PublishUsers(prepared)
	if !bytes.Equal(service.users.Load().uPSK["alice"], keyA) {
		t.Fatal("prepared state retained caller-owned key memory")
	}

	states := []struct {
		users []string
		keys  [][]byte
	}{
		{users: []string{"alice", "bob"}, keys: [][]byte{keyA, keyB}},
		{users: []string{"alice", "bob"}, keys: [][]byte{keyB, keyA}},
	}
	if err := service.UpdateUsers(states[0].users, states[0].keys); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errors := make(chan error, 1)
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		<-start
		for index := 0; index < 4000; index++ {
			state := states[index%len(states)]
			if updateErr := service.UpdateUsers(state.users, state.keys); updateErr != nil {
				select {
				case errors <- updateErr:
				default:
				}
				return
			}
		}
	}()
	for reader := 0; reader < 8; reader++ {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			for iteration := 0; iteration < 8000; iteration++ {
				if validationErr := validateMultiUserState(service.users.Load(), keyA, keyB); validationErr != nil {
					select {
					case errors <- validationErr:
					default:
					}
					return
				}
			}
		}()
	}
	close(start)
	group.Wait()
	close(errors)
	for stateErr := range errors {
		t.Fatal(stateErr)
	}
}

func TestMultiServiceConcurrentAuthenticationAndUpdates(t *testing.T) {
	t.Parallel()

	iPSK := bytes.Repeat([]byte{0x44}, 16)
	keyA := bytes.Repeat([]byte{0x55}, 16)
	keyB := bytes.Repeat([]byte{0x66}, 16)
	service, err := NewMultiService[string](
		"2022-blake3-aes-128-gcm",
		iPSK,
		60,
		atomicTestHandler{},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.UpdateUsers([]string{"alice", "bob"}, [][]byte{keyA, keyB}); err != nil {
		t.Fatal(err)
	}

	clients := make([]shadowsocks.Method, 2)
	clients[0], err = New("2022-blake3-aes-128-gcm", [][]byte{iPSK, keyA}, nil)
	if err != nil {
		t.Fatal(err)
	}
	clients[1], err = New("2022-blake3-aes-128-gcm", [][]byte{iPSK, keyB}, nil)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errors := make(chan error, 1)
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		<-start
		for index := 0; index < 2000; index++ {
			keys := [][]byte{keyA, keyB}
			if index%2 != 0 {
				keys = [][]byte{keyB, keyA}
			}
			if updateErr := service.UpdateUsers([]string{"alice", "bob"}, keys); updateErr != nil {
				select {
				case errors <- updateErr:
				default:
				}
				return
			}
		}
	}()
	for worker := 0; worker < 6; worker++ {
		group.Add(1)
		go func(client shadowsocks.Method) {
			defer group.Done()
			<-start
			for iteration := 0; iteration < 200; iteration++ {
				if handshakeErr := runAtomicTestHandshake(service, client); handshakeErr != nil {
					select {
					case errors <- handshakeErr:
					default:
					}
					return
				}
			}
		}(clients[worker%len(clients)])
	}
	close(start)
	group.Wait()
	close(errors)
	for raceErr := range errors {
		t.Fatal(raceErr)
	}
}

func validateMultiUserState(state *multiUserState[string], keyA, keyB []byte) error {
	if state == nil {
		return fmt.Errorf("published state is nil")
	}
	aliceKey := state.uPSK["alice"]
	bobKey := state.uPSK["bob"]
	validForward := bytes.Equal(aliceKey, keyA) && bytes.Equal(bobKey, keyB)
	validSwapped := bytes.Equal(aliceKey, keyB) && bytes.Equal(bobKey, keyA)
	if !validForward && !validSwapped {
		return fmt.Errorf("uPSK map contains a mixed generation")
	}
	for user, key := range map[string][]byte{"alice": aliceKey, "bob": bobKey} {
		hash512 := blake3.Sum512(key)
		var hash [aes.BlockSize]byte
		copy(hash[:], hash512[:])
		if state.uPSKHash[hash] != user {
			return fmt.Errorf("uPSK hash map does not match user %q", user)
		}

		expectedCipher, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		var plaintext, expected, actual [aes.BlockSize]byte
		expectedCipher.Encrypt(expected[:], plaintext[:])
		userCipher := state.uCipher[user]
		if userCipher == nil {
			return fmt.Errorf("user cipher is missing for %q", user)
		}
		userCipher.Encrypt(actual[:], plaintext[:])
		if actual != expected {
			return fmt.Errorf("user cipher does not match user %q", user)
		}
	}
	return nil
}

//nolint:staticcheck // The v0.2.8 service contract still uses metadata.Metadata.
func runAtomicTestHandshake(service *MultiService[string], client shadowsocks.Method) error {
	serverConn, clientConn := net.Pipe()
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- service.NewConnection(context.Background(), serverConn, M.Metadata{})
	}()

	protocolConn, err := client.DialConn(clientConn, M.ParseSocksaddr("example.com:443"))
	if err != nil {
		_ = clientConn.Close()
		_ = serverConn.Close()
		<-serverDone
		return err
	}
	_ = protocolConn.Close()
	_ = clientConn.Close()
	serverErr := <-serverDone
	_ = serverConn.Close()
	return serverErr
}

type atomicTestHandler struct{}

//nolint:staticcheck // The v0.2.8 handler contract still uses metadata.Metadata.
func (atomicTestHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	user, loaded := auth.UserFromContext[string](ctx)
	if !loaded {
		return fmt.Errorf("authenticated user is missing")
	}
	if user != "alice" && user != "bob" {
		return fmt.Errorf("unexpected authenticated user %q", user)
	}
	return conn.Close()
}

//nolint:staticcheck // The v0.2.8 handler contract still uses metadata.Metadata.
func (atomicTestHandler) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata M.Metadata) error {
	return conn.Close()
}

func (atomicTestHandler) NewError(ctx context.Context, err error) {}
