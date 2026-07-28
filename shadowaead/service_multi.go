package shadowaead

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"net/netip"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing/common/atomic"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/common/udpnat"
)

var _ shadowsocks.MultiService[int] = (*MultiService[int])(nil)

type multiUserCandidate[U comparable] struct {
	user       U
	credential [maxLegacyKeySize]byte
	method     Method
}

// The authenticated user and credential keep a shared UDP source from reusing stale metadata or
// a response cipher after an identity change or password rotation.
type multiPacketSessionKey[U comparable] struct {
	source     netip.AddrPort
	user       U
	credential [maxLegacyKeySize]byte
}

type multiUserState[U comparable] struct {
	candidates []multiUserCandidate[U]
	// Trying the hot candidate first introduces a timing side channel. Legacy Shadowsocks lacks
	// active-probing resistance, so this is an accepted performance trade-off for compatibility.
	// Keeping the hint in the published state binds it to that exact user generation.
	hot atomic.Pointer[multiUserCandidate[U]]
}

// PreparedUsers is a complete immutable multi-user authentication state.
type PreparedUsers[U comparable] struct {
	state *multiUserState[U]
}

type MultiService[U comparable] struct {
	name          string
	keySaltLength int
	constructor   func(key []byte) (cipher.AEAD, error)
	users         atomic.TypedValue[*multiUserState[U]]
	handler       shadowsocks.Handler
	udpNat        *udpnat.Service[multiPacketSessionKey[U]]
}

func NewMultiService[U comparable](method string, udpTimeout int64, handler shadowsocks.Handler) (*MultiService[U], error) {
	spec, err := parseMethod(method)
	if err != nil {
		return nil, err
	}
	s := &MultiService[U]{
		name:          method,
		keySaltLength: spec.keySaltLength,
		constructor:   spec.constructor,
		handler:       handler,
		udpNat:        udpnat.New[multiPacketSessionKey[U]](udpTimeout, handler),
	}
	s.users.Store(&multiUserState[U]{})
	return s, nil
}

func (s *MultiService[U]) Name() string {
	return s.name
}

// PrepareUsers validates and compiles a complete immutable authentication state.
func (s *MultiService[U]) PrepareUsers(userList []U, keyList [][]byte) (*PreparedUsers[U], error) {
	return s.prepareUsers(userList, keyList, true)
}

func (s *MultiService[U]) prepareUsers(userList []U, keyList [][]byte, copyKeys bool) (*PreparedUsers[U], error) {
	if len(userList) != len(keyList) {
		return nil, E.New("user and key list length mismatch")
	}

	state := &multiUserState[U]{
		candidates: make([]multiUserCandidate[U], len(userList)),
	}
	seenUsers := make(map[U]struct{}, len(userList))
	seenCredentials := make(map[[maxLegacyKeySize]byte]struct{}, len(userList))
	for index, user := range userList {
		if _, loaded := seenUsers[user]; loaded {
			return nil, E.New("duplicate user")
		}
		seenUsers[user] = struct{}{}

		key := keyList[index]
		if len(key) != s.keySaltLength {
			return nil, shadowsocks.ErrBadKey
		}
		var credential [maxLegacyKeySize]byte
		copy(credential[:], key)
		if _, loaded := seenCredentials[credential]; loaded {
			return nil, E.New("duplicate credential")
		}
		seenCredentials[credential] = struct{}{}

		if copyKeys {
			keyCopy := make([]byte, len(key))
			copy(keyCopy, key)
			key = keyCopy
		}
		state.candidates[index] = multiUserCandidate[U]{
			user:       user,
			credential: credential,
			method: Method{
				name:          s.name,
				keySaltLength: s.keySaltLength,
				constructor:   s.constructor,
				key:           key,
			},
		}
	}
	return &PreparedUsers[U]{state: state}, nil
}

// PrepareUsersWithPasswords derives and compiles a complete immutable authentication state.
func (s *MultiService[U]) PrepareUsersWithPasswords(userList []U, passwordList []string) (*PreparedUsers[U], error) {
	if len(userList) != len(passwordList) {
		return nil, E.New("user and password list length mismatch")
	}
	keyList := make([][]byte, len(passwordList))
	for index, password := range passwordList {
		if password == "" {
			return nil, shadowsocks.ErrMissingPassword
		}
		keyList[index] = shadowsocks.Key([]byte(password), s.keySaltLength)
	}
	return s.prepareUsers(userList, keyList, false)
}

// PublishUsers atomically installs a prepared authentication state.
func (s *MultiService[U]) PublishUsers(users *PreparedUsers[U]) {
	s.users.Store(users.state)
}

func (s *MultiService[U]) UpdateUsers(userList []U, keyList [][]byte) error {
	users, err := s.PrepareUsers(userList, keyList)
	if err != nil {
		return err
	}
	s.PublishUsers(users)
	return nil
}

func (s *MultiService[U]) UpdateUsersWithPasswords(userList []U, passwordList []string) error {
	users, err := s.PrepareUsersWithPasswords(userList, passwordList)
	if err != nil {
		return err
	}
	s.PublishUsers(users)
	return nil
}

func (s *MultiService[U]) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	err := s.newConnection(ctx, conn, metadata)
	if err != nil {
		err = &shadowsocks.ServerConnError{Conn: conn, Source: metadata.Source, Cause: err}
	}
	return err
}

func (s *MultiService[U]) newConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	state := s.users.Load()
	if state == nil || len(state.candidates) == 0 {
		return shadowsocks.ErrNoUsers
	}
	header := buf.NewSize(s.keySaltLength + PacketLengthBufferSize + Overhead)
	defer header.Release()

	_, err := header.ReadFullFrom(conn, header.FreeLen())
	if err != nil {
		return E.Cause(err, "read header")
	} else if !header.IsFull() {
		return ErrBadHeader
	}

	candidate, readCipher, length, err := s.matchTCP(state, header.To(s.keySaltLength), header.From(s.keySaltLength))
	if err != nil {
		return err
	}
	if int(length) > MaxPacketSize {
		return ErrBadHeader
	}
	reader := NewReader(conn, readCipher, MaxPacketSize)
	increaseNonce(reader.nonce)
	if err = reader.ReadWithLength(length); err != nil {
		return err
	}

	destination, err := M.SocksaddrSerializer.ReadAddrPort(reader)
	if err != nil {
		return err
	}
	state.hot.Store(candidate)

	metadata.Protocol = "shadowsocks"
	metadata.Destination = destination

	return s.handler.NewConnection(auth.ContextWithUser(ctx, candidate.user), &serverConn{
		Method: &candidate.method,
		Conn:   conn,
		reader: reader,
	}, metadata)
}

func (s *MultiService[U]) WriteIsThreadUnsafe() {
}

func (s *MultiService[U]) NewPacket(ctx context.Context, conn N.PacketConn, buffer *buf.Buffer, metadata M.Metadata) error {
	err := s.newPacket(ctx, conn, buffer, metadata)
	if err != nil {
		err = &shadowsocks.ServerPacketError{Source: metadata.Source, Cause: err}
	}
	return err
}

func (s *MultiService[U]) newPacket(ctx context.Context, conn N.PacketConn, buffer *buf.Buffer, metadata M.Metadata) error {
	state := s.users.Load()
	if state == nil || len(state.candidates) == 0 {
		return shadowsocks.ErrNoUsers
	}
	if buffer.Len() < s.keySaltLength+Overhead {
		return io.ErrShortBuffer
	}
	salt := buffer.To(s.keySaltLength)
	ciphertext := buffer.From(s.keySaltLength)
	plaintextScratch := make([]byte, 0, len(ciphertext)-Overhead)
	candidate, packet, err := s.matchPacket(state, salt, ciphertext, plaintextScratch)
	if err != nil {
		return err
	}

	buffer.Advance(s.keySaltLength)
	buffer.Truncate(len(packet))
	copy(buffer.Bytes(), packet)

	destination, err := M.SocksaddrSerializer.ReadAddrPort(buffer)
	if err != nil {
		return err
	}
	state.hot.Store(candidate)

	metadata.Protocol = "shadowsocks"
	metadata.Destination = destination
	s.udpNat.NewPacket(auth.ContextWithUser(ctx, candidate.user), multiPacketSessionKey[U]{
		source:     metadata.Source.AddrPort(),
		user:       candidate.user,
		credential: candidate.credential,
	}, buffer, metadata, func(natConn N.PacketConn) N.PacketWriter {
		return &serverPacketWriter{&candidate.method, conn, natConn}
	})
	return nil
}

func (s *MultiService[U]) matchTCP(state *multiUserState[U], salt []byte, encryptedLength []byte) (*multiUserCandidate[U], cipher.AEAD, uint16, error) {
	var kdf legacyHKDF
	kdf.Reset(salt)
	var subkey [maxLegacyKeySize]byte
	var plaintext [PacketLengthBufferSize]byte
	var lastErr error

	hot := state.hot.Load()
	if hot != nil {
		readCipher, length, err := s.tryTCP(hot, &kdf, subkey[:s.keySaltLength], &plaintext, encryptedLength)
		if err == nil {
			return hot, readCipher, length, nil
		}
		lastErr = err
	}
	for index := range state.candidates {
		candidate := &state.candidates[index]
		if candidate == hot {
			continue
		}
		readCipher, length, err := s.tryTCP(candidate, &kdf, subkey[:s.keySaltLength], &plaintext, encryptedLength)
		if err == nil {
			return candidate, readCipher, length, nil
		}
		lastErr = err
	}
	return nil, nil, 0, lastErr
}

func (s *MultiService[U]) tryTCP(candidate *multiUserCandidate[U], kdf *legacyHKDF, subkey []byte, plaintext *[PacketLengthBufferSize]byte, encryptedLength []byte) (cipher.AEAD, uint16, error) {
	kdf.Derive(candidate.method.key, subkey)
	readCipher, err := s.constructor(subkey)
	if err != nil {
		return nil, 0, err
	}
	plaintext[0] = 0
	plaintext[1] = 0
	opened, err := readCipher.Open(plaintext[:0], rw.ZeroBytes[:readCipher.NonceSize()], encryptedLength, nil)
	if err != nil {
		return nil, 0, err
	}
	if len(opened) != PacketLengthBufferSize {
		return nil, 0, ErrBadHeader
	}
	return readCipher, binary.BigEndian.Uint16(opened), nil
}

func (s *MultiService[U]) matchPacket(state *multiUserState[U], salt []byte, ciphertext []byte, plaintextScratch []byte) (*multiUserCandidate[U], []byte, error) {
	var kdf legacyHKDF
	kdf.Reset(salt)
	var subkey [maxLegacyKeySize]byte
	var lastErr error

	hot := state.hot.Load()
	if hot != nil {
		packet, err := s.tryPacket(hot, &kdf, subkey[:s.keySaltLength], ciphertext, plaintextScratch[:0])
		if err == nil {
			return hot, packet, nil
		}
		lastErr = err
	}
	for index := range state.candidates {
		candidate := &state.candidates[index]
		if candidate == hot {
			continue
		}
		packet, err := s.tryPacket(candidate, &kdf, subkey[:s.keySaltLength], ciphertext, plaintextScratch[:0])
		if err == nil {
			return candidate, packet, nil
		}
		lastErr = err
	}
	return nil, nil, lastErr
}

func (s *MultiService[U]) tryPacket(candidate *multiUserCandidate[U], kdf *legacyHKDF, subkey []byte, ciphertext []byte, plaintextScratch []byte) ([]byte, error) {
	kdf.Derive(candidate.method.key, subkey)
	readCipher, err := s.constructor(subkey)
	if err != nil {
		return nil, err
	}
	return readCipher.Open(plaintextScratch[:0], rw.ZeroBytes[:readCipher.NonceSize()], ciphertext, nil)
}

func (s *MultiService[U]) NewError(ctx context.Context, err error) {
	s.handler.NewError(ctx, err)
}
