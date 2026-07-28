package shadowaead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"io"
	"net"
	"os"

	"github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/rw"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

var List = []string{
	"aes-128-gcm",
	"aes-192-gcm",
	"aes-256-gcm",
	"chacha20-ietf-poly1305",
	"xchacha20-ietf-poly1305",
}

type methodSpec struct {
	keySaltLength int
	constructor   func(key []byte) (cipher.AEAD, error)
}

func parseMethod(method string) (methodSpec, error) {
	switch method {
	case "aes-128-gcm":
		return methodSpec{16, aeadCipher(aes.NewCipher, cipher.NewGCM)}, nil
	case "aes-192-gcm":
		return methodSpec{24, aeadCipher(aes.NewCipher, cipher.NewGCM)}, nil
	case "aes-256-gcm":
		return methodSpec{32, aeadCipher(aes.NewCipher, cipher.NewGCM)}, nil
	case "chacha20-ietf-poly1305":
		return methodSpec{32, chacha20poly1305.New}, nil
	case "xchacha20-ietf-poly1305":
		return methodSpec{32, chacha20poly1305.NewX}, nil
	default:
		return methodSpec{}, os.ErrInvalid
	}
}

var _ shadowsocks.Method = (*Method)(nil)

func New(method string, key []byte, password string) (*Method, error) {
	spec, err := parseMethod(method)
	if err != nil {
		return nil, err
	}
	m := &Method{
		name:          method,
		keySaltLength: spec.keySaltLength,
		constructor:   spec.constructor,
	}
	if len(key) == m.keySaltLength {
		m.key = key
	} else if len(key) > 0 {
		return nil, shadowsocks.ErrBadKey
	} else if password == "" {
		return nil, shadowsocks.ErrMissingPassword
	} else {
		m.key = shadowsocks.Key([]byte(password), m.keySaltLength)
	}
	return m, nil
}

func Kdf(key, iv []byte, buffer *buf.Buffer) {
	kdf := hkdf.New(sha1.New, key, iv, []byte("ss-subkey"))
	common.Must1(buffer.ReadFullFrom(kdf, buffer.FreeLen()))
}

const (
	legacyHKDFInfo   = "ss-subkey"
	maxLegacyKeySize = 32
)

type legacyHKDF struct {
	extractInner [sha1.BlockSize]byte
	extractOuter [sha1.BlockSize]byte
	scratch      [sha1.BlockSize + maxLegacyKeySize]byte
}

func (kdf *legacyHKDF) Reset(salt []byte) {
	for index := 0; index < sha1.BlockSize; index++ {
		kdf.extractInner[index] = 0x36
		kdf.extractOuter[index] = 0x5c
	}
	for index, value := range salt {
		kdf.extractInner[index] ^= value
		kdf.extractOuter[index] ^= value
	}
}

func (kdf *legacyHKDF) Derive(key []byte, output []byte) {
	copy(kdf.scratch[:sha1.BlockSize], kdf.extractInner[:])
	copy(kdf.scratch[sha1.BlockSize:], key)
	inner := sha1.Sum(kdf.scratch[:sha1.BlockSize+len(key)])

	copy(kdf.scratch[:sha1.BlockSize], kdf.extractOuter[:])
	copy(kdf.scratch[sha1.BlockSize:], inner[:])
	prk := sha1.Sum(kdf.scratch[:sha1.BlockSize+sha1.Size])

	block := kdf.expand(prk, nil, 1)
	written := copy(output, block[:])
	if written < len(output) {
		block = kdf.expand(prk, block[:], 2)
		copy(output[written:], block[:])
	}
}

func (kdf *legacyHKDF) expand(key [sha1.Size]byte, previous []byte, counter byte) [sha1.Size]byte {
	for index := 0; index < sha1.BlockSize; index++ {
		kdf.scratch[index] = 0x36
	}
	for index, value := range key {
		kdf.scratch[index] ^= value
	}
	offset := sha1.BlockSize
	offset += copy(kdf.scratch[offset:], previous)
	offset += copy(kdf.scratch[offset:], legacyHKDFInfo)
	kdf.scratch[offset] = counter
	offset++
	inner := sha1.Sum(kdf.scratch[:offset])

	for index := 0; index < sha1.BlockSize; index++ {
		kdf.scratch[index] = 0x5c
	}
	for index, value := range key {
		kdf.scratch[index] ^= value
	}
	copy(kdf.scratch[sha1.BlockSize:], inner[:])
	return sha1.Sum(kdf.scratch[:sha1.BlockSize+sha1.Size])
}

func aeadCipher(block func(key []byte) (cipher.Block, error), aead func(block cipher.Block) (cipher.AEAD, error)) func(key []byte) (cipher.AEAD, error) {
	return func(key []byte) (cipher.AEAD, error) {
		b, err := block(key)
		if err != nil {
			return nil, err
		}
		return aead(b)
	}
}

type Method struct {
	name          string
	keySaltLength int
	constructor   func(key []byte) (cipher.AEAD, error)
	key           []byte
}

func (m *Method) Name() string {
	return m.name
}

func (m *Method) DialConn(conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	shadowsocksConn := &clientConn{
		Conn:        conn,
		Method:      m,
		destination: destination,
	}
	return shadowsocksConn, shadowsocksConn.writeRequest(nil)
}

func (m *Method) DialEarlyConn(conn net.Conn, destination M.Socksaddr) net.Conn {
	return &clientConn{
		Conn:        conn,
		Method:      m,
		destination: destination,
	}
}

func (m *Method) DialPacketConn(conn net.Conn) N.NetPacketConn {
	return &clientPacketConn{m, conn}
}

type clientConn struct {
	net.Conn
	*Method
	destination M.Socksaddr
	reader      *Reader
	writer      *Writer
}

func (c *clientConn) writeRequest(payload []byte) error {
	salt := buf.NewSize(c.keySaltLength)
	defer salt.Release()
	salt.WriteRandom(c.keySaltLength)

	key := buf.NewSize(c.keySaltLength)

	Kdf(c.key, salt.Bytes(), key)
	writeCipher, err := c.constructor(key.Bytes())
	key.Release()
	if err != nil {
		return err
	}
	writer := NewWriter(c.Conn, writeCipher, MaxPacketSize)
	header := writer.Buffer()
	common.Must1(header.Write(salt.Bytes()))
	bufferedWriter := writer.BufferedWriter(header.Len())

	if len(payload) > 0 {
		err = M.SocksaddrSerializer.WriteAddrPort(bufferedWriter, c.destination)
		if err != nil {
			return err
		}

		_, err = bufferedWriter.Write(payload)
		if err != nil {
			return err
		}
	} else {
		err = M.SocksaddrSerializer.WriteAddrPort(bufferedWriter, c.destination)
		if err != nil {
			return err
		}
	}

	err = bufferedWriter.Flush()
	if err != nil {
		return err
	}

	c.writer = writer
	return nil
}

func (c *clientConn) readResponse() error {
	salt := buf.NewSize(c.keySaltLength)
	defer salt.Release()
	_, err := salt.ReadFullFrom(c.Conn, c.keySaltLength)
	if err != nil {
		return err
	}
	key := buf.NewSize(c.keySaltLength)
	defer key.Release()
	Kdf(c.key, salt.Bytes(), key)
	readCipher, err := c.constructor(key.Bytes())
	if err != nil {
		return err
	}
	c.reader = NewReader(
		c.Conn,
		readCipher,
		MaxPacketSize,
	)
	return nil
}

func (c *clientConn) Read(p []byte) (n int, err error) {
	if c.reader == nil {
		if err = c.readResponse(); err != nil {
			return
		}
	}
	return c.reader.Read(p)
}

func (c *clientConn) WriteTo(w io.Writer) (n int64, err error) {
	if c.reader == nil {
		if err = c.readResponse(); err != nil {
			return
		}
	}
	return c.reader.WriteTo(w)
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if c.writer == nil {
		err = c.writeRequest(p)
		if err != nil {
			return
		}
		return len(p), nil
	}
	return c.writer.Write(p)
}

func (c *clientConn) NeedHandshake() bool {
	return c.writer == nil
}

func (c *clientConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *clientConn) Upstream() any {
	return c.Conn
}

type clientPacketConn struct {
	*Method
	net.Conn
}

func (c *clientPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	header := buf.With(buffer.ExtendHeader(c.keySaltLength + M.SocksaddrSerializer.AddrPortLen(destination)))
	header.WriteRandom(c.keySaltLength)
	err := M.SocksaddrSerializer.WriteAddrPort(header, destination)
	if err != nil {
		return err
	}
	key := buf.NewSize(c.keySaltLength)
	Kdf(c.key, buffer.To(c.keySaltLength), key)
	writeCipher, err := c.constructor(key.Bytes())
	key.Release()
	if err != nil {
		return err
	}
	writeCipher.Seal(buffer.Index(c.keySaltLength), rw.ZeroBytes[:writeCipher.NonceSize()], buffer.From(c.keySaltLength), nil)
	buffer.Extend(Overhead)
	return common.Error(c.Write(buffer.Bytes()))
}

func (c *clientPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	n, err := c.Read(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	if buffer.Len() < c.keySaltLength {
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	key := buf.NewSize(c.keySaltLength)
	Kdf(c.key, buffer.To(c.keySaltLength), key)
	readCipher, err := c.constructor(key.Bytes())
	key.Release()
	if err != nil {
		return M.Socksaddr{}, err
	}
	packet, err := readCipher.Open(buffer.Index(c.keySaltLength), rw.ZeroBytes[:readCipher.NonceSize()], buffer.From(c.keySaltLength), nil)
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Advance(c.keySaltLength)
	buffer.Truncate(len(packet))
	if err != nil {
		return M.Socksaddr{}, err
	}
	return M.SocksaddrSerializer.ReadAddrPort(buffer)
}

func (c *clientPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buffer := buf.With(p)
	destination, err := c.ReadPacket(buffer)
	if err != nil {
		return
	}
	if destination.IsFqdn() {
		addr = destination
	} else {
		addr = destination.UDPAddr()
	}
	n = copy(p, buffer.Bytes())
	return
}

func (c *clientPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	destination := M.SocksaddrFromNet(addr)
	buffer := buf.NewSize(c.keySaltLength + M.SocksaddrSerializer.AddrPortLen(destination) + len(p) + Overhead)
	defer buffer.Release()
	buffer.Resize(c.keySaltLength+M.SocksaddrSerializer.AddrPortLen(destination), 0)
	common.Must1(buffer.Write(p))
	err = c.WritePacket(buffer, destination)
	if err != nil {
		return
	}
	return len(p), nil
}

func (c *clientPacketConn) FrontHeadroom() int {
	return c.keySaltLength + M.MaxSocksaddrLength
}

func (c *clientPacketConn) RearHeadroom() int {
	return Overhead
}

func (c *clientPacketConn) ReaderMTU() int {
	return MaxPacketSize
}

func (c *clientPacketConn) WriterMTU() int {
	return MaxPacketSize
}

func (c *clientPacketConn) Upstream() any {
	return c.Conn
}
