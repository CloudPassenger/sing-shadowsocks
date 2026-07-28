package shadowaead

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func BenchmarkMultiServiceMatch(b *testing.B) {
	for _, userCount := range []int{1, 10, 100, 1000} {
		b.Run(fmt.Sprintf("users=%d", userCount), func(b *testing.B) {
			userList := make([]string, userCount)
			passwordList := make([]string, userCount)
			requestList := make([][]byte, userCount)
			for index := 0; index < userCount; index++ {
				userList[index] = fmt.Sprintf("user-%04d", index)
				passwordList[index] = fmt.Sprintf("password-%04d", index)
				requestList[index] = makeBenchmarkTCPRequest(b, "aes-128-gcm", passwordList[index])
			}

			service, err := NewMultiService[string]("aes-128-gcm", 60, benchmarkHandler{})
			if err != nil {
				b.Fatal(err)
			}
			if err = service.UpdateUsersWithPasswords(userList, passwordList); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				conn := benchmarkConn{Reader: *bytes.NewReader(requestList[index%userCount])}
				if err = service.newConnection(context.Background(), &conn, M.Metadata{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkMultiServiceHotMatch(b *testing.B) {
	for _, userCount := range []int{1, 10, 100, 1000} {
		b.Run(fmt.Sprintf("users=%d", userCount), func(b *testing.B) {
			userList := make([]string, userCount)
			passwordList := make([]string, userCount)
			for index := 0; index < userCount; index++ {
				userList[index] = fmt.Sprintf("user-%04d", index)
				passwordList[index] = fmt.Sprintf("password-%04d", index)
			}
			request := makeBenchmarkTCPRequest(b, "aes-128-gcm", passwordList[userCount-1])

			service, err := NewMultiService[string]("aes-128-gcm", 60, benchmarkHandler{})
			if err != nil {
				b.Fatal(err)
			}
			if err = service.UpdateUsersWithPasswords(userList, passwordList); err != nil {
				b.Fatal(err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				conn := benchmarkConn{Reader: *bytes.NewReader(request)}
				if err = service.newConnection(context.Background(), &conn, M.Metadata{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func makeBenchmarkTCPRequest(tb testing.TB, methodName string, password string) []byte {
	tb.Helper()

	method, err := New(methodName, nil, password)
	if err != nil {
		tb.Fatal(err)
	}
	salt := make([]byte, method.keySaltLength)
	for index := range salt {
		salt[index] = byte(index + 1)
	}
	key := buf.NewSize(method.keySaltLength)
	defer key.Release()
	Kdf(method.key, salt, key)
	requestCipher, err := method.constructor(key.Bytes())
	if err != nil {
		tb.Fatal(err)
	}

	destination := M.ParseSocksaddr("example.com:443")
	payload := buf.NewSize(M.SocksaddrSerializer.AddrPortLen(destination))
	defer payload.Release()
	if err = M.SocksaddrSerializer.WriteAddrPort(payload, destination); err != nil {
		tb.Fatal(err)
	}

	nonce := make([]byte, requestCipher.NonceSize())
	var length [PacketLengthBufferSize]byte
	binary.BigEndian.PutUint16(length[:], uint16(payload.Len()))
	request := make([]byte, 0, len(salt)+len(length)+Overhead+payload.Len()+Overhead)
	request = append(request, salt...)
	request = requestCipher.Seal(request, nonce, length[:], nil)
	increaseNonce(nonce)
	request = requestCipher.Seal(request, nonce, payload.Bytes(), nil)
	return request
}

type benchmarkConn struct {
	bytes.Reader
}

func (c *benchmarkConn) Write(payload []byte) (int, error) { return len(payload), nil }
func (c *benchmarkConn) Close() error                      { return nil }
func (c *benchmarkConn) LocalAddr() net.Addr               { return benchmarkAddr("local") }
func (c *benchmarkConn) RemoteAddr() net.Addr              { return benchmarkAddr("remote") }
func (c *benchmarkConn) SetDeadline(time.Time) error       { return nil }
func (c *benchmarkConn) SetReadDeadline(time.Time) error   { return nil }
func (c *benchmarkConn) SetWriteDeadline(time.Time) error  { return nil }

type benchmarkAddr string

func (a benchmarkAddr) Network() string { return string(a) }
func (a benchmarkAddr) String() string  { return string(a) }

type benchmarkHandler struct{}

//nolint:staticcheck // The v0.2.8 handler contract still uses metadata.Metadata.
func (benchmarkHandler) NewConnection(context.Context, net.Conn, M.Metadata) error { return nil }

//nolint:staticcheck // The v0.2.8 handler contract still uses metadata.Metadata.
func (benchmarkHandler) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error {
	return nil
}

func (benchmarkHandler) NewError(context.Context, error) {}
