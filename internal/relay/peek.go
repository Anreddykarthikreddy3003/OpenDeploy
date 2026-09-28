package relay

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	maxHelloBytes  = 16 << 10
	maxHeaderBytes = 16 << 10
)

var errPeeked = errors.New("peeked")

// recordingConn feeds reads from r (recording them) and refuses writes, so
// a TLS server handshake can parse the ClientHello without responding.
type recordingConn struct {
	r   io.Reader
	buf bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.buf.Write(p[:n])
	return n, err
}
func (c *recordingConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c *recordingConn) Close() error                       { return nil }
func (c *recordingConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *recordingConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *recordingConn) SetDeadline(t time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(t time.Time) error { return nil }

// PeekSNI reads a TLS ClientHello from conn and returns the lower-cased SNI
// and every byte consumed (to be replayed to the backend unchanged). The
// relay never completes a handshake.
func PeekSNI(conn net.Conn, timeout time.Duration) (string, []byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})
	rc := &recordingConn{r: io.LimitReader(conn, maxHelloBytes)}
	var sni string
	err := tls.Server(rc, &tls.Config{GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
		sni = h.ServerName
		return nil, errPeeked
	}}).Handshake()
	if !errors.Is(err, errPeeked) {
		if err == nil {
			err = errors.New("unexpected handshake completion")
		}
		return "", rc.buf.Bytes(), err
	}
	if sni == "" {
		return "", rc.buf.Bytes(), errors.New("client hello without SNI")
	}
	return strings.ToLower(strings.TrimSuffix(sni, ".")), rc.buf.Bytes(), nil
}

// PeekHost reads an HTTP/1.x request head and returns its Host (without
// port) and the consumed bytes.
func PeekHost(conn net.Conn, timeout time.Duration) (string, []byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})
	rc := &recordingConn{r: io.LimitReader(conn, maxHeaderBytes)}
	req, err := http.ReadRequest(bufio.NewReaderSize(rc, 4096))
	if err != nil {
		return "", rc.buf.Bytes(), err
	}
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return "", rc.buf.Bytes(), errors.New("request without Host")
	}
	return host, rc.buf.Bytes(), nil
}

// prefixConn replays already-consumed bytes before the live connection.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func withPrefix(c net.Conn, prefix []byte) net.Conn {
	return &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(prefix), c)}
}
