// Package wsock is a minimal RFC 6455 WebSocket client (ws:// and wss://,
// custom headers, HTTP CONNECT / SOCKS5 proxies) with no dependencies.
package wsock

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kcd-dev/muse-go/internal/netproxy"
)

const (
	OpText   = 0x1
	OpBinary = 0x2
	opCont   = 0x0
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xA
)

type Options struct {
	Header    http.Header
	Proxy     string // http://host:port, socks5://user:pass@host:port; "" = environment, "direct" = bypass
	TLSConfig *tls.Config
	Timeout   time.Duration
	MaxSize   int // largest accepted message, default 64 MiB
}

type Conn struct {
	conn      net.Conn
	br        *bufio.Reader
	writeInit sync.Once
	writeGate chan struct{}
	maxSize   int
}

// Dial opens a WebSocket connection.
func Dial(ctx context.Context, rawURL string, o Options) (*Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, errors.New("invalid websocket URL")
	}
	if u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("invalid websocket URL")
	}
	if o.Timeout == 0 {
		o.Timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	secure := u.Scheme == "wss"
	if !secure && u.Scheme != "ws" {
		return nil, fmt.Errorf("unsupported websocket scheme %q", u.Scheme)
	}
	host := u.Host
	if u.Port() == "" {
		if secure {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	proxy, err := netproxy.Resolve(o.Proxy, rawURL)
	if err != nil {
		return nil, err
	}
	conn, err := netproxy.DialContext(ctx, proxy, host)
	if err != nil {
		return nil, err
	}
	baseConn := conn
	stopCancel := context.AfterFunc(ctx, func() { _ = baseConn.Close() })
	defer stopCancel()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if secure {
		cfg := &tls.Config{}
		if o.TLSConfig != nil {
			cfg = o.TLSConfig.Clone()
		}
		if cfg.ServerName == "" {
			cfg.ServerName = u.Hostname()
		}
		cfg.NextProtos = []string{"http/1.1"} // the upgrade needs HTTP/1.1
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("tls: %w", err)
		}
		conn = tc
	}

	keyBytes := make([]byte, 16)
	_, _ = rand.Read(keyBytes)
	key := base64.StdEncoding.EncodeToString(keyBytes)
	var b strings.Builder
	b.WriteString("GET " + u.RequestURI() + " HTTP/1.1\r\nHost: " + u.Host + "\r\n")
	b.WriteString("Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n")
	for k, vs := range o.Header {
		for _, v := range vs {
			b.WriteString(k + ": " + v + "\r\n")
		}
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReaderSize(conn, 1<<16)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("invalid websocket upgrade response")
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, &HandshakeError{Status: resp.StatusCode}
	}
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(h[:]) {
		conn.Close()
		return nil, errors.New("websocket handshake: bad accept key")
	}
	if !stopCancel() || ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}
	_ = conn.SetDeadline(time.Time{})
	max := o.MaxSize
	if max == 0 {
		max = 64 << 20
	}
	return &Conn{conn: conn, br: br, maxSize: max}, nil
}

type HandshakeError struct {
	Status int
}

func (e *HandshakeError) Error() string {
	return fmt.Sprintf("websocket upgrade refused: HTTP %d", e.Status)
}

// DialProxy exposes the proxy-aware dialer for HTTP clients.
func DialProxy(ctx context.Context, proxy, target string) (net.Conn, error) {
	return netproxy.DialContext(ctx, proxy, target)
}

func (c *Conn) writeFrame(op byte, payload []byte) error {
	return c.writeFrameContext(context.Background(), op, payload)
}

func (c *Conn) writeFrameContext(ctx context.Context, op byte, payload []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c.writeInit.Do(func() { c.writeGate = make(chan struct{}, 1) })
	select {
	case c.writeGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.writeGate }()
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	_ = c.conn.SetWriteDeadline(deadline)
	// Once bytes may have been written the frame cannot safely be resumed.
	stopCancel := context.AfterFunc(ctx, func() { _ = c.conn.Close() })
	defer stopCancel()
	n := len(payload)
	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|op)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 0x80|127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	var mask [4]byte
	_, _ = rand.Read(mask[:])
	hdr = append(hdr, mask[:]...)
	buf := make([]byte, len(hdr)+n)
	copy(buf, hdr)
	for i := 0; i < n; i++ {
		buf[len(hdr)+i] = payload[i] ^ mask[i&3]
	}
	nw, err := c.conn.Write(buf)
	if err == nil && nw != len(buf) {
		err = io.ErrShortWrite
	}
	if err != nil {
		_ = c.conn.Close()
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (c *Conn) WriteText(p []byte) error   { return c.writeFrame(OpText, p) }
func (c *Conn) WriteBinary(p []byte) error { return c.writeFrame(OpBinary, p) }
func (c *Conn) WriteBinaryContext(ctx context.Context, p []byte) error {
	return c.writeFrameContext(ctx, OpBinary, p)
}
func (c *Conn) Ping() error { return c.writeFrame(opPing, nil) }

// ReadMessage returns the next data message and its opcode, answering pings
// and reassembling fragments.
func (c *Conn) ReadMessage() (int, []byte, error) {
	var msg []byte
	msgOp := 0
	for {
		var h [2]byte
		if _, err := io.ReadFull(c.br, h[:]); err != nil {
			return 0, nil, err
		}
		fin := h[0]&0x80 != 0
		op := h[0] & 0x0F
		masked := h[1]&0x80 != 0
		n := uint64(h[1] & 0x7F)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(c.br, b[:]); err != nil {
				return 0, nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(c.br, b[:]); err != nil {
				return 0, nil, err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(c.br, mask[:]); err != nil {
				return 0, nil, err
			}
		}
		if n > uint64(c.maxSize) || len(msg)+int(n) > c.maxSize {
			return 0, nil, errors.New("websocket message too large")
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i&3]
			}
		}
		switch op {
		case opPing:
			_ = c.writeFrame(opPong, payload)
			continue
		case opPong:
			continue
		case opClose:
			_ = c.conn.Close()
			return 0, nil, io.EOF
		case OpText, OpBinary:
			msgOp = int(op)
			fallthrough
		case opCont:
			msg = append(msg, payload...)
			if fin {
				return msgOp, msg, nil
			}
		}
	}
}

// Close aborts the transport directly so it can interrupt a blocked writer.
func (c *Conn) Close() error { return c.conn.Close() }
