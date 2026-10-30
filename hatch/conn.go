package hatch

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kcd-dev/muse-go/internal/wsock"
)

// Session holds what the muse.ai HTTP bootstrap hands out for one VM.
type Session struct {
	VMID        string
	Endpoint    string
	AuthToken   string `json:"-"`
	NotaryToken string `json:"-"`
}

type Options struct {
	URL       string // gateway base, default wss://hatch.metaaivm.com/v1/noise
	AppID     string // default hatch-web
	Origin    string // default https://muse.ai
	UserAgent string
	Locale    string
	Proxy     string
	TLSConfig *tls.Config
	Timeout   time.Duration
}

var ErrClosed = errors.New("hatch: connection closed")

// HandshakeError reports a refused upgrade or failed Noise handshake.
type HandshakeError struct {
	Status int
	Err    error
}

func (e *HandshakeError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("hatch 网关拒绝连接 (HTTP %d)", e.Status)
	}
	return "hatch 握手失败"
}
func (e *HandshakeError) Unwrap() error { return e.Err }

// Conn is one encrypted gateway connection multiplexing many streams.
type Conn struct {
	ws        *wsock.Conn
	tx, rx    *CipherState
	writeGate chan struct{}
	appID     string
	locale    string

	mu      sync.Mutex
	streams map[int64]*Stream
	nextID  int64
	closed  chan struct{}
	err     error

	lastActive atomic.Int64
}

func newRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// Connect opens the WebSocket and runs the Noise XX handshake as initiator.
func Connect(ctx context.Context, s *Session, o Options) (*Conn, error) {
	if s == nil || s.VMID == "" || s.AuthToken == "" {
		return nil, errors.New("hatch: VM ID and auth token are required")
	}
	if o.URL == "" {
		o.URL = "wss://hatch.metaaivm.com/v1/noise"
	}
	u, parseErr := url.Parse(o.URL)
	if parseErr != nil || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("hatch: invalid gateway URL")
	}
	ip := net.ParseIP(u.Hostname())
	local := u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())
	if u.Scheme != "wss" && !(u.Scheme == "ws" && local) {
		return nil, errors.New("hatch: gateway requires TLS except on loopback")
	}
	if o.AppID == "" {
		o.AppID = "hatch-web"
	}
	if o.Origin == "" {
		o.Origin = "https://muse.ai"
	}
	if o.Locale == "" {
		o.Locale = "en-US"
	}
	if o.Timeout == 0 {
		o.Timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	q := url.Values{}
	q.Set("vm_id", s.VMID)
	q.Set("auth_token", s.AuthToken)
	q.Set("app_id", o.AppID)
	q.Set("request_id", newRequestID())
	if s.NotaryToken != "" {
		q.Set("notary_token", s.NotaryToken)
	}
	h := http.Header{}
	h.Set("Origin", o.Origin)
	h.Set("Accept-Language", "en-US,en;q=0.9")
	h.Set("Cache-Control", "no-cache")
	h.Set("Pragma", "no-cache")
	if o.UserAgent != "" {
		h.Set("User-Agent", o.UserAgent)
	}
	ws, err := wsock.Dial(ctx, o.URL+"?"+q.Encode(), wsock.Options{Header: h, Proxy: o.Proxy, TLSConfig: o.TLSConfig, Timeout: o.Timeout})
	if err != nil {
		var he *wsock.HandshakeError
		if errors.As(err, &he) {
			return nil, &HandshakeError{Status: he.Status, Err: err}
		}
		return nil, &HandshakeError{Err: err}
	}
	c, err := handshake(ctx, ws, o)
	if err != nil {
		ws.Close()
		return nil, &HandshakeError{Err: err}
	}
	return c, nil
}

func handshake(ctx context.Context, ws *wsock.Conn, o Options) (*Conn, error) {
	hs := NewHandshake(true, nil, nil, nil)
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	m1, err := hs.WriteMessage(pbuf{}.bytes(1, nonce)) // {bytes client_nonce = 1}
	if err != nil {
		return nil, err
	}
	if err := ws.WriteBinaryContext(ctx, m1); err != nil {
		return nil, err
	}
	type res struct {
		b   []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		_, b, err := ws.ReadMessage()
		ch <- res{b, err}
	}()
	var m2 []byte
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("waiting for message 2: %w", r.err)
		}
		m2 = r.b
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(o.Timeout):
		return nil, errors.New("timeout waiting for message 2")
	}
	payload2, err := hs.ReadMessage(m2)
	if err != nil {
		return nil, err
	}
	if looksLikeRVChallenge(payload2) {
		return nil, errors.New("该账号是机密 VM（需要 RV 密钥认证），暂不支持")
	}
	m3, err := hs.WriteMessage(nil)
	if err != nil {
		return nil, err
	}
	if err := ws.WriteBinaryContext(ctx, m3); err != nil {
		return nil, err
	}
	tx, rx := hs.Split()
	c := &Conn{ws: ws, tx: tx, rx: rx, appID: o.AppID, locale: o.Locale,
		streams: map[int64]*Stream{}, nextID: 1, closed: make(chan struct{}), writeGate: make(chan struct{}, 1)}
	c.touch()
	go c.readLoop()
	go c.pingLoop()
	return c, nil
}

// looksLikeRVChallenge detects the confidential-VM challenge
// (hatch.noise.NoiseHandshakeMessage2: attestation=1, state=2, vm_nonce=3).
// Standard VMs send an attestation blob without the state/nonce fields.
func looksLikeRVChallenge(p []byte) bool {
	if len(p) == 0 {
		return false
	}
	fs, err := parsePB(p)
	if err != nil {
		return false
	}
	var state, nonce bool
	for _, f := range fs {
		if f.num == 2 && f.wire == 0 && (f.v == 1 || f.v == 2) {
			state = true
		}
		if f.num == 3 && f.wire == 2 && len(f.b) == 32 {
			nonce = true
		}
	}
	return state && nonce
}

func (c *Conn) touch() { c.lastActive.Store(time.Now().UnixNano()) }

// Idle reports how long the connection has carried no traffic.
func (c *Conn) Idle() time.Duration { return time.Since(time.Unix(0, c.lastActive.Load())) }

func (c *Conn) Alive() bool {
	select {
	case <-c.closed:
		return false
	default:
		return true
	}
}

func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Conn) Close() error {
	c.shutdown(ErrClosed)
	return nil
}

func (c *Conn) shutdown(err error) {
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return
	default:
	}
	c.err = err
	close(c.closed)
	streams := c.streams
	c.streams = map[int64]*Stream{}
	c.mu.Unlock()
	_ = c.ws.Close()
	for _, s := range streams {
		s.finish(err)
	}
}

func (c *Conn) pingLoop() {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.closed:
			return
		case <-t.C:
			err := c.ws.Ping()
			if err != nil {
				c.shutdown(err)
				return
			}
		}
	}
}

func (c *Conn) readLoop() {
	var re Reassembler
	for {
		_, msg, err := c.ws.ReadMessage()
		if err != nil {
			c.shutdown(fmt.Errorf("hatch: %w", err))
			return
		}
		c.touch()
		plain, err := c.rx.Decrypt(nil, msg)
		if err != nil {
			c.shutdown(err) // nonces are now out of sync; the channel is unusable
			return
		}
		full, err := re.Feed(plain)
		if err != nil || full == nil {
			continue
		}
		fr, err := DecodeResponse(full)
		if err != nil {
			continue
		}
		c.mu.Lock()
		s := c.streams[fr.StreamID]
		c.mu.Unlock()
		if s != nil {
			s.feed(fr)
		}
	}
}

func (c *Conn) send(svc Service, f *Frame) error {
	return c.sendContext(context.Background(), svc, f)
}

func (c *Conn) sendContext(ctx context.Context, svc Service, f *Frame) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	select {
	case c.writeGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.closed:
		return ErrClosed
	}
	defer func() { <-c.writeGate }()
	if err := ctx.Err(); err != nil {
		return err
	}
	env := EncodeRequest(svc, f)
	if !c.Alive() {
		if err := c.Err(); err != nil {
			return err
		}
		return ErrClosed
	}
	for _, chunk := range SplitChunks(env, sendChunkPayload) {
		if err := c.ws.WriteBinaryContext(ctx, c.tx.Encrypt(nil, chunk)); err != nil {
			c.shutdown(err)
			return err
		}
	}
	c.touch()
	return nil
}

// Request describes one call routed to a VM service.
type Request struct {
	Method  string
	Path    string
	Body    []byte // JSON for POST
	Service Service
	Headers []Header
}

// Open sends a request and returns its response stream.
func (c *Conn) Open(r Request) (*Stream, error) {
	return c.OpenContext(context.Background(), r)
}

// OpenContext includes queueing and sending in the caller's deadline.
func (c *Conn) OpenContext(ctx context.Context, r Request) (*Stream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return nil, c.err
	}
	id := c.nextID
	c.nextID++
	s := &Stream{c: c, id: id, svc: r.Service, notify: make(chan struct{}, 1)}
	c.streams[id] = s
	c.mu.Unlock()

	hdr := []Header{{"x-request-id", newRequestID()}, {"x-app-id", c.appID}, {"Accept-Language", c.locale}}
	if len(r.Body) > 0 {
		hdr = append([]Header{{"Content-Type", "application/json"}}, hdr...)
	}
	hdr = append(hdr, r.Headers...)
	req := &AppRequest{Verb: r.Method, Path: r.Path, Headers: hdr, Body: r.Body, EndBody: true}
	if err := c.sendContext(ctx, r.Service, &Frame{StreamID: id, Request: req}); err != nil {
		c.drop(id)
		return nil, err
	}
	return s, nil
}

func (c *Conn) drop(id int64) {
	c.mu.Lock()
	delete(c.streams, id)
	c.mu.Unlock()
}

// Response is a fully read unary reply.
type Response struct {
	Status  int
	Headers []Header
	Body    []byte
}

func (r *Response) JSON(v any) error { return json.Unmarshal(r.Body, v) }

// Do performs a unary request and waits for the whole body.
func (c *Conn) Do(ctx context.Context, r Request) (*Response, error) {
	s, err := c.OpenContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if err := s.Wait(ctx); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return &Response{Status: s.status, Headers: s.headers, Body: s.all}, nil
}

// DoJSON is Do with a JSON body for non-GET requests. For GET requests, encode
// query parameters in path; params is ignored.
func (c *Conn) DoJSON(ctx context.Context, svc Service, method, path string, params any) (*Response, error) {
	var body []byte
	if method != http.MethodGet && params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		body = b
	}
	return c.Do(ctx, Request{Method: method, Path: path, Body: body, Service: svc})
}

// Stream is one request's response: a status, then body bytes until end.
type Stream struct {
	c         *Conn
	id        int64
	svc       Service
	mu        sync.Mutex
	status    int
	headers   []Header
	gotHead   bool
	all       []byte
	streaming bool
	pending   []byte // body bytes not yet consumed by NextJSON / NextChunk
	limit     int    // cap on pending while streaming
	scan      jsonScan
	done      bool
	err       error
	notify    chan struct{}
}

func (s *Stream) wake() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

const maxResponseBody = 512 << 20
const maxStreamPending = 8 << 20

// The shared connection reader cannot pause one stream without blocking its
// other streams. Keep the existing response-size allowance for a burst while
// NextChunk's consumer writes to disk; a smaller pending limit would reject
// otherwise valid media solely because the consumer was briefly descheduled.
// Incremental consumption normally retains much less than this worst case.
const maxChunkPending = maxResponseBody

func (s *Stream) feed(f *Frame) {
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return
	}
	var body []byte
	switch {
	case f.Response != nil:
		s.gotHead = true
		s.status, s.headers = f.Response.Status, f.Response.Headers
		body = f.Response.Body
		s.done = f.Response.EndBody
	case f.IsChunk:
		body = f.Chunk
		s.done = f.ChunkEnd
	case f.Reset != nil:
		s.done = true
		// A reset after headers still represents a truncated response.
		s.err = fmt.Errorf("hatch: stream reset (%d)", f.Reset.Code)
	}
	buffer, limit := &s.all, maxResponseBody
	if s.streaming {
		buffer, limit = &s.pending, s.limit
	}
	if len(body) > limit-len(*buffer) {
		s.done = true
		s.err = errors.New("hatch: response body too large")
	} else {
		*buffer = append(*buffer, body...)
	}
	done := s.done
	s.mu.Unlock()
	if done {
		s.c.drop(s.id)
	}
	s.wake()
}

func (s *Stream) finish(err error) {
	s.mu.Lock()
	if !s.done {
		s.done = true
		if s.err == nil {
			s.err = err
		}
	}
	s.mu.Unlock()
	s.wake()
}

func (s *Stream) Status() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func (s *Stream) Headers() []Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Header(nil), s.headers...)
}

// Wait blocks until the body is complete.
func (s *Stream) Wait(ctx context.Context) error {
	for {
		s.mu.Lock()
		done, err := s.done, s.err
		s.mu.Unlock()
		if done {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.notify:
		}
	}
}

// startStreaming switches the body from whole-response buffering to pending
// bytes consumed incrementally. Callers hold s.mu.
func (s *Stream) startStreamingLocked(limit int) {
	if !s.streaming {
		s.streaming = true
		s.pending = s.all
		s.all = nil
		s.limit = limit
	}
}

// NextJSON returns the next JSON value from an NDJSON / concatenated-JSON
// body, or io.EOF when the stream ended.
func (s *Stream) NextJSON(ctx context.Context) (json.RawMessage, error) {
	s.mu.Lock()
	s.startStreamingLocked(maxStreamPending)
	s.mu.Unlock()
	for {
		s.mu.Lock()
		v, ok := s.cutPendingLocked()
		if ok {
			s.mu.Unlock()
			return v, nil
		}
		done, err := s.done, s.err
		s.mu.Unlock()
		if done {
			if err != nil {
				return nil, err
			}
			return nil, io.EOF
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.notify:
		}
	}
}

// NextChunk returns the body bytes received since the previous call, or
// io.EOF once the body ended. Unlike Wait it never holds the whole body.
func (s *Stream) NextChunk(ctx context.Context) ([]byte, error) {
	s.mu.Lock()
	s.startStreamingLocked(maxChunkPending)
	s.mu.Unlock()
	for {
		s.mu.Lock()
		if len(s.pending) > 0 {
			b := s.pending
			s.pending = nil
			s.mu.Unlock()
			return b, nil
		}
		done, err := s.done, s.err
		s.mu.Unlock()
		if done {
			if err != nil {
				return nil, err
			}
			return nil, io.EOF
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.notify:
		}
	}
}

// cutPendingLocked takes the next JSON value off pending. Objects and arrays
// are found by a resumable scan, so a large record arriving in many chunks is
// not re-parsed from its start on every chunk.
func (s *Stream) cutPendingLocked() (json.RawMessage, bool) {
	if s.scan.pos == 0 {
		s.pending = bytes.TrimLeft(s.pending, " \t\r\n")
	}
	if len(s.pending) > 0 && (s.pending[0] == '{' || s.pending[0] == '[') {
		n := s.scan.end(s.pending)
		if n < 0 {
			return nil, false
		}
		if v := s.pending[:n]; json.Valid(v) {
			s.pending = s.pending[n:]
			return append(json.RawMessage(nil), v...), true
		}
	}
	s.scan = jsonScan{}
	v, rest, ok := cutJSON(s.pending)
	s.pending = rest
	return v, ok
}

// jsonScan locates the end of the top-level object or array at the start of
// a growing buffer, resuming where the previous call stopped.
type jsonScan struct {
	pos, depth int
	inStr, esc bool
}

// end returns the length of the complete value, or -1 when more input is
// needed. It resets itself after finding a value.
func (j *jsonScan) end(buf []byte) int {
	for ; j.pos < len(buf); j.pos++ {
		c := buf[j.pos]
		switch {
		case j.inStr:
			if j.esc {
				j.esc = false
			} else if c == '\\' {
				j.esc = true
			} else if c == '"' {
				j.inStr = false
			}
		case c == '"':
			j.inStr = true
		case c == '{' || c == '[':
			j.depth++
		case c == '}' || c == ']':
			if j.depth--; j.depth == 0 {
				n := j.pos + 1
				*j = jsonScan{}
				return n
			}
		}
	}
	return -1
}

// cutJSON splits the first complete JSON value off buf.
func cutJSON(buf []byte) (json.RawMessage, []byte, bool) {
	for {
		trimmed := bytes.TrimLeft(buf, " \t\r\n")
		if len(trimmed) == 0 {
			return nil, buf, false
		}
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		var raw json.RawMessage
		if err := dec.Decode(&raw); err == nil {
			return raw, trimmed[dec.InputOffset():], true
		} else if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, buf, false // value continues in the next chunk
		}
		// Garbage line (e.g. an SSE prefix): skip to the next newline.
		i := bytes.IndexByte(trimmed, '\n')
		if i < 0 {
			return nil, buf, false
		}
		buf = trimmed[i+1:]
	}
}

// Close cancels the stream on the gateway if it is still open.
func (s *Stream) Close() {
	s.mu.Lock()
	done := s.done
	s.done = true
	s.mu.Unlock()
	s.c.drop(s.id)
	s.wake()
	if !done && s.c.Alive() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = s.c.sendContext(ctx, s.svc, &Frame{StreamID: s.id, Reset: &Reset{Code: 1, Reason: "client done"}})
	}
}
