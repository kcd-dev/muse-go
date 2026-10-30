package fakemuse

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/kcd-dev/muse-go/hatch"
)

// Gateway imitates the Hatch gateway: a Noise XX responder followed by the
// chat / history / media / approval routes the protocol driver uses.
type Gateway struct {
	mu        sync.Mutex
	threads   map[string][]map[string]any
	nextMsg   int
	Decisions []string // approval decisions received
	// Optional immutable test hook; configure before serving any requests.
	HistoryResponse func(sessionID string) ([]byte, bool)
}

func NewGateway() *Gateway { return &Gateway{threads: map[string][]map[string]any{}} }

// ---- server-side websocket (just enough for tests)

type wsConn struct {
	c   net.Conn
	br  *bufio.Reader
	wmu sync.Mutex
}

func upgrade(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, fmt.Errorf("not a websocket request")
	}
	c, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return nil, err
	}
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		base64.StdEncoding.EncodeToString(h[:]) + "\r\n\r\n")
	_ = rw.Flush()
	return &wsConn{c: c, br: rw.Reader}, nil
}

func (w *wsConn) read() ([]byte, error) {
	for {
		var h [2]byte
		if _, err := io.ReadFull(w.br, h[:]); err != nil {
			return nil, err
		}
		op := h[0] & 0x0F
		n := uint64(h[1] & 0x7F)
		switch n {
		case 126:
			var b [2]byte
			_, _ = io.ReadFull(w.br, b[:])
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			_, _ = io.ReadFull(w.br, b[:])
			n = binary.BigEndian.Uint64(b[:])
		}
		var mask [4]byte
		_, _ = io.ReadFull(w.br, mask[:])
		p := make([]byte, n)
		if _, err := io.ReadFull(w.br, p); err != nil {
			return nil, err
		}
		for i := range p {
			p[i] ^= mask[i&3]
		}
		switch op {
		case 0x8:
			return nil, io.EOF
		case 0x9, 0xA:
			continue
		}
		return p, nil
	}
}

func (w *wsConn) write(p []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	hdr := []byte{0x82}
	switch n := len(p); {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127)
		hdr = binary.BigEndian.AppendUint64(hdr, uint64(n))
	}
	_, err := w.c.Write(append(hdr, p...))
	return err
}

// ---- gateway session

type session struct {
	g      *Gateway
	ws     *wsConn
	tx, rx *hatch.CipherState
	smu    sync.Mutex // tx nonce order must match write order
}

func (s *session) send(f *hatch.Frame) {
	s.smu.Lock()
	defer s.smu.Unlock()
	for _, chunk := range hatch.SplitChunks(hatch.EncodeResponse(f), 16<<10) {
		_ = s.ws.write(s.tx.Encrypt(nil, chunk))
	}
}

func (s *session) reply(id int64, status int, body []byte, end bool, headers ...hatch.Header) {
	s.send(&hatch.Frame{StreamID: id, Response: &hatch.AppResponse{Status: status, Body: body, EndBody: end, Headers: headers}})
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("auth_token") != "tok" || r.URL.Query().Get("vm_id") != "vm1" {
		http.Error(w, "bad token", 401)
		return
	}
	ws, err := upgrade(w, r)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	defer ws.c.Close()
	hs := hatch.NewHandshake(false, nil, nil, nil)
	m1, err := ws.read()
	if err != nil {
		return
	}
	if _, err := hs.ReadMessage(m1); err != nil {
		return
	}
	m2, _ := hs.WriteMessage(nil)
	_ = ws.write(m2)
	m3, err := ws.read()
	if err != nil {
		return
	}
	if _, err := hs.ReadMessage(m3); err != nil {
		return
	}
	rx, tx := hs.Split()
	s := &session{g: g, ws: ws, tx: tx, rx: rx}
	var re hatch.Reassembler
	for {
		msg, err := ws.read()
		if err != nil {
			return
		}
		plain, err := rx.Decrypt(nil, msg)
		if err != nil {
			return
		}
		full, err := re.Feed(plain)
		if err != nil || full == nil {
			continue
		}
		svc, fr, err := hatch.DecodeRequest(full)
		if err != nil || fr.Request == nil {
			continue
		}
		go s.route(svc, fr.StreamID, fr.Request)
	}
}

func (s *session) route(svc hatch.Service, id int64, req *hatch.AppRequest) {
	g := s.g
	u, _ := url.Parse(req.Path)
	switch {
	case req.Verb == "POST" && u.Path == "/api/nodes/register":
		s.reply(id, 200, []byte(`{}`), true)
	case req.Verb == "POST" && u.Path == "/chat/stream":
		var body struct {
			SessionID string           `json:"session_id"`
			Message   string           `json:"message"`
			Items     []map[string]any `json:"items"`
		}
		_ = json.Unmarshal(req.Body, &body)
		g.mu.Lock()
		g.nextMsg++
		mid := fmt.Sprintf("m%d", g.nextMsg)
		g.threads[body.SessionID] = append(g.threads[body.SessionID],
			map[string]any{"event_name": "message.user", "message_id": mid, "text": body.Message})
		g.mu.Unlock()
		s.reply(id, 200, []byte(`{"message_id":"`+mid+`"}`+"\n"), false)
		refs := 0
		for _, it := range body.Items {
			if it["type"] == "image" && it["data_base64"] != "" {
				refs++
			}
		}
		go g.simulate(body.SessionID, body.Message, refs)
	case req.Verb == "GET" && u.Path == "/chat/history":
		if g.HistoryResponse != nil {
			if body, ok := g.HistoryResponse(u.Query().Get("session_id")); ok {
				s.reply(id, 200, body, true)
				return
			}
		}
		g.mu.Lock() // the simulator mutates events in place
		b, _ := json.Marshal(map[string]any{"chat_events": g.threads[u.Query().Get("session_id")]})
		g.mu.Unlock()
		s.reply(id, 200, b, true)
	case req.Verb == "GET" && strings.HasPrefix(u.Path, "/media/raw/"):
		if u.Path != "/media/raw/workspace/out/cat.png" {
			s.reply(id, 404, nil, true)
			return
		}
		png := PNG()
		// Large bodies arrive as a head plus body chunks.
		s.reply(id, 200, png[:10], false, hatch.Header{Key: "content-type", Value: "image/png"})
		s.send(&hatch.Frame{StreamID: id, IsChunk: true, Chunk: png[10:], ChunkEnd: true})
	case svc == hatch.ServiceSentinel && req.Verb == "GET" && u.Path == "/approvals":
		g.mu.Lock()
		list := []map[string]any{}
		for sid, evs := range g.threads {
			if strings.Contains(fmt.Sprint(evs[0]["text"]), "fetch the web") && !g.decided(sid) {
				list = append(list, map[string]any{"approval_id": "ap-" + sid, "status": "pending",
					"scope":            map[string]any{"thread_id": sid},
					"decision_options": []any{map[string]any{"kind": "allow_once"}, map[string]any{"kind": "deny"}}})
			}
		}
		g.mu.Unlock()
		b, _ := json.Marshal(map[string]any{"approvals": list})
		s.reply(id, 200, b, true)
	case svc == hatch.ServiceSentinel && req.Verb == "POST" && strings.HasPrefix(u.Path, "/approvals/"):
		var body map[string]any
		_ = json.Unmarshal(req.Body, &body)
		g.mu.Lock()
		g.Decisions = append(g.Decisions, strings.TrimPrefix(fmt.Sprint(body["approval_id"]), "ap-")+"="+fmt.Sprint(body["decision"]))
		g.mu.Unlock()
		s.reply(id, 200, []byte(`{"ok":true}`), true)
	case req.Verb == "GET" && u.Path == "/model":
		s.reply(id, 200, []byte(`{"model":"muse-spark"}`), true)
	default:
		s.reply(id, 404, []byte(`{"error":"not found"}`), true)
	}
}

func (g *Gateway) decided(sid string) bool {
	for _, d := range g.Decisions {
		if strings.HasPrefix(d, sid+"=") {
			return true
		}
	}
	return false
}

// simulate grows an assistant reply in the thread history like the VM does.
func (g *Gateway) simulate(sid, msg string, refs int) {
	if strings.Contains(msg, "fetch the web") {
		for !func() bool { g.mu.Lock(); defer g.mu.Unlock(); return g.decided(sid) }() {
			time.Sleep(50 * time.Millisecond)
		}
	}
	add := func(ev map[string]any) {
		g.mu.Lock()
		g.threads[sid] = append(g.threads[sid], ev)
		g.mu.Unlock()
	}
	// Like the real VM: metadata.streaming while growing, payload.status once done.
	setText := func(t string, final bool) {
		g.mu.Lock()
		evs := g.threads[sid]
		for i := len(evs) - 1; i >= 0; i-- {
			if evs[i]["event_name"] == "message.assistant" {
				p := map[string]any{"text": t, "metadata": map[string]any{"streaming": true}}
				if final {
					p = map[string]any{"text": t, "status": "completed", "metadata": map[string]any{}}
				}
				evs[i]["payload"] = p
				break
			}
		}
		g.mu.Unlock()
	}
	time.Sleep(100 * time.Millisecond)
	if strings.Contains(msg, "draw") {
		add(map[string]any{"event_name": "message.assistant", "message_id": "a-" + sid, "payload": map[string]any{"text": "Generating…"}})
		time.Sleep(300 * time.Millisecond)
		add(map[string]any{"event_name": "delta.presentation", "payload": map[string]any{"kind": "image",
			"images": []any{map[string]any{"path": "sandbox://workspace/out/cat.png", "mime": "image/png"}}}})
		setText("Here is your cat.", true)
		return
	}
	if strings.Contains(msg, "refuse") {
		add(map[string]any{"event_name": "message.assistant", "message_id": "a-" + sid, "payload": map[string]any{"text": "I can't generate that image because of our content policy.", "status": "completed"}})
		return
	}
	reply := fmt.Sprintf("Hello **world**, refs=%d. Here is code:\n\n```go\nfmt.Println(\"hi\")\n```", refs)
	add(map[string]any{"event_name": "message.assistant", "message_id": "a-" + sid, "payload": map[string]any{"text": ""}})
	words := strings.SplitAfter(reply, " ")
	for i := range words {
		setText(strings.Join(words[:i+1], ""), false)
		time.Sleep(150 * time.Millisecond)
	}
	setText(reply, true)
}
