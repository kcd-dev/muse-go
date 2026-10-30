package muse

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/kcd-dev/muse-go/internal/netproxy"
)

// Cookies that identify a logged-in muse.ai session. hatch_gw / hatch_vml are
// not issued to every session any more, so only hatch_sess is mandatory.
var (
	RequiredCookies = []string{"hatch_sess"}
	KnownCookies    = []string{"hatch_sess", "hatch_native_auth_device", "hatch_gw", "hatch_vml"}
)

const DefaultUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

type SessionInfo struct {
	OK       bool              `json:"ok"`
	Status   string            `json:"status"`
	VMID     string            `json:"vm_id,omitempty"`
	VMState  string            `json:"vm_state,omitempty"`
	WakeHTTP int               `json:"wake_http,omitempty"`
	Cookies  map[string]string `json:"-"`
	Expires  map[string]int64  `json:"-"`
}

func MissingCookies(c map[string]string) []string {
	var out []string
	for _, n := range RequiredCookies {
		if c[n] == "" {
			out = append(out, n)
		}
	}
	return out
}

func CookieHeader(c map[string]string) string {
	parts := make([]string, 0, len(c))
	for k, v := range c {
		if v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// ParseCookies accepts "a=1; b=2", a JSON object, a JSON cookie array
// (EditThisCookie / DevTools export) or one cookie per line.
func ParseCookies(text string) map[string]string {
	text = strings.TrimSpace(text)
	out := map[string]string{}
	if text == "" {
		return out
	}
	if strings.HasPrefix(text, "{") {
		var m map[string]any
		if json.Unmarshal([]byte(text), &m) == nil {
			if inner, ok := m["cookies"]; ok {
				b, _ := json.Marshal(inner)
				return ParseCookies(string(b))
			}
			for k, v := range m {
				if s, ok := v.(string); ok {
					out[k] = s
				}
			}
			return out
		}
	}
	if strings.HasPrefix(text, "[") {
		var arr []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		}
		if json.Unmarshal([]byte(text), &arr) == nil {
			for _, c := range arr {
				if c.Name != "" {
					out[c.Name] = c.Value
				}
			}
			return out
		}
	}
	text = strings.TrimPrefix(text, "Cookie:")
	for _, part := range strings.FieldsFunc(text, func(r rune) bool { return r == ';' || r == '\n' }) {
		part = strings.TrimSpace(part)
		// Tab separated rows copied from the DevTools cookie table.
		if fields := strings.Split(part, "\t"); len(fields) >= 2 && !strings.Contains(fields[0], "=") {
			out[strings.TrimSpace(fields[0])] = strings.TrimSpace(fields[1])
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		if ok && strings.TrimSpace(k) != "" {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

func httpClient(proxy string, timeout time.Duration) *http.Client {
	return netproxy.NewHTTPClient(proxy, timeout)
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// RenewSession calls /api/session (which rotates short-lived cookies through
// Set-Cookie) and optionally wakes the account's cloud VM so the first chat
// does not wait for a cold start.
func RenewSession(ctx context.Context, site string, cookies map[string]string, proxy string, wake bool) (*SessionInfo, error) {
	if site == "" {
		site = "https://muse.ai"
	}
	site = strings.TrimRight(site, "/")
	if err := validateEndpoint(site, false); err != nil {
		return nil, err
	}
	cl := httpClient(proxy, 20*time.Second)
	defer cl.CloseIdleConnections()
	jar := map[string]string{}
	for k, v := range cookies {
		jar[k] = v
	}
	info := &SessionInfo{Cookies: jar, Expires: map[string]int64{}}

	var lastHeaders http.Header
	get := func() (map[string]any, int, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, site+"/api/session", nil)
		setHeaders(req, site, jar)
		resp, err := cl.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		lastHeaders = resp.Header.Clone()
		mergeSetCookies(resp, jar, info.Expires)
		var body map[string]any
		if strings.Contains(resp.Header.Get("Content-Type"), "json") {
			_ = json.NewDecoder(resp.Body).Decode(&body)
		}
		return body, resp.StatusCode, nil
	}

	body, code, err := get()
	if err != nil {
		return nil, wrap(KindTransient, "/api/session 网络请求失败", err)
	}
	switch {
	case code == 401:
		return nil, errf(KindAuth, "会话已失效 (/api/session HTTP 401)，请重新导入 Cookie")
	case code == 429:
		return nil, classifyHTTPError("/api/session", 429, "上游限流", responseHeaders(lastHeaders))
	case code == 403:
		return nil, errf(KindTransient, "/api/session HTTP 403：访问被拒绝，检查出口 IP/地区，不能据此判定 Cookie 失效")
	case code != 200:
		return nil, errf(KindTransient, "/api/session HTTP %d", code)
	}
	info.Status, _ = body["status"].(string)
	info.VMID, _ = body["vm_id"].(string)
	info.VMState, _ = body["vm_state"].(string)
	info.OK = info.Status == "assigned"
	if !info.OK {
		if info.Status == "" || info.Status == "unauthenticated" || info.Status == "anonymous" {
			return info, errf(KindAuth, "会话未登录 (/api/session status=%q)", info.Status)
		}
		return info, nil
	}
	if !wake || info.VMID == "" || info.VMState == "RUNNING" || info.VMState == "DISABLED" {
		return info, nil
	}
	payload, _ := json.Marshal(map[string]any{"vm_id": info.VMID, "retry_count": 0, "connect_attempt_id": newUUID()})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, site+"/api/hatch/vm/wake", strings.NewReader(string(payload)))
	setHeaders(req, site, jar)
	req.Header.Set("Content-Type", "application/json")
	if resp, err := cl.Do(req); err == nil {
		info.WakeHTTP = resp.StatusCode
		mergeSetCookies(resp, jar, info.Expires)
		resp.Body.Close()
	}
	// The wake answer itself says little (403 for an already running VM);
	// trust the state the session endpoint reports.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return info, ctx.Err()
		case <-time.After(2 * time.Second):
		}
		if b, c, err := get(); err == nil && c == 200 {
			if s, _ := b["vm_state"].(string); s != "" {
				info.VMState = s
				if s == "RUNNING" {
					break
				}
			}
		}
	}
	return info, nil
}

func setHeaders(req *http.Request, site string, jar map[string]string) {
	req.Header.Set("User-Agent", DefaultUA)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", site)
	req.Header.Set("Referer", site+"/thread/new")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Cookie", CookieHeader(jar))
}

func mergeSetCookies(resp *http.Response, jar map[string]string, exp map[string]int64) {
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 {
			continue
		}
		if c.Value != "" {
			jar[c.Name] = c.Value
		}
		switch {
		case c.MaxAge > 0:
			exp[c.Name] = time.Now().Unix() + int64(c.MaxAge)
		case !c.Expires.IsZero():
			exp[c.Name] = c.Expires.Unix()
		}
	}
}
