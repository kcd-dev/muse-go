package muse

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/kcd-dev/muse-go/hatch"
)

// siteClient makes authenticated muse.ai requests for one account and keeps
// the cookies the site rotates through Set-Cookie.
type siteClient struct {
	site   string
	client *http.Client

	mu      sync.Mutex
	cookies map[string]string
	expires map[string]int64
	changed bool
}

func newSiteClient(site, proxy string, cookies map[string]string) *siteClient {
	jar := make(map[string]string, len(cookies))
	for k, v := range cookies {
		jar[k] = v
	}
	return &siteClient{site: site, client: httpClient(proxy, 30*time.Second), cookies: jar, expires: map[string]int64{}}
}

// Rotated returns the current cookies if the site changed any since the last call.
func (c *siteClient) Rotated() (map[string]string, map[string]int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.changed {
		return nil, nil, false
	}
	c.changed = false
	ck := make(map[string]string, len(c.cookies))
	for k, v := range c.cookies {
		ck[k] = v
	}
	ex := make(map[string]int64, len(c.expires))
	for k, v := range c.expires {
		ex[k] = v
	}
	return ck, ex, true
}

func (c *siteClient) do(ctx context.Context, method, path string, body any) (map[string]any, int, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.site+path, rd)
	if err != nil {
		return nil, 0, err
	}
	c.mu.Lock()
	cookie := CookieHeader(c.cookies)
	c.mu.Unlock()
	req.Header.Set("User-Agent", DefaultUA)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", c.site)
	req.Header.Set("Referer", c.site+"/")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Cookie", cookie)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, wrap(KindTransient, method+" "+path+" 网络错误", err)
	}
	defer resp.Body.Close()
	c.mu.Lock()
	before := CookieHeader(c.cookies)
	mergeSetCookies(resp, c.cookies, c.expires)
	if CookieHeader(c.cookies) != before || len(resp.Cookies()) > 0 {
		c.changed = true
	}
	c.mu.Unlock()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode == 401 {
		return out, resp.StatusCode, errf(KindAuth, "会话已失效 (%s HTTP 401)，请重新导入 Cookie", path)
	}
	if resp.StatusCode >= 400 {
		return out, resp.StatusCode, classifyHTTPError(path, resp.StatusCode, string(raw), responseHeaders(resp.Header))
	}
	return out, resp.StatusCode, nil
}

func str(m map[string]any, k string) string {
	if v, ok := m[k]; ok && v != nil {
		return fmt.Sprint(v)
	}
	return ""
}

// sessionInfo reads /api/session (and rotates the long-lived cookies).
func (c *siteClient) sessionInfo(ctx context.Context) (*SessionInfo, map[string]any, error) {
	body, _, err := c.do(ctx, http.MethodGet, "/api/session?vm_state=live", nil)
	if err != nil {
		return nil, body, err
	}
	info := &SessionInfo{Status: str(body, "status"), VMID: str(body, "vm_id"), VMState: str(body, "vm_state")}
	info.OK = info.Status == "assigned"
	return info, body, nil
}

// bootstrap resolves the account's VM (waking it when needed) and fetches the
// short-lived tokens for the gateway WebSocket.
func (c *siteClient) bootstrap(ctx context.Context) (*hatch.Session, *SessionInfo, error) {
	info, body, err := c.sessionInfo(ctx)
	if err != nil {
		return nil, nil, err
	}
	endpoint := str(body, "endpoint_url")
	if info.VMID == "" {
		if issue := str(body, "vm_resolution_issue"); issue != "" {
			return nil, info, errf(KindTransient, "muse.ai 未分配 VM")
		}
		if info.Status == "" || strings.Contains(strings.ToLower(info.Status), "unauth") {
			return nil, info, errf(KindAuth, "会话未登录")
		}
		return nil, info, errf(KindTransient, "muse.ai 未分配 VM")
	}
	if !strings.EqualFold(info.VMState, "RUNNING") {
		_, _, _ = c.do(ctx, http.MethodPost, "/api/hatch/vm/wake", map[string]any{
			"vm_id": info.VMID, "retry_count": 1, "connect_attempt_id": newUUID()})
		deadline := time.Now().Add(60 * time.Second)
		for !strings.EqualFold(info.VMState, "RUNNING") {
			if time.Now().After(deadline) {
				return nil, info, errf(KindTransient, "VM 未能启动")
			}
			if err := sleep(ctx, 1500*time.Millisecond); err != nil {
				return nil, info, err
			}
			if i, b, err := c.sessionInfo(ctx); err == nil {
				info, body = i, b
				if e := str(b, "endpoint_url"); e != "" {
					endpoint = e
				}
			} else if KindOf(err) == KindAuth {
				return nil, info, err
			}
		}
		// Let the VM's noise listener bind before the upgrade.
		if err := sleep(ctx, 1500*time.Millisecond); err != nil {
			return nil, info, err
		}
	}
	tokenReq := map[string]any{"vmAddress": endpoint, "vmName": info.VMID}
	tok, code, err := c.do(ctx, http.MethodPost, "/api/hatch/token", tokenReq)
	if err != nil && (code == 401 || code == 403) {
		// A stale hatch_vml is the usual cause; refreshing the session fixes it.
		if _, _, err2 := c.sessionInfo(ctx); err2 == nil {
			tok, _, err = c.do(ctx, http.MethodPost, "/api/hatch/token", tokenReq)
		}
	}
	if err != nil {
		return nil, info, err
	}
	s := &hatch.Session{VMID: info.VMID, Endpoint: endpoint, AuthToken: str(tok, "token")}
	if s.AuthToken == "" {
		return nil, info, errf(KindTransient, "/api/hatch/token 未返回 token")
	}
	// The notary token is optional for standard VMs.
	if n, _, err := c.do(ctx, http.MethodPost, "/api/hatch/noise-notary-token", map[string]any{"vmName": info.VMID}); err == nil {
		s.NotaryToken = strings.TrimSpace(str(n, "notaryToken"))
	}
	return s, info, nil
}
