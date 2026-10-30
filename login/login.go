// Package login authenticates existing Muse accounts through a password or email OTP.
// Passwords and verification codes are provided by the caller. The package does
// not register accounts, retrieve credentials, or complete onboarding requirements.
package login

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/kcd-dev/muse-go/internal/netproxy"
)

var validOTP = regexp.MustCompile(`^[0-9]{4,16}$`)

// ErrManualIntervention means the existing account requires a verification or
// setup step that this protocol library does not perform.
var ErrManualIntervention = errors.New("需要在浏览器中完成账号验证或设置后重试")

const defaultSite = "https://muse.ai"
const userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
const maxResponse = 2 << 20

// Options are used for a single login with a new, isolated cookie jar. Supply
// exactly one of Password or GetOTP. The package does not obtain either secret.
// Password is preserved byte-for-byte, including leading and trailing spaces.
// Callbacks must respect cancellation through their context and must not log codes.
type Options struct {
	SiteURL  string
	Email    string
	Password string `json:"-"`
	Proxy    string `json:"-"`
	Region   string
	Timeout  time.Duration
	// OnStage receives fixed progress identifiers, never credentials or upstream bodies.
	OnStage func(string) `json:"-"`
	// GetOTP is invoked after the server accepts the code-send request. sentAt
	// marks that request, allowing the caller to identify this login attempt.
	// Return a 4–16 digit code; return ctx.Err() when the context is canceled.
	GetOTP func(ctx context.Context, sentAt time.Time) (string, error) `json:"-"`
	// Transport is an optional test/integration transport. A nil value uses the
	// configured account proxy. A supplied transport owns its routing policy.
	Transport http.RoundTripper `json:"-"`
}

type Result struct {
	Email            string            `json:"email"`
	IdentityVerified bool              `json:"identity_verified"`
	AccountID        string            `json:"account_id,omitempty"`
	SessionStatus    string            `json:"session_status,omitempty"`
	Cookies          map[string]string `json:"-"`
	CookieExpires    map[string]int64  `json:"-"`
}

// Error contains only fixed workflow details, never upstream bodies or URLs.
type Error struct {
	Stage      string
	Code       string
	HTTPStatus int
	Err        error
}

func (e *Error) Error() string {
	if e.Code == "manual_intervention" {
		return ErrManualIntervention.Error()
	}
	if e.Code == "password_unavailable" {
		return "此账号当前未开放密码登录，请使用邮箱验证码"
	}
	if e.Code == "password_state_unrecognized" {
		return "登录服务返回了未识别的账号状态，未提交密码"
	}
	if e.HTTPStatus != 0 {
		return fmt.Sprintf("登录步骤 %s 失败 (HTTP %d)", e.Stage, e.HTTPStatus)
	}
	return "登录步骤 " + e.Stage + " 失败: " + e.Code
}
func (e *Error) Unwrap() error                    { return e.Err }
func failure(stage, code string, err error) error { return &Error{Stage: stage, Code: code, Err: err} }

func NormalizeEmail(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	address, err := mail.ParseAddress(raw)
	if err != nil || address.Name != "" || address.Address != raw || len(raw) > 254 || strings.ContainsAny(raw, "\r\n\t ") || strings.Count(raw, "@") != 1 {
		return "", errors.New("邮箱地址格式无效")
	}
	return strings.ToLower(raw), nil
}

func ValidateOptions(o Options) error {
	if _, err := NormalizeEmail(o.Email); err != nil {
		return err
	}
	if _, err := siteURL(o.SiteURL); err != nil {
		return err
	}
	if _, err := netproxy.Normalize(o.Proxy); err != nil {
		return err
	}
	if o.Password != "" && (len(o.Password) > 4096 || !utf8.ValidString(o.Password)) {
		return errors.New("密码格式无效或超过长度限制")
	}
	if o.Password != "" && o.GetOTP != nil {
		return errors.New("密码登录不能同时配置验证码输入")
	}
	if o.Password == "" && o.GetOTP == nil {
		return errors.New("请提供密码或验证码回调 GetOTP")
	}
	if o.Region != "" && !regexp.MustCompile(`^[A-Za-z]{2}$`).MatchString(o.Region) {
		return errors.New("地区应为两位国家代码")
	}
	if o.Timeout < 0 || o.Timeout > 15*time.Minute {
		return errors.New("登录超时必须在 0–900 秒之间")
	}
	return nil
}

func siteURL(raw string) (*url.URL, error) {
	if raw == "" {
		raw = defaultSite
	}
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("登录站点地址无效")
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, errors.New("登录站点必须使用 HTTPS")
		}
	}
	return u, nil
}

// Login authenticates once and returns only cookies applicable to Muse's origin.
// Password mode uses the site's contact-initialization endpoint, which may send
// an email code, but never retrieves, confirms, or falls back to OTPs.
// No passwords, cookies, OTPs or proxy credentials are logged or persisted.
func Login(ctx context.Context, o Options) (*Result, error) {
	if err := ValidateOptions(o); err != nil {
		return nil, err
	}
	if o.Timeout == 0 {
		o.Timeout = 4 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	email, _ := NormalizeEmail(o.Email)
	base, _ := siteURL(o.SiteURL)
	route, err := netproxy.Resolve(o.Proxy, base.String())
	if err != nil {
		return nil, failure("initializing", "invalid_proxy", nil)
	}
	jar := newJar()
	client := netproxy.NewHTTPClient(route, 30*time.Second)
	client.Jar = jar
	if o.Transport != nil {
		client.Transport = o.Transport
	}
	defer client.CloseIdleConnections()
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, failure("initializing", "random_source_failed", nil)
	}
	random[6] = (random[6] & 15) | 64
	random[8] = (random[8] & 63) | 128
	h := hex.EncodeToString(random[:])
	s := &session{base: base, client: client, waterfall: h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], email: email, onStage: o.OnStage}
	s.stage("initializing")
	home, err := s.request(ctx, "/", nil, "")
	if err != nil {
		return nil, err
	}
	home, err = s.navigate(ctx, home, 6)
	if err != nil {
		return nil, err
	}
	if home.status != 200 || !sameOrigin(base, home.target) {
		return nil, s.manual()
	}
	restart, err := s.request(ctx, "/api/auth/native/restart", map[string]any{}, "")
	if err != nil {
		return nil, err
	}
	if err = s.requireSuccess(restart); err != nil {
		return nil, err
	}
	s.csrf = stringValue(restart.data, "csrf_token")
	if s.csrf == "" {
		return nil, failure(s.phase, "missing_csrf", nil)
	}
	var confirmed *response
	if o.Password != "" {
		confirmed, err = s.confirmPassword(ctx, o, restart)
		o.Password = ""
	} else {
		confirmed, err = s.confirmOTP(ctx, o)
	}
	if err != nil {
		return nil, err
	}
	if err = s.requireSuccess(confirmed); err != nil {
		return nil, err
	}
	if err = s.checkIdentity(confirmed.data); err != nil {
		return nil, err
	}
	if err = s.checkGate(confirmed.data); err != nil {
		return nil, err
	}
	return s.finishLogin(ctx, confirmed, jar)
}

func (s *session) confirmOTP(ctx context.Context, o Options) (*response, error) {
	s.stage("sending_otp")
	sentAt := time.Now()
	payload := map[string]any{"contact_point": s.email}
	if o.Region != "" {
		payload["region"] = strings.ToUpper(o.Region)
	}
	sent, err := s.request(ctx, "/api/auth/native/send-otp", payload, s.csrf)
	if err != nil {
		return nil, err
	}
	if err = s.requireSuccess(sent); err != nil {
		return nil, err
	}
	if err = s.checkIdentity(sent.data); err != nil {
		return nil, err
	}
	if err = s.checkGate(sent.data); err != nil {
		return nil, err
	}
	if stringValue(sent.data, "registration_state") != "otp_sent" {
		return nil, failure(s.phase, "otp_not_confirmed_sent", nil)
	}
	if csrf := stringValue(sent.data, "csrf_token"); csrf != "" {
		s.csrf = csrf
	}
	s.stage("waiting_otp")
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	code, err := o.GetOTP(ctx, sentAt)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, failure(s.phase, "otp_unavailable", nil)
	}
	code = strings.TrimSpace(code)
	if !validOTP.MatchString(code) {
		return nil, failure(s.phase, "invalid_otp", nil)
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	s.stage("confirming")
	confirmed, err := s.request(ctx, "/api/auth/native/confirm-otp", map[string]any{"otp_code": code, "return_to": "/"}, s.csrf)
	code = ""
	return confirmed, err
}

func (s *session) finishLogin(ctx context.Context, confirmed *response, jar *recordingJar) (*Result, error) {
	// Existing accounts sometimes require the standard Meta session handoff.
	if meta, ok := confirmed.data["auth_meta_session"].(map[string]any); ok {
		if token := stringValue(meta, "frl_access_token"); token != "" {
			if s.base.String() != defaultSite {
				return nil, s.manual()
			}
			handoff, err := s.request(ctx, "https://auth.meta.com/hatch/session/bootstrap/", url.Values{"frl_access_token": {token}}, "")
			if err != nil {
				return nil, err
			}
			handoff, err = s.navigate(ctx, handoff, 8)
			if err != nil {
				return nil, err
			}
			if handoff.status >= 400 {
				return nil, s.manual()
			}
		}
	}
	s.stage("verifying")
	// The browser checks the authenticated session with a bodyless POST.
	auth, err := s.requestMethod(ctx, http.MethodPost, "/api/auth/check", nil, "")
	if err != nil {
		return nil, err
	}
	if err = s.requireSuccess(auth); err != nil {
		return nil, err
	}
	// The browser uses this endpoint as an HTTP/checkpoint gate; a successful
	// response need not include an authenticated field. An explicit value must
	// still be literal true, and the actual session is verified below.
	if value, present := auth.data["authenticated"]; present {
		if authenticated, ok := value.(bool); !ok || !authenticated {
			return nil, failure(s.phase, "session_not_authenticated", nil)
		}
	}
	if err = s.checkIdentity(auth.data); err != nil {
		return nil, err
	}
	info, err := s.request(ctx, "/api/session", nil, "")
	if err != nil {
		return nil, err
	}
	if err = s.requireSuccess(info); err != nil {
		return nil, err
	}
	if err = s.checkIdentity(info.data); err != nil {
		return nil, err
	}
	status := stringValue(info.data, "status")
	if status != "assigned" || strings.TrimSpace(stringValue(info.data, "vm_id")) == "" {
		return nil, failure(s.phase, "session_not_authenticated", nil)
	}
	cookieScope := *s.base
	cookieScope.Path = "/api/session"
	cookies, expires := jar.snapshot(&cookieScope)
	if cookies["hatch_sess"] == "" {
		return nil, failure(s.phase, "missing_session_cookie", nil)
	}
	result := &Result{Email: s.email, IdentityVerified: true, SessionStatus: status, Cookies: cookies, CookieExpires: expires}
	for _, data := range []map[string]any{auth.data, info.data, confirmed.data} {
		if id := stringValue(data, "account_id"); id != "" {
			result.AccountID = id
			break
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	s.stage("completed")
	return result, nil
}

type session struct {
	base                          *url.URL
	client                        *http.Client
	waterfall, csrf, email, phase string
	onStage                       func(string)
}

func (s *session) stage(phase string) {
	s.phase = phase
	if s.onStage != nil {
		s.onStage(phase)
	}
}
func (s *session) manual() error {
	s.stage("manual_intervention")
	return &Error{Stage: s.phase, Code: "manual_intervention", Err: ErrManualIntervention}
}

type response struct {
	status   int
	data     map[string]any
	location string
	target   *url.URL
}

func (s *session) request(ctx context.Context, target string, payload any, csrf string) (*response, error) {
	method := http.MethodGet
	if payload != nil {
		method = http.MethodPost
	}
	return s.requestMethod(ctx, method, target, payload, csrf)
}

func (s *session) requestMethod(ctx context.Context, method, target string, payload any, csrf string) (*response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, failure(s.phase, "invalid_target", nil)
	}
	u = s.base.ResolveReference(u)
	if !s.allowed(u) {
		return nil, s.manual()
	}
	var body io.Reader
	form, isForm := payload.(url.Values)
	if payload != nil {
		if isForm {
			body = strings.NewReader(form.Encode())
		} else {
			encoded, err := json.Marshal(payload)
			if err != nil {
				return nil, failure(s.phase, "invalid_payload", nil)
			}
			body = bytes.NewReader(encoded)
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, failure(s.phase, "invalid_request", nil)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json, text/html;q=0.9, */*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Referer", s.base.String()+"/")
	if sameOrigin(s.base, u) {
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		if csrf != "" {
			req.Header.Set("X-Hatch-CSRF-Token", csrf)
		}
		if method == http.MethodPost {
			req.Header.Set("X-Hatch-Waterfall-Id", s.waterfall)
		}
	} else {
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Dest", "document")
	}
	if method == http.MethodGet && !strings.HasPrefix(u.Path, "/api/") {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		if s.phase == "initializing" && u.Path == "/" {
			req.Header.Set("Sec-Fetch-Site", "none")
		}
	}
	if method == http.MethodPost {
		req.Header.Set("Origin", s.base.String())
		if isForm {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	resp, err := s.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, failure(s.phase, "network_error", nil)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, failure(s.phase, "read_failed", nil)
	}
	if len(raw) > maxResponse {
		return nil, failure(s.phase, "response_too_large", nil)
	}
	out := &response{status: resp.StatusCode, target: u}
	_ = json.Unmarshal(raw, &out.data)
	if loc, err := resp.Location(); err == nil {
		out.location = loc.String()
	}
	return out, nil
}
func (s *session) requireSuccess(r *response) error {
	if err := s.checkGate(r.data); err != nil {
		return err
	}
	if isRedirect(r.status) {
		return s.manual()
	}
	if r.status == http.StatusForbidden {
		return s.manual()
	}
	if r.status < 200 || r.status >= 300 {
		return &Error{Stage: s.phase, Code: "upstream_error", HTTPStatus: r.status}
	}
	return nil
}
func (s *session) navigate(ctx context.Context, r *response, hops int) (*response, error) {
	for i := 0; isRedirect(r.status); i++ {
		if i >= hops || r.location == "" {
			return nil, s.manual()
		}
		u, err := url.Parse(r.location)
		if err != nil || !s.allowed(u) {
			return nil, s.manual()
		}
		r, err = s.request(ctx, u.String(), nil, "")
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}
func sameOrigin(a, b *url.URL) bool { return a.Scheme == b.Scheme && strings.EqualFold(a.Host, b.Host) }
func (s *session) allowed(u *url.URL) bool {
	if u.User != nil || u.Fragment != "" {
		return false
	}
	if sameOrigin(s.base, u) {
		return true
	}
	if s.base.String() != defaultSite || u.Scheme != "https" || u.Port() != "" {
		return false
	}
	switch u.Hostname() {
	case "auth.muse.ai":
		return true
	case "auth.meta.com":
		return u.Path == "/hatch/session/bootstrap/" || u.Path == "/aymh/redirect-cycle/" || u.Path == "/oidc" || strings.HasPrefix(u.Path, "/oidc/")
	case "www.facebook.com", "www.instagram.com":
		return u.Path == "/aymh/redirect-cycle/"
	}
	return false
}
func isRedirect(n int) bool                           { return n == 301 || n == 302 || n == 303 || n == 307 || n == 308 }
func stringValue(m map[string]any, key string) string { v, _ := m[key].(string); return v }
func (s *session) checkGate(data map[string]any) error {
	for _, key := range []string{"error", "code", "error_code", "type"} {
		value := strings.ToLower(stringValue(data, key))
		for _, marker := range []string{"captcha", "checkpoint", "consent_required", "age_verification", "challenge_required"} {
			if strings.Contains(value, marker) {
				return s.manual()
			}
		}
	}
	if stringValue(data, "checkpoint_url") != "" {
		return s.manual()
	}
	state := strings.ToLower(stringValue(data, "registration_state"))
	if state == "ntp_upsell" || strings.Contains(state, "required") || strings.Contains(state, "checkpoint") || strings.Contains(state, "blocked") {
		return s.manual()
	}
	for _, key := range []string{"requires_age_verification", "requires_consent", "requires_name", "reactivation_required"} {
		if value, _ := data[key].(bool); value {
			return s.manual()
		}
	}
	return nil
}
func (s *session) checkIdentity(data map[string]any) error {
	var check func(map[string]any, int) error
	check = func(m map[string]any, depth int) error {
		for _, key := range []string{"email", "email_address", "contact_point"} {
			if value := stringValue(m, key); value != "" {
				normalized, err := NormalizeEmail(value)
				if err != nil || normalized != s.email {
					return failure(s.phase, "identity_mismatch", nil)
				}
			}
		}
		if depth < 2 {
			for _, key := range []string{"user", "account", "profile", "identity"} {
				if child, ok := m[key].(map[string]any); ok {
					if err := check(child, depth+1); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}
	return check(data, 0)
}

// recordingJar tracks expiry separately because CookieJar.Cookies intentionally
// returns only name/value pairs. snapshot still filters via the real jar.
type recordingJar struct {
	inner   http.CookieJar
	mu      sync.Mutex
	expires map[string]int64
}

func newJar() *recordingJar {
	inner, _ := cookiejar.New(nil)
	return &recordingJar{inner: inner, expires: map[string]int64{}}
}
func (j *recordingJar) Cookies(u *url.URL) []*http.Cookie { return j.inner.Cookies(u) }
func (j *recordingJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.inner.SetCookies(u, cookies)
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range cookies {
		key := u.Hostname() + "|" + c.Name
		if c.MaxAge < 0 {
			delete(j.expires, key)
			continue
		}
		if c.MaxAge > 0 {
			j.expires[key] = time.Now().Add(time.Duration(c.MaxAge) * time.Second).Unix()
		} else if !c.Expires.IsZero() {
			j.expires[key] = c.Expires.Unix()
		}
	}
}
func (j *recordingJar) snapshot(u *url.URL) (map[string]string, map[string]int64) {
	cookies := map[string]string{}
	expires := map[string]int64{}
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, c := range j.inner.Cookies(u) {
		cookies[c.Name] = c.Value
		if expiry := j.expires[u.Hostname()+"|"+c.Name]; expiry > 0 {
			expires[c.Name] = expiry
		}
	}
	return cookies, expires
}
