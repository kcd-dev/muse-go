package muse

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kcd-dev/muse-go/hatch"
	"github.com/kcd-dev/muse-go/internal/fakemuse"
)

func TestHTTPThrottlingClassification(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   Kind
	}{
		{429, "rate limit reached", KindRateLimit},
		{429, `{"code":"insufficient_quota"}`, KindQuota},
		{401, "session expired", KindAuth},
		{403, "region blocked", KindTransient},
		{400, "invalid input", KindBadRequest},
	} {
		err := classifyHTTPError("/test", tc.status, tc.body, []hatch.Header{{Key: "Retry-After", Value: "12"}})
		if KindOf(err) != tc.want || RetryAfterOf(err) != 12*time.Second {
			t.Fatalf("status %d: kind=%v retry=%v", tc.status, KindOf(err), RetryAfterOf(err))
		}
	}
	wrapped := &NoRetry{Err: wrap(KindTransient, "unknown delivery", context.Canceled)}
	if Retryable(wrapped) || !errors.Is(wrapped, context.Canceled) {
		t.Fatal("NoRetry lost retry or cancellation semantics")
	}
}

func newTestProto(t *testing.T, siteURL, gatewayURL string) (*ProtoEngine, *Account) {
	t.Helper()
	e := NewProtoEngine(&Config{SiteURL: siteURL, GatewayURL: gatewayURL, ChatTimeout: 5 * time.Second, ApprovalPolicy: "off"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(e.Close)
	return e, &Account{ID: "test", Label: "test", Cookies: map[string]string{"hatch_sess": "s1"}}
}

func TestDropDuringBootstrapDoesNotPublishConnection(t *testing.T) {
	fake, _ := fakemuse.NewWithGateway()
	defer fake.Close()
	started, proceed := make(chan struct{}), make(chan struct{})
	var once sync.Once
	site := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/session" {
			once.Do(func() { close(started) })
			<-proceed
		}
		fake.Config.Handler.ServeHTTP(w, r)
	}))
	defer site.Close()
	e, acc := newTestProto(t, site.URL, "ws"+strings.TrimPrefix(fake.URL, "http")+"/v1/noise")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		lease, err := e.acquire(ctx, acc)
		if lease != nil {
			e.release(acc.ID, lease)
		}
		result <- err
	}()
	<-started
	e.Drop(acc.ID)
	close(proceed)
	if err := <-result; !errors.Is(err, hatch.ErrClosed) {
		t.Fatalf("acquire after Drop: %v", err)
	}
	if e.IsWarm(acc.ID) || e.WarmCount() != 0 {
		t.Fatal("retired connection was published")
	}
}

func TestConcurrentConnectionLifecycle(t *testing.T) {
	site, _ := fakemuse.NewWithGateway()
	defer site.Close()
	e, acc := newTestProto(t, site.URL, "ws"+strings.TrimPrefix(site.URL, "http")+"/v1/noise")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				lease, err := e.acquire(ctx, acc)
				if err == nil {
					_ = e.IsWarm(acc.ID)
					_ = e.WarmCount()
					e.release(acc.ID, lease)
				}
				if j%2 == 0 {
					e.Drop(acc.ID)
				}
			}
		}()
	}
	wg.Wait()
	e.Close()
	if e.WarmCount() != 0 {
		t.Fatal("connections survived close")
	}
	if _, err := e.acquire(ctx, acc); !errors.Is(err, hatch.ErrClosed) {
		t.Fatalf("closed engine accepted acquire: %v", err)
	}
}

func TestCancelPartialChatReturnsError(t *testing.T) {
	site, _ := fakemuse.NewWithGateway()
	defer site.Close()
	e, acc := newTestProto(t, site.URL, "ws"+strings.TrimPrefix(site.URL, "http")+"/v1/noise")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result, err := e.Chat(ctx, acc, "hello", nil, func(string) { cancel() })
	if result != nil || !errors.Is(err, context.Canceled) || Retryable(err) {
		t.Fatalf("partial canceled chat: result=%+v err=%v", result, err)
	}
}
