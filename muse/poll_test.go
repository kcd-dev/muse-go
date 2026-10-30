package muse

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kcd-dev/muse-go/internal/fakemuse"
)

func TestPollDelayFollowsStream(t *testing.T) {
	if d := pollDelay(0, nil); d != pollInterval {
		t.Fatalf("no stream: %v", d)
	}
	s := newStreamSignal()
	if d := pollDelay(0, s); d != pollInterval {
		t.Fatalf("silent stream must not slow polling: %v", d)
	}
	s.record()
	if d := pollDelay(time.Minute, s); d != pollInterval {
		t.Fatalf("fresh stream activity: %v", d)
	}
	s.last.Store(time.Now().Add(-5 * time.Second).UnixNano())
	if d := pollDelay(0, s); d != streamQuietPoll {
		t.Fatalf("quiet stream: %v", d)
	}
	s.end()
	if d := pollDelay(0, s); d != pollInterval {
		t.Fatalf("ended stream: %v", d)
	}
}

func TestWaitPollWakesEarlyButKeepsGap(t *testing.T) {
	s := newStreamSignal()
	s.record()
	start := time.Now()
	waitPoll(t.Context(), time.Minute, start, s)
	if d := time.Since(start); d < pollInterval || d > 5*time.Second {
		t.Fatalf("waited %v", d)
	}
}

// The endpoint has a finite history window. Once the initiating message is
// evicted, identical responses must not reuse derived state from an older body.
func TestHistoryCacheDoesNotReturnStaleAnswerAfterAnchorDisappears(t *testing.T) {
	site, gateway := fakemuse.NewWithGateway()
	defer site.Close()
	var requests atomic.Int32
	gateway.HistoryResponse = func(sessionID string) ([]byte, bool) {
		if sessionID != "history-window" {
			return nil, false
		}
		if requests.Add(1) == 1 {
			return []byte(`{"chat_events":[{"event_name":"message.user","message_id":"anchor","text":"review prompt"},{"event_name":"message.assistant","payload":{"text":"stale partial answer"}}]}`), true
		}
		return []byte(`{"chat_events":[{"event_name":"message.assistant","payload":{"text":"new answer","status":"completed"}}]}`), true
	}
	e, acc := newTestProto(t, site.URL, "ws"+strings.TrimPrefix(site.URL, "http")+"/v1/noise")
	setupCtx, setupCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer setupCancel()
	lease, err := e.acquire(setupCtx, acc)
	if err != nil {
		t.Fatal(err)
	}
	defer e.release(acc.ID, lease)
	oldSettle, oldPoll := textSettle, pollInterval
	textSettle, pollInterval = 20*time.Millisecond, 5*time.Millisecond
	defer func() { textSettle, pollInterval = oldSettle, oldPoll }()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	got, err := e.followThread(ctx, lease.conn, "history-window", "anchor", "review prompt", "", nil, nil, nil)
	if got != nil || err == nil {
		t.Fatalf("stale history returned success: result=%+v err=%v", got, err)
	}
	// The socket deadline and context timer can race; both are legitimate
	// timeout exits, but an earlier network failure must not make this pass.
	var timeout net.Error
	deadline, _ := ctx.Deadline()
	if !errors.Is(err, context.DeadlineExceeded) && !(errors.As(err, &timeout) && timeout.Timeout() && !time.Now().Before(deadline)) {
		t.Fatalf("history exited before the test timeout: %v", err)
	}
	if requests.Load() < 3 {
		t.Fatal("test did not receive repeated unchanged history")
	}
}
