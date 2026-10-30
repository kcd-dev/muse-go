package muse

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kcd-dev/muse-go/internal/fakemuse"
)

func TestMediaTextOnlyCompletionRequiresTerminalAndQuiet(t *testing.T) {
	for _, tc := range []struct {
		name, text                               string
		done, assistantActive, toolActive, ended bool
		quiet                                    time.Duration
		want                                     bool
	}{
		{"active assistant beyond old 15 seconds", "Loading video tool", false, true, false, false, time.Minute, false},
		{"active assistant despite message done", "Loading video tool", true, true, false, false, time.Minute, false},
		{"active rendering beyond old 45 seconds", "Generating video", false, true, false, false, time.Hour, false},
		{"unknown state must not become refusal", "Loading video tool", false, false, false, false, time.Hour, false},
		{"tool running after completed message", "I cannot generate that video yet", true, false, true, false, time.Hour, false},
		{"recent stream or tool activity", "I cannot generate that video", true, false, false, false, 0, false},
		{"completed tools and explicit refusal", "I cannot generate that video", true, false, false, false, time.Minute, true},
		{"completed question", "Which scene should I use?", true, false, false, false, time.Minute, true},
		{"working message completion is not turn completion", "Generating video", true, false, false, false, time.Hour, false},
		{"explicit turn completion", "Generating video", true, false, false, true, time.Minute, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mediaTextOnlySettled(tc.text, tc.done, tc.assistantActive, tc.toolActive, tc.ended, tc.quiet); got != tc.want {
				t.Fatalf("settled=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestMediaLifecycleDoesNotTreatUnknownStatusAsDone(t *testing.T) {
	for _, status := range []string{"pending", "queued", "running", "in_progress", "streaming"} {
		active, done := mediaLifecycle(map[string]any{"status": status})
		if !active || done {
			t.Fatalf("%s: active=%v done=%v", status, active, done)
		}
	}
	for _, payload := range []map[string]any{nil, {"status": "new-unrecognized-state"}, {"metadata": map[string]any{"streaming": false}}} {
		active, done := mediaLifecycle(payload)
		if active || done {
			t.Fatalf("unknown lifecycle: active=%v done=%v", active, done)
		}
	}
	active, done := mediaLifecycle(map[string]any{"status": "completed", "metadata": map[string]any{"streaming": true}})
	if !active || done {
		t.Fatal("streaming must take precedence over a stale completed status")
	}
}

func completionToolEvent(id, state string) map[string]any {
	return map[string]any{"event_name": "tool.progress", "payload": map[string]any{"tool_call_id": id, "state": state}}
}

func TestMediaHistoryLifecycleTracksSeparateTools(t *testing.T) {
	events := []map[string]any{completionToolEvent("one", "running"), completionToolEvent("two", "pending"), completionToolEvent("one", "completed")}
	if !mediaHistoryInProgress(events) {
		t.Fatal("completion of one tool must not finish another")
	}
	events = append(events, completionToolEvent("two", "failed"))
	if mediaHistoryInProgress(events) {
		t.Fatal("completed tool lifecycle must not block a final refusal")
	}
	events = append(events, completionToolEvent("three", "running"), map[string]any{"event_name": "turn.completed"})
	if mediaHistoryInProgress(events) {
		t.Fatal("whole-turn completion must clear earlier activity")
	}
	events = append(events, completionToolEvent("four", "running"))
	if !mediaHistoryInProgress(events) {
		t.Fatal("new activity after a completion must reopen the wait")
	}
}

func TestMediaHistoryFinalAnswerClosesOnlyEarlierToolActivity(t *testing.T) {
	for _, tc := range []struct {
		name, text, status string
		subagent, later    bool
		wantActive         bool
	}{
		{"final refusal", "I cannot generate that video", "completed", false, false, false},
		{"final clarification", "Which scene should I use?", "completed", false, false, false},
		{"new tool after final answer", "I cannot generate that video", "completed", false, true, true},
		{"completed progress message", "Generating video", "completed", false, false, true},
		{"incomplete refusal", "I cannot generate that video", "in_progress", false, false, true},
		{"unknown lifecycle", "I cannot generate that video", "new-state", false, false, true},
		{"subagent refusal", "I cannot generate that video", "completed", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			answer := map[string]any{"event_name": "message.assistant", "payload": map[string]any{"text": tc.text, "status": tc.status}}
			if tc.subagent {
				answer["reply_to_message_id"] = "tool-message"
			}
			events := []map[string]any{completionToolEvent("old", "pending"), answer}
			if tc.later {
				events = append(events, completionToolEvent("new", "pending"))
			}
			if got := mediaHistoryInProgress(events); got != tc.wantActive {
				t.Fatalf("active=%v want=%v", got, tc.wantActive)
			}
		})
	}
	if !mediaHistoryInProgress([]map[string]any{completionToolEvent("old", "pending"), {"event_name": "delta.message_done"}}) {
		t.Fatal("message boundary must not clear active tools")
	}
}

func TestEventsFingerprintTracksSameLengthTextAndToolProgress(t *testing.T) {
	events := []map[string]any{{"event_name": "message.assistant", "payload": map[string]any{"text": "first"}}, {"event_name": "tool.progress", "payload": map[string]any{"percent": 10}}}
	first := eventsFingerprint(events)
	events[0]["payload"].(map[string]any)["text"] = "later"
	second := eventsFingerprint(events)
	if first == second {
		t.Fatal("same-length text update was treated as inactivity")
	}
	events[1]["payload"].(map[string]any)["percent"] = 20
	if second == eventsFingerprint(events) {
		t.Fatal("tool progress update was treated as inactivity")
	}
}

func TestFollowMediaWaitsForToolThenCollectsLateVideo(t *testing.T) {
	for _, final := range []string{"video", "refusal", "timeout", "unknown_message.done", "unknown_delta.message_done", "empty_assistant_video", "empty_assistant_timeout", "empty_assistant_terminal"} {
		t.Run(final, func(t *testing.T) {
			unknownAssistant := strings.HasPrefix(final, "unknown_")
			emptyAssistant := strings.HasPrefix(final, "empty_assistant_")
			wantVideo := final == "video" || final == "empty_assistant_video"
			wantTimeout := final == "timeout" || unknownAssistant || final == "empty_assistant_timeout" || final == "empty_assistant_terminal"
			site, gateway := fakemuse.NewWithGateway()
			defer site.Close()
			var polls atomic.Int32
			gateway.HistoryResponse = func(sessionID string) ([]byte, bool) {
				if sessionID != "media-completion" {
					return nil, false
				}
				n := polls.Add(1)
				events := []map[string]any{
					{"event_name": "message.user", "message_id": "anchor", "text": "create video"},
					{"event_name": "message.assistant", "payload": map[string]any{"text": "I cannot generate the video yet", "status": "completed"}},
					completionToolEvent("render", "running"),
				}
				if unknownAssistant {
					// Even refusal-looking text is not final without its own
					// lifecycle status. The unrelated message boundary used to
					// promote this unknown state to done and return immediately.
					delete(events[1]["payload"].(map[string]any), "status")
					events[2] = map[string]any{"event_name": strings.TrimPrefix(final, "unknown_")}
				}
				if emptyAssistant {
					// No tool event masks the empty assistant lifecycle. The
					// preceding completed text must neither end this new reply
					// nor survive in a later media result.
					payload := map[string]any{"text": "", "metadata": map[string]any{"streaming": true}}
					if final == "empty_assistant_terminal" {
						payload = map[string]any{"text": "", "status": "completed"}
					}
					events[2] = map[string]any{"event_name": "message.assistant", "payload": payload}
					if final == "empty_assistant_terminal" {
						events = append(events, map[string]any{"event_name": "turn.completed"})
					}
				}
				if n >= 6 && !wantTimeout {
					events = append(events, completionToolEvent("render", "completed"))
					if wantVideo {
						events = append(events, map[string]any{"event_name": "delta.presentation", "payload": map[string]any{"kind": "video", "videos": []any{map[string]any{"path": "sandbox://workspace/out/late.mp4", "mime": "video/mp4"}}}})
					}
				}
				body, _ := json.Marshal(map[string]any{"chat_events": events})
				return body, true
			}
			e, account := newTestProto(t, site.URL, "ws"+strings.TrimPrefix(site.URL, "http")+"/v1/noise")
			setupCtx, setupCancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer setupCancel()
			lease, err := e.acquire(setupCtx, account)
			if err != nil {
				t.Fatal(err)
			}
			defer e.release(account.ID, lease)
			oldSettle, oldMediaSettle, oldPoll := textSettle, mediaSettle, pollInterval
			textSettle, mediaSettle, pollInterval = 10*time.Millisecond, 10*time.Millisecond, 5*time.Millisecond
			defer func() { textSettle, mediaSettle, pollInterval = oldSettle, oldMediaSettle, oldPoll }()
			budget := time.Second
			if wantTimeout {
				budget = 150 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			got, err := e.followThread(ctx, lease.conn, "media-completion", "anchor", "create video", "video", nil, nil, nil)
			if wantTimeout {
				if got != nil || err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
					t.Fatalf("active media must wait for deadline: result=%+v err=%v context=%v", got, err, ctx.Err())
				}
			} else if err != nil || got == nil {
				t.Fatalf("finished media: result=%+v err=%v", got, err)
			} else if wantVideo && (len(got.media) != 1 || got.media[0].Path != "workspace/out/late.mp4") {
				t.Fatalf("late video was lost: %+v", got)
			} else if emptyAssistant && got.text != "" {
				t.Fatalf("old answer survived the new empty assistant: %q", got.text)
			} else if final == "refusal" && len(got.media) != 0 {
				t.Fatalf("unexpected media: %+v", got)
			}
			if polls.Load() < 6 {
				t.Fatalf("returned before tool completed: polls=%d", polls.Load())
			}
		})
	}
}
