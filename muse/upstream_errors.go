package muse

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kcd-dev/muse-go/hatch"
)

// classifyHTTPError distinguishes throttling from exhausted credits. A generic
// 429 must not remove an otherwise healthy account for the quota reset period.
func classifyHTTPError(path string, status int, body string, headers []hatch.Header) error {
	kind := KindTransient
	switch status {
	case http.StatusUnauthorized:
		kind = KindAuth
	case http.StatusTooManyRequests:
		kind = KindRateLimit
		lower := strings.ToLower(body)
		for _, marker := range []string{"insufficient_quota", "out of credits", "credits exhausted", "额度不足", "积分不足"} {
			if strings.Contains(lower, marker) {
				kind = KindQuota
				break
			}
		}
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
		kind = KindBadRequest
	}
	result := &Error{Kind: kind, Msg: fmt.Sprintf("%s HTTP %d", path, status)}
	for _, h := range headers {
		if !strings.EqualFold(h.Key, "Retry-After") {
			continue
		}
		if seconds, err := strconv.ParseInt(strings.TrimSpace(h.Value), 10, 64); err == nil && seconds > 0 {
			result.RetryAfter = time.Duration(min(seconds, int64(24*60*60))) * time.Second
		} else if deadline, err := http.ParseTime(h.Value); err == nil {
			result.RetryAfter = min(max(time.Until(deadline), 0), 24*time.Hour)
		}
	}
	return result
}

func responseHeaders(h http.Header) []hatch.Header {
	var headers []hatch.Header
	for key, values := range h {
		for _, value := range values {
			headers = append(headers, hatch.Header{Key: key, Value: value})
		}
	}
	return headers
}
