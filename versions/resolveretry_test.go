package versions

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-zpkg/zpkb/httpretry"
)

// flakyServer answers `failures` requests with `status`, then 200 "ok".
func flakyServer(t *testing.T, failures int32, status int) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) <= failures {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// Transient, then success: the host is down for a while and the lane survives.
func TestResolveRetriesTransientStatusThenSucceeds(t *testing.T) {
	for _, status := range []int{500, 502, 503, 429} {
		var slept []time.Duration
		old := sleepFn
		sleepFn = func(d time.Duration) { slept = append(slept, d) }
		srv, calls := flakyServer(t, 4, status)
		body, err := httpGet(srv.URL)
		sleepFn = old
		if err != nil || body != "ok" {
			t.Fatalf("status %d: body=%q err=%v", status, body, err)
		}
		if *calls != 5 || len(slept) != 4 {
			t.Errorf("status %d: calls=%d sleeps=%v, want 5 calls and 4 waits", status, *calls, slept)
		}
	}
}

// 404 and 403 are answers: one request, no wait, and never a TransientError.
func TestResolveDoesNotRetryAnAnswer(t *testing.T) {
	for _, status := range []int{404, 403, 401, 410} {
		old := sleepFn
		sleepFn = func(time.Duration) { t.Errorf("status %d: slept before a retry", status) }
		srv, calls := flakyServer(t, 100, status)
		_, err := httpGet(srv.URL)
		sleepFn = old
		if err == nil || IsTransient(err) {
			t.Errorf("status %d: err=%v, want a plain status error", status, err)
		}
		if *calls != 1 {
			t.Errorf("status %d: %d requests, want 1", status, *calls)
		}
	}
}

// Retries exhausted on a 5xx: the distinct verdict, after exactly the attempts.
func TestResolveExhaustedStatusIsTransientError(t *testing.T) {
	old := sleepFn
	sleepFn = func(time.Duration) {}
	defer func() { sleepFn = old }()
	srv, calls := flakyServer(t, 1000, 503)
	_, err := httpGet(srv.URL)
	if !IsTransient(err) {
		t.Fatalf("err=%v, want a TransientError", err)
	}
	if int(*calls) != httpretry.ResolveAttempts {
		t.Errorf("%d requests, want %d", *calls, httpretry.ResolveAttempts)
	}
}

// Exhausted on a TLS-handshake-like timeout, and the waits stay under the cap.
func TestResolveExhaustedTimeoutIsTransientErrorWithinBudget(t *testing.T) {
	defer restoreDo(httpDo)
	var total time.Duration
	old := sleepFn
	sleepFn = func(d time.Duration) { total += d }
	defer func() { sleepFn = old }()
	calls := 0
	httpDo = func(*http.Request) (*http.Response, error) {
		calls++
		return nil, &net.OpError{Op: "remote error", Err: timeoutErr{}}
	}
	_, err := httpGet("https://musl.example/releases.html")
	if !IsTransient(err) {
		t.Fatalf("err=%v, want a TransientError", err)
	}
	if calls != httpretry.ResolveAttempts {
		t.Errorf("calls=%d", calls)
	}
	if total > httpretry.ResolveBudget || total < 25*time.Second {
		t.Errorf("slept %v, want about 30s and never over %v", total, httpretry.ResolveBudget)
	}
}

func TestResolveBackoffGrowsAndIsCapped(t *testing.T) {
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 20 * time.Second, 20 * time.Second}
	for n, w := range want {
		if got := httpretry.ResolveBackoff(n); got != w {
			t.Errorf("ResolveBackoff(%d)=%v, want %v", n, got, w)
		}
	}
}

// The time budget, not the attempt count, ends the retries when it is smaller:
// with 5s, waits of 2s then 4s would pass it, so there are 2 requests.
func TestResolveBudgetEndsTheRetriesBeforeTheAttempts(t *testing.T) {
	defer restoreDo(httpDo)
	oldB, oldS := resolveBudget, sleepFn
	resolveBudget, sleepFn = 5*time.Second, func(time.Duration) {}
	defer func() { resolveBudget, sleepFn = oldB, oldS }()
	calls := 0
	httpDo = func(*http.Request) (*http.Response, error) {
		calls++
		return nil, &net.OpError{Op: "dial", Err: timeoutErr{}}
	}
	req, _ := http.NewRequest(http.MethodGet, "https://slow.example/", nil)
	_, err := httpDoRetrying(req)
	if calls != 2 || !IsTransient(err) {
		t.Errorf("calls=%d err=%v, want 2 requests and a TransientError", calls, err)
	}
}

// A spent 5xx comes back as the RESPONSE with no error: the caller names the
// status; only a transport failure becomes a TransientError here.
func TestHTTPDoRetryingReturnsASpent5xxAsAResponse(t *testing.T) {
	defer restoreDo(httpDo)
	httpDo = func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: http.NoBody}, nil
	}
	req, _ := http.NewRequest(http.MethodGet, "https://down.example/", nil)
	resp, err := httpDoRetrying(req)
	if err != nil || resp == nil || resp.StatusCode != 503 {
		t.Fatalf("resp=%v err=%v", resp, err)
	}
}
