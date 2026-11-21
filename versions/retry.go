package versions

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-zpkg/zpkb/httpretry"
)

// sleepFn paces the retry backoff; a test sets it to a no-op.
var sleepFn = time.Sleep

// TransientError is a host that never ANSWERED within the retry budget:
// timeouts, TLS handshake timeouts, resets, 429 and 5xx, repeated until the
// attempts or the time budget ran out. It says nothing about the recipe, which
// is why `zpkb lint --check-newest-pinned` reports it apart from a stale pin
// (go-zpkg/zpkb#524). A 404 or a 403 is an answer and is never this type.
type TransientError struct {
	Host     string // host that failed to answer
	Attempts int    // requests made
	Err      error  // the last failure
}

func (e *TransientError) Error() string {
	return fmt.Sprintf("%s did not answer after %d attempt(s): %v", e.Host, e.Attempts, e.Err)
}

func (e *TransientError) Unwrap() error { return e.Err }

// IsTransient reports whether err is, or wraps, a TransientError.
func IsTransient(err error) bool {
	var te *TransientError
	return errors.As(err, &te)
}

// httpDoRetrying repeats a request whose host failed to answer, up to
// httpretry.ResolveAttempts times with exponential backoff, and never sleeping
// more than httpretry.ResolveBudget in total.
//
// Resolving a version is one GET against whatever host the recipe names, and
// those hosts are not all well. Seven x.org recipes were lost in a single batch
// to `dial tcp 131.252.210.176:443: i/o timeout` — and that host is not down:
// three consecutive requests to it answered 200 in 8.2s, 200 in 2.4s, then
// timed out. Giving a flaky host exactly one chance reports our own bad luck as
// a recipe with no candidate version.
//
// A response that ARRIVED is returned as-is, whatever its status, except the
// two shapes that mean "not now": 429 and 5xx. A 404 is an answer.
//
// When the budget is spent on a transport failure the error is a
// *TransientError; callers turn a spent 5xx/429 response into one with
// transientStatus.
func httpDoRetrying(req *http.Request) (*http.Response, error) {
	var slept time.Duration
	for attempt := 0; ; attempt++ {
		resp, err := httpDo(req)
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		if !httpretry.Transient(err, status) {
			return resp, err
		}
		wait := httpretry.ResolveBackoff(attempt)
		if attempt == httpretry.ResolveAttempts-1 || slept+wait > httpretry.ResolveBudget {
			if err != nil {
				return resp, &TransientError{Host: req.URL.Host, Attempts: attempt + 1, Err: err}
			}
			return resp, nil
		}
		if resp != nil {
			// Drain nothing: the body is unread and about to be replaced.
			resp.Body.Close()
		}
		slept += wait
		sleepFn(wait)
	}
}
