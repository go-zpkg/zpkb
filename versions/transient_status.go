package versions

import (
	"net/url"

	"github.com/go-zpkg/zpkb/httpretry"
)

// transientStatus wraps a spent 429/5xx answer as a TransientError and returns
// any other status error (404, 403…) unchanged: those are answers.
func transientStatus(rawURL string, status int, plain error) error {
	if !httpretry.Transient(nil, status) {
		return plain
	}
	host := rawURL
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		host = u.Host
	}
	return &TransientError{Host: host, Attempts: httpretry.ResolveAttempts, Err: plain}
}
