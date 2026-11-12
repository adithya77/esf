package baseten

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Provider-level sentinel errors, mirroring the Cube adapter's vocabulary so
// the factory never pattern-matches on vendor error strings.
var (
	// ErrUnavailable means Baseten or Blaxel could not be reached, or
	// answered with a transient failure.
	ErrUnavailable = errors.New("baseten: control plane unavailable")
	// ErrSandboxNotFound means the sandbox no longer exists.
	ErrSandboxNotFound = errors.New("baseten: sandbox not found")
	// ErrAuthentication means the API key or minted token was rejected.
	ErrAuthentication = errors.New("baseten: authentication failed")
	// ErrInvalidSpec means the factory asked for something the API refused.
	ErrInvalidSpec = errors.New("baseten: invalid sandbox specification")
	// ErrNotConfigured means required configuration is missing.
	ErrNotConfigured = errors.New("baseten: not configured")
	// ErrUnsupportedPolicy means a requested egress policy cannot be enforced
	// exactly. The provider refuses rather than apply a weaker policy.
	ErrUnsupportedPolicy = errors.New("baseten: egress policy cannot be enforced")
	// ErrEgressEnforcement means the sandbox did not come up with the proxy
	// firewall, so later lockdown would be advisory only.
	ErrEgressEnforcement = errors.New("baseten: egress enforcement unavailable")
)

// apiError is a non-2xx response. Message is the server's own error field,
// bounded; the raw body is never kept, because some responses echo the
// request (including proxy secrets) back.
type apiError struct {
	Status  int
	Op      string
	Message string
}

func (e *apiError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("%s: HTTP %d", e.Op, e.Status)
	}
	return fmt.Sprintf("%s: HTTP %d: %s", e.Op, e.Status, e.Message)
}

// classify maps an HTTP status onto a provider sentinel, keeping the original
// error in the chain for diagnosis.
func classify(err error) error {
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		return err
	}
	switch {
	case apiErr.Status == http.StatusNotFound:
		return fmt.Errorf("%w: %v", ErrSandboxNotFound, err)
	case apiErr.Status == http.StatusUnauthorized || apiErr.Status == http.StatusForbidden:
		return fmt.Errorf("%w: %v", ErrAuthentication, err)
	case apiErr.Status == http.StatusTooManyRequests || apiErr.Status >= 500:
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	case apiErr.Status >= 400:
		return fmt.Errorf("%w: %v", ErrInvalidSpec, err)
	}
	return err
}

func isNotFound(err error) bool {
	var apiErr *apiError
	return errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound
}

// boundMessage keeps server error text short and single-line.
func boundMessage(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	const limit = 300
	if len(s) > limit {
		s = s[:limit] + "..."
	}
	return s
}
