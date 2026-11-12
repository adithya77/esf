package baseten

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// tokenRefreshMargin renews a token this long before it expires, so a
	// request never races the expiry.
	tokenRefreshMargin = 5 * time.Minute
	// tokenFallbackLifetime applies when a token's exp claim is unreadable.
	tokenFallbackLifetime = 30 * time.Minute
	// maxErrorBody bounds how much of an error response is read.
	maxErrorBody = 64 << 10
	// maxJSONBody bounds a decoded JSON response.
	maxJSONBody = 32 << 20
)

// tokenSource mints and caches the Blaxel-audience token a Baseten API key
// grants. The key itself is only ever sent to Baseten's token endpoint.
type tokenSource struct {
	apiURL string
	apiKey string
	http   *http.Client
	now    func() time.Time
	// timeout bounds one mint. The mutex is held across the request (so
	// concurrent callers share one mint), which makes the bound essential:
	// an unbounded mint would stall every request on the worker, cleanup
	// included.
	timeout time.Duration

	mu        sync.Mutex
	token     string
	refreshAt time.Time
}

func (t *tokenSource) Token(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token != "" && t.now().Before(t.refreshAt) {
		return t.token, nil
	}
	if t.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.timeout)
		defer cancel()
	}
	body, _ := json.Marshal(map[string]any{"scopes": []string{"sandboxes"}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(t.apiURL, "/")+"/v1/token", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+t.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := t.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: mint sandbox token: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", classify(readAPIError(resp, "mint sandbox token"))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxErrorBody)).Decode(&out); err != nil || out.Token == "" {
		return "", fmt.Errorf("%w: mint sandbox token: malformed response", ErrUnavailable)
	}
	now := t.now()
	t.token = out.Token
	t.refreshAt = refreshTime(now, tokenExpiry(out.Token, now))
	return t.token, nil
}

// Invalidate drops the cached token after the API rejects it.
func (t *tokenSource) Invalidate(token string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.token == token {
		t.token = ""
	}
}

// refreshTime renews tokenRefreshMargin before expiry, or halfway through a
// lifetime shorter than twice the margin. Without the second case, a short
// token (or a fast worker clock) would never be cached and every request
// would mint under the lock.
func refreshTime(now, expires time.Time) time.Time {
	margin := tokenRefreshMargin
	if lifetime := expires.Sub(now); lifetime < 2*margin {
		margin = lifetime / 2
	}
	return expires.Add(-margin)
}

// tokenExpiry reads the JWT exp claim. The signature is not verified: the
// value only schedules renewal, and a wrong value at worst renews early or
// triggers one retry on 401.
func tokenExpiry(token string, now time.Time) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			var claims struct {
				Exp int64 `json:"exp"`
			}
			if json.Unmarshal(payload, &claims) == nil && claims.Exp > 0 {
				return time.Unix(claims.Exp, 0)
			}
		}
	}
	return now.Add(tokenFallbackLifetime)
}

// client issues authenticated requests to the Blaxel control plane and to
// sandbox data planes. Both accept the same bearer token.
type client struct {
	controlPlane   string
	requestTimeout time.Duration
	http           *http.Client
	tokens         *tokenSource

	wsMu      sync.Mutex
	workspace string
}

// request describes one API call. Body is re-read on a retry, so it is
// supplied as bytes rather than a reader.
type request struct {
	Method      string
	URL         string
	Body        []byte
	ContentType string
	Op          string
	// NoWorkspace omits the workspace header (used to discover it).
	NoWorkspace bool
	// Timeout overrides the default per-request timeout; negative means the
	// caller's context is the only bound.
	Timeout time.Duration
}

// do sends a request and returns the response with a 2xx status, or a
// classified error. A 401 is retried once with a freshly minted token,
// because a token can be revoked or expire between the cache check and use.
func (c *client) do(ctx context.Context, r request) (*http.Response, context.CancelFunc, error) {
	for attempt := 0; ; attempt++ {
		token, err := c.tokens.Token(ctx)
		if err != nil {
			return nil, nil, err
		}
		workspace := ""
		if !r.NoWorkspace {
			if workspace, err = c.resolveWorkspace(ctx); err != nil {
				return nil, nil, err
			}
		}
		reqCtx, cancel := ctx, context.CancelFunc(func() {})
		timeout := r.Timeout
		if timeout == 0 {
			timeout = c.requestTimeout
		}
		if timeout > 0 {
			reqCtx, cancel = context.WithTimeout(ctx, timeout)
		}
		var body io.Reader
		if r.Body != nil {
			body = bytes.NewReader(r.Body)
		}
		req, err := http.NewRequestWithContext(reqCtx, r.Method, r.URL, body)
		if err != nil {
			cancel()
			return nil, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if workspace != "" {
			req.Header.Set("X-Blaxel-Workspace", workspace)
		}
		if r.ContentType != "" {
			req.Header.Set("Content-Type", r.ContentType)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			cancel()
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			return nil, nil, fmt.Errorf("%w: %s: %v", ErrUnavailable, r.Op, err)
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			drainAndClose(resp)
			cancel()
			c.tokens.Invalidate(token)
			continue
		}
		if resp.StatusCode/100 != 2 {
			err := readAPIError(resp, r.Op)
			cancel()
			return nil, nil, err
		}
		return resp, cancel, nil
	}
}

// doJSON sends a JSON request and decodes a JSON response into out (if
// non-nil). Errors are raw *apiError values so callers can test for 404
// before classifying.
func (c *client) doJSON(ctx context.Context, r request, in, out any) error {
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		r.Body = data
		r.ContentType = "application/json"
	}
	resp, cancel, err := c.do(ctx, r)
	if err != nil {
		return err
	}
	defer cancel()
	defer drainAndClose(resp)
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJSONBody)).Decode(out); err != nil {
		return fmt.Errorf("%w: %s: decode response: %v", ErrUnavailable, r.Op, err)
	}
	return nil
}

// resolveWorkspace returns the configured workspace or discovers the single
// workspace the token can access. Ambiguity is a configuration error, never
// a guess.
func (c *client) resolveWorkspace(ctx context.Context) (string, error) {
	c.wsMu.Lock()
	defer c.wsMu.Unlock()
	if c.workspace != "" {
		return c.workspace, nil
	}
	var workspaces []struct {
		Name string `json:"name"`
	}
	if err := c.doJSON(ctx, request{Method: http.MethodGet, URL: c.controlPlane + "/workspaces", Op: "list workspaces", NoWorkspace: true}, nil, &workspaces); err != nil {
		return "", classify(err)
	}
	switch len(workspaces) {
	case 1:
		c.workspace = workspaces[0].Name
		return c.workspace, nil
	case 0:
		return "", fmt.Errorf("%w: the Baseten key can access no sandbox workspace", ErrNotConfigured)
	default:
		names := make([]string, 0, len(workspaces))
		for _, ws := range workspaces {
			names = append(names, ws.Name)
		}
		return "", fmt.Errorf("%w: several workspaces are visible (%s); set baseten.workspace", ErrNotConfigured, strings.Join(names, ", "))
	}
}

func readAPIError(resp *http.Response, op string) error {
	defer drainAndClose(resp)
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	var body struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
	}
	msg := ""
	if json.Unmarshal(raw, &body) == nil {
		var s string
		switch {
		case body.Message != "":
			msg = body.Message
		case json.Unmarshal(body.Error, &s) == nil:
			msg = s
		}
	} else if !bytes.ContainsAny(raw, "{[") {
		// A plain-text error (proxies, load balancers) carries no request echo.
		msg = string(raw)
	}
	return &apiError{Status: resp.StatusCode, Op: op, Message: boundMessage(msg)}
}

func drainAndClose(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
	_ = resp.Body.Close()
}
