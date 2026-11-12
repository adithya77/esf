package baseten

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mitkox/esf/internal/sandbox"
)

// ProviderName is the identifier recorded in evidence.
const ProviderName = "baseten"

const (
	// createReadyTimeout bounds how long Create waits for DEPLOYED.
	createReadyTimeout = 5 * time.Minute
	// destroyTimeout bounds how long Destroy waits for TERMINATED.
	destroyTimeout = 2 * time.Minute

	statusDeployed   = "DEPLOYED"
	statusDeleting   = "DELETING"
	statusTerminated = "TERMINATED"
)

// statusStarting lists the deployment states that become DEPLOYED by waiting.
var statusStarting = map[string]bool{"": true, "UPLOADING": true, "BUILDING": true, "BUILT": true, "DEPLOYING": true}

// Provider is a sandbox.Provider backed by Baseten Sandboxes.
type Provider struct {
	cfg  Config
	api  *client
	log  *slog.Logger
	poll time.Duration
}

// Option customizes a Provider.
type Option func(*Provider)

// WithLogger sets the structured logger.
func WithLogger(log *slog.Logger) Option {
	return func(p *Provider) {
		if log != nil {
			p.log = log
		}
	}
}

// WithHTTPClient replaces the HTTP client (tests use an httptest TLS client).
func WithHTTPClient(c *http.Client) Option {
	return func(p *Provider) {
		if c != nil {
			p.api.http = c
			p.api.tokens.http = c
		}
	}
}

// withPollInterval shortens status polling in tests.
func withPollInterval(d time.Duration) Option {
	return func(p *Provider) { p.poll = d }
}

// New validates the configuration, loads the API key, and returns a
// provider. It does not contact the network; call Ping for that.
func New(cfg Config, opts ...Option) (*Provider, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	key, err := cfg.LoadAPIKey()
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{}
	p := &Provider{
		cfg:  cfg,
		log:  slog.New(slog.DiscardHandler),
		poll: time.Second,
		api: &client{
			controlPlane:   strings.TrimRight(cfg.ControlPlaneURL, "/"),
			requestTimeout: cfg.RequestTimeout.Std(),
			http:           httpClient,
			workspace:      strings.TrimSpace(cfg.Workspace),
			tokens:         &tokenSource{apiURL: cfg.APIURL, apiKey: key, http: httpClient, now: time.Now, timeout: cfg.RequestTimeout.Std()},
		},
	}
	for _, opt := range opts {
		opt(p)
	}
	return p, nil
}

func (p *Provider) Name() string { return ProviderName }

// Capabilities: the platform has snapshots and standby, but none are wired
// into the factory, so none are advertised.
func (p *Provider) Capabilities() sandbox.Capabilities { return sandbox.Capabilities{} }

// Config returns a copy of the provider configuration (the key is not part
// of it).
func (p *Provider) Config() Config { return p.cfg }

// Close releases idle HTTP connections. It does not destroy any sandbox.
func (p *Provider) Close() error {
	p.api.http.CloseIdleConnections()
	return nil
}

// Ping verifies the key mints a token, the workspace is reachable, and the
// configured region offers the egress proxy every sandbox depends on.
func (p *Provider) Ping(ctx context.Context) error {
	var conf struct {
		Regions []struct {
			Name           string `json:"name"`
			ProxyAvailable bool   `json:"proxyAvailable"`
		} `json:"regions"`
	}
	if err := p.api.doJSON(ctx, request{Method: http.MethodGet, URL: p.api.controlPlane + "/configuration", Op: "read configuration"}, nil, &conf); err != nil {
		return classify(err)
	}
	found := false
	for _, region := range conf.Regions {
		if region.Name == p.cfg.Region {
			if !region.ProxyAvailable {
				return fmt.Errorf("%w: region %s does not offer the egress proxy", ErrEgressEnforcement, p.cfg.Region)
			}
			found = true
		}
	}
	if !found {
		return fmt.Errorf("%w: region %s is not available to this workspace", ErrNotConfigured, p.cfg.Region)
	}
	if _, err := p.listPage(ctx, ""); err != nil {
		return err
	}
	return nil
}

// sandboxResource is the subset of Blaxel's sandbox resource the factory
// reads. Updates round-trip the raw spec instead, so unknown fields survive.
type sandboxResource struct {
	Metadata struct {
		Name      string            `json:"name"`
		URL       string            `json:"url"`
		Labels    map[string]string `json:"labels"`
		CreatedAt string            `json:"createdAt"`
	} `json:"metadata"`
	Spec struct {
		Runtime struct {
			Image string `json:"image"`
		} `json:"runtime"`
		Network networkSpec `json:"network"`
	} `json:"spec"`
	Status string `json:"status"`
}

func (r sandboxResource) info() sandbox.Info {
	started, _ := time.Parse(time.RFC3339Nano, r.Metadata.CreatedAt)
	state := strings.ToLower(r.Status)
	if r.Status == statusDeployed {
		state = sandbox.StateRunning
	}
	return sandbox.Info{
		ID:         r.Metadata.Name,
		Template:   r.Spec.Runtime.Image,
		State:      state,
		StartedAt:  started,
		Metadata:   r.Metadata.Labels,
		ProviderID: ProviderName,
	}
}

// Create starts a sandbox with the proxy firewall and the requested policy,
// waits until it is deployed, and verifies the firewall is in effect.
func (p *Provider) Create(ctx context.Context, spec sandbox.Spec) (sandbox.Sandbox, error) {
	template := spec.Template
	if template == "" {
		template = p.cfg.Template
	}
	if template == "" {
		return nil, fmt.Errorf("%w: no template configured", ErrNotConfigured)
	}
	network, err := translateNetwork(spec.Network)
	if err != nil {
		return nil, err
	}
	idle := spec.IdleTimeout
	if idle <= 0 {
		idle = p.cfg.IdleTimeout.Std()
	}
	if idle < minIdleTimeout {
		idle = minIdleTimeout
	}
	memory := p.cfg.MemoryMiB
	if spec.Limits.MemoryMiB > 0 {
		if spec.Limits.MemoryMiB < minMemoryMiB {
			return nil, fmt.Errorf("%w: memory limit %d MiB is below the %d MiB minimum", ErrInvalidSpec, spec.Limits.MemoryMiB, minMemoryMiB)
		}
		memory = spec.Limits.MemoryMiB
	}
	name, err := randomName()
	if err != nil {
		return nil, err
	}

	runtime := map[string]any{"image": template, "memory": memory}
	if len(spec.Env) > 0 {
		envs := make([]map[string]string, 0, len(spec.Env))
		for k, v := range spec.Env {
			envs = append(envs, map[string]string{"name": k, "value": v})
		}
		runtime["envs"] = envs
	}
	body := map[string]any{
		"metadata": map[string]any{"name": name, "labels": spec.Metadata},
		"spec": map[string]any{
			"region":    p.cfg.Region,
			"runtime":   runtime,
			"lifecycle": idleLifecycle(idle),
			"network":   network,
		},
	}

	started := time.Now()
	// The create response is discarded: it echoes proxy secrets back.
	if err := p.api.doJSON(ctx, request{Method: http.MethodPost, URL: p.api.controlPlane + "/sandboxes", Op: "create sandbox"}, body, nil); err != nil {
		return nil, fmt.Errorf("create sandbox from template %s: %w", template, classify(err))
	}
	res, err := p.ready(ctx, name, true)
	if err != nil {
		p.cleanupFailedCreate(name)
		return nil, err
	}
	sb, err := p.handle(res)
	if err != nil {
		p.cleanupFailedCreate(name)
		return nil, err
	}
	p.log.InfoContext(ctx, "baseten sandbox created",
		slog.String("sandbox.id", name),
		slog.String("sandbox.template", template),
		slog.Duration("duration", time.Since(started)))
	return sb, nil
}

// ready waits until the sandbox is DEPLOYED and verifies the proxy firewall
// is in effect. Every handle the provider gives out passes through here, so a
// sandbox recovered after an ambiguous create (found by List, then
// reattached) gets the same checks as a fresh one.
//
// Transient control-plane errors are retried; right after a create, a 404 is
// too, because the control plane may not yet serve what it just accepted.
func (p *Provider) ready(ctx context.Context, name string, justCreated bool) (sandboxResource, error) {
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, createReadyTimeout)
	defer cancel()
	failures := 0
	last := "unknown"
	for {
		res, err := p.get(ctx, name)
		transient := errors.Is(err, ErrUnavailable) || (justCreated && errors.Is(err, ErrSandboxNotFound))
		switch {
		case parent.Err() != nil:
			return sandboxResource{}, fmt.Errorf("wait for sandbox %s: %w", name, parent.Err())
		case err != nil && (!transient || failures >= maxPollFailures):
			return sandboxResource{}, fmt.Errorf("wait for sandbox %s: %w", name, err)
		case err != nil:
			failures++
		case res.Status == statusDeployed:
			if !res.Spec.Network.enforced() {
				return sandboxResource{}, fmt.Errorf("%w: sandbox %s is running without the proxy firewall", ErrEgressEnforcement, name)
			}
			return res, nil
		case res.Status == statusDeleting || res.Status == statusTerminated:
			return sandboxResource{}, fmt.Errorf("sandbox %s: %w (status %s)", name, ErrSandboxNotFound, res.Status)
		case !statusStarting[res.Status]:
			// FAILED, DEACTIVATED, ARCHIVED and anything new will not become
			// usable by waiting. Standby is a separate field (state), not a
			// status, and does not reach this branch.
			return sandboxResource{}, fmt.Errorf("%w: sandbox %s is %s", ErrUnavailable, name, res.Status)
		default:
			failures = 0
			last = res.Status
		}
		if err := sleep(ctx, p.poll); err != nil {
			if parent.Err() != nil {
				return sandboxResource{}, fmt.Errorf("wait for sandbox %s: %w", name, parent.Err())
			}
			return sandboxResource{}, fmt.Errorf("%w: sandbox %s not deployed within %s (last status %s)", ErrUnavailable, name, createReadyTimeout, last)
		}
	}
}

// cleanupFailedCreate removes a sandbox the factory will not hand out. It
// uses a fresh context because the create context may already be expired.
func (p *Provider) cleanupFailedCreate(name string) {
	ctx, cancel := context.WithTimeout(context.Background(), destroyTimeout)
	defer cancel()
	if err := p.Destroy(ctx, name); err != nil {
		p.log.Warn("baseten sandbox cleanup after failed create", slog.String("sandbox.id", name), slog.Any("error", err))
	}
}

// Reattach returns a handle to a live sandbox by ID.
func (p *Provider) Reattach(ctx context.Context, sandboxID string) (sandbox.Sandbox, error) {
	if strings.TrimSpace(sandboxID) == "" {
		return nil, fmt.Errorf("%w: empty sandbox id", ErrInvalidSpec)
	}
	res, err := p.ready(ctx, sandboxID, false)
	if err != nil {
		return nil, fmt.Errorf("reattach to sandbox %s: %w", sandboxID, err)
	}
	return p.handle(res)
}

func (p *Provider) handle(res sandboxResource) (*basetenSandbox, error) {
	u, err := url.Parse(res.Metadata.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		// The token is sent to this URL; never send it over plaintext.
		return nil, fmt.Errorf("%w: sandbox %s has no HTTPS data-plane URL", ErrUnavailable, res.Metadata.Name)
	}
	return &basetenSandbox{
		provider:    p,
		id:          res.Metadata.Name,
		template:    res.Spec.Runtime.Image,
		dataPlane:   strings.TrimRight(res.Metadata.URL, "/"),
		outputLimit: p.cfg.CommandOutputBytes,
	}, nil
}

// Destroy deletes a sandbox and waits until the platform reports it gone,
// so a following List never reports it as a leak. It is idempotent.
func (p *Provider) Destroy(ctx context.Context, sandboxID string) error {
	if sandboxID == "" {
		return nil
	}
	err := p.api.doJSON(ctx, request{Method: http.MethodDelete, URL: p.sandboxURL(sandboxID), Op: "delete sandbox"}, nil, nil)
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("destroy sandbox %s: %w", sandboxID, classify(err))
	}
	ctx, cancel := context.WithTimeout(ctx, destroyTimeout)
	defer cancel()
	failures := 0
	for {
		res, err := p.get(ctx, sandboxID)
		if errors.Is(err, ErrSandboxNotFound) {
			return nil
		}
		if err != nil && (!errors.Is(err, ErrUnavailable) || failures >= maxPollFailures) {
			return fmt.Errorf("verify sandbox %s destroyed: %w", sandboxID, err)
		}
		if err != nil {
			failures++
		} else if res.Status == statusTerminated {
			p.log.InfoContext(ctx, "baseten sandbox destroyed", slog.String("sandbox.id", sandboxID))
			return nil
		}
		if err := sleep(ctx, p.poll); err != nil {
			return fmt.Errorf("%w: sandbox %s not confirmed terminated after %s", ErrUnavailable, sandboxID, destroyTimeout)
		}
	}
}

// List returns sandboxes that are not yet terminated. A DELETING sandbox is
// still reported: it is not gone until the platform says so.
func (p *Provider) List(ctx context.Context) ([]sandbox.Info, error) {
	var out []sandbox.Info
	cursor := ""
	for {
		page, err := p.listPage(ctx, cursor)
		if err != nil {
			return nil, err
		}
		for _, res := range page.items {
			if res.Status == statusTerminated {
				continue
			}
			out = append(out, res.info())
		}
		if page.next == "" {
			return out, nil
		}
		cursor = page.next
	}
}

type listPage struct {
	items []sandboxResource
	next  string
}

// listPage reads one page. The API returns either the whole list as a bare
// array or a page as {data, meta.nextCursor}; both are accepted.
func (p *Provider) listPage(ctx context.Context, cursor string) (listPage, error) {
	// No limit is sent: an API version that answers with a bare array would
	// truncate it silently, and a paging version pages without being asked.
	target := p.api.controlPlane + "/sandboxes"
	if cursor != "" {
		target += "?" + url.Values{"cursor": {cursor}}.Encode()
	}
	var raw json.RawMessage
	if err := p.api.doJSON(ctx, request{Method: http.MethodGet, URL: target, Op: "list sandboxes"}, nil, &raw); err != nil {
		return listPage{}, fmt.Errorf("list sandboxes: %w", classify(err))
	}
	var page listPage
	if trimmed := strings.TrimSpace(string(raw)); strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(raw, &page.items); err != nil {
			return listPage{}, fmt.Errorf("%w: decode sandbox list: %v", ErrUnavailable, err)
		}
		return page, nil
	}
	var wrapped struct {
		Data []sandboxResource `json:"data"`
		Meta struct {
			NextCursor string `json:"nextCursor"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(raw, &wrapped); err != nil {
		return listPage{}, fmt.Errorf("%w: decode sandbox list: %v", ErrUnavailable, err)
	}
	if wrapped.Meta.NextCursor == cursor && cursor != "" {
		return listPage{}, fmt.Errorf("%w: sandbox list cursor did not advance", ErrUnavailable)
	}
	return listPage{items: wrapped.Data, next: wrapped.Meta.NextCursor}, nil
}

func (p *Provider) get(ctx context.Context, name string) (sandboxResource, error) {
	var res sandboxResource
	if err := p.api.doJSON(ctx, request{Method: http.MethodGet, URL: p.sandboxURL(name), Op: "get sandbox"}, nil, &res); err != nil {
		return sandboxResource{}, classify(err)
	}
	return res, nil
}

func (p *Provider) sandboxURL(name string) string {
	return p.api.controlPlane + "/sandboxes/" + url.PathEscape(name)
}

// Adopt replaces a sandbox's labels and idle-delete policy and reads the
// labels back. Labels are ownership: a mismatch is an error, never a partial
// success.
func (p *Provider) Adopt(ctx context.Context, sandboxID string, metadata map[string]string, idleTimeout time.Duration) error {
	var current struct {
		Metadata map[string]any `json:"metadata"`
		Spec     map[string]any `json:"spec"`
	}
	if err := p.api.doJSON(ctx, request{Method: http.MethodGet, URL: p.sandboxURL(sandboxID), Op: "get sandbox"}, nil, &current); err != nil {
		return fmt.Errorf("adopt sandbox %s: %w", sandboxID, classify(err))
	}
	if current.Metadata == nil || current.Spec == nil {
		return fmt.Errorf("%w: sandbox %s has no metadata", ErrUnavailable, sandboxID)
	}
	current.Metadata["labels"] = metadata
	// The same rule as Create: no requested timeout means the configured one.
	if idleTimeout <= 0 {
		idleTimeout = p.cfg.IdleTimeout.Std()
	}
	current.Spec["lifecycle"] = idleLifecycle(max(idleTimeout, minIdleTimeout))
	if err := p.api.doJSON(ctx, request{Method: http.MethodPut, URL: p.sandboxURL(sandboxID), Op: "adopt sandbox"},
		map[string]any{"metadata": current.Metadata, "spec": current.Spec}, nil); err != nil {
		return fmt.Errorf("adopt sandbox %s: %w", sandboxID, classify(err))
	}
	res, err := p.get(ctx, sandboxID)
	if err != nil {
		return fmt.Errorf("read back sandbox %s: %w", sandboxID, err)
	}
	if !maps.Equal(res.Metadata.Labels, metadata) {
		return fmt.Errorf("%w: sandbox %s does not report the requested metadata", ErrUnavailable, sandboxID)
	}
	return nil
}

// idleLifecycle is the ttl-idle delete policy used at create and adoption.
func idleLifecycle(idle time.Duration) map[string]any {
	return map[string]any{"expirationPolicies": []map[string]string{{
		"type": "ttl-idle", "value": strconv.Itoa(int(idle/time.Second)) + "s", "action": "delete",
	}}}
}

// updateNetwork replaces a live sandbox's network block and reads it back.
// The firewall cannot change after creation, so a sandbox without it is
// refused instead of being given an allowlist it would not enforce.
func (p *Provider) updateNetwork(ctx context.Context, name string, network sandbox.Network) error {
	want, err := translateNetwork(network)
	if err != nil {
		return err
	}
	var current struct {
		Metadata map[string]any `json:"metadata"`
		Spec     map[string]any `json:"spec"`
	}
	if err := p.api.doJSON(ctx, request{Method: http.MethodGet, URL: p.sandboxURL(name), Op: "get sandbox"}, nil, &current); err != nil {
		return classify(err)
	}
	if current.Spec == nil {
		return fmt.Errorf("%w: sandbox %s has no spec", ErrUnavailable, name)
	}
	var have networkSpec
	if raw, err := json.Marshal(current.Spec["network"]); err == nil {
		_ = json.Unmarshal(raw, &have)
	}
	if !have.enforced() {
		return fmt.Errorf("%w: sandbox %s was created without the proxy firewall", ErrEgressEnforcement, name)
	}
	current.Spec["network"] = want
	// The update response is discarded for the same reason as create's.
	if err := p.api.doJSON(ctx, request{Method: http.MethodPut, URL: p.sandboxURL(name), Op: "update sandbox network"},
		map[string]any{"metadata": current.Metadata, "spec": current.Spec}, nil); err != nil {
		return classify(err)
	}
	res, err := p.get(ctx, name)
	if err != nil {
		return fmt.Errorf("read back network policy: %w", err)
	}
	if !networkInEffect(want, res.Spec.Network) {
		return fmt.Errorf("%w: sandbox %s does not report the requested network policy", ErrEgressEnforcement, name)
	}
	return nil
}

// networkInEffect compares what was requested with what the API reports.
// Secrets are write-only and are excluded from the comparison.
func networkInEffect(want, have networkSpec) bool {
	if !have.enforced() {
		return false
	}
	strip := func(n networkSpec) networkSpec {
		out := networkSpec{Firewall: n.Firewall, Proxy: &proxySpec{}}
		if n.Proxy != nil {
			out.Proxy.AllowedDomains = n.Proxy.AllowedDomains
			out.Proxy.ForbiddenDomains = n.Proxy.ForbiddenDomains
			for _, r := range n.Proxy.Routing {
				headers := make(map[string]string, len(r.Headers))
				for k, v := range r.Headers {
					headers[http.CanonicalHeaderKey(k)] = v
				}
				out.Proxy.Routing = append(out.Proxy.Routing, proxyRoute{Destinations: r.Destinations, Headers: headers})
			}
		}
		return out
	}
	return reflect.DeepEqual(normalize(strip(want)), normalize(strip(have)))
}

// normalize treats nil and empty alike and ignores order and duplicates,
// because the API may return lists sorted, deduplicated, or omitted when
// empty. None of these change what the proxy enforces.
func normalize(n networkSpec) networkSpec {
	set := func(in []string) []string {
		if len(in) == 0 {
			return nil
		}
		out := slices.Clone(in)
		slices.Sort(out)
		return slices.Compact(out)
	}
	if n.Firewall != nil {
		n.Firewall = &firewallSpec{Rulesets: set(n.Firewall.Rulesets)}
	}
	if n.Proxy != nil {
		p := *n.Proxy
		p.AllowedDomains = set(p.AllowedDomains)
		p.ForbiddenDomains = set(p.ForbiddenDomains)
		routes := make([]proxyRoute, 0, len(p.Routing))
		for _, r := range p.Routing {
			routes = append(routes, proxyRoute{Destinations: set(r.Destinations), Headers: r.Headers})
		}
		slices.SortFunc(routes, func(a, b proxyRoute) int {
			return strings.Compare(strings.Join(a.Destinations, ","), strings.Join(b.Destinations, ","))
		})
		p.Routing = nil
		if len(routes) > 0 {
			p.Routing = routes
		}
		n.Proxy = &p
	}
	return n
}

// randomName generates a platform-valid, unguessable name for a sandbox or
// a process.
func randomName() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "esf-" + hex.EncodeToString(buf), nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

var (
	_ sandbox.Provider     = (*Provider)(nil)
	_ sandbox.Sandbox      = (*basetenSandbox)(nil)
	_ sandbox.FileStreamer = (*basetenSandbox)(nil)
	_ sandbox.Adopter      = (*Provider)(nil)
)
