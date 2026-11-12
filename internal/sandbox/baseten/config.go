// Package baseten implements the factory's sandbox provider on Baseten
// Sandboxes.
//
// Baseten Sandboxes run on Blaxel microVMs. A Baseten API key mints a
// short-lived Blaxel-audience token (POST /v1/token), and that token drives
// Blaxel's control plane and each sandbox's data plane directly. The Blaxel
// control plane is used rather than Baseten's own sandbox API because only it
// exposes the egress proxy the factory's network lockdown and credential
// injection depend on: Baseten's create and update calls carry no network
// fields at all.
//
// Every sandbox is created with the proxy firewall ruleset, which forces all
// egress through Blaxel's proxy and can only be set at creation. That is what
// makes the later runtime lockdown (sandbox.NetworkUpdater) enforceable rather
// than advisory, so a sandbox that comes back without it is destroyed and the
// create fails closed.
package baseten

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/mitkox/esf/internal/sandbox"
	"github.com/mitkox/esf/internal/secretfile"
	"github.com/mitkox/esf/internal/tomlx"
)

// Defaults. The API endpoints are the public Baseten and Blaxel services; the
// template and region have no default because placement and image are
// operator decisions the factory must not guess.
const (
	DefaultAPIURL             = "https://api.baseten.co"
	DefaultControlPlaneURL    = "https://api.blaxel.ai/v0"
	DefaultMemoryMiB          = 4096
	DefaultIdleTimeout        = 30 * time.Minute
	DefaultRequestTimeout     = 60 * time.Second
	DefaultCommandOutputBytes = sandbox.DefaultCommandOutputBytes
	// DefaultMaxFileBytes bounds ReadFile so a runaway file inside the sandbox
	// cannot exhaust worker memory.
	DefaultMaxFileBytes int64 = 256 << 20

	// apiKeyEnv is read when api_key_file is not configured.
	apiKeyEnv = "BASETEN_API_KEY"
	// minIdleTimeout is the platform minimum for a ttl-idle policy.
	minIdleTimeout = time.Minute
	// minMemoryMiB is the smallest microVM the factory requests.
	minMemoryMiB = 512
)

// Config configures the Baseten provider.
//
// SECURITY: the API key is a credential. It is read from a 0600 file (or the
// BASETEN_API_KEY environment variable) by LoadAPIKey and is never written to
// configuration, evidence, logs, or a sandbox.
type Config struct {
	// APIKeyFile is a 0600 file holding the Baseten API key.
	APIKeyFile string `toml:"api_key_file"`
	// APIURL is the Baseten API that mints sandbox tokens.
	APIURL string `toml:"api_url"`
	// ControlPlaneURL is the Blaxel control-plane API (including /v0).
	ControlPlaneURL string `toml:"control_plane_url"`
	// Workspace is the Blaxel workspace backing the Baseten team. Empty means
	// "the only workspace the token can see", resolved on first use.
	Workspace string `toml:"workspace"`
	// Region pins sandbox placement. The region must report the egress proxy
	// as available; Ping verifies it.
	Region string `toml:"region"`
	// Template is the default sandbox image (for example
	// "blaxel/claude-code:latest"). A run may override it with an
	// operator-declared workspace template.
	Template string `toml:"template"`
	// MemoryMiB sizes the microVM; CPU scales with it (1 vCPU per 2048 MiB).
	MemoryMiB int `toml:"memory_mib"`
	// IdleTimeout deletes a sandbox after this long without activity. It is a
	// leak backstop; the factory's own verified cleanup is authoritative.
	IdleTimeout tomlx.Duration `toml:"idle_timeout"`
	// RequestTimeout bounds individual control-plane requests.
	RequestTimeout tomlx.Duration `toml:"request_timeout"`
	// CommandOutputBytes bounds stdout and stderr inside the sandbox.
	CommandOutputBytes int64 `toml:"command_output_bytes"`
}

// WithDefaults fills unset fields with the documented defaults.
func (c Config) WithDefaults() Config {
	if c.APIURL == "" {
		c.APIURL = DefaultAPIURL
	}
	if c.ControlPlaneURL == "" {
		c.ControlPlaneURL = DefaultControlPlaneURL
	}
	if c.MemoryMiB == 0 {
		c.MemoryMiB = DefaultMemoryMiB
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = tomlx.FromStd(DefaultIdleTimeout)
	}
	if c.RequestTimeout == 0 {
		c.RequestTimeout = tomlx.FromStd(DefaultRequestTimeout)
	}
	if c.CommandOutputBytes == 0 {
		c.CommandOutputBytes = DefaultCommandOutputBytes
	}
	return c
}

// Validate checks the static configuration. It does not read the key file;
// LoadAPIKey does, so `factory config validate` works without the secret.
func (c Config) Validate() error {
	c = c.WithDefaults()
	var problems []string
	for _, endpoint := range []struct{ name, value string }{
		{"api_url", c.APIURL},
		{"control_plane_url", c.ControlPlaneURL},
	} {
		if err := validateHTTPS(endpoint.value); err != nil {
			problems = append(problems, endpoint.name+" "+err.Error())
		}
	}
	if strings.TrimSpace(c.Region) == "" {
		problems = append(problems, "region is required (a region whose egress proxy is available, for example us-pdx-1)")
	}
	if strings.TrimSpace(c.Template) == "" {
		problems = append(problems, "template is required (a sandbox image such as blaxel/claude-code:latest)")
	}
	if c.MemoryMiB < minMemoryMiB {
		problems = append(problems, "memory_mib must be at least 512")
	}
	if c.IdleTimeout.Std() < minIdleTimeout {
		problems = append(problems, "idle_timeout must be at least 1m")
	}
	if c.RequestTimeout < 0 {
		problems = append(problems, "request_timeout must not be negative")
	}
	if c.CommandOutputBytes < 2048 {
		problems = append(problems, "command_output_bytes must be at least 2048")
	}
	if strings.TrimSpace(c.APIKeyFile) == "" && os.Getenv(apiKeyEnv) == "" {
		problems = append(problems, "api_key_file is required (a 0600 file holding the Baseten API key), or set "+apiKeyEnv)
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid baseten configuration: %s", strings.Join(problems, "; "))
	}
	return nil
}

// LoadAPIKey resolves the API key from api_key_file, falling back to the
// environment. The file must be owner-only; a world-readable key is refused.
func (c Config) LoadAPIKey() (string, error) {
	if path := strings.TrimSpace(c.APIKeyFile); path != "" {
		data, err := secretfile.Read(path, 4096)
		if err != nil {
			return "", fmt.Errorf("%w: read baseten api_key_file: %v", ErrNotConfigured, err)
		}
		key := strings.TrimSpace(string(data))
		if key == "" {
			return "", fmt.Errorf("%w: baseten api_key_file is empty", ErrNotConfigured)
		}
		return key, nil
	}
	if key := strings.TrimSpace(os.Getenv(apiKeyEnv)); key != "" {
		return key, nil
	}
	return "", fmt.Errorf("%w: no Baseten API key (set api_key_file or %s)", ErrNotConfigured, apiKeyEnv)
}

// KeySource describes where the key comes from, for diagnostics. It never
// includes the key.
func (c Config) KeySource() string {
	if path := strings.TrimSpace(c.APIKeyFile); path != "" {
		return "file " + path
	}
	if os.Getenv(apiKeyEnv) != "" {
		return "environment " + apiKeyEnv
	}
	return "unset"
}

// String is safe to log: it never includes the key.
func (c Config) String() string {
	c = c.WithDefaults()
	return fmt.Sprintf("baseten{control_plane=%s workspace=%q region=%s template=%s}",
		c.ControlPlaneURL, c.Workspace, c.Region, c.Template)
}

func validateHTTPS(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return errors.New("must be an absolute URL")
	}
	if u.Scheme != "https" {
		return errors.New("must use HTTPS: it carries the API key and egress credentials")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must not contain userinfo, query, or fragment")
	}
	return nil
}
