package factory

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/mitkox/esf/internal/sandbox"
	"github.com/mitkox/esf/internal/sandbox/baseten"
	"github.com/mitkox/esf/internal/sandbox/cube"
)

// sandboxBackend declares everything the factory needs to know about one
// sandbox provider. Adding a provider is one entry in sandboxBackends; no
// other code branches on the provider name.
type sandboxBackend struct {
	validate func(Config) error
	// template is the provider's default template (a Cube template ID, a
	// Baseten image).
	template func(Config) string
	// controlPlaneURL is where provider-side egress credentials are sent.
	controlPlaneURL func(Config) string
	// secrets are registered with the redactor before any run starts.
	secrets func(Config) []string
	build   func(Config, *slog.Logger) (sandbox.Provider, error)
	// evidence is recorded in every run's environment record. Never secrets.
	evidence func(Config) map[string]any
	// doctor lists "label: value" lines for `factory doctor`. Never secrets.
	doctor func(Config) []string
	// reachableCheck names the structured-doctor connectivity check.
	reachableCheck string
	// productionCheck is the provider's `doctor --profile production` gate.
	productionCheck func(Config) (string, error)
	// pingSummary describes what a successful Ping proved.
	pingSummary func(Config) string
}

var sandboxBackends = map[string]sandboxBackend{
	cube.ProviderName: {
		validate:        func(c Config) error { return c.Cube.Validate() },
		template:        func(c Config) string { return c.Cube.TemplateID },
		controlPlaneURL: func(c Config) string { return c.Cube.APIURL },
		secrets:         func(c Config) []string { return nonEmpty(c.Cube.APIKey) },
		build: func(c Config, log *slog.Logger) (sandbox.Provider, error) {
			if c.Limits.CommandOutputBytes > 0 {
				c.Cube.CommandOutputBytes = c.Limits.CommandOutputBytes
			}
			return cube.New(c.Cube, cube.WithLogger(log))
		},
		evidence: func(c Config) map[string]any {
			return map[string]any{"cube_api_url": c.Cube.APIURL, "cube_version": c.Cube.Version}
		},
		doctor: func(c Config) []string {
			key := "unset"
			if c.Cube.APIKey != "" {
				key = "[REDACTED]"
			}
			return []string{"cube api:        " + c.Cube.APIURL, "cube template:   " + c.Cube.TemplateID, "cube api key:    " + key}
		},
		reachableCheck: "cube_reachable",
		productionCheck: func(c Config) (string, error) {
			if c.Cube.ProxyNodeIP != "" && c.Cube.ProxyScheme != "https" {
				return "cube_data_tls", fmt.Errorf("cube.proxy_scheme must be https")
			}
			return "cube_data_tls", nil
		},
		pingSummary: func(c Config) string { return "template " + c.Cube.TemplateID + " exists" },
	},
	baseten.ProviderName: {
		validate:        func(c Config) error { return c.Baseten.Validate() },
		template:        func(c Config) string { return c.Baseten.Template },
		controlPlaneURL: func(c Config) string { return c.Baseten.WithDefaults().ControlPlaneURL },
		secrets: func(c Config) []string {
			key, err := c.Baseten.LoadAPIKey()
			if err != nil {
				return nil
			}
			return []string{key}
		},
		build: func(c Config, log *slog.Logger) (sandbox.Provider, error) {
			if c.Limits.CommandOutputBytes > 0 {
				c.Baseten.CommandOutputBytes = c.Limits.CommandOutputBytes
			}
			return baseten.New(c.Baseten, baseten.WithLogger(log))
		},
		evidence: func(c Config) map[string]any {
			b := c.Baseten.WithDefaults()
			return map[string]any{"baseten_control_plane_url": b.ControlPlaneURL, "baseten_region": b.Region}
		},
		doctor: func(c Config) []string {
			b := c.Baseten.WithDefaults()
			return []string{"baseten api:     " + b.ControlPlaneURL, "baseten region:  " + b.Region,
				"baseten image:   " + b.Template, "baseten api key: " + b.KeySource()}
		},
		reachableCheck: "baseten_reachable",
		// The data plane is HTTPS by construction, but egress enforcement
		// depends on a vendor public preview.
		productionCheck: func(Config) (string, error) {
			return "sandbox_provider_production", fmt.Errorf("baseten egress enforcement depends on Blaxel's proxy, which is a public preview and not production-qualified")
		},
		pingSummary: func(c Config) string {
			// The image is pulled at create time; Ping cannot check it.
			return "region " + c.Baseten.Region + " has the egress proxy, template " + c.Baseten.Template
		},
	},
}

// SandboxProvider returns the selected provider name, defaulting to Cube so
// existing configurations keep their meaning.
func (c Config) SandboxProvider() string {
	provider := strings.ToLower(strings.TrimSpace(c.Sandbox.Provider))
	if provider == "" || provider == "cube" {
		return cube.ProviderName
	}
	return provider
}

// sandboxBackend returns the selected provider's declaration.
func (c Config) sandboxBackend() (sandboxBackend, error) {
	backend, ok := sandboxBackends[c.SandboxProvider()]
	if !ok {
		names := make([]string, 0, len(sandboxBackends))
		for name := range sandboxBackends {
			names = append(names, name)
		}
		sort.Strings(names)
		return sandboxBackend{}, fmt.Errorf("sandbox.provider %q is not supported (use one of: %s)", c.Sandbox.Provider, strings.Join(names, ", "))
	}
	return backend, nil
}

// mustBackend is for accessors called after Validate, which has already
// rejected an unknown provider; an empty backend yields zero values.
func (c Config) mustBackend() sandboxBackend {
	backend, _ := c.sandboxBackend()
	return backend
}

// SandboxTemplate is the selected provider's default template.
func (c Config) SandboxTemplate() string {
	if b := c.mustBackend(); b.template != nil {
		return b.template(c)
	}
	return ""
}

// SandboxDoctorLines describes the provider configuration for `doctor`.
func (c Config) SandboxDoctorLines() []string {
	if b := c.mustBackend(); b.doctor != nil {
		return b.doctor(c)
	}
	return nil
}

// SandboxReachableCheck names the structured-doctor connectivity check.
func (c Config) SandboxReachableCheck() string {
	if b := c.mustBackend(); b.reachableCheck != "" {
		return b.reachableCheck
	}
	return "sandbox_reachable"
}

// SandboxProductionCheck is the provider's production-profile gate.
func (c Config) SandboxProductionCheck() (string, error) {
	b, err := c.sandboxBackend()
	if err != nil {
		return "sandbox_provider", err
	}
	return b.productionCheck(c)
}

// SandboxPingSummary describes what a successful Ping verified.
func (c Config) SandboxPingSummary() string {
	if b := c.mustBackend(); b.pingSummary != nil {
		return b.pingSummary(c)
	}
	return ""
}

// sandboxControlPlaneURL is where provider-side egress credentials are sent.
func (c Config) sandboxControlPlaneURL() string {
	if b := c.mustBackend(); b.controlPlaneURL != nil {
		return b.controlPlaneURL(c)
	}
	return ""
}

func (c Config) sandboxSecrets() []string {
	if b := c.mustBackend(); b.secrets != nil {
		return b.secrets(c)
	}
	return nil
}

func (c Config) sandboxEvidence() map[string]any {
	if b := c.mustBackend(); b.evidence != nil {
		return b.evidence(c)
	}
	return nil
}

// NewSandboxProvider builds the provider selected by sandbox.provider.
func NewSandboxProvider(cfg Config, log *slog.Logger) (sandbox.Provider, error) {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	backend, err := cfg.sandboxBackend()
	if err != nil {
		return nil, err
	}
	p, err := backend.build(cfg, log)
	if err != nil {
		return nil, fmt.Errorf("build %s provider: %w", cfg.SandboxProvider(), err)
	}
	return p, nil
}

func nonEmpty(values ...string) []string {
	var out []string
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
