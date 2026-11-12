package factory

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mitkox/esf/internal/sandbox/baseten"
	"github.com/mitkox/esf/internal/sandbox/cube"
)

func basetenConfig(t *testing.T) Config {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "baseten-api-key")
	if err := os.WriteFile(keyFile, []byte("bt-secret-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Default()
	cfg.Hardening.AcknowledgeOpenEgress = true
	cfg.Cube = cube.Config{} // a Baseten deployment needs no Cube settings
	cfg.Sandbox.Provider = "baseten"
	cfg.Baseten = baseten.Config{APIKeyFile: keyFile, Region: "us-pdx-1", Template: "blaxel/claude-code:latest"}
	return cfg
}

func TestSandboxProviderSelection(t *testing.T) {
	cfg := basetenConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("baseten config without cube settings: %v", err)
	}
	if cfg.SandboxProvider() != baseten.ProviderName || cfg.SandboxTemplate() != "blaxel/claude-code:latest" {
		t.Fatalf("provider=%q template=%q", cfg.SandboxProvider(), cfg.SandboxTemplate())
	}
	p, err := NewSandboxProvider(cfg, nil)
	if err != nil || p.Name() != baseten.ProviderName {
		t.Fatalf("NewSandboxProvider: %v %v", p, err)
	}

	cfg.Baseten.Region = ""
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "region") {
		t.Fatalf("selected provider's section is not validated: %v", err)
	}

	cfg.Sandbox.Provider = "firecracker"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("unknown provider accepted: %v", err)
	}
}

func TestDefaultProviderIsCube(t *testing.T) {
	t.Setenv("CUBE_API_URL", "http://127.0.0.1:4000")
	t.Setenv("CUBE_TEMPLATE_ID", "tpl-test")
	cfg := Default()
	cfg.Hardening.AcknowledgeOpenEgress = true
	for _, name := range []string{"", "cube", "cubesandbox"} {
		cfg.Sandbox.Provider = name
		if cfg.SandboxProvider() != cube.ProviderName || cfg.SandboxTemplate() != "tpl-test" {
			t.Fatalf("%q: provider=%q template=%q", name, cfg.SandboxProvider(), cfg.SandboxTemplate())
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%q: %v", name, err)
		}
	}
	// Cube remains validated when it is the provider.
	cfg.Cube.APIURL = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("cube provider validated without an API URL")
	}
}

func TestBasetenCredentialControlPlaneMustBeHTTPS(t *testing.T) {
	cfg := basetenConfig(t)
	if got := cfg.sandboxControlPlaneURL(); got != baseten.DefaultControlPlaneURL {
		t.Fatalf("control plane = %q", got)
	}
	if err := validateCredentialControlPlane(cfg.sandboxControlPlaneURL()); err != nil {
		t.Fatalf("default control plane rejected: %v", err)
	}
}

func TestBasetenKeyIsRedacted(t *testing.T) {
	cfg := basetenConfig(t)
	harnesses, err := cfg.BuildHarnesses()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(collectSecrets(cfg, harnesses), "bt-secret-key") {
		t.Fatal("the Baseten API key is not registered with the redactor")
	}
}

// Every backend must declare every hook: a missing one would silently fall
// back to a zero value (no secrets redacted, no control-plane check).
func TestSandboxBackendsAreComplete(t *testing.T) {
	for name, b := range sandboxBackends {
		if b.validate == nil || b.template == nil || b.controlPlaneURL == nil || b.secrets == nil || b.build == nil ||
			b.evidence == nil || b.doctor == nil || b.reachableCheck == "" || b.productionCheck == nil || b.pingSummary == nil {
			t.Errorf("sandbox backend %q is missing a declaration: %+v", name, b)
		}
	}
}

func TestBasetenDoctorAndEvidenceCarryNoSecret(t *testing.T) {
	cfg := basetenConfig(t)
	all := strings.Join(cfg.SandboxDoctorLines(), "\n") + cfg.SandboxPingSummary()
	for _, v := range cfg.sandboxEvidence() {
		all += fmt.Sprint(v)
	}
	if strings.Contains(all, "bt-secret-key") {
		t.Fatal("doctor or evidence output contains the API key")
	}
	if name, err := cfg.SandboxProductionCheck(); name != "sandbox_provider_production" || err == nil {
		t.Fatalf("production check = %q, %v", name, err)
	}
	if cfg.SandboxReachableCheck() != "baseten_reachable" {
		t.Fatal(cfg.SandboxReachableCheck())
	}
}
