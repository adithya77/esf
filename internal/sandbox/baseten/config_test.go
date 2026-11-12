package baseten

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mitkox/esf/internal/tomlx"
)

func validConfig(t *testing.T) Config {
	t.Helper()
	keyFile := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyFile, []byte(" k-123 \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Config{APIKeyFile: keyFile, Region: "us-pdx-1", Template: "blaxel/claude-code:latest"}
}

func TestConfigDefaultsAndValidation(t *testing.T) {
	cfg := validConfig(t)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	d := cfg.WithDefaults()
	if d.APIURL != DefaultAPIURL || d.ControlPlaneURL != DefaultControlPlaneURL || d.MemoryMiB != DefaultMemoryMiB ||
		d.IdleTimeout.Std() != DefaultIdleTimeout || d.CommandOutputBytes != DefaultCommandOutputBytes {
		t.Fatalf("defaults: %+v", d)
	}

	t.Setenv(apiKeyEnv, "")
	for name, mutate := range map[string]func(*Config){
		"region":             func(c *Config) { c.Region = "" },
		"template":           func(c *Config) { c.Template = "" },
		"http api_url":       func(c *Config) { c.APIURL = "http://api.baseten.co" },
		"http control":       func(c *Config) { c.ControlPlaneURL = "http://api.blaxel.ai/v0" },
		"userinfo":           func(c *Config) { c.ControlPlaneURL = "https://u:p@api.blaxel.ai/v0" },
		"memory":             func(c *Config) { c.MemoryMiB = 100 },
		"idle below minimum": func(c *Config) { c.IdleTimeout = 1e9 },
		"output limit":       func(c *Config) { c.CommandOutputBytes = 10 },
		"no key":             func(c *Config) { c.APIKeyFile = "" },
	} {
		cfg := validConfig(t)
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadAPIKey(t *testing.T) {
	cfg := validConfig(t)
	key, err := cfg.LoadAPIKey()
	if err != nil || key != "k-123" {
		t.Fatalf("key=%q err=%v", key, err)
	}
	if err := os.Chmod(cfg.APIKeyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.LoadAPIKey(); !errors.Is(err, ErrNotConfigured) || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("world-readable key accepted: %v", err)
	}

	t.Setenv(apiKeyEnv, "from-env")
	cfg.APIKeyFile = ""
	if key, err := cfg.LoadAPIKey(); err != nil || key != "from-env" {
		t.Fatalf("env fallback: %q %v", key, err)
	}
}

func TestStringNeverContainsKey(t *testing.T) {
	cfg := validConfig(t)
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cfg.String(), "k-123") || strings.Contains(p.Config().String(), "k-123") {
		t.Fatal("config string leaks the key")
	}
	if p.api.tokens.apiKey != "k-123" {
		t.Fatal("API key not resolved")
	}
}

func TestTokenExpiry(t *testing.T) {
	now := time.Unix(1000, 0)
	if got := tokenExpiry("not-a-jwt", now); !got.Equal(now.Add(tokenFallbackLifetime)) {
		t.Fatalf("fallback = %v", got)
	}
}

func tomlxDuration(d time.Duration) tomlx.Duration { return tomlx.FromStd(d) }

func TestShortLivedTokensAreStillCached(t *testing.T) {
	now := time.Unix(1000, 0)
	if got := refreshTime(now, now.Add(2*time.Hour)); !got.Equal(now.Add(2*time.Hour - tokenRefreshMargin)) {
		t.Fatalf("long token refresh at %v", got)
	}
	if got := refreshTime(now, now.Add(4*time.Minute)); !got.Equal(now.Add(2 * time.Minute)) {
		t.Fatalf("short token refresh at %v, want halfway", got)
	}
}

func TestKeySourceNeverShowsKey(t *testing.T) {
	cfg := validConfig(t)
	if got := cfg.KeySource(); got != "file "+cfg.APIKeyFile {
		t.Fatal(got)
	}
	t.Setenv(apiKeyEnv, "secret-env-key")
	cfg.APIKeyFile = ""
	if got := cfg.KeySource(); got != "environment BASETEN_API_KEY" {
		t.Fatal(got)
	}
}
