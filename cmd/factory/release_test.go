package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateConfigTextPreservesSettingsAndComments(t *testing.T) {
	old := "# operator note\nfactory_version = \"0.1.0\"\n[cube]\napi_url = \"http://127.0.0.1:4000\"\n"
	updated, changed, err := migrateConfigText(old)
	if err != nil || !changed {
		t.Fatalf("migration: changed=%v error=%v", changed, err)
	}
	if !strings.HasPrefix(updated, "schema_version = 1\n# operator note") || strings.Contains(updated, "factory_version") || !strings.Contains(updated, "api_url =") {
		t.Fatalf("migration lost settings: %q", updated)
	}
	if _, _, err := migrateConfigText("schema_version = 99\n"); err == nil {
		t.Fatal("accepted newer config schema")
	}
}

func TestProductionDoctorDoesNotQualifyBaseten(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "factory.toml")
	config := "[sandbox]\nprovider = \"baseten\"\n[baseten]\napi_key_file = \"" + keyFile + "\"\nregion = \"us-pdx-1\"\ntemplate = \"blaxel/claude-code:latest\"\n[hardening]\nacknowledge_open_egress = true\n"
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = write
	runErr := runStructuredDoctor(context.Background(), path, "production", "json", true)
	os.Stdout = stdout
	_ = write.Close()
	out, _ := io.ReadAll(read)
	if runErr == nil {
		t.Fatal("production doctor passed a Baseten deployment")
	}
	if !strings.Contains(string(out), `"name": "sandbox_provider_production"`) || !strings.Contains(string(out), "public preview") {
		t.Fatalf("missing fail-closed check:\n%s", out)
	}
	if strings.Contains(string(out), "cube_data_tls") {
		t.Fatalf("Cube-only check ran for Baseten:\n%s", out)
	}
}
