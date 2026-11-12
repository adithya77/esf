//go:build baseten

// Live test of a private GitHub clone with a proxy-injected token on Baseten.
//
//	FACTORY_BASETEN_API_KEY_FILE=... FACTORY_GITHUB_TOKEN_FILE=... \
//	FACTORY_GITHUB_REPO=https://github.com/<owner>/<repo> [FACTORY_GITHUB_REV=main] \
//	  go test -tags baseten ./internal/factory -run LiveGitHub -v
package factory

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	artifacts "github.com/mitkox/esf/internal/factoryartifacts"
	"github.com/mitkox/esf/internal/repository"
	"github.com/mitkox/esf/internal/sandbox"
	"github.com/mitkox/esf/internal/sandbox/baseten"
)

func TestLiveGitHubCloneWithInjectedToken(t *testing.T) {
	keyFile, tokenFile, repoURL := os.Getenv("FACTORY_BASETEN_API_KEY_FILE"), os.Getenv("FACTORY_GITHUB_TOKEN_FILE"), os.Getenv("FACTORY_GITHUB_REPO")
	if keyFile == "" || tokenFile == "" || repoURL == "" {
		t.Skip("set FACTORY_BASETEN_API_KEY_FILE, FACTORY_GITHUB_TOKEN_FILE and FACTORY_GITHUB_REPO")
	}
	rev := os.Getenv("FACTORY_GITHUB_REV")
	if rev == "" {
		rev = "HEAD"
	}
	token, err := readCredentialFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}

	cfg := testValidConfigForCredentialPolicy()
	cfg.Sandbox.Provider = baseten.ProviderName
	cfg.Baseten = baseten.Config{APIKeyFile: keyFile, Region: "us-pdx-1", Template: "blaxel/py-app:latest", MemoryMiB: 2048}
	cfg.Repositories.Allowed = []string{strings.TrimSuffix(repoURL, ".git")}
	cfg.Repositories.GitHubTokenFile = tokenFile
	provider, err := NewSandboxProvider(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := cfg.BuildHarnesses()
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifacts.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	acts, err := NewActivities(ActivitiesOptions{Config: cfg, Provider: provider, Repositories: repository.New(cfg.Repositories.Allowed),
		Harnesses: reg, Profiles: cfg.VerificationProfiles(), ArtifactFactory: store, Redactor: NewRedactor()})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	locked := sandbox.Network{AllowInternet: boolPointer(false)}
	sb, err := provider.Create(ctx, sandbox.Spec{Metadata: map[string]string{"origin": "factory-integration-test", "test": "github-clone"}, IdleTimeout: 10 * time.Minute, Network: locked})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if err := provider.Destroy(ctx, sb.ID()); err != nil {
			t.Errorf("Destroy: %v", err)
		}
		infos, _ := provider.List(ctx)
		for _, info := range infos {
			if info.ID == sb.ID() {
				t.Errorf("sandbox %s leaked", sb.ID())
			}
		}
	})

	run := func(script string) sandbox.Execution {
		t.Helper()
		exec, err := sb.Execute(ctx, sandbox.Command{Script: script, Timeout: 2 * time.Minute})
		if err != nil {
			t.Fatal(err)
		}
		return exec
	}
	dest := "/workspace/repository"
	// Before preparation, the locked sandbox cannot see the repository.
	if exec := run("git ls-remote " + repoURL + " >/dev/null 2>&1 && echo open || echo closed"); !strings.Contains(exec.Stdout, "closed") {
		t.Fatal("the repository was reachable before the clone policy was applied")
	}

	started := time.Now()
	out, err := acts.PrepareRepository(ctx, PrepareRepositoryInput{RunID: "run-live-gh", SandboxID: sb.ID(), Network: locked,
		Request: RunRequest{RunID: "run-live-gh", Repository: repoURL, Revision: rev, Task: "t", AgentHarness: "opencode2", VerificationProfile: "default"}})
	if err != nil {
		t.Fatalf("PrepareRepository: %v", err)
	}
	t.Logf("MEASURE repo=%s rev=%s sha=%s prepare=%s", repoURL, rev, out.Baseline.SHA, time.Since(started).Round(time.Millisecond))
	if len(out.Baseline.SHA) != 40 || !out.Baseline.Shallow || out.Baseline.Credential == "" {
		t.Fatalf("baseline = %+v", out.Baseline)
	}
	if exec := run("git -C " + dest + " rev-list --count HEAD"); strings.TrimSpace(exec.Stdout) != "1" {
		t.Fatalf("history depth %q", exec.Stdout)
	}
	// The token never entered the VM: not in the environment, any process,
	// the repository's config, or the filesystem.
	leak := run("env; cat /proc/*/environ 2>/dev/null | tr '\\0' '\\n'; cat " + dest + "/.git/config; grep -rIl -F -- '" + token[:12] + "' /workspace /root /tmp /etc 2>/dev/null")
	if strings.Contains(leak.Stdout+leak.Stderr, token) || strings.Contains(leak.Stdout, token[:12]) {
		t.Fatal("the GitHub token is visible inside the sandbox")
	}
	// After preparation the credential route is gone.
	if exec := run("git -C " + dest + " ls-remote origin >/dev/null 2>&1 && echo open || echo closed"); !strings.Contains(exec.Stdout, "closed") {
		t.Fatal("the repository was still reachable after the credential was withdrawn")
	}
}
