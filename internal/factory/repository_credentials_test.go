package factory

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	artifacts "github.com/mitkox/esf/internal/factoryartifacts"
	"github.com/mitkox/esf/internal/repository"
	"github.com/mitkox/esf/internal/sandbox"
)

const testGitHubToken = "github_pat_test_TOKEN_value"

func githubTokenConfig(t *testing.T) Config {
	t.Helper()
	file := filepath.Join(t.TempDir(), "github-token")
	if err := os.WriteFile(file, []byte(testGitHubToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testValidConfigForCredentialPolicy()
	cfg.Repositories.Allowed = []string{"https://github.com/acme/"}
	cfg.Repositories.GitHubTokenFile = file
	return cfg
}

func TestRepositoryCloneNetworkScopesTheTokenToOneRepository(t *testing.T) {
	cfg := githubTokenConfig(t)
	network, secrets, applies, err := cfg.repositoryCloneNetwork("https://github.com/acme/service.git")
	if err != nil || !applies {
		t.Fatalf("applies=%v err=%v", applies, err)
	}
	if network.AllowsInternet() {
		t.Fatal("the clone policy must deny all other egress")
	}
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + testGitHubToken))
	if !reflect.DeepEqual(secrets, []string{testGitHubToken, basic}) {
		t.Fatalf("secrets to redact = %v", secrets)
	}
	var endpoints []string
	for _, rule := range network.Rules {
		m := rule.Match
		if m.Host != "github.com" || m.SNI != "github.com" || m.Scheme != "https" || len(m.Method) != 1 {
			t.Fatalf("rule match too wide: %+v", m)
		}
		inj := rule.Action.Inject
		if !rule.Action.Allow || len(inj) != 1 || inj[0].Header != "Authorization" || inj[0].Format != "Basic ${SECRET}" || inj[0].Secret != basic {
			t.Fatalf("rule action: %+v", rule.Action)
		}
		endpoints = append(endpoints, m.Method[0]+" "+m.Path)
	}
	// Fetch only: no git-receive-pack, so a write-scoped token cannot push.
	want := []string{
		"GET /acme/service/info/refs", "POST /acme/service/git-upload-pack",
		"GET /acme/service.git/info/refs", "POST /acme/service.git/git-upload-pack",
	}
	if !reflect.DeepEqual(endpoints, want) {
		t.Fatalf("endpoints = %v", endpoints)
	}
}

func TestRepositoryCloneNetworkAppliesOnlyToGitHubHTTPS(t *testing.T) {
	cfg := githubTokenConfig(t)
	for _, url := range []string{"https://gitlab.com/acme/service", "ssh://github.com/acme/service", "https://github.com.evil.example/acme/service", "https://api.github.com/acme/service"} {
		if _, _, applies, err := cfg.repositoryCloneNetwork(url); applies || err != nil {
			t.Errorf("%s: applies=%v err=%v", url, applies, err)
		}
	}
	if _, _, applies, err := cfg.repositoryCloneNetwork("https://github.com/acme/.github"); !applies || err != nil {
		t.Errorf(".github repository: applies=%v err=%v", applies, err)
	}
	for _, url := range []string{"https://github.com/acme", "https://github.com/acme/service/tree/main", "https://github.com/acme/..", "https://github.com/-x/y"} {
		if _, _, _, err := cfg.repositoryCloneNetwork(url); err == nil {
			t.Errorf("%s: accepted", url)
		}
	}
	cfg.Repositories.GitHubTokenFile = ""
	if _, _, applies, _ := cfg.repositoryCloneNetwork("https://github.com/acme/service"); applies {
		t.Fatal("applied without a token file")
	}
}

func TestRepositoryTokenFileMustBeOwnerOnly(t *testing.T) {
	cfg := githubTokenConfig(t)
	if err := os.Chmod(cfg.Repositories.GitHubTokenFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := cfg.repositoryCloneNetwork("https://github.com/acme/service"); err == nil || !strings.Contains(err.Error(), "github_token_file") {
		t.Fatalf("world-readable token accepted: %v", err)
	}
	cfg.Repositories.GitHubTokenFile = "relative/token"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "github_token_file must be an absolute path") {
		t.Fatalf("relative token path accepted: %v", err)
	}
}

func TestGitHubTokenIsRedactedAtStartup(t *testing.T) {
	cfg := githubTokenConfig(t)
	got := cfg.repositoryCredentialSecrets()
	if len(got) != 2 || got[0] != testGitHubToken {
		t.Fatalf("secrets = %v", got)
	}
}

// netSandbox lets a test fail a specific network update.
type netSandbox struct {
	sandbox.Sandbox
	updates []sandbox.Network
	failOn  int // 1-based update to fail; 0 never
}

func (n *netSandbox) UpdateNetwork(_ context.Context, network sandbox.Network) error {
	n.updates = append(n.updates, network)
	if len(n.updates) == n.failOn {
		// Control planes may echo the submitted policy, secrets included.
		msg := "control plane said no"
		for _, rule := range network.Rules {
			for _, inj := range rule.Action.Inject {
				msg += "; secret " + inj.Secret
			}
		}
		return errors.New(msg)
	}
	return nil
}

// plainSandbox has no runtime network control.
type plainSandbox struct{ sandbox.Sandbox }

type wrapProvider struct {
	*sandbox.Fake
	wrap func(sandbox.Sandbox) sandbox.Sandbox
}

func (w wrapProvider) Reattach(ctx context.Context, id string) (sandbox.Sandbox, error) {
	sb, err := w.Fake.Reattach(ctx, id)
	if err != nil {
		return nil, err
	}
	return w.wrap(sb), nil
}

func credentialActivities(t *testing.T, wrap func(sandbox.Sandbox) sandbox.Sandbox) (*Activities, *sandbox.Fake, string) {
	t.Helper()
	cfg := githubTokenConfig(t)
	fake := sandbox.NewFake()
	fake.ExecuteFunc = func(cmd sandbox.Command) (sandbox.Execution, error) {
		if len(cmd.Argv) > 3 && cmd.Argv[3] == "rev-parse" {
			return sandbox.Execution{Stdout: "0123456789abcdef0123456789abcdef01234567\n"}, nil
		}
		return sandbox.Execution{}, nil
	}
	sb, err := fake.Create(context.Background(), sandbox.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifacts.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var provider sandbox.Provider = fake
	if wrap != nil {
		provider = wrapProvider{Fake: fake, wrap: wrap}
	}
	reg, err := cfg.BuildHarnesses()
	if err != nil {
		t.Fatal(err)
	}
	acts, err := NewActivities(ActivitiesOptions{
		Config: cfg, Provider: provider, Repositories: repository.New(cfg.Repositories.Allowed), Harnesses: reg,
		Profiles: cfg.VerificationProfiles(), ArtifactFactory: store, Redactor: NewRedactor(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return acts, fake, sb.ID()
}

func lockedPolicy() sandbox.Network {
	return sandbox.Network{AllowInternet: boolPointer(false)}
}

func remoteInput(sandboxID string, network sandbox.Network) PrepareRepositoryInput {
	return PrepareRepositoryInput{
		RunID: "run-gh", SandboxID: sandboxID, Network: network,
		Request: RunRequest{RunID: "run-gh", Repository: "https://github.com/acme/service", Revision: "main", Task: "t", AgentHarness: "opencode2", VerificationProfile: "default"},
	}
}

func TestCredentialedCloneAppliesThenWithdrawsTheToken(t *testing.T) {
	acts, fake, id := credentialActivities(t, nil)
	runPolicy := sandbox.Network{AllowInternet: boolPointer(false), AllowOut: []string{"pypi.org"}}
	out, err := acts.PrepareRepository(context.Background(), remoteInput(id, runPolicy))
	if err != nil {
		t.Fatalf("PrepareRepository: %v", err)
	}
	networks := fake.Networks(id)
	if len(networks) != 2 || len(networks[0].Rules) != 4 || !reflect.DeepEqual(networks[1], runPolicy) {
		t.Fatalf("network updates = %+v; want the clone policy, then the run policy restored", networks)
	}
	if !out.Baseline.Shallow || out.Baseline.Credential == "" {
		t.Fatalf("baseline = %+v", out.Baseline)
	}
	var fetched bool
	for _, cmd := range fake.Commands(id) {
		line := strings.Join(cmd.Argv, " ") + cmd.Script
		for _, v := range cmd.Env {
			line += v
		}
		if strings.Contains(line, testGitHubToken) || strings.Contains(line, "x-access-token") {
			t.Fatalf("the token reached a sandbox command: %q", line)
		}
		if strings.Contains(line, "fetch --depth 1 --no-tags --end-of-options origin main:refs/esf/base") {
			fetched = true
		}
	}
	if !fetched {
		t.Fatal("no shallow fetch of the exact revision")
	}
}

func TestCredentialedCloneRestoresEvenWhenTheFetchFails(t *testing.T) {
	acts, fake, id := credentialActivities(t, nil)
	fake.ExecuteFunc = func(cmd sandbox.Command) (sandbox.Execution, error) {
		if strings.Contains(strings.Join(cmd.Argv, " "), "fetch") {
			return sandbox.Execution{ExitCode: 128, Stderr: "fatal: repository not found"}, nil
		}
		return sandbox.Execution{}, nil
	}
	if _, err := acts.PrepareRepository(context.Background(), remoteInput(id, lockedPolicy())); err == nil {
		t.Fatal("a failed fetch succeeded")
	}
	if networks := fake.Networks(id); len(networks) != 2 || len(networks[1].Rules) != 0 {
		t.Fatalf("token route not withdrawn after a failed fetch: %+v", networks)
	}
}

func TestCredentialedCloneFailsClosed(t *testing.T) {
	t.Run("provider without network control", func(t *testing.T) {
		acts, fake, id := credentialActivities(t, func(sb sandbox.Sandbox) sandbox.Sandbox { return plainSandbox{sb} })
		_, err := acts.PrepareRepository(context.Background(), remoteInput(id, lockedPolicy()))
		if err == nil || !strings.Contains(err.Error(), "refusing to clone") {
			t.Fatalf("err = %v", err)
		}
		if len(fake.Commands(id)) != 0 {
			t.Fatal("cloned without the proxy credential")
		}
	})
	t.Run("clone policy rejected", func(t *testing.T) {
		var ns *netSandbox
		acts, fake, id := credentialActivities(t, func(sb sandbox.Sandbox) sandbox.Sandbox { ns = &netSandbox{Sandbox: sb, failOn: 1}; return ns })
		_, err := acts.PrepareRepository(context.Background(), remoteInput(id, lockedPolicy()))
		basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + testGitHubToken))
		if err == nil || strings.Contains(err.Error(), testGitHubToken) || strings.Contains(err.Error(), basic) {
			t.Fatalf("err = %v", err)
		}
		if len(fake.Commands(id)) != 0 {
			t.Fatal("fetched although the credential policy was not applied")
		}
		// The failed apply may still have gone live; the run policy is restored.
		if len(ns.updates) != 2 || !reflect.DeepEqual(ns.updates[1], lockedPolicy()) {
			t.Fatalf("updates after a failed apply = %+v", ns.updates)
		}
	})
	t.Run("run policy is the unstated deployment default", func(t *testing.T) {
		acts, fake, id := credentialActivities(t, nil)
		_, err := acts.PrepareRepository(context.Background(), remoteInput(id, sandbox.Network{}))
		if err == nil || !strings.Contains(err.Error(), "explicit egress policy") {
			t.Fatalf("err = %v", err)
		}
		if len(fake.Networks(id)) != 0 || len(fake.Commands(id)) != 0 {
			t.Fatal("cloned although the run policy could not be restored exactly")
		}
	})
	t.Run("restore rejected", func(t *testing.T) {
		acts, _, id := credentialActivities(t, func(sb sandbox.Sandbox) sandbox.Sandbox { return &netSandbox{Sandbox: sb, failOn: 2} })
		if _, err := acts.PrepareRepository(context.Background(), remoteInput(id, lockedPolicy())); err == nil || !strings.Contains(err.Error(), "withdraw repository credential") {
			t.Fatalf("a run continued with the token route in place: %v", err)
		}
	})
}

func TestUncredentialedRemoteCloneIsUnchanged(t *testing.T) {
	acts, fake, id := credentialActivities(t, nil)
	acts.cfg.Repositories.GitHubTokenFile = ""
	if _, err := acts.PrepareRepository(context.Background(), remoteInput(id, sandbox.Network{})); err != nil {
		t.Fatal(err)
	}
	if len(fake.Networks(id)) != 0 {
		t.Fatal("network changed for an uncredentialed clone")
	}
	for _, cmd := range fake.Commands(id) {
		if strings.Contains(strings.Join(cmd.Argv, " "), "git clone --no-tags --recurse-submodules") {
			return
		}
	}
	t.Fatal("the full clone path was not used")
}

func TestTokenFileIsCheckedAtStartupAndNeedsNetworkControl(t *testing.T) {
	cfg := githubTokenConfig(t)
	if err := cfg.CheckRepositoryCredentials(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg.Repositories.GitHubTokenFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cfg.CheckRepositoryCredentials(); err == nil {
		t.Fatal("a world-readable token passed the startup check")
	}

	cfg = githubTokenConfig(t)
	sandboxBackends["no-network-control"] = sandboxBackend{validate: func(Config) error { return nil }}
	t.Cleanup(func() { delete(sandboxBackends, "no-network-control") })
	cfg.Sandbox.Provider = "no-network-control"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "egress credential injection") {
		t.Fatalf("token accepted for a provider without network control: %v", err)
	}
}

func TestTokenRequiresHTTPSControlPlaneAndStatedPolicies(t *testing.T) {
	cfg := githubTokenConfig(t)
	cfg.Cube.APIURL = "http://10.0.0.5:3000"
	// Providers already require HTTPS for a remote control plane; the token
	// check is defence in depth. Either way the configuration is refused.
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("plaintext control plane accepted for the token: %v", err)
	}

	cfg = githubTokenConfig(t)
	cfg.Egress = map[string]EgressPolicyConfig{"open": {}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), `egress policy "open" must set allow_internet`) {
		t.Fatalf("unstated policy accepted: %v", err)
	}

	cfg = githubTokenConfig(t)
	cfg.Hardening.AcknowledgeOpenEgress = true
	cfg.Scopes = map[string]ScopeConfig{"default": {}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), `scope "default" must name an egress policy`) {
		t.Fatalf("scope without a policy accepted under acknowledged open egress: %v", err)
	}
}
