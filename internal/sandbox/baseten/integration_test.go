//go:build baseten

// Live tests against Baseten Sandboxes. Run with:  make test-baseten
//
// They need FACTORY_BASETEN_API_KEY_FILE (a 0600 file holding a Baseten API
// key). FACTORY_BASETEN_REGION and FACTORY_BASETEN_TEMPLATE override the
// defaults below. Every test creates its own sandboxes, tags them, destroys
// them, and asserts they are gone: a leaked microVM is a test failure.
package baseten

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mitkox/esf/internal/sandbox"
)

const testOrigin = "factory-integration-test"

func liveProvider(t *testing.T) *Provider {
	t.Helper()
	keyFile := os.Getenv("FACTORY_BASETEN_API_KEY_FILE")
	if keyFile == "" {
		t.Fatal("FACTORY_BASETEN_API_KEY_FILE is not set")
	}
	cfg := Config{
		APIKeyFile: keyFile,
		Region:     envOr("FACTORY_BASETEN_REGION", "us-pdx-1"),
		Template:   envOr("FACTORY_BASETEN_TEMPLATE", "blaxel/claude-code:latest"),
		MemoryMiB:  2048,
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// liveSandbox creates a sandbox and registers verified cleanup.
func liveSandbox(t *testing.T, p *Provider, network sandbox.Network) sandbox.Sandbox {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	sb, err := p.Create(ctx, sandbox.Spec{
		Metadata:    map[string]string{"origin": testOrigin, "test": strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-"))},
		IdleTimeout: 10 * time.Minute,
		Env:         map[string]string{"ESF_IT_ENV": "kept"},
		Network:     network,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		if err := p.Destroy(ctx, sb.ID()); err != nil {
			t.Errorf("Destroy: %v", err)
		}
		infos, err := p.List(ctx)
		if err != nil {
			t.Errorf("List after destroy: %v", err)
		}
		for _, info := range infos {
			if info.ID == sb.ID() {
				t.Errorf("sandbox %s leaked (state %s)", sb.ID(), info.State)
			}
		}
	})
	return sb
}

func run(t *testing.T, sb sandbox.Sandbox, cmd sandbox.Command) sandbox.Execution {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if cmd.Timeout == 0 {
		cmd.Timeout = 90 * time.Second
	}
	exec, err := sb.Execute(ctx, cmd)
	if err != nil {
		t.Fatalf("Execute %q: %v", cmd.Description, err)
	}
	return exec
}

func TestLivePing(t *testing.T) {
	p := liveProvider(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := p.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestLiveExecuteAndReattach(t *testing.T) {
	p := liveProvider(t)
	sb := liveSandbox(t, p, sandbox.Network{})

	exec := run(t, sb, sandbox.Command{Script: "echo out; echo err >&2; exit 3"})
	if exec.ExitCode != 3 || exec.Stdout != "out\n" || exec.Stderr != "err\n" || exec.TimedOut {
		t.Fatalf("exit/stream separation: %+v", exec)
	}
	exec = run(t, sb, sandbox.Command{Argv: []string{"sh", "-c", `pwd; printf '%s' "$ESF_X"`, "it's"}, Dir: "/tmp", Env: map[string]string{"ESF_X": "a b'c"}})
	if !exec.Succeeded() || exec.Stdout != "/tmp\na b'c" {
		t.Fatalf("dir/env/quoting: %+v", exec)
	}
	exec = run(t, sb, sandbox.Command{Script: "sleep 30", Timeout: 3 * time.Second})
	if !exec.TimedOut {
		t.Fatalf("timeout not reported: %+v", exec)
	}
	exec = run(t, sb, sandbox.Command{Script: "head -c 10000000 /dev/zero"})
	if exec.ExitCode != 122 || !strings.Contains(exec.Stderr, "ESF_OUTPUT_LIMIT_EXCEEDED") {
		t.Fatalf("output limit not enforced: exit=%d stderr=%q", exec.ExitCode, exec.Stderr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	again, err := p.Reattach(ctx, sb.ID())
	if err != nil {
		t.Fatalf("Reattach: %v", err)
	}
	if again.Template() != sb.Template() {
		t.Fatalf("reattached template %q, want %q", again.Template(), sb.Template())
	}
	if exec := run(t, again, sandbox.Command{Argv: []string{"true"}}); !exec.Succeeded() {
		t.Fatalf("reattached execute: %+v", exec)
	}
}

func TestLiveFileRoundTrip(t *testing.T) {
	p := liveProvider(t)
	sb := liveSandbox(t, p, sandbox.Network{})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	for _, size := range []int{1024, 12 << 20} { // single request, then multipart
		data := make([]byte, size)
		_, _ = rand.Read(data)
		path := "/tmp/esf it/sub/blob.bin"
		if err := sb.WriteFile(ctx, path, data); err != nil {
			t.Fatalf("WriteFile %d bytes: %v", size, err)
		}
		sum := sha256.Sum256(data)
		exec := run(t, sb, sandbox.Command{Argv: []string{"sha256sum", path}})
		if !exec.Succeeded() || !strings.HasPrefix(exec.Stdout, hex.EncodeToString(sum[:])) {
			t.Fatalf("%d bytes: in-sandbox digest %q, want %x", size, exec.Stdout, sum)
		}
		back, err := sb.ReadFile(ctx, path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if !bytes.Equal(back, data) {
			t.Fatalf("%d bytes: read back %d bytes that differ", size, len(back))
		}
	}
	if err := sb.WriteFile(ctx, "/tmp/prompt.txt", []byte("hello; $(rm -rf /)\n")); err != nil {
		t.Fatal(err)
	}
	exec := run(t, sb, sandbox.Command{Argv: []string{"cat"}, StdinPath: "/tmp/prompt.txt"})
	if exec.Stdout != "hello; $(rm -rf /)\n" {
		t.Fatalf("StdinPath: %+v", exec)
	}
	if _, err := sb.ReadFile(ctx, "/tmp/does-not-exist"); err == nil {
		t.Fatal("ReadFile of a missing file succeeded")
	}
}

// TestLiveRuntimeLockdownInjectsWithoutExposing is the property the provider
// exists for: after UpdateNetwork, only the allowed endpoint is reachable,
// the proxy attaches the credential, and the sandbox never sees it.
func TestLiveRuntimeLockdownInjectsWithoutExposing(t *testing.T) {
	p := liveProvider(t)
	sb := liveSandbox(t, p, sandbox.Network{})

	code := `curl -sS -o /dev/null --max-time 10 -w '%{http_code}' `
	if exec := run(t, sb, sandbox.Command{Script: code + "https://example.com"}); exec.Stdout != "200" {
		t.Fatalf("setup phase should reach the internet: %+v", exec)
	}

	// UpdateNetwork round-trips the whole spec (as the vendor SDK does); the
	// live sandbox must keep its files and environment across it.
	if err := sb.WriteFile(context.Background(), "/tmp/state.txt", []byte("before-lockdown")); err != nil {
		t.Fatal(err)
	}

	secretBytes := make([]byte, 16)
	_, _ = rand.Read(secretBytes)
	secret := "esf-it-" + hex.EncodeToString(secretBytes)
	deny := false
	err := sb.(sandbox.NetworkUpdater).UpdateNetwork(context.Background(), sandbox.Network{
		AllowInternet: &deny,
		Rules: []sandbox.NetworkRule{{
			Name:  "factory-test-model",
			Match: sandbox.NetworkMatch{Scheme: "https", Host: "httpbin.org", SNI: "httpbin.org", Method: []string{"GET"}, Path: "/headers"},
			Action: sandbox.NetworkAction{Allow: true, Audit: "metadata", Inject: []sandbox.HeaderInjection{{
				Header: "x-api-key", Secret: secret, Format: "${SECRET}",
			}}},
		}},
	})
	if err != nil {
		t.Fatalf("UpdateNetwork: %v", err)
	}

	if exec := run(t, sb, sandbox.Command{Script: `cat /tmp/state.txt; printf ' %s' "$ESF_IT_ENV"`}); exec.Stdout != "before-lockdown kept" {
		t.Fatalf("the network update disturbed the live sandbox: %+v", exec)
	}
	if exec := run(t, sb, sandbox.Command{Script: code + "https://example.com"}); exec.Stdout == "200" {
		t.Fatalf("locked-down sandbox reached example.com: %+v", exec)
	}
	if exec := run(t, sb, sandbox.Command{Script: code + "-X POST https://httpbin.org/headers"}); exec.Stdout == "200" {
		t.Fatalf("method restriction not enforced: %+v", exec)
	}
	if exec := run(t, sb, sandbox.Command{Script: code + "https://httpbin.org/get"}); exec.Stdout == "200" {
		t.Fatalf("path restriction not enforced: %+v", exec)
	}
	if exec := run(t, sb, sandbox.Command{Script: "timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443' && echo open || echo closed"}); !strings.Contains(exec.Stdout, "closed") {
		t.Fatalf("direct egress bypassed the proxy: %+v", exec)
	}
	// The agent sends a placeholder; the proxy must replace it.
	echo := run(t, sb, sandbox.Command{Script: "curl -sS --max-time 10 -H 'x-api-key: cube-egress-managed-placeholder' https://httpbin.org/headers"})
	if !strings.Contains(echo.Stdout, secret) || strings.Contains(echo.Stdout, "placeholder") {
		t.Fatalf("credential was not injected in place of the placeholder (stdout redacted, %d bytes)", len(echo.Stdout))
	}
	leak := run(t, sb, sandbox.Command{Script: "env; cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n'; grep -rl esf-it- /etc /root /tmp /blaxel 2>/dev/null"})
	if strings.Contains(leak.Stdout+leak.Stderr, secret) {
		t.Fatal("the injected credential is visible inside the sandbox")
	}
}

// TestLiveDenyWins pins down the proxy's precedence, which the platform
// documents inconsistently: the factory's contract is that deny wins.
func TestLiveDenyWins(t *testing.T) {
	p := liveProvider(t)
	deny := false
	sb := liveSandbox(t, p, sandbox.Network{AllowInternet: &deny, AllowOut: []string{"httpbin.org", "*.example.com"}, DenyOut: []string{"www.example.com"}})
	code := `curl -sS -o /dev/null --max-time 10 -w '%{http_code}' `
	// Positive control: without it, a proxy that blocks everything would pass.
	if exec := run(t, sb, sandbox.Command{Script: code + "https://httpbin.org/get"}); exec.Stdout != "200" {
		t.Fatalf("httpbin.org is allowed but unreachable: %+v", exec)
	}
	if exec := run(t, sb, sandbox.Command{Script: code + "https://www.example.com"}); exec.Stdout == "200" {
		t.Fatalf("www.example.com matches allow *.example.com and deny_out; deny must win: %+v", exec)
	}
	if exec := run(t, sb, sandbox.Command{Script: code + "https://example.com"}); exec.Stdout == "200" {
		t.Fatalf("example.com is not matched by *.example.com but was reachable: %+v", exec)
	}
}
