package baseten

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mitkox/esf/internal/sandbox"
)

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestCreateRequestsProxyFirewallAndWaitsForDeploy(t *testing.T) {
	f := newFake(t)
	p := f.provider(t)
	sb, err := p.Create(ctxT(t), sandbox.Spec{
		Metadata:    map[string]string{"origin": "factory", "run_id": "run-1"},
		Env:         map[string]string{"FOO": "bar"},
		IdleTimeout: 10 * time.Minute,
		Limits:      sandbox.Limits{MemoryMiB: 8192},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !strings.HasPrefix(sb.ID(), "esf-") || sb.Template() != "blaxel/claude-code:latest" {
		t.Fatalf("handle: id=%q template=%q", sb.ID(), sb.Template())
	}
	req := f.body("POST /v0/sandboxes")
	spec := req["spec"].(map[string]any)
	if spec["region"] != "us-pdx-1" {
		t.Fatalf("region: %v", spec["region"])
	}
	runtime := spec["runtime"].(map[string]any)
	if runtime["memory"] != float64(8192) || runtime["image"] != "blaxel/claude-code:latest" {
		t.Fatalf("runtime: %v", runtime)
	}
	if envs := runtime["envs"].([]any); len(envs) != 1 || envs[0].(map[string]any)["name"] != "FOO" {
		t.Fatalf("envs: %v", runtime["envs"])
	}
	policy := spec["lifecycle"].(map[string]any)["expirationPolicies"].([]any)[0].(map[string]any)
	if policy["type"] != "ttl-idle" || policy["value"] != "600s" || policy["action"] != "delete" {
		t.Fatalf("lifecycle: %v", policy)
	}
	network := spec["network"].(map[string]any)
	if rs := network["firewall"].(map[string]any)["rulesets"].([]any); len(rs) != 1 || rs[0] != "proxy" {
		t.Fatalf("firewall: %v", network)
	}
	if allowed := network["proxy"].(map[string]any)["allowedDomains"].([]any); len(allowed) != 1 || allowed[0] != "*" {
		t.Fatalf("an open create must keep a non-empty proxy block: %v", network)
	}
	labels := req["metadata"].(map[string]any)["labels"].(map[string]any)
	if labels["run_id"] != "run-1" {
		t.Fatalf("labels: %v", labels)
	}
	if f.count("GET /v0/sandboxes/"+sb.ID()) < 2 {
		t.Fatal("Create returned before the sandbox was deployed")
	}
}

func TestCreateFailsClosedWithoutFirewallAndCleansUp(t *testing.T) {
	f := newFake(t)
	f.onCreate = func(map[string]any) (string, map[string]any) {
		// The platform accepted the create but dropped the firewall.
		return "DEPLOYED", map[string]any{"proxy": map[string]any{"allowedDomains": []string{"*"}}}
	}
	p := f.provider(t)
	_, err := p.Create(ctxT(t), sandbox.Spec{})
	if !errors.Is(err, ErrEgressEnforcement) {
		t.Fatalf("err = %v, want ErrEgressEnforcement", err)
	}
	if f.count("DELETE /v0/sandboxes/") != 1 {
		t.Fatal("the unenforceable sandbox was not destroyed")
	}
}

func TestCreateRefusesUnenforceablePolicyBeforeCallingAPI(t *testing.T) {
	f := newFake(t)
	p := f.provider(t)
	deny := false
	_, err := p.Create(ctxT(t), sandbox.Spec{Network: sandbox.Network{AllowInternet: &deny, AllowOut: []string{"10.0.0.0/8"}}})
	if !errors.Is(err, ErrUnsupportedPolicy) {
		t.Fatalf("err = %v", err)
	}
	if f.count("POST /v0/sandboxes") != 0 {
		t.Fatal("an unenforceable policy reached the API")
	}
}

func TestCreateFailedStatusIsUnavailable(t *testing.T) {
	f := newFake(t)
	f.onCreate = func(map[string]any) (string, map[string]any) { return "FAILED", nil }
	p := f.provider(t)
	if _, err := p.Create(ctxT(t), sandbox.Spec{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestAPIKeyOnlyReachesTokenEndpointAndTokenIsCached(t *testing.T) {
	f := newFake(t)
	p := f.provider(t)
	for i := 0; i < 3; i++ {
		if _, err := p.List(ctxT(t)); err != nil {
			t.Fatal(err)
		}
	}
	// The fake rejects the raw key everywhere but /v1/token, so success here
	// already proves the key stayed put; also check minting happened once.
	if f.tokens != 1 {
		t.Fatalf("minted %d tokens, want 1 cached", f.tokens)
	}
}

func TestExpiredTokenIsRefreshed(t *testing.T) {
	f := newFake(t)
	p := f.provider(t)
	if _, err := p.List(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	p.api.tokens.now = func() time.Time { return time.Now().Add(3 * time.Hour) }
	if _, err := p.List(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if f.tokens != 2 {
		t.Fatalf("minted %d tokens, want a refresh", f.tokens)
	}
}

func TestRejectedKeyIsAuthenticationError(t *testing.T) {
	f := newFake(t)
	f.rejectToken = true
	p := f.provider(t)
	err := p.Ping(ctxT(t))
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), testAPIKey) {
		t.Fatal("error leaks the API key")
	}
}

func TestWorkspaceDiscovery(t *testing.T) {
	f := newFake(t)
	p := f.provider(t)
	if err := p.Ping(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if p.api.workspace != "baseten-team" {
		t.Fatalf("workspace = %q", p.api.workspace)
	}

	f2 := newFake(t)
	f2.workspaces = []string{"a", "b"}
	err := f2.provider(t).Ping(ctxT(t))
	if !errors.Is(err, ErrNotConfigured) || !strings.Contains(err.Error(), "a, b") {
		t.Fatalf("ambiguous workspaces: %v", err)
	}

	f3 := newFake(t)
	f3.workspaces = []string{"a", "b"}
	if err := f3.provider(t, func(c *Config) { c.Workspace = "b" }).Ping(ctxT(t)); err != nil {
		t.Fatalf("explicit workspace: %v", err)
	}
}

func TestPingRequiresProxyInRegion(t *testing.T) {
	f := newFake(t)
	f.regions = []map[string]any{{"name": "us-pdx-1", "proxyAvailable": false}}
	if err := f.provider(t).Ping(ctxT(t)); !errors.Is(err, ErrEgressEnforcement) {
		t.Fatalf("err = %v", err)
	}
	f.regions = []map[string]any{{"name": "eu-lon-1", "proxyAvailable": true}}
	if err := f.provider(t).Ping(ctxT(t)); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v", err)
	}
}

func TestReattachAndNotFound(t *testing.T) {
	f := newFake(t)
	p := f.provider(t)
	sb, err := p.Create(ctxT(t), sandbox.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	again, err := p.Reattach(ctxT(t), sb.ID())
	if err != nil || again.ID() != sb.ID() {
		t.Fatalf("Reattach: %v", err)
	}
	if _, err := p.Reattach(ctxT(t), "esf-missing"); !errors.Is(err, ErrSandboxNotFound) {
		t.Fatalf("missing: %v", err)
	}
	f.sandboxes[sb.ID()]["status"] = "TERMINATED"
	if _, err := p.Reattach(ctxT(t), sb.ID()); !errors.Is(err, ErrSandboxNotFound) {
		t.Fatalf("terminated: %v", err)
	}
}

func TestDestroyWaitsUntilTerminatedAndIsIdempotent(t *testing.T) {
	f := newFake(t)
	f.deleteWait = 3
	p := f.provider(t)
	sb, err := p.Create(ctxT(t), sandbox.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	if err := sb.Destroy(ctxT(t)); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if got := f.sandboxes[sb.ID()]["status"]; got != "TERMINATED" {
		t.Fatalf("Destroy returned while %v", got)
	}
	infos, _ := p.List(ctxT(t))
	if len(infos) != 0 {
		t.Fatalf("terminated sandbox still listed: %v", infos)
	}
	if err := p.Destroy(ctxT(t), sb.ID()); err != nil {
		t.Fatalf("second Destroy: %v", err)
	}
	if err := p.Destroy(ctxT(t), "esf-never-existed"); err != nil {
		t.Fatalf("Destroy of unknown: %v", err)
	}
}

func TestListMapsInfoAndFollowsPages(t *testing.T) {
	for _, paged := range []bool{false, true} {
		f := newFake(t)
		f.listPages = paged
		p := f.provider(t)
		for i := 0; i < 3; i++ {
			if _, err := p.Create(ctxT(t), sandbox.Spec{Metadata: map[string]string{"origin": "factory"}}); err != nil {
				t.Fatal(err)
			}
		}
		infos, err := p.List(ctxT(t))
		if err != nil {
			t.Fatal(err)
		}
		if len(infos) != 3 {
			t.Fatalf("paged=%v: %d infos", paged, len(infos))
		}
		for _, info := range infos {
			if info.State != sandbox.StateRunning || info.Template != "blaxel/claude-code:latest" ||
				info.Metadata["origin"] != "factory" || info.ProviderID != ProviderName || info.StartedAt.IsZero() {
				t.Fatalf("info: %+v", info)
			}
		}
	}
}

func TestUpdateNetworkPreservesSpecAndVerifiesReadBack(t *testing.T) {
	f := newFake(t)
	p := f.provider(t)
	sb, err := p.Create(ctxT(t), sandbox.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	deny := false
	err = sb.(sandbox.NetworkUpdater).UpdateNetwork(ctxT(t), sandbox.Network{
		AllowInternet: &deny,
		Rules: []sandbox.NetworkRule{{
			Name:   "model",
			Match:  sandbox.NetworkMatch{Scheme: "https", Host: "api.example.com", SNI: "api.example.com", Method: []string{"POST"}, Path: "/v1/messages"},
			Action: sandbox.NetworkAction{Allow: true, Inject: []sandbox.HeaderInjection{{Header: "x-api-key", Secret: "sk-secret-value", Format: "${SECRET}"}}},
		}},
	})
	if err != nil {
		t.Fatalf("UpdateNetwork: %v", err)
	}
	put := f.body("PUT /v0/sandboxes/" + sb.ID())
	spec := put["spec"].(map[string]any)
	if spec["runtime"].(map[string]any)["image"] != "blaxel/claude-code:latest" || spec["region"] != "us-pdx-1" {
		t.Fatalf("update dropped the rest of the spec: %v", spec)
	}
	proxy := spec["network"].(map[string]any)["proxy"].(map[string]any)
	if allowed := proxy["allowedDomains"].([]any); len(allowed) != 1 || allowed[0] != "POST:api.example.com/v1/messages" {
		t.Fatalf("allowlist: %v", proxy)
	}
	route := proxy["routing"].([]any)[0].(map[string]any)
	if route["headers"].(map[string]any)["X-Api-Key"] != "{{SECRET:esf-secret-0}}" ||
		route["secrets"].(map[string]any)["esf-secret-0"] != "sk-secret-value" {
		t.Fatalf("route: %v", route)
	}
}

func TestUpdateNetworkRefusesSandboxWithoutFirewall(t *testing.T) {
	f := newFake(t)
	p := f.provider(t)
	sb, err := p.Create(ctxT(t), sandbox.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	delete(f.sandboxes[sb.ID()]["spec"].(map[string]any), "network")
	deny := false
	err = sb.(sandbox.NetworkUpdater).UpdateNetwork(ctxT(t), sandbox.Network{AllowInternet: &deny})
	if !errors.Is(err, ErrEgressEnforcement) {
		t.Fatalf("err = %v", err)
	}
	if f.count("PUT ") != 0 {
		t.Fatal("an unenforceable policy was written")
	}
}

func TestNetworkInEffectDetectsDrift(t *testing.T) {
	deny := false
	want, err := translateNetwork(sandbox.Network{AllowInternet: &deny, AllowOut: []string{"github.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if !networkInEffect(want, want) {
		t.Fatal("identical policies differ")
	}
	drift := want
	drift.Proxy = &proxySpec{AllowedDomains: []string{"*"}}
	if networkInEffect(want, drift) {
		t.Fatal("a widened allowlist was accepted")
	}
	noFirewall := want
	noFirewall.Firewall = nil
	if networkInEffect(want, noFirewall) {
		t.Fatal("a missing firewall was accepted")
	}
}

func TestExecuteStartsDetachedAndPolls(t *testing.T) {
	f := newFake(t)
	f.processAfter = func(name string, polls int) map[string]any {
		if polls < 3 {
			return map[string]any{"status": "running"}
		}
		return map[string]any{"status": "failed", "exitCode": 3, "stdout": "out\n", "stderr": "err\n"}
	}
	p := f.provider(t)
	sb, _ := p.Create(ctxT(t), sandbox.Spec{})
	exec, err := sb.Execute(ctxT(t), sandbox.Command{Argv: []string{"echo", "a b"}, Dir: "/work", Env: map[string]string{"K": "v"}, Timeout: 90 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if exec.ExitCode != 3 || exec.Stdout != "out\n" || exec.Stderr != "err\n" || exec.TimedOut {
		t.Fatalf("exec: %+v", exec)
	}
	req := f.body("POST /data/process")
	if req["waitForCompletion"] != false || req["keepAlive"] != true || req["timeout"] != float64(90) ||
		req["workingDir"] != "/work" || req["env"].(map[string]any)["K"] != "v" {
		t.Fatalf("start request: %v", req)
	}
	command := req["command"].(string)
	if !strings.Contains(command, "'echo' 'a b'") || !strings.Contains(command, "ESF_OUTPUT_LIMIT_EXCEEDED") {
		t.Fatalf("command not quoted and bounded: %q", command)
	}
}

func TestExecuteReportsServerTimeout(t *testing.T) {
	f := newFake(t)
	f.processAfter = func(string, int) map[string]any {
		return map[string]any{"status": "killed", "exitCode": 137}
	}
	p := f.provider(t)
	sb, _ := p.Create(ctxT(t), sandbox.Spec{})
	exec, err := sb.Execute(ctxT(t), sandbox.Command{Script: "sleep 100", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !exec.TimedOut || exec.ExitCode != -1 {
		t.Fatalf("exec: %+v", exec)
	}
}

func TestExecuteKillsOnContextDeadline(t *testing.T) {
	f := newFake(t)
	f.processAfter = func(string, int) map[string]any { return map[string]any{"status": "running"} }
	p := f.provider(t)
	sb, _ := p.Create(ctxT(t), sandbox.Spec{})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	exec, err := sb.Execute(ctx, sandbox.Command{Script: "sleep 100"})
	if err != nil {
		t.Fatal(err)
	}
	if !exec.TimedOut || exec.ExitCode != -1 {
		t.Fatalf("exec: %+v", exec)
	}
	if len(f.killed) != 1 {
		t.Fatalf("abandoned process not killed: %v", f.killed)
	}
	// A context deadline also bounds the server-side timeout.
	if timeout := f.body("POST /data/process")["timeout"].(float64); timeout < 1 || timeout > 1 {
		t.Fatalf("server timeout = %v, want the remaining deadline (1s)", timeout)
	}
}

func TestExecuteToleratesTransientPollFailures(t *testing.T) {
	f := newFake(t)
	p := f.provider(t)
	sb, _ := p.Create(ctxT(t), sandbox.Spec{})
	f.pollFailures = maxPollFailures
	exec, err := sb.Execute(ctxT(t), sandbox.Command{Argv: []string{"true"}})
	if err != nil || exec.Stdout != "ok\n" {
		t.Fatalf("exec=%+v err=%v", exec, err)
	}
	f.pollFailures = maxPollFailures + 1
	if _, err := sb.Execute(ctxT(t), sandbox.Command{Argv: []string{"true"}}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("persistent failure: %v", err)
	}
}

func TestFileRoundTripSingleAndMultipart(t *testing.T) {
	f := newFake(t)
	p := f.provider(t)
	sb, _ := p.Create(ctxT(t), sandbox.Spec{})
	small := []byte{0, 1, 2, 0xff, '\n'}
	if err := sb.WriteFile(ctxT(t), "/tmp/a b/x.bin", small); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.files["/tmp/a%20b/x.bin"]; !ok {
		t.Fatalf("absolute path not preserved: %v", keys(f.files))
	}
	got, err := sb.ReadFile(ctxT(t), "/tmp/a b/x.bin")
	if err != nil || !bytes.Equal(got, small) {
		t.Fatalf("read back %v err=%v", got, err)
	}

	large := bytes.Repeat([]byte{7, 0, 9}, (singleUploadBytes*2+100)/3)
	if err := sb.WriteFile(ctxT(t), "/srv/big.bin", large); err != nil {
		t.Fatal(err)
	}
	if got := f.files["/srv/big.bin"]; !bytes.Equal(got, large) {
		t.Fatalf("multipart reassembled %d bytes, want %d", len(got), len(large))
	}
	if parts := len(f.uploads["up0"]); parts != 3 {
		t.Fatalf("parts = %d", parts)
	}
	complete := f.body("POST /data/filesystem-multipart/up0/complete")
	if len(complete["parts"].([]any)) != 3 {
		t.Fatalf("complete: %v", complete)
	}
}

func TestMultipartFailureAborts(t *testing.T) {
	f := newFake(t)
	f.failPart = true
	p := f.provider(t)
	sb, _ := p.Create(ctxT(t), sandbox.Spec{})
	err := sb.WriteFile(ctxT(t), "/srv/big.bin", make([]byte, singleUploadBytes*2))
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err = %v", err)
	}
	if f.aborted != 1 {
		t.Fatal("failed upload was not aborted")
	}
}

func TestReadMissingFileIsNotFound(t *testing.T) {
	f := newFake(t)
	p := f.provider(t)
	sb, _ := p.Create(ctxT(t), sandbox.Spec{})
	if _, err := sb.ReadFile(ctxT(t), "/nope"); !errors.Is(err, ErrSandboxNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestFilePathRefusesRelativeAndTraversal(t *testing.T) {
	for _, p := range []string{"relative/x", "/", "/a/../etc/passwd", "/a/./b"} {
		if _, err := filePath(p); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
	if got, _ := filePath("/a b/c%d"); got != "/a%20b/c%25d" {
		t.Fatalf("escaped = %q", got)
	}
}

func TestErrorsNeverEchoResponseBodies(t *testing.T) {
	err := readAPIError(fakeResponse(400, `{"error":"bad","spec":{"secrets":{"k":"sk-live-secret"}}}`), "op")
	if strings.Contains(err.Error(), "sk-live-secret") || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("error = %v", err)
	}
	err = readAPIError(fakeResponse(502, "upstream reset"), "op")
	if !strings.Contains(err.Error(), "upstream reset") {
		t.Fatalf("plain-text error lost: %v", err)
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestCreateToleratesReadAfterCreateLag(t *testing.T) {
	f := newFake(t)
	f.missingGets = 2
	if _, err := f.provider(t).Create(ctxT(t), sandbox.Spec{}); err != nil {
		t.Fatalf("a 404 right after create failed the create: %v", err)
	}
}

func TestReattachEnforcesFirewallAndWaitsForDeploy(t *testing.T) {
	f := newFake(t)
	p := f.provider(t)
	sb, err := p.Create(ctxT(t), sandbox.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	// A sandbox recovered by List after an ambiguous create may still be
	// starting: Reattach waits instead of handing out an unready data plane.
	f.sandboxes[sb.ID()]["status"] = "DEPLOYING"
	f.sandboxes[sb.ID()]["polls"] = 0
	if _, err := p.Reattach(ctxT(t), sb.ID()); err != nil {
		t.Fatalf("Reattach of a deploying sandbox: %v", err)
	}
	// ...and one without the firewall is refused, not handed out.
	delete(f.sandboxes[sb.ID()]["spec"].(map[string]any), "network")
	if _, err := p.Reattach(ctxT(t), sb.ID()); !errors.Is(err, ErrEgressEnforcement) {
		t.Fatalf("Reattach without firewall: %v", err)
	}
	// A missing sandbox is not retried as if it were lagging.
	if _, err := p.Reattach(ctxT(t), "esf-gone"); !errors.Is(err, ErrSandboxNotFound) || f.count("GET /v0/sandboxes/esf-gone") != 1 {
		t.Fatalf("missing sandbox: %v (gets=%d)", err, f.count("GET /v0/sandboxes/esf-gone"))
	}
}

func TestExecuteRejectsUnknownProcessStatus(t *testing.T) {
	for _, status := range []string{"", "starting"} {
		f := newFake(t)
		f.processAfter = func(string, int) map[string]any { return map[string]any{"status": status, "exitCode": 0} }
		p := f.provider(t)
		sb, _ := p.Create(ctxT(t), sandbox.Spec{})
		// An error, not a result: a zero Execution would read as exit 0.
		if _, err := sb.Execute(ctxT(t), sandbox.Command{Argv: []string{"true"}}); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("status %q: err = %v", status, err)
		}
		if len(f.killed) != 1 {
			t.Fatalf("status %q: process not killed", status)
		}
	}
}

func TestUnboundedCommandStillGetsServerTimeout(t *testing.T) {
	f := newFake(t)
	p := f.provider(t)
	sb, _ := p.Create(ctxT(t), sandbox.Spec{})
	if _, err := sb.Execute(context.Background(), sandbox.Command{Argv: []string{"true"}}); err != nil {
		t.Fatal(err)
	}
	if got := f.body("POST /data/process")["timeout"]; got != float64(maxCommandDuration/time.Second) {
		t.Fatalf("timeout = %v; keepAlive without a timeout would outlive an abandoned run", got)
	}
}

func TestTokenMintIsBounded(t *testing.T) {
	f := newFake(t)
	f.tokenDelay = 5 * time.Second
	p := f.provider(t, func(c *Config) { c.RequestTimeout = tomlxDuration(200 * time.Millisecond) })
	started := time.Now()
	if _, err := p.List(context.Background()); err == nil {
		t.Fatal("a stalled mint succeeded")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("mint held the token lock for %s", elapsed)
	}
}

func TestListDoesNotRequestATruncatedPage(t *testing.T) {
	f := newFake(t)
	if _, err := f.provider(t).List(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if len(f.listQueries) != 1 || f.listQueries[0] != "" {
		t.Fatalf("list queries = %q", f.listQueries)
	}
}

func TestReadyFailsFastOnUnusableStatusAndReportsCancellation(t *testing.T) {
	f := newFake(t)
	p := f.provider(t)
	sb, err := p.Create(ctxT(t), sandbox.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	f.sandboxes[sb.ID()]["status"] = "DEACTIVATED"
	started := time.Now()
	if _, err := p.Reattach(ctxT(t), sb.ID()); !errors.Is(err, ErrUnavailable) || time.Since(started) > time.Second {
		t.Fatalf("DEACTIVATED: %v after %s", err, time.Since(started))
	}
	f.sandboxes[sb.ID()]["status"] = "BUILDING" // never finishes in the fake
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := p.Reattach(ctx, sb.ID()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("caller deadline reported as %v", err)
	}
}

func TestDestroyToleratesTransientErrors(t *testing.T) {
	f := newFake(t)
	p := f.provider(t)
	sb, err := p.Create(ctxT(t), sandbox.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	f.getFailures = maxPollFailures
	if err := p.Destroy(ctxT(t), sb.ID()); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
}

func TestCreateRejectsMemoryBelowMinimum(t *testing.T) {
	f := newFake(t)
	_, err := f.provider(t).Create(ctxT(t), sandbox.Spec{Limits: sandbox.Limits{MemoryMiB: 64}})
	if !errors.Is(err, ErrInvalidSpec) || f.count("POST /v0/sandboxes") != 0 {
		t.Fatalf("err = %v", err)
	}
}

func TestNetworkInEffectIgnoresOrderAndDuplicates(t *testing.T) {
	want := networkSpec{Firewall: &firewallSpec{Rulesets: []string{"proxy"}}, Proxy: &proxySpec{
		AllowedDomains: []string{"b.example", "a.example", "a.example"},
		Routing:        []proxyRoute{{Destinations: []string{"y.example"}, Headers: map[string]string{"X": "1"}}, {Destinations: []string{"x.example"}}},
	}}
	have := networkSpec{Firewall: &firewallSpec{Rulesets: []string{"proxy"}}, Proxy: &proxySpec{
		AllowedDomains: []string{"a.example", "b.example"},
		Routing:        []proxyRoute{{Destinations: []string{"x.example"}}, {Destinations: []string{"y.example"}, Headers: map[string]string{"x": "1"}}},
	}}
	if !networkInEffect(want, have) {
		t.Fatal("an equivalent policy was reported as not in effect")
	}
	have.Proxy.AllowedDomains = append(have.Proxy.AllowedDomains, "c.example")
	if networkInEffect(want, have) {
		t.Fatal("a widened policy was accepted")
	}
}
