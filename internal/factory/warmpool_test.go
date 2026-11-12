package factory

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	artifacts "github.com/mitkox/esf/internal/factoryartifacts"
	"github.com/mitkox/esf/internal/repository"
	"github.com/mitkox/esf/internal/sandbox"
	"github.com/mitkox/esf/internal/tomlx"
)

type warmFixture struct {
	acts  *Activities
	fake  *sandbox.Fake
	repo  string
	store artifacts.Factory
	mu    sync.Mutex
	cmds  []string
}

func newWarmFixture(t *testing.T, mutate ...func(*Config)) *warmFixture {
	t.Helper()
	f := &warmFixture{repo: newFixtureRepo(t)}
	cfg := testValidConfigForCredentialPolicy()
	cfg.Storage.DataDir = t.TempDir()
	cfg.Repositories.LocalPaths = []string{f.repo}
	cfg.Sandbox.BasePackages = nil
	cfg.Sandbox.Warm = WarmPoolConfig{Enabled: true, Size: 2, Repositories: []WarmRepository{{LocalPath: f.repo}}}
	for _, m := range mutate {
		m(&cfg)
	}
	f.fake = sandbox.NewFake()
	f.fake.ExecuteFunc = func(cmd sandbox.Command) (sandbox.Execution, error) {
		f.mu.Lock()
		f.cmds = append(f.cmds, cmd.Description+" "+strings.Join(cmd.Argv, " "))
		f.mu.Unlock()
		if cmd.Description == "check for submodules" {
			return sandbox.Execution{ExitCode: 1}, nil // no .gitmodules
		}
		return gitAwareExecute("")(cmd)
	}
	reg, err := cfg.BuildHarnesses()
	if err != nil {
		t.Fatal(err)
	}
	f.store, err = artifacts.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f.acts, err = NewActivities(ActivitiesOptions{
		Config: cfg, Provider: f.fake, Harnesses: reg, Profiles: cfg.VerificationProfiles(), ArtifactFactory: f.store,
		Repositories: repository.New(nil, repository.WithLocalPaths(cfg.Repositories.LocalPaths)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *warmFixture) ran(description string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.cmds {
		if strings.HasPrefix(c, description) {
			return true
		}
	}
	return false
}

func (f *warmFixture) status(t *testing.T) WarmPoolStatus {
	t.Helper()
	st, err := NewWarmPoolService(f.acts).Status()
	if err != nil || len(st) != 1 {
		t.Fatalf("status %v %v", st, err)
	}
	return st[0]
}

func runInput(f *warmFixture) CreateSandboxInput {
	return CreateSandboxInput{ExecutionID: "wf-1", RunID: "run-warm", Harness: "opencode2", LocalPath: f.repo,
		Network: sandbox.Network{AllowInternet: boolPointer(false)}}
}

func TestWarmPoolFillsToSizeWithUnownedMembers(t *testing.T) {
	f := newWarmFixture(t)
	if err := NewWarmPoolService(f.acts).Fill(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := f.status(t); st.Ready != 2 || st.Filling != 0 {
		t.Fatalf("status = %+v", st)
	}
	infos, _ := f.fake.List(context.Background())
	if len(infos) != 2 {
		t.Fatalf("live sandboxes = %d", len(infos))
	}
	for _, info := range infos {
		// Pool members never look like a run's sandbox (or a leak).
		if info.Metadata["origin"] != warmPoolOrigin || info.Metadata["run_id"] != "" {
			t.Fatalf("member labels = %v", info.Metadata)
		}
	}
	if !f.ran("warm secret check") {
		t.Fatal("members were not checked for credentials")
	}
	// A second fill is a no-op: the pool is full.
	if err := NewWarmPoolService(f.acts).Fill(context.Background()); err != nil || len(f.fake.Live()) != 2 {
		t.Fatalf("over-filled: %d live, %v", len(f.fake.Live()), err)
	}
}

func TestWarmClaimHandsOverOwnershipAndPolicy(t *testing.T) {
	f := newWarmFixture(t)
	if err := NewWarmPoolService(f.acts).Fill(context.Background()); err != nil {
		t.Fatal(err)
	}
	in := runInput(f)
	out, err := f.acts.CreateSandbox(context.Background(), in)
	if err != nil || out.Warm == nil {
		t.Fatalf("claim: %+v %v", out, err)
	}
	infos, _ := f.fake.List(context.Background())
	var claimed sandbox.Info
	for _, info := range infos {
		if info.ID == out.SandboxID {
			claimed = info
		}
	}
	if !ownsSandbox(claimed, in.RunID, in.ExecutionID) {
		t.Fatalf("claimed sandbox is not owned by the run: %v", claimed.Metadata)
	}
	nets := f.fake.Networks(out.SandboxID)
	if len(nets) == 0 || !reflect.DeepEqual(nets[len(nets)-1], in.Network) {
		t.Fatalf("the run's egress policy was not applied: %+v", nets)
	}
	if st := f.status(t); st.Ready != 1 {
		t.Fatalf("pool after claim = %+v", st)
	}
	if out.Warm.Base.SHA != testSHA {
		t.Fatalf("claim base = %+v", out.Warm.Base)
	}
	// Adoption also gave it the run's idle timeout and the warm labels.
	if claimed.Metadata[warmPoolLabel] == "" || claimed.Metadata[warmBaseLabel] != testSHA {
		t.Fatalf("warm labels = %v", claimed.Metadata)
	}
	// A retried CreateSandbox recovers the claimed sandbox by ownership, as
	// warm, and applies the run's policy again.
	before := len(f.fake.Networks(out.SandboxID))
	again, err := f.acts.CreateSandbox(context.Background(), in)
	if err != nil || again.SandboxID != out.SandboxID || again.Warm == nil || again.Warm.Base.SHA != testSHA {
		t.Fatalf("recovery: %+v %v", again, err)
	}
	if nets := f.fake.Networks(out.SandboxID); len(nets) != before+1 || !reflect.DeepEqual(nets[len(nets)-1], in.Network) {
		t.Fatalf("recovery did not re-apply the run's policy: %+v", nets)
	}
}

func TestWarmClaimFallsBackToCold(t *testing.T) {
	cases := map[string]func(*CreateSandboxInput){
		"run environment":     func(in *CreateSandboxInput) { in.Env = map[string]string{"K": "v"} },
		"different resources": func(in *CreateSandboxInput) { in.Limits = sandbox.Limits{MemoryMiB: 8192} },
		"other repository":    func(in *CreateSandboxInput) { in.LocalPath = "/elsewhere" },
		"unstated policy":     func(in *CreateSandboxInput) { in.Network = sandbox.Network{} },
		"other directory":     func(in *CreateSandboxInput) { in.RepositoryDir = "/workspace/app" },
		"workspace packages":  func(in *CreateSandboxInput) { in.BasePackages = []string{"git", "make"} },
		"workspace setup":     func(in *CreateSandboxInput) { in.SetupScript = "echo workspace" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newWarmFixture(t)
			if err := NewWarmPoolService(f.acts).Fill(context.Background()); err != nil {
				t.Fatal(err)
			}
			in := runInput(f)
			mutate(&in)
			out, err := f.acts.CreateSandbox(context.Background(), in)
			if err != nil || out.Warm != nil {
				t.Fatalf("expected a cold create: %+v %v", out, err)
			}
			if st := f.status(t); st.Ready != 2 {
				t.Fatalf("a member was consumed: %+v", st)
			}
		})
	}
}

func TestExpiredMembersAreReapedNotClaimed(t *testing.T) {
	f := newWarmFixture(t, func(c *Config) { c.Sandbox.Warm.MaxAge = tomlx.FromStd(time.Nanosecond) })
	if err := NewWarmPoolService(f.acts).Fill(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Millisecond)
	out, err := f.acts.CreateSandbox(context.Background(), runInput(f))
	if err != nil || out.Warm != nil {
		t.Fatalf("an expired member was claimed: %+v %v", out, err)
	}
	// Only the cold sandbox remains: the expired members were destroyed (in
	// the background, so the run did not wait for it).
	deadline := time.Now().Add(5 * time.Second)
	for len(f.fake.Live()) != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if live := f.fake.Live(); len(live) != 1 || live[0] != out.SandboxID {
		t.Fatalf("live = %v", live)
	}
}

func TestWarmMemberWithCredentialsIsRefused(t *testing.T) {
	f := newWarmFixture(t)
	base := f.fake.ExecuteFunc
	f.fake.ExecuteFunc = func(cmd sandbox.Command) (sandbox.Execution, error) {
		if cmd.Description == "warm secret check" {
			return sandbox.Execution{ExitCode: 1, Stderr: "warm sandbox holds credentials: git-credential-config"}, nil
		}
		return base(cmd)
	}
	err := NewWarmPoolService(f.acts).Fill(context.Background())
	if err == nil || !strings.Contains(err.Error(), "holds credentials") {
		t.Fatalf("err = %v", err)
	}
	if st := f.status(t); st.Ready != 0 || st.Filling != 0 || len(f.fake.Live()) != 0 {
		t.Fatalf("refused member kept: %+v live=%v", st, f.fake.Live())
	}
}

func TestDrainDestroysEveryMember(t *testing.T) {
	f := newWarmFixture(t)
	pool := NewWarmPoolService(f.acts)
	if err := pool.Fill(context.Background()); err != nil {
		t.Fatal(err)
	}
	n, err := pool.Drain(context.Background())
	if err != nil || n != 2 || len(f.fake.Live()) != 0 {
		t.Fatalf("drain: n=%d live=%v err=%v", n, f.fake.Live(), err)
	}
	if st := f.status(t); st.Ready != 0 {
		t.Fatalf("status after drain = %+v", st)
	}
}

func TestWarmPrepareRerunsOnlyWhenLockfilesChange(t *testing.T) {
	f := newWarmFixture(t, func(c *Config) { c.Sandbox.Warm.PrepareCommand = []string{"yarn", "install", "--immutable"} })
	sb, err := f.fake.Create(context.Background(), sandbox.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(claim *WarmClaim) Preparation {
		t.Helper()
		f.mu.Lock()
		f.cmds = nil
		f.mu.Unlock()
		_, err := f.acts.PrepareRepository(context.Background(), PrepareRepositoryInput{
			RunID: "run-warm", SandboxID: sb.ID(), Network: sandbox.Network{AllowInternet: boolPointer(false)}, Warm: claim,
			AcquireDuration: 2 * time.Second,
			Request:         RunRequest{RunID: "run-warm", LocalPath: f.repo, RepositoryKind: "local", Revision: "HEAD", Task: "t", AgentHarness: "opencode2", VerificationProfile: "default"},
		})
		if err != nil {
			t.Fatalf("PrepareRepository: %v", err)
		}
		store, _ := f.store.ForRun("run-warm")
		var ev Preparation
		data, err := store.Read(ArtifactPreparation)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.Unmarshal(data, &ev)
		return ev
	}

	// Unchanged lockfiles: no prepare.
	ev := prepare(&WarmClaim{Base: repository.WarmBase{SHA: testSHA}})
	if ev.Path != "warm" || ev.PrepareRerun || f.ran("warm prepare command") || ev.AcquireDuration != 2*time.Second {
		t.Fatalf("evidence = %+v", ev)
	}
	// A lockfile changed since the base: prepare runs again.
	ev = prepare(&WarmClaim{Base: repository.WarmBase{SHA: testSHA, LockfileHashes: map[string]string{"yarn.lock": "old"}}})
	if !ev.PrepareRerun || !f.ran("warm prepare command") {
		t.Fatalf("prepare did not re-run: %+v", ev)
	}
	// The cold path records its evidence too.
	ev = prepare(nil)
	if ev.Path != "cold" || ev.Warm != nil {
		t.Fatalf("cold evidence = %+v", ev)
	}
}

func TestWarmPoolValidation(t *testing.T) {
	cfg := testValidConfigForCredentialPolicy()
	cfg.Sandbox.Warm = WarmPoolConfig{Enabled: true}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "relabel") || !strings.Contains(err.Error(), "sandbox.warm.repositories") {
		t.Fatalf("cube + empty pool accepted: %v", err)
	}
}

func TestDrainLeavesClaimsAndOtherDeploymentsAlone(t *testing.T) {
	f := newWarmFixture(t)
	pool := NewWarmPoolService(f.acts)
	if err := pool.Fill(context.Background()); err != nil {
		t.Fatal(err)
	}
	key := f.acts.cfg.warmKey(f.acts.cfg.Sandbox.Warm.Repositories[0])
	var claimingID string
	if err := f.acts.warm.update(key, func(doc *warmPoolFile) {
		doc.Members[0].State, doc.Members[0].ClaimedAt = warmClaiming, time.Now()
		claimingID = doc.Members[0].SandboxID
	}); err != nil {
		t.Fatal(err)
	}
	other, err := f.fake.Create(context.Background(), sandbox.Spec{Metadata: map[string]string{"origin": warmPoolOrigin, "pool": "another-deployment"}})
	if err != nil {
		t.Fatal(err)
	}
	n, err := pool.Drain(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("drained %d, %v", n, err)
	}
	live := strings.Join(f.fake.Live(), ",")
	if !strings.Contains(live, claimingID) || !strings.Contains(live, other.ID()) {
		t.Fatalf("drain destroyed a claim or another deployment's member: live=%s", live)
	}
}

func TestWarmPrepareSandboxSkipsSetupAlreadyDone(t *testing.T) {
	f := newWarmFixture(t, func(c *Config) { c.Sandbox.SetupScript = "echo setup" })
	sb, err := f.fake.Create(context.Background(), sandbox.Spec{})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.cmds = nil
	f.mu.Unlock()
	_, _ = f.acts.PrepareSandbox(context.Background(), PrepareSandboxInput{RunID: "r", SandboxID: sb.ID(), Harness: "opencode2",
		SetupScript: "echo setup", WorkspaceResolved: true, Warm: true})
	if f.ran("operator setup script") || f.ran("install factory base packages") {
		t.Fatal("a warm sandbox ran its setup again")
	}
}

func TestRepositoryWithSubmodulesIsNotPooled(t *testing.T) {
	f := newWarmFixture(t)
	base := f.fake.ExecuteFunc
	f.fake.ExecuteFunc = func(cmd sandbox.Command) (sandbox.Execution, error) {
		if cmd.Description == "check for submodules" {
			return sandbox.Execution{ExitCode: 0}, nil
		}
		return base(cmd)
	}
	err := NewWarmPoolService(f.acts).Fill(context.Background())
	if err == nil || !strings.Contains(err.Error(), "submodules") || len(f.fake.Live()) != 0 {
		t.Fatalf("err=%v live=%v", err, f.fake.Live())
	}
}

func TestRemoteRevisionExpressionsGoCold(t *testing.T) {
	f := newWarmFixture(t)
	in := runInput(f)
	in.LocalPath, in.Repository, in.Revision = "", "https://github.com/acme/service", "main~1"
	if f.acts.warmEligible(in, sandbox.Spec{Template: f.acts.cfg.SandboxTemplate()}) {
		t.Fatal("a revision the warm fetch cannot name was eligible")
	}
	in.Revision = "main"
	if !f.acts.warmEligible(in, sandbox.Spec{Template: f.acts.cfg.SandboxTemplate()}) {
		t.Fatal("a ref name was not eligible")
	}
}
